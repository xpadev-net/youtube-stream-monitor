package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"go.uber.org/zap"
)

const (
	// LabelApp is the app label for worker pods.
	LabelApp = "app"
	// LabelAppValue is the value for the app label.
	LabelAppValue = "stream-monitor"
	// LabelMonitorID is the label key for monitor ID.
	LabelMonitorID = "monitor-id"
	// PodNamePrefix is the prefix for worker pod names.
	PodNamePrefix = "stream-monitor-"
)

// Client wraps Kubernetes client operations.
type Client struct {
	clientset  *kubernetes.Clientset
	namespace  string
	workerImage string
	workerTag   string
}

// Config holds configuration for creating a K8s client.
type Config struct {
	InCluster      bool
	KubeConfigPath string
	Namespace      string
	WorkerImage    string
	WorkerImageTag string
}

// NewClient creates a new Kubernetes client.
func NewClient(cfg Config) (*Client, error) {
	var config *rest.Config
	var err error

	if cfg.InCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("create in-cluster config: %w", err)
		}
	} else {
		kubeconfig := cfg.KubeConfigPath
		if kubeconfig == "" {
			if home := homedir.HomeDir(); home != "" {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("create out-of-cluster config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}

	namespace := cfg.Namespace
	if namespace == "" {
		namespace = "default"
	}

	return &Client{
		clientset:   clientset,
		namespace:   namespace,
		workerImage: cfg.WorkerImage,
		workerTag:   cfg.WorkerImageTag,
	}, nil
}

// CreatePodParams contains parameters for creating a worker pod.
type CreatePodParams struct {
	MonitorID        string
	StreamURL        string
	CallbackURL      string
	InternalAPIKey   string
	WebhookURL       string
	WebhookSigningKey string
	Config           *db.MonitorConfig
	Metadata         json.RawMessage
	HTTPProxy        string
	HTTPSProxy       string
}

// CreateWorkerPod creates a new worker pod for monitoring.
func (c *Client) CreateWorkerPod(ctx context.Context, params CreatePodParams) (*corev1.Pod, error) {
	podName := PodNamePrefix + params.MonitorID

	// Serialize config to JSON
	configJSON, err := json.Marshal(params.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	// Build environment variables
	envVars := []corev1.EnvVar{
		{Name: "MONITOR_ID", Value: params.MonitorID},
		{Name: "STREAM_URL", Value: params.StreamURL},
		{Name: "CALLBACK_URL", Value: params.CallbackURL},
		{Name: "INTERNAL_API_KEY", Value: params.InternalAPIKey},
		{Name: "WEBHOOK_URL", Value: params.WebhookURL},
		{Name: "WEBHOOK_SIGNING_KEY", Value: params.WebhookSigningKey},
		{Name: "CONFIG_JSON", Value: string(configJSON)},
	}

	// Add proxy settings if configured
	if params.HTTPProxy != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "HTTP_PROXY", Value: params.HTTPProxy})
	}
	if params.HTTPSProxy != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "HTTPS_PROXY", Value: params.HTTPSProxy})
	}

	// Add metadata if present
	if params.Metadata != nil {
		envVars = append(envVars, corev1.EnvVar{Name: "METADATA_JSON", Value: string(params.Metadata)})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: c.namespace,
			Labels: map[string]string{
				LabelApp:       LabelAppValue,
				LabelMonitorID: params.MonitorID,
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Name:  "worker",
					Image: fmt.Sprintf("%s:%s", c.workerImage, c.workerTag),
					Env:   envVars,
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz",
								Port: intstr.FromInt(8081),
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       30,
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/readyz",
								Port: intstr.FromInt(8081),
							},
						},
						InitialDelaySeconds: 5,
						PeriodSeconds:       10,
					},
					Resources: corev1.ResourceRequirements{},
				},
			},
		},
	}

	created, err := c.clientset.CoreV1().Pods(c.namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create pod: %w", err)
	}

	log.Info("worker pod created",
		zap.String("pod_name", podName),
		zap.String("monitor_id", params.MonitorID),
	)

	return created, nil
}

// GetGatewayInternalBaseURL returns the base URL for the gateway internal API.
func (c *Client) GetGatewayInternalBaseURL(ctx context.Context) (string, error) {
	services, err := c.clientset.CoreV1().Services(c.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=gateway",
	})
	if err != nil {
		return "", fmt.Errorf("list gateway services: %w", err)
	}
	if len(services.Items) == 0 {
		return "", fmt.Errorf("no gateway service found")
	}

	if len(services.Items) > 1 {
		log.Warn("multiple gateway services found, using first",
			zap.Int("count", len(services.Items)),
		)
	}

	service := services.Items[0]
	if len(service.Spec.Ports) == 0 {
		return "", fmt.Errorf("gateway service has no ports")
	}

	port := service.Spec.Ports[0].Port
	for _, svcPort := range service.Spec.Ports {
		if svcPort.Name == "http" {
			port = svcPort.Port
			break
		}
	}
	if port == 0 {
		return "", fmt.Errorf("gateway service port is zero")
	}

	return fmt.Sprintf("http://%s:%d", service.Name, port), nil
}

// DeleteWorkerPod deletes a worker pod.
func (c *Client) DeleteWorkerPod(ctx context.Context, monitorID string) error {
	podName := PodNamePrefix + monitorID

	err := c.clientset.CoreV1().Pods(c.namespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.Warn("pod not found for deletion", zap.String("pod_name", podName))
			return nil
		}
		return fmt.Errorf("delete pod: %w", err)
	}

	log.Info("worker pod deleted", zap.String("pod_name", podName))
	return nil
}

// GetWorkerPod retrieves a worker pod by monitor ID.
func (c *Client) GetWorkerPod(ctx context.Context, monitorID string) (*corev1.Pod, error) {
	podName := PodNamePrefix + monitorID

	pod, err := c.clientset.CoreV1().Pods(c.namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get pod: %w", err)
	}

	return pod, nil
}

// ListWorkerPods lists all worker pods.
func (c *Client) ListWorkerPods(ctx context.Context) ([]corev1.Pod, error) {
	labelSelector := fmt.Sprintf("%s=%s", LabelApp, LabelAppValue)

	list, err := c.clientset.CoreV1().Pods(c.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	return list.Items, nil
}

// IsPodRunning checks if a pod is in running state.
func (c *Client) IsPodRunning(pod *corev1.Pod) bool {
	return pod != nil && pod.Status.Phase == corev1.PodRunning
}

// IsPodFailed checks if a pod has failed.
func (c *Client) IsPodFailed(pod *corev1.Pod) bool {
	return pod != nil && pod.Status.Phase == corev1.PodFailed
}

// GetPodMonitorID extracts the monitor ID from a pod's labels.
func GetPodMonitorID(pod *corev1.Pod) string {
	if pod == nil || pod.Labels == nil {
		return ""
	}
	return pod.Labels[LabelMonitorID]
}

// WaitForPodReady waits for a pod to become ready.
func (c *Client) WaitForPodReady(ctx context.Context, monitorID string, timeout time.Duration) error {
	podName := PodNamePrefix + monitorID
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pod, err := c.clientset.CoreV1().Pods(c.namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				time.Sleep(1 * time.Second)
				continue
			}
			return fmt.Errorf("get pod: %w", err)
		}

		if c.IsPodRunning(pod) {
			// Check if all containers are ready
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return nil
				}
			}
		}

		if c.IsPodFailed(pod) {
			return fmt.Errorf("pod failed")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return fmt.Errorf("timeout waiting for pod to be ready")
}

