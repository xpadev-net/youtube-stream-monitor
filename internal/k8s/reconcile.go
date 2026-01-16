package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/webhook"
)

// ReconcileResult contains the result of a reconciliation.
type ReconcileResult struct {
	MissingPods   int
	ZombiePods    int
	OrphanedPods  int
	Errors        []string
	StartTime     time.Time
	EndTime       time.Time
	TimedOut      bool
}

// Reconciler handles reconciliation between DB and K8s state.
type Reconciler struct {
	k8sClient     *Client
	repo          *db.MonitorRepository
	webhookSender *webhook.Sender
	timeout       time.Duration
}

// NewReconciler creates a new reconciler.
func NewReconciler(k8sClient *Client, repo *db.MonitorRepository, webhookSender *webhook.Sender, timeout time.Duration) *Reconciler {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Reconciler{
		k8sClient:     k8sClient,
		repo:          repo,
		webhookSender: webhookSender,
		timeout:       timeout,
	}
}

// ReconcileStartup performs reconciliation at Gateway startup.
// This is idempotent and safe to run multiple times.
func (r *Reconciler) ReconcileStartup(ctx context.Context) (*ReconcileResult, error) {
	result := &ReconcileResult{
		StartTime: time.Now(),
	}

	// Create context with timeout
	reconcileCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	log.Info("starting reconciliation",
		zap.Duration("timeout", r.timeout),
	)

	// Get snapshot of DB state (all active monitors)
	activeMonitors, err := r.repo.GetActiveMonitors(reconcileCtx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("get active monitors: %v", err))
		log.Error("failed to get active monitors", zap.Error(err))
		return result, nil // Don't block startup
	}

	// Get snapshot of K8s state (all worker pods)
	pods, err := r.k8sClient.ListWorkerPods(reconcileCtx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("list worker pods: %v", err))
		log.Error("failed to list worker pods", zap.Error(err))
		return result, nil // Don't block startup
	}

	// Build maps for quick lookup
	dbMonitors := make(map[string]*db.Monitor)
	for _, m := range activeMonitors {
		dbMonitors[m.ID] = m
	}

	podMonitors := make(map[string]bool)
	for _, p := range pods {
		monitorID := GetPodMonitorID(&p)
		if monitorID != "" {
			podMonitors[monitorID] = true
		}
	}

	// Check for context timeout
	select {
	case <-reconcileCtx.Done():
		result.TimedOut = true
		log.Warn("reconciliation timed out")
		return result, nil
	default:
	}

	// Find missing pods: monitors in DB but no pod
	for monitorID, monitor := range dbMonitors {
		if !podMonitors[monitorID] {
			result.MissingPods++
			log.Warn("missing pod for active monitor",
				zap.String("monitor_id", monitorID),
				zap.String("status", string(monitor.Status)),
			)

			// Update monitor status to error
			updated, err := r.repo.UpdateStatusWithCondition(
				reconcileCtx,
				monitorID,
				monitor.Status,
				db.StatusError,
			)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("update status for %s: %v", monitorID, err))
				continue
			}

			if updated {
				// Send monitor.error webhook
				r.sendErrorWebhook(reconcileCtx, monitor, "missing_pod", "Pod not found during reconciliation")
			}
		}
	}

	// Find zombie pods: pods for monitors that are stopped/deleted/error
	for _, p := range pods {
		monitorID := GetPodMonitorID(&p)
		if monitorID == "" {
			continue
		}

		monitor, exists := dbMonitors[monitorID]
		if !exists {
			// Orphaned pod: no corresponding monitor in DB
			result.OrphanedPods++
			log.Warn("orphaned pod found",
				zap.String("pod_name", p.Name),
				zap.String("monitor_id", monitorID),
			)

			// Delete the orphaned pod
			if err := r.k8sClient.DeleteWorkerPod(reconcileCtx, monitorID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("delete orphaned pod %s: %v", monitorID, err))
			}
			continue
		}

		// Check for zombie pods (status is stopped or error, but pod exists)
		if monitor.Status == db.StatusStopped || monitor.Status == db.StatusError || monitor.Status == db.StatusCompleted {
			result.ZombiePods++
			log.Warn("zombie pod found",
				zap.String("pod_name", p.Name),
				zap.String("monitor_id", monitorID),
				zap.String("status", string(monitor.Status)),
			)

			// Delete the zombie pod
			if err := r.k8sClient.DeleteWorkerPod(reconcileCtx, monitorID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("delete zombie pod %s: %v", monitorID, err))
			}
		}
	}

	result.EndTime = time.Now()

	log.Info("reconciliation completed",
		zap.Int("missing_pods", result.MissingPods),
		zap.Int("zombie_pods", result.ZombiePods),
		zap.Int("orphaned_pods", result.OrphanedPods),
		zap.Int("errors", len(result.Errors)),
		zap.Duration("duration", result.EndTime.Sub(result.StartTime)),
	)

	return result, nil
}

// sendErrorWebhook sends a monitor.error webhook.
func (r *Reconciler) sendErrorWebhook(ctx context.Context, monitor *db.Monitor, reason, message string) {
	if r.webhookSender == nil {
		return
	}

	payload := &webhook.Payload{
		EventType: webhook.EventMonitorError,
		MonitorID: monitor.ID,
		StreamURL: monitor.StreamURL,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"reason":  reason,
			"message": message,
		},
		Metadata: monitor.Metadata,
	}

	// Try to send webhook, but don't block if it fails
	go func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result := r.webhookSender.Send(sendCtx, monitor.CallbackURL, payload)
		if !result.Success {
			log.Warn("failed to send error webhook during reconciliation",
				zap.String("monitor_id", monitor.ID),
				zap.String("error", result.Error),
			)
		}
	}()
}

// CreateMonitorPod creates a pod for a monitor and updates the pod_name in DB.
func (r *Reconciler) CreateMonitorPod(ctx context.Context, monitor *db.Monitor, internalAPIKey, webhookSigningKey string) error {
	gatewayBaseURL, err := r.k8sClient.GetGatewayInternalBaseURL(ctx)
	if err != nil {
		return fmt.Errorf("get gateway internal base URL: %w", err)
	}

	params := CreatePodParams{
		MonitorID:         monitor.ID,
		StreamURL:         monitor.StreamURL,
		CallbackURL:       gatewayBaseURL,
		InternalAPIKey:    internalAPIKey,
		WebhookURL:        monitor.CallbackURL,
		WebhookSigningKey: webhookSigningKey,
		Config:            &monitor.Config,
		Metadata:          monitor.Metadata,
	}

	// Deserialize config from monitor if needed
	if monitor.Config.CheckIntervalSec == 0 {
		var config db.MonitorConfig
		if err := json.Unmarshal([]byte(`{}`), &config); err == nil {
			params.Config = &config
		}
	}

	pod, err := r.k8sClient.CreateWorkerPod(ctx, params)
	if err != nil {
		return fmt.Errorf("create worker pod: %w", err)
	}

	// Update pod_name in DB
	if err := r.repo.UpdatePodName(ctx, monitor.ID, pod.Name); err != nil {
		log.Error("failed to update pod_name in DB",
			zap.String("monitor_id", monitor.ID),
			zap.Error(err),
		)
	}

	return nil
}

// DeleteMonitorPod deletes the pod for a monitor.
func (r *Reconciler) DeleteMonitorPod(ctx context.Context, monitorID string) error {
	return r.k8sClient.DeleteWorkerPod(ctx, monitorID)
}
