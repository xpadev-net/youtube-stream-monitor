package k8s

import (
	"testing"
)

func TestPodNamePrefix(t *testing.T) {
	if PodNamePrefix != "stream-monitor-" {
		t.Errorf("PodNamePrefix = %v, want stream-monitor-", PodNamePrefix)
	}
}

func TestLabelConstants(t *testing.T) {
	if LabelApp != "app" {
		t.Errorf("LabelApp = %v, want app", LabelApp)
	}

	if LabelAppValue != "stream-monitor" {
		t.Errorf("LabelAppValue = %v, want stream-monitor", LabelAppValue)
	}

	if LabelMonitorID != "monitor-id" {
		t.Errorf("LabelMonitorID = %v, want monitor-id", LabelMonitorID)
	}
}

func TestPodNameFormat(t *testing.T) {
	monitorID := "mon-0190a5c8-e4b0-7d8a-9c1d-2e3f4a5b6c7d"
	expectedPodName := PodNamePrefix + monitorID

	if expectedPodName != "stream-monitor-mon-0190a5c8-e4b0-7d8a-9c1d-2e3f4a5b6c7d" {
		t.Errorf("Pod name format = %v, want stream-monitor-mon-0190a5c8-e4b0-7d8a-9c1d-2e3f4a5b6c7d", expectedPodName)
	}
}

// TestCreatePodParams tests the structure of CreatePodParams
func TestCreatePodParams(t *testing.T) {
	params := CreatePodParams{
		MonitorID:         "mon-123",
		StreamURL:         "https://www.youtube.com/watch?v=test",
		CallbackURL:       "http://gateway:8080",
		InternalAPIKey:    "internal-key",
		WebhookURL:        "https://example.com/webhook",
		WebhookSigningKey: "signing-key",
		HTTPProxy:         "",
		HTTPSProxy:        "",
	}

	if params.MonitorID != "mon-123" {
		t.Errorf("CreatePodParams.MonitorID = %v, want mon-123", params.MonitorID)
	}

	if params.StreamURL != "https://www.youtube.com/watch?v=test" {
		t.Errorf("CreatePodParams.StreamURL = %v, want https://www.youtube.com/watch?v=test", params.StreamURL)
	}
}

// TestConfigStructure tests the Config structure
func TestConfigStructure(t *testing.T) {
	cfg := Config{
		InCluster:      false,
		KubeConfigPath: "/path/to/kubeconfig",
		Namespace:      "default",
		WorkerImage:    "stream-monitor-worker",
		WorkerImageTag: "latest",
	}

	if cfg.Namespace != "default" {
		t.Errorf("Config.Namespace = %v, want default", cfg.Namespace)
	}

	if cfg.WorkerImage != "stream-monitor-worker" {
		t.Errorf("Config.WorkerImage = %v, want stream-monitor-worker", cfg.WorkerImage)
	}
}

// Note: Full integration tests for Kubernetes client would require:
// - A test Kubernetes cluster (e.g., kind)
// - Mock Kubernetes API server
// - Test fixtures for Pod creation/deletion
// These are beyond the scope of basic unit tests and should be part of
// integration test suite with proper test infrastructure.
