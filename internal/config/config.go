package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
)

// GatewayConfig holds configuration for the API Gateway.
type GatewayConfig struct {
	// Server settings
	Port        int
	Environment string

	// Database
	DatabaseURL string

	// API Keys
	APIKey         string
	InternalAPIKey string
	WebhookSigningKey string

	// Kubernetes
	Namespace       string
	WorkerImage     string
	WorkerImageTag  string
	InCluster       bool
	KubeConfigPath  string
	MaxMonitors     int
	ReconcileOnBoot bool
	ReconcileTimeout time.Duration

	// Timeouts
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// WorkerConfig holds configuration for the Worker.
type WorkerConfig struct {
	// Identity
	MonitorID string
	StreamURL string

	// Callback
	CallbackURL    string
	InternalAPIKey string

	// Config JSON (from CONFIG_JSON env var)
	ScheduledStartTime   *time.Time
	WaitingModeInterval  time.Duration
	ManifestFetchTimeout time.Duration
	SegmentFetchTimeout  time.Duration
	AnalysisInterval     time.Duration
	BlackoutThreshold    time.Duration
	SilenceThreshold     time.Duration
	SilenceDBThreshold   float64
	DelayThreshold       time.Duration
	Metadata             json.RawMessage

	// Webhook
	WebhookURL        string
	WebhookSigningKey string

	// Proxy
	HTTPProxy  string
	HTTPSProxy string

	// FFmpeg
	FFmpegPath string
	FFprobePath string

	// yt-dlp
	YtDlpPath string

	// streamlink
	StreamlinkPath string
}

// LoadGatewayConfig loads the gateway configuration from environment variables.
func LoadGatewayConfig() (*GatewayConfig, error) {
	cfg := &GatewayConfig{
		Port:            getEnvInt("PORT", 8080),
		Environment:     getEnv("ENVIRONMENT", "development"),
		DatabaseURL:     getEnv("DATABASE_URL", ""),
		APIKey:          getEnv("API_KEY", ""),
		InternalAPIKey:  getEnv("INTERNAL_API_KEY", ""),
		WebhookSigningKey: getEnv("WEBHOOK_SIGNING_KEY", ""),
		Namespace:       getEnv("NAMESPACE", "default"),
		WorkerImage:     getEnv("WORKER_IMAGE", "stream-monitor-worker"),
		WorkerImageTag:  getEnv("WORKER_IMAGE_TAG", "latest"),
		InCluster:       getEnvBool("IN_CLUSTER", false),
		KubeConfigPath:  getEnv("KUBECONFIG", ""),
		MaxMonitors:     getEnvInt("MAX_MONITORS", 50),
		ReconcileOnBoot: getEnvBool("RECONCILE_ON_BOOT", true),
		ReconcileTimeout: getEnvDuration("RECONCILE_TIMEOUT", 30*time.Second),
		ReadTimeout:     getEnvDuration("READ_TIMEOUT", 30*time.Second),
		WriteTimeout:    getEnvDuration("WRITE_TIMEOUT", 30*time.Second),
		ShutdownTimeout: getEnvDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API_KEY is required")
	}
	if cfg.InternalAPIKey == "" {
		return nil, fmt.Errorf("INTERNAL_API_KEY is required")
	}
	if cfg.WebhookSigningKey == "" {
		return nil, fmt.Errorf("WEBHOOK_SIGNING_KEY is required")
	}

	return cfg, nil
}

// LoadWorkerConfig loads the worker configuration from environment variables.
func LoadWorkerConfig() (*WorkerConfig, error) {
	cfg := &WorkerConfig{
		MonitorID:            getEnv("MONITOR_ID", ""),
		StreamURL:            getEnv("STREAM_URL", ""),
		CallbackURL:          getEnv("CALLBACK_URL", ""),
		InternalAPIKey:       getEnv("INTERNAL_API_KEY", ""),
		WebhookURL:           getEnv("WEBHOOK_URL", ""),
		WebhookSigningKey:    getEnv("WEBHOOK_SIGNING_KEY", ""),
		HTTPProxy:            getEnv("HTTP_PROXY", ""),
		HTTPSProxy:           getEnv("HTTPS_PROXY", ""),
		FFmpegPath:           getEnv("FFMPEG_PATH", "ffmpeg"),
		FFprobePath:          getEnv("FFPROBE_PATH", "ffprobe"),
		YtDlpPath:            getEnv("YTDLP_PATH", "yt-dlp"),
		StreamlinkPath:       getEnv("STREAMLINK_PATH", "streamlink"),
		WaitingModeInterval:  getEnvDuration("WAITING_MODE_INTERVAL", 60*time.Second),
		ManifestFetchTimeout: getEnvDuration("MANIFEST_FETCH_TIMEOUT", 10*time.Second),
		SegmentFetchTimeout:  getEnvDuration("SEGMENT_FETCH_TIMEOUT", 30*time.Second),
		AnalysisInterval:     getEnvDuration("ANALYSIS_INTERVAL", 10*time.Second),
		BlackoutThreshold:    getEnvDuration("BLACKOUT_THRESHOLD", 5*time.Second),
		SilenceThreshold:     getEnvDuration("SILENCE_THRESHOLD", 5*time.Second),
		SilenceDBThreshold:   db.DefaultMonitorConfig().SilenceDBThreshold,
		DelayThreshold:       getEnvDuration("DELAY_THRESHOLD", 300*time.Second),
	}

	if configJSON := os.Getenv("CONFIG_JSON"); configJSON != "" {
		var monitorConfig db.MonitorConfig
		if err := json.Unmarshal([]byte(configJSON), &monitorConfig); err != nil {
			return nil, fmt.Errorf("parse CONFIG_JSON: %w", err)
		}

		if monitorConfig.ScheduledStartTime != nil {
			cfg.ScheduledStartTime = monitorConfig.ScheduledStartTime
		}
		if monitorConfig.CheckIntervalSec > 0 {
			cfg.AnalysisInterval = time.Duration(monitorConfig.CheckIntervalSec) * time.Second
		}
		if monitorConfig.BlackoutThresholdSec > 0 {
			cfg.BlackoutThreshold = time.Duration(monitorConfig.BlackoutThresholdSec) * time.Second
		}
		if monitorConfig.SilenceThresholdSec > 0 {
			cfg.SilenceThreshold = time.Duration(monitorConfig.SilenceThresholdSec) * time.Second
		}
		if monitorConfig.StartDelayToleranceSec > 0 {
			cfg.DelayThreshold = time.Duration(monitorConfig.StartDelayToleranceSec) * time.Second
		}
		if monitorConfig.SilenceDBThreshold != 0 {
			cfg.SilenceDBThreshold = monitorConfig.SilenceDBThreshold
		}
	}

	if metadataJSON := os.Getenv("METADATA_JSON"); metadataJSON != "" {
		var metadata json.RawMessage
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			return nil, fmt.Errorf("parse METADATA_JSON: %w", err)
		}
		cfg.Metadata = metadata
	}

	if cfg.MonitorID == "" {
		return nil, fmt.Errorf("MONITOR_ID is required")
	}
	if cfg.StreamURL == "" {
		return nil, fmt.Errorf("STREAM_URL is required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("CALLBACK_URL is required")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}
