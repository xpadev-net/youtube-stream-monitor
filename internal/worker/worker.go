package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/config"
	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ffmpeg"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/manifest"
	"github.com/xpadev-net/youtube-stream-tracker/internal/webhook"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ytdlp"
)

// State represents the worker's current state.
type State string

const (
	StateWaiting    State = "waiting"
	StateMonitoring State = "monitoring"
	StateCompleted  State = "completed"
	StateError      State = "error"
)

// Worker monitors a single YouTube stream.
type Worker struct {
	cfg            *config.WorkerConfig
	ytdlpClient    *ytdlp.Client
	manifestParser *manifest.Parser
	analyzer       *ffmpeg.Analyzer
	webhookSender  *webhook.Sender
	callbackClient *CallbackClient

	// State
	mu                  sync.Mutex
	state               State
	streamStatus        db.StreamStatus
	currentManifestURL  string
	lastSegmentSequence uint64
	segmentErrorStart   *time.Time

	// Analysis state
	blackoutStart       *time.Time
	silenceStart        *time.Time
	totalSegments       int
	blackoutEvents      int
	silenceEvents       int
	blackoutAlertSent   bool
	silenceAlertSent    bool
	consecutiveBlack    float64
	consecutiveSilence  float64

	// Metadata for webhooks
	metadata json.RawMessage
}

// NewWorker creates a new worker.
func NewWorker(cfg *config.WorkerConfig) *Worker {
	return &Worker{
		cfg:            cfg,
		ytdlpClient:    ytdlp.NewClient(cfg.YtDlpPath, cfg.StreamlinkPath, cfg.HTTPProxy, cfg.HTTPSProxy),
		manifestParser: manifest.NewParser(cfg.ManifestFetchTimeout),
		analyzer:       ffmpeg.NewAnalyzer(cfg.FFmpegPath, cfg.FFprobePath, "/tmp/segments", cfg.SilenceDBThreshold),
		webhookSender:  webhook.NewSender(cfg.WebhookSigningKey),
		callbackClient: NewCallbackClient(cfg.CallbackURL, cfg.InternalAPIKey),
		state:          StateWaiting,
		streamStatus:   db.StreamStatusUnknown,
	}
}

// Run starts the worker's main loop.
func (w *Worker) Run(ctx context.Context) error {
	log.Info("worker starting",
		zap.String("monitor_id", w.cfg.MonitorID),
		zap.String("stream_url", w.cfg.StreamURL),
	)

	// Ensure temp directory exists
	if err := w.analyzer.EnsureTmpDir(); err != nil {
		return fmt.Errorf("ensure tmp dir: %w", err)
	}
	defer w.analyzer.CleanupMonitor(w.cfg.MonitorID)

	// Main loop
	for {
		select {
		case <-ctx.Done():
			log.Info("worker stopping due to context cancellation")
			return w.gracefulShutdown(ctx)
		default:
		}

		switch w.getState() {
		case StateWaiting:
			if err := w.waitingMode(ctx); err != nil {
				log.Error("waiting mode error", zap.Error(err))
				w.transitionToError(ctx, err.Error())
				return err
			}
		case StateMonitoring:
			if err := w.monitoringMode(ctx); err != nil {
				log.Error("monitoring mode error", zap.Error(err))
				w.transitionToError(ctx, err.Error())
				return err
			}
		case StateCompleted:
			log.Info("monitoring completed")
			return nil
		case StateError:
			return fmt.Errorf("worker in error state")
		}
	}
}

// waitingMode checks if the stream is live and waits if not.
func (w *Worker) waitingMode(ctx context.Context) error {
	log.Info("entering waiting mode")
	w.reportStatus(ctx, db.StatusWaiting, nil)

	ticker := time.NewTicker(w.cfg.WaitingModeInterval)
	defer ticker.Stop()

	// Check if delayed alert should be sent
	delayAlertSent := false

	for {
		if w.getState() == StateError {
			return fmt.Errorf("worker in error state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			isLive, info, err := w.ytdlpClient.IsStreamLive(ctx, w.cfg.StreamURL)
			if err != nil {
				log.Warn("failed to check stream status", zap.Error(err))
				continue
			}

			// Update stream status
			if isLive {
				w.mu.Lock()
				w.streamStatus = db.StreamStatusLive
				w.mu.Unlock()

				// Send stream started event
				w.sendWebhook(ctx, webhook.EventStreamStarted, map[string]interface{}{
					"title": info.Title,
				})

				// Transition to monitoring
				w.setState(StateMonitoring)
				log.Info("stream is live, transitioning to monitoring mode")
				return nil
			}

			// Check for scheduled start delay
			if w.cfg.ScheduledStartTime != nil && !delayAlertSent {
				threshold := w.cfg.ScheduledStartTime.Add(w.cfg.DelayThreshold)
				if time.Now().After(threshold) {
					delay := time.Since(*w.cfg.ScheduledStartTime)
					w.sendWebhook(ctx, webhook.EventStreamDelayed, map[string]interface{}{
						"scheduled_start_time": w.cfg.ScheduledStartTime.Format(time.RFC3339),
						"delay_sec":            int(delay.Seconds()),
						"tolerance_sec":        int(w.cfg.DelayThreshold.Seconds()),
					})
					delayAlertSent = true
				}
			}

			// Update status based on info
			if info != nil {
				switch info.LiveStatus {
				case "is_upcoming":
					w.mu.Lock()
					w.streamStatus = db.StreamStatusScheduled
					w.mu.Unlock()
				case "was_live", "not_live":
					// Stream ended before we could monitor it
					w.mu.Lock()
					w.streamStatus = db.StreamStatusEnded
					w.mu.Unlock()
					w.setState(StateCompleted)
					w.reportStatus(ctx, db.StatusCompleted, nil)
					return nil
				}
			}

			log.Debug("stream not yet live, continuing to wait",
				zap.String("live_status", info.LiveStatus),
			)
		}
	}
}

// monitoringMode performs segment analysis.
func (w *Worker) monitoringMode(ctx context.Context) error {
	log.Info("entering monitoring mode")
	w.reportStatus(ctx, db.StatusMonitoring, nil)

	// Get initial manifest URL
	manifestURL, err := w.ytdlpClient.GetManifestURL(ctx, w.cfg.StreamURL)
	if err != nil {
		return fmt.Errorf("get manifest URL: %w", err)
	}
	w.mu.Lock()
	w.currentManifestURL = manifestURL
	w.mu.Unlock()

	log.Info("got manifest URL", zap.String("url", manifestURL))

	ticker := time.NewTicker(w.cfg.AnalysisInterval)
	defer ticker.Stop()

	manifestRefreshTicker := time.NewTicker(30 * time.Second)
	defer manifestRefreshTicker.Stop()

	for {
		if w.getState() == StateError {
			return fmt.Errorf("worker in error state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-manifestRefreshTicker.C:
			// Refresh manifest URL periodically
			newURL, err := w.ytdlpClient.GetManifestURL(ctx, w.cfg.StreamURL)
			if err != nil {
				log.Warn("failed to refresh manifest URL", zap.Error(err))
			} else {
				w.mu.Lock()
				w.currentManifestURL = newURL
				w.mu.Unlock()
			}
		case <-ticker.C:
			if err := w.analyzeLatestSegment(ctx); err != nil {
				log.Warn("segment analysis failed", zap.Error(err))
				if w.handleSegmentError(ctx, err) {
					w.reportStatus(ctx, db.StatusCompleted, nil)
					return nil
				}
			} else {
				w.clearSegmentError()
			}
		}
	}
}

// analyzeLatestSegment fetches and analyzes the latest segment.
func (w *Worker) analyzeLatestSegment(ctx context.Context) error {
	w.mu.Lock()
	manifestURL := w.currentManifestURL
	w.mu.Unlock()

	// Get latest segment info
	segment, err := w.manifestParser.GetLatestSegment(ctx, manifestURL)
	if err != nil {
		return fmt.Errorf("get latest segment: %w", err)
	}

	// Skip if we already processed this segment
	if segment.Sequence <= w.lastSegmentSequence {
		return nil
	}

	log.Debug("analyzing segment",
		zap.Uint64("sequence", segment.Sequence),
		zap.Float64("duration", segment.Duration),
	)

	// Download segment
	data, err := w.manifestParser.FetchSegment(ctx, segment.URL)
	if err != nil {
		return fmt.Errorf("fetch segment: %w", err)
	}

	// Save segment to temp file
	segmentPath, err := w.analyzer.SaveSegment(w.cfg.MonitorID, data)
	if err != nil {
		return fmt.Errorf("save segment: %w", err)
	}
	defer w.analyzer.CleanupSegment(segmentPath)

	// Analyze segment
	result, err := w.analyzer.AnalyzeSegment(ctx, segmentPath)
	if err != nil {
		return fmt.Errorf("analyze segment: %w", err)
	}

	// Update state
	w.mu.Lock()
	w.lastSegmentSequence = segment.Sequence
	w.totalSegments++
	w.mu.Unlock()

	// Process results
	w.processBlackDetection(ctx, result.Black, segment.Duration)
	w.processSilenceDetection(ctx, result.Silence, segment.Duration)

	// Report status update
	w.reportStatusUpdate(ctx)

	return nil
}

// processBlackDetection handles blackout detection results.
func (w *Worker) processBlackDetection(ctx context.Context, result *ffmpeg.BlackDetectResult, segmentDuration float64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if result.FullyBlack {
		// Accumulate consecutive black duration
		w.consecutiveBlack += segmentDuration

		if w.blackoutStart == nil {
			now := time.Now()
			w.blackoutStart = &now
		}

		// Check threshold (only once per blackout event)
		if !w.blackoutAlertSent && w.consecutiveBlack >= w.cfg.BlackoutThreshold.Seconds() {
			w.blackoutEvents++
			w.blackoutAlertSent = true
			startTime := *w.blackoutStart
			duration := w.consecutiveBlack
			thresholdSec := int(w.cfg.BlackoutThreshold.Seconds())
			w.mu.Unlock()
			w.sendWebhook(ctx, webhook.EventAlertBlackout, map[string]interface{}{
				"duration_sec":  duration,
				"started_at":    startTime.Format(time.RFC3339),
				"threshold_sec": thresholdSec,
			})
			w.mu.Lock()
		}
	} else {
		// Recovered from blackout
		if w.blackoutAlertSent && w.blackoutStart != nil {
			startTime := *w.blackoutStart
			totalDuration := w.consecutiveBlack
			w.blackoutAlertSent = false
			w.mu.Unlock()
			w.sendWebhook(ctx, webhook.EventAlertBlackoutRecovered, map[string]interface{}{
				"total_duration_sec": totalDuration,
				"started_at":         startTime.Format(time.RFC3339),
				"recovered_at":       time.Now().Format(time.RFC3339),
			})
			w.mu.Lock()
		}
		w.consecutiveBlack = 0
		w.blackoutStart = nil
	}
}

// processSilenceDetection handles silence detection results.
func (w *Worker) processSilenceDetection(ctx context.Context, result *ffmpeg.SilenceDetectResult, segmentDuration float64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if result.FullySilent {
		// Accumulate consecutive silence duration
		w.consecutiveSilence += segmentDuration

		if w.silenceStart == nil {
			now := time.Now()
			w.silenceStart = &now
		}

		// Check threshold (only once per silence event)
		if !w.silenceAlertSent && w.consecutiveSilence >= w.cfg.SilenceThreshold.Seconds() {
			w.silenceEvents++
			w.silenceAlertSent = true
			startTime := *w.silenceStart
			duration := w.consecutiveSilence
			thresholdSec := int(w.cfg.SilenceThreshold.Seconds())
			w.mu.Unlock()
			w.sendWebhook(ctx, webhook.EventAlertSilence, map[string]interface{}{
				"duration_sec":  duration,
				"started_at":    startTime.Format(time.RFC3339),
				"threshold_sec": thresholdSec,
			})
			w.mu.Lock()
		}
	} else {
		// Recovered from silence
		if w.silenceAlertSent && w.silenceStart != nil {
			startTime := *w.silenceStart
			totalDuration := w.consecutiveSilence
			w.silenceAlertSent = false
			w.mu.Unlock()
			w.sendWebhook(ctx, webhook.EventAlertSilenceRecovered, map[string]interface{}{
				"total_duration_sec": totalDuration,
				"started_at":         startTime.Format(time.RFC3339),
				"recovered_at":       time.Now().Format(time.RFC3339),
			})
			w.mu.Lock()
		}
		w.consecutiveSilence = 0
		w.silenceStart = nil
	}
}

// handleSegmentError handles segment fetch/analysis errors.
func (w *Worker) handleSegmentError(ctx context.Context, err error) bool {
	w.mu.Lock()

	if w.state == StateCompleted {
		w.mu.Unlock()
		return true
	}

	if w.segmentErrorStart == nil {
		now := time.Now()
		w.segmentErrorStart = &now
	}

	// Check if error has persisted for 60 seconds
	if time.Since(*w.segmentErrorStart) >= 60*time.Second {
		w.mu.Unlock()

		// Check if stream is still live
		isLive, _, checkErr := w.ytdlpClient.IsStreamLive(ctx, w.cfg.StreamURL)
		if checkErr != nil {
			log.Warn("failed to check stream status during segment error", zap.Error(checkErr))
			return false
		}

		if !isLive {
			// Stream ended
			w.sendWebhook(ctx, webhook.EventStreamEnded, nil)
			w.setState(StateCompleted)
			return true
		}

		// Send segment error alert
		w.sendWebhook(ctx, webhook.EventAlertSegmentError, map[string]interface{}{
			"error":        err.Error(),
			"duration_sec": 60,
		})
		return false
	}

	w.mu.Unlock()
	return false
}

// clearSegmentError clears the segment error state.
func (w *Worker) clearSegmentError() {
	w.mu.Lock()
	w.segmentErrorStart = nil
	w.mu.Unlock()
}

// sendWebhook sends a webhook notification.
func (w *Worker) sendWebhook(ctx context.Context, eventType webhook.EventType, data map[string]interface{}) {
	payload := &webhook.Payload{
		EventType: eventType,
		MonitorID: w.cfg.MonitorID,
		StreamURL: w.cfg.StreamURL,
		Timestamp: time.Now(),
		Data:      data,
		Metadata:  w.metadata,
	}

	result := w.webhookSender.Send(ctx, w.cfg.WebhookURL, payload)
	if !result.Success {
		log.Error("webhook delivery failed",
			zap.String("event_type", string(eventType)),
			zap.Int("attempts", result.Attempts),
			zap.String("error", result.Error),
		)

		// Per requirements: if webhook fails after all retries, delete the monitoring job
		// (don't send monitor.error event)
		w.setState(StateError)
	}
}

// reportStatus reports the current status to the gateway.
func (w *Worker) reportStatus(ctx context.Context, status db.MonitorStatus, stats *StatusUpdate) {
	if err := w.callbackClient.ReportStatus(ctx, w.cfg.MonitorID, status, stats); err != nil {
		log.Warn("failed to report status to gateway", zap.Error(err))
	}
}

// reportStatusUpdate reports statistics update to the gateway.
func (w *Worker) reportStatusUpdate(ctx context.Context) {
	w.mu.Lock()
	stats := &StatusUpdate{
		StreamStatus:   string(w.streamStatus),
		VideoHealth:    w.getVideoHealth(),
		AudioHealth:    w.getAudioHealth(),
		TotalSegments:  w.totalSegments,
		BlackoutEvents: w.blackoutEvents,
		SilenceEvents:  w.silenceEvents,
	}
	w.mu.Unlock()

	if err := w.callbackClient.ReportStatus(ctx, w.cfg.MonitorID, db.StatusMonitoring, stats); err != nil {
		log.Warn("failed to report status update", zap.Error(err))
	}
}

// getVideoHealth returns the current video health status.
func (w *Worker) getVideoHealth() string {
	if w.blackoutStart != nil {
		return string(db.HealthWarning)
	}
	return string(db.HealthOK)
}

// getAudioHealth returns the current audio health status.
func (w *Worker) getAudioHealth() string {
	if w.silenceStart != nil {
		return string(db.HealthWarning)
	}
	return string(db.HealthOK)
}

// transitionToError handles transitioning to error state.
func (w *Worker) transitionToError(ctx context.Context, reason string) {
	w.setState(StateError)
	w.reportStatus(ctx, db.StatusError, nil)
}

// gracefulShutdown performs cleanup on shutdown.
func (w *Worker) gracefulShutdown(ctx context.Context) error {
	log.Info("performing graceful shutdown")

	// Clean up temp files
	w.analyzer.CleanupMonitor(w.cfg.MonitorID)

	log.Info("graceful shutdown complete")
	return nil
}

// getState returns the current state.
func (w *Worker) getState() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// setState sets the current state.
func (w *Worker) setState(state State) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state = state
}

// SetMetadata sets the metadata for webhooks.
func (w *Worker) SetMetadata(metadata json.RawMessage) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.metadata = metadata
}
