package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/httpapi"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ids"
	"github.com/xpadev-net/youtube-stream-tracker/internal/k8s"
	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/validation"
)

var youtubeWatchURLRegex = regexp.MustCompile(`^https?://(www\.)?youtube\.com/watch\?v=[a-zA-Z0-9_-]{11}`)

var validMonitorStatuses = map[db.MonitorStatus]bool{
	db.StatusInitializing: true,
	db.StatusWaiting:      true,
	db.StatusMonitoring:   true,
	db.StatusCompleted:    true,
	db.StatusStopped:      true,
	db.StatusError:        true,
}

var validStreamStatuses = map[db.StreamStatus]bool{
	db.StreamStatusUnknown:   true,
	db.StreamStatusScheduled: true,
	db.StreamStatusLive:      true,
	db.StreamStatusEnded:     true,
}

var validHealthStatuses = map[db.HealthStatus]bool{
	db.HealthOK:      true,
	db.HealthWarning: true,
	db.HealthError:   true,
	db.HealthUnknown: true,
}

// Handler holds dependencies for API handlers.
type Handler struct {
	repo                       *db.MonitorRepository
	maxMonitors                int
	reconciler                 *k8s.Reconciler
	internalAPIKey             string
	webhookSigningKey          string
	secretsName                string
	internalAPIKeySecretKey    string
	webhookSigningKeySecretKey string
}

// NewHandler creates a new API handler.
func NewHandler(repo *db.MonitorRepository, maxMonitors int, reconciler *k8s.Reconciler, internalAPIKey, webhookSigningKey, secretsName, internalAPIKeySecretKey, webhookSigningKeySecretKey string) *Handler {
	return &Handler{
		repo:                       repo,
		maxMonitors:                maxMonitors,
		reconciler:                 reconciler,
		internalAPIKey:             internalAPIKey,
		webhookSigningKey:          webhookSigningKey,
		secretsName:                secretsName,
		internalAPIKeySecretKey:    internalAPIKeySecretKey,
		webhookSigningKeySecretKey: webhookSigningKeySecretKey,
	}
}

// CreateMonitorRequest represents the request body for creating a monitor.
type CreateMonitorRequest struct {
	StreamURL   string                 `json:"stream_url" binding:"required"`
	CallbackURL string                 `json:"callback_url" binding:"required"`
	Config      *MonitorConfigRequest  `json:"config,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MonitorConfigRequest represents the config part of the create request.
type MonitorConfigRequest struct {
	CheckIntervalSec       *int       `json:"check_interval_sec,omitempty"`
	BlackoutThresholdSec   *int       `json:"blackout_threshold_sec,omitempty"`
	SilenceThresholdSec    *int       `json:"silence_threshold_sec,omitempty"`
	SilenceDBThreshold     *float64   `json:"silence_db_threshold,omitempty"`
	ScheduledStartTime     *time.Time `json:"scheduled_start_time,omitempty"`
	StartDelayToleranceSec *int       `json:"start_delay_tolerance_sec,omitempty"`
}

// CreateMonitorResponse represents the response for creating a monitor.
type CreateMonitorResponse struct {
	MonitorID string `json:"monitor_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// CreateMonitor handles POST /api/v1/monitors
func (h *Handler) CreateMonitor(c *gin.Context) {
	var req CreateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpapi.RespondValidationError(c, "Invalid request body: "+err.Error())
		return
	}

	// Validate stream URL
	if !isValidYouTubeWatchURL(req.StreamURL) {
		httpapi.RespondError(c, http.StatusBadRequest, httpapi.ErrCodeInvalidURL,
			"The provided stream URL is not a valid YouTube watch URL")
		return
	}

	// Validate callback URL
	if _, err := url.ParseRequestURI(req.CallbackURL); err != nil {
		httpapi.RespondValidationError(c, "Invalid callback URL")
		return
	}
	if err := validation.ValidateOutboundURL(c.Request.Context(), req.CallbackURL, false); err != nil {
		httpapi.RespondValidationError(c, fmt.Sprintf("Invalid callback URL: %s", err.Error()))
		return
	}

	// Check max monitors limit
	count, err := h.repo.CountActiveMonitors(c.Request.Context())
	if err != nil {
		log.Error("failed to count active monitors", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to check monitor limit")
		return
	}
	if count >= h.maxMonitors {
		httpapi.RespondError(c, http.StatusTooManyRequests, httpapi.ErrCodeMaxMonitors,
			"Maximum number of active monitors reached")
		return
	}

	// Build config
	config := db.DefaultMonitorConfig()
	if req.Config != nil {
		if req.Config.CheckIntervalSec != nil {
			config.CheckIntervalSec = *req.Config.CheckIntervalSec
		}
		if req.Config.BlackoutThresholdSec != nil {
			config.BlackoutThresholdSec = *req.Config.BlackoutThresholdSec
		}
		if req.Config.SilenceThresholdSec != nil {
			config.SilenceThresholdSec = *req.Config.SilenceThresholdSec
		}
		if req.Config.SilenceDBThreshold != nil {
			config.SilenceDBThreshold = *req.Config.SilenceDBThreshold
		}
		if req.Config.ScheduledStartTime != nil {
			config.ScheduledStartTime = req.Config.ScheduledStartTime
		}
		if req.Config.StartDelayToleranceSec != nil {
			config.StartDelayToleranceSec = *req.Config.StartDelayToleranceSec
		}
	}

	// Build metadata
	var metadata json.RawMessage
	if req.Metadata != nil {
		metadata, _ = json.Marshal(req.Metadata)
	}

	// Create monitor
	monitorID := ids.NewMonitorID()
	monitor, err := h.repo.Create(c.Request.Context(), db.CreateMonitorParams{
		ID:          monitorID,
		StreamURL:   req.StreamURL,
		CallbackURL: req.CallbackURL,
		Config:      config,
		Metadata:    metadata,
	})
	if err != nil {
		if errors.Is(err, db.ErrDuplicateMonitor) {
			httpapi.RespondConflict(c, httpapi.ErrCodeDuplicateMonitor,
				"A monitor for this stream URL already exists")
			return
		}
		log.Error("failed to create monitor", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to create monitor")
		return
	}

	log.Info("monitor created",
		zap.String("monitor_id", monitor.ID),
		zap.String("stream_url", monitor.StreamURL),
	)

	if h.reconciler == nil {
		log.Error("k8s reconciler not configured")
		_ = h.repo.UpdateStatus(c.Request.Context(), monitor.ID, db.StatusError)
		httpapi.RespondInternalError(c, "Failed to start worker pod")
		return
	}

	if err := h.reconciler.CreateMonitorPod(c.Request.Context(), monitor, h.internalAPIKey, h.webhookSigningKey, h.secretsName, h.internalAPIKeySecretKey, h.webhookSigningKeySecretKey); err != nil {
		log.Error("failed to create worker pod", zap.Error(err))
		_ = h.repo.UpdateStatus(c.Request.Context(), monitor.ID, db.StatusError)
		httpapi.RespondInternalError(c, "Failed to start worker pod")
		return
	}

	httpapi.RespondCreated(c, CreateMonitorResponse{
		MonitorID: monitor.ID,
		Status:    string(monitor.Status),
		CreatedAt: monitor.CreatedAt.Format(time.RFC3339),
	})
}

// GetMonitorResponse represents the response for getting a monitor.
type GetMonitorResponse struct {
	MonitorID    string          `json:"monitor_id"`
	StreamURL    string          `json:"stream_url"`
	Status       string          `json:"status"`
	StreamStatus string          `json:"stream_status,omitempty"`
	Health       *HealthResponse `json:"health,omitempty"`
	Statistics   *StatsResponse  `json:"statistics,omitempty"`
	CreatedAt    string          `json:"created_at"`
}

// HealthResponse represents health status in the response.
type HealthResponse struct {
	Video       string `json:"video"`
	Audio       string `json:"audio"`
	LastCheckAt string `json:"last_check_at,omitempty"`
}

// StatsResponse represents statistics in the response.
type StatsResponse struct {
	TotalSegmentsAnalyzed int `json:"total_segments_analyzed"`
	BlackoutEvents        int `json:"blackout_events"`
	SilenceEvents         int `json:"silence_events"`
}

// GetMonitor handles GET /api/v1/monitors/:monitor_id
func (h *Handler) GetMonitor(c *gin.Context) {
	monitorID := c.Param("monitor_id")
	if !ids.IsValidMonitorID(monitorID) {
		httpapi.RespondNotFound(c, "Monitor not found")
		return
	}

	monitorWithStats, err := h.repo.GetWithStats(c.Request.Context(), monitorID)
	if err != nil {
		if errors.Is(err, db.ErrMonitorNotFound) {
			httpapi.RespondNotFound(c, "Monitor not found")
			return
		}
		log.Error("failed to get monitor", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to get monitor")
		return
	}

	resp := GetMonitorResponse{
		MonitorID: monitorWithStats.ID,
		StreamURL: monitorWithStats.StreamURL,
		Status:    string(monitorWithStats.Status),
		CreatedAt: monitorWithStats.CreatedAt.Format(time.RFC3339),
	}

	if monitorWithStats.Stats != nil {
		resp.StreamStatus = string(monitorWithStats.Stats.StreamStatus)
		resp.Health = &HealthResponse{
			Video: string(monitorWithStats.Stats.VideoHealth),
			Audio: string(monitorWithStats.Stats.AudioHealth),
		}
		if monitorWithStats.Stats.LastCheckAt != nil {
			resp.Health.LastCheckAt = monitorWithStats.Stats.LastCheckAt.Format(time.RFC3339)
		}
		resp.Statistics = &StatsResponse{
			TotalSegmentsAnalyzed: monitorWithStats.Stats.TotalSegments,
			BlackoutEvents:        monitorWithStats.Stats.BlackoutEvents,
			SilenceEvents:         monitorWithStats.Stats.SilenceEvents,
		}
	}

	httpapi.RespondOK(c, resp)
}

// DeleteMonitorResponse represents the response for deleting a monitor.
type DeleteMonitorResponse struct {
	MonitorID string `json:"monitor_id"`
	Status    string `json:"status"`
	StoppedAt string `json:"stopped_at"`
}

// DeleteMonitor handles DELETE /api/v1/monitors/:monitor_id
func (h *Handler) DeleteMonitor(c *gin.Context) {
	monitorID := c.Param("monitor_id")
	if !ids.IsValidMonitorID(monitorID) {
		httpapi.RespondNotFound(c, "Monitor not found")
		return
	}

	// Get current monitor to check it exists
	_, err := h.repo.GetByID(c.Request.Context(), monitorID)
	if err != nil {
		if errors.Is(err, db.ErrMonitorNotFound) {
			httpapi.RespondNotFound(c, "Monitor not found")
			return
		}
		log.Error("failed to get monitor", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to get monitor")
		return
	}

	// Update status to stopped
	if err := h.repo.UpdateStatus(c.Request.Context(), monitorID, db.StatusStopped); err != nil {
		log.Error("failed to update monitor status", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to stop monitor")
		return
	}

	log.Info("monitor stopped", zap.String("monitor_id", monitorID))

	// Delete worker pod if reconciler is configured
	if h.reconciler != nil {
		if err := h.reconciler.DeleteMonitorPod(c.Request.Context(), monitorID); err != nil {
			// Log error but don't fail the request (DB update already succeeded)
			log.Error("failed to delete worker pod",
				zap.String("monitor_id", monitorID),
				zap.Error(err),
			)
		} else {
			log.Info("worker pod deleted", zap.String("monitor_id", monitorID))
		}
	}

	httpapi.RespondOK(c, DeleteMonitorResponse{
		MonitorID: monitorID,
		Status:    string(db.StatusStopped),
		StoppedAt: time.Now().Format(time.RFC3339),
	})
}

// ListMonitorsResponse represents the response for listing monitors.
type ListMonitorsResponse struct {
	Monitors   []MonitorSummary `json:"monitors"`
	Pagination PaginationInfo   `json:"pagination"`
}

// MonitorSummary represents a monitor in the list response.
type MonitorSummary struct {
	MonitorID string `json:"monitor_id"`
	StreamURL string `json:"stream_url"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// PaginationInfo represents pagination information.
type PaginationInfo struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// ListMonitors handles GET /api/v1/monitors
func (h *Handler) ListMonitors(c *gin.Context) {
	// Parse query parameters
	var params db.ListParams

	if status := c.Query("status"); status != "" {
		s := db.MonitorStatus(status)
		if !validMonitorStatuses[s] {
			httpapi.RespondValidationError(c, "Invalid status value")
			return
		}
		params.Status = &s
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			params.Limit = limit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			params.Offset = offset
		}
	}

	monitors, total, err := h.repo.List(c.Request.Context(), params)
	if err != nil {
		log.Error("failed to list monitors", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to list monitors")
		return
	}

	summaries := make([]MonitorSummary, len(monitors))
	for i, m := range monitors {
		summaries[i] = MonitorSummary{
			MonitorID: m.ID,
			StreamURL: m.StreamURL,
			Status:    string(m.Status),
			CreatedAt: m.CreatedAt.Format(time.RFC3339),
		}
	}

	limit := params.Limit
	if limit == 0 {
		limit = 50
	}

	httpapi.RespondOK(c, ListMonitorsResponse{
		Monitors: summaries,
		Pagination: PaginationInfo{
			Total:  total,
			Limit:  limit,
			Offset: params.Offset,
		},
	})
}

// UpdateStatusRequest represents the request body for updating monitor status (internal API).
type UpdateStatusRequest struct {
	Status       string `json:"status" binding:"required"`
	StreamStatus string `json:"stream_status,omitempty"`
	Health       *struct {
		Video string `json:"video"`
		Audio string `json:"audio"`
	} `json:"health,omitempty"`
	Statistics *struct {
		TotalSegmentsAnalyzed *int `json:"total_segments_analyzed,omitempty"`
		BlackoutEvents        *int `json:"blackout_events,omitempty"`
		SilenceEvents         *int `json:"silence_events,omitempty"`
	} `json:"statistics,omitempty"`
}

// TerminateMonitorRequest represents the request body for terminating a monitor (internal API).
type TerminateMonitorRequest struct {
	Reason string `json:"reason"`
}

// UpdateMonitorStatus handles PUT /internal/v1/monitors/:monitor_id/status
func (h *Handler) UpdateMonitorStatus(c *gin.Context) {
	monitorID := c.Param("monitor_id")
	if !ids.IsValidMonitorID(monitorID) {
		httpapi.RespondNotFound(c, "Monitor not found")
		return
	}

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpapi.RespondValidationError(c, "Invalid request body: "+err.Error())
		return
	}

	// Validate status
	status := db.MonitorStatus(req.Status)
	if !validMonitorStatuses[status] {
		httpapi.RespondValidationError(c, "Invalid status value")
		return
	}

	// Pre-validate incoming enum-like fields before any DB operations to avoid partial writes
	if req.StreamStatus != "" {
		ss := db.StreamStatus(req.StreamStatus)
		if !validStreamStatuses[ss] {
			httpapi.RespondValidationError(c, "invalid stream_status: "+req.StreamStatus)
			return
		}
	}
	if req.Health != nil {
		if req.Health.Video != "" {
			vh := db.HealthStatus(req.Health.Video)
			if !validHealthStatuses[vh] {
				httpapi.RespondValidationError(c, "invalid health.video: "+req.Health.Video)
				return
			}
		}
		if req.Health.Audio != "" {
			ah := db.HealthStatus(req.Health.Audio)
			if !validHealthStatuses[ah] {
				httpapi.RespondValidationError(c, "invalid health.audio: "+req.Health.Audio)
				return
			}
		}
	}

	// Update monitor status
	if err := h.repo.UpdateStatus(c.Request.Context(), monitorID, status); err != nil {
		if errors.Is(err, db.ErrMonitorNotFound) {
			httpapi.RespondNotFound(c, "Monitor not found")
			return
		}
		log.Error("failed to update monitor status", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to update monitor status")
		return
	}

	// Update stats if provided
	if req.Health != nil || req.Statistics != nil || req.StreamStatus != "" {
		stats, err := h.repo.GetStats(c.Request.Context(), monitorID)
		if err != nil {
			log.Error("failed to get monitor stats", zap.Error(err))
		} else if stats != nil {
			now := time.Now()
			stats.LastCheckAt = &now

			// Validate stream_status
			if req.StreamStatus != "" {
				stats.StreamStatus = db.StreamStatus(req.StreamStatus)
			}
			if req.Health != nil {
				if req.Health.Video != "" {
					stats.VideoHealth = db.HealthStatus(req.Health.Video)
				}
				if req.Health.Audio != "" {
					stats.AudioHealth = db.HealthStatus(req.Health.Audio)
				}
			}
			if req.Statistics != nil {
				if req.Statistics.TotalSegmentsAnalyzed != nil {
					stats.TotalSegments = *req.Statistics.TotalSegmentsAnalyzed
				}
				if req.Statistics.BlackoutEvents != nil {
					stats.BlackoutEvents = *req.Statistics.BlackoutEvents
				}
				if req.Statistics.SilenceEvents != nil {
					stats.SilenceEvents = *req.Statistics.SilenceEvents
				}
			}

			if err := h.repo.UpdateStats(c.Request.Context(), stats); err != nil {
				log.Error("failed to update monitor stats", zap.Error(err))
			}
		}
	}

	log.Info("monitor status updated",
		zap.String("monitor_id", monitorID),
		zap.String("status", req.Status),
	)

	httpapi.RespondOK(c, gin.H{
		"monitor_id": monitorID,
		"status":     req.Status,
	})
}

// TerminateMonitor handles POST /internal/v1/monitors/:monitor_id/terminate
func (h *Handler) TerminateMonitor(c *gin.Context) {
	monitorID := c.Param("monitor_id")
	if !ids.IsValidMonitorID(monitorID) {
		httpapi.RespondNotFound(c, "Monitor not found")
		return
	}

	var req TerminateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpapi.RespondValidationError(c, "Invalid request body: "+err.Error())
		return
	}

	if err := h.repo.Delete(c.Request.Context(), monitorID); err != nil {
		if errors.Is(err, db.ErrMonitorNotFound) {
			log.Info("monitor already deleted",
				zap.String("monitor_id", monitorID),
				zap.String("reason", req.Reason),
			)
			if h.reconciler != nil {
				if err := h.reconciler.DeleteMonitorPod(c.Request.Context(), monitorID); err != nil {
					log.Error("failed to delete worker pod",
						zap.String("monitor_id", monitorID),
						zap.Error(err),
					)
				}
			}
			httpapi.RespondOK(c, gin.H{
				"monitor_id": monitorID,
				"deleted":    false,
			})
			return
		}
		log.Error("failed to delete monitor", zap.Error(err))
		httpapi.RespondInternalError(c, "Failed to delete monitor")
		return
	}

	if h.reconciler != nil {
		if err := h.reconciler.DeleteMonitorPod(c.Request.Context(), monitorID); err != nil {
			log.Error("failed to delete worker pod",
				zap.String("monitor_id", monitorID),
				zap.Error(err),
			)
		}
	}

	log.Info("monitor terminated",
		zap.String("monitor_id", monitorID),
		zap.String("reason", req.Reason),
	)

	httpapi.RespondOK(c, gin.H{
		"monitor_id": monitorID,
		"deleted":    true,
	})
}

func isValidYouTubeWatchURL(urlStr string) bool {
	if !youtubeWatchURLRegex.MatchString(urlStr) {
		return false
	}

	// Parse URL to ensure it's well-formed
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Check host
	host := strings.ToLower(parsed.Host)
	if host != "youtube.com" && host != "www.youtube.com" {
		return false
	}

	// Check for v parameter
	videoID := parsed.Query().Get("v")
	if len(videoID) != 11 {
		return false
	}

	return true
}
