package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/validation"
)

// CallbackClient handles communication with the Gateway's internal API.
type CallbackClient struct {
	baseURL        string
	internalAPIKey string
	httpClient     *http.Client
}

// NewCallbackClient creates a new callback client.
func NewCallbackClient(baseURL, internalAPIKey string) *CallbackClient {
	return &CallbackClient{
		baseURL:        baseURL,
		internalAPIKey: internalAPIKey,
		// Allow private IPs for in-cluster gateway service resolution.
		httpClient: validation.NewSafeHTTPClientWithPrivate(10*time.Second, true),
	}
}

// StatusUpdate contains fields for updating monitor status.
type StatusUpdate struct {
	StreamStatus   string `json:"stream_status,omitempty"`
	VideoHealth    string `json:"video_health,omitempty"`
	AudioHealth    string `json:"audio_health,omitempty"`
	TotalSegments  int    `json:"total_segments,omitempty"`
	BlackoutEvents int    `json:"blackout_events,omitempty"`
	SilenceEvents  int    `json:"silence_events,omitempty"`
}

// StatusRequest is the request body for status update.
type StatusRequest struct {
	Status       string `json:"status"`
	StreamStatus string `json:"stream_status,omitempty"`
	Health       *struct {
		Video string `json:"video"`
		Audio string `json:"audio"`
	} `json:"health,omitempty"`
	Statistics *struct {
		TotalSegmentsAnalyzed int `json:"total_segments_analyzed,omitempty"`
		BlackoutEvents        int `json:"blackout_events,omitempty"`
		SilenceEvents         int `json:"silence_events,omitempty"`
	} `json:"statistics,omitempty"`
}

// ReportStatus reports the current status to the gateway.
func (c *CallbackClient) ReportStatus(ctx context.Context, monitorID string, status db.MonitorStatus, update *StatusUpdate) error {
	// Internal callbacks are expected to target the in-cluster gateway service.
	if err := validation.ValidateOutboundURL(ctx, c.baseURL, true); err != nil {
		return fmt.Errorf("invalid internal callback url: %w", err)
	}
	url := fmt.Sprintf("%s/internal/v1/monitors/%s/status", c.baseURL, monitorID)

	req := StatusRequest{
		Status: string(status),
	}

	if update != nil {
		if update.StreamStatus != "" {
			req.StreamStatus = update.StreamStatus
		}
		if update.VideoHealth != "" || update.AudioHealth != "" {
			req.Health = &struct {
				Video string `json:"video"`
				Audio string `json:"audio"`
			}{
				Video: update.VideoHealth,
				Audio: update.AudioHealth,
			}
		}
		if update.TotalSegments > 0 || update.BlackoutEvents > 0 || update.SilenceEvents > 0 {
			req.Statistics = &struct {
				TotalSegmentsAnalyzed int `json:"total_segments_analyzed,omitempty"`
				BlackoutEvents        int `json:"blackout_events,omitempty"`
				SilenceEvents         int `json:"silence_events,omitempty"`
			}{
				TotalSegmentsAnalyzed: update.TotalSegments,
				BlackoutEvents:        update.BlackoutEvents,
				SilenceEvents:         update.SilenceEvents,
			}
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-API-Key", c.internalAPIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("gateway returned status %d", resp.StatusCode)
	}

	return nil
}

// TerminateMonitor requests that the gateway delete the monitor and its pod.
func (c *CallbackClient) TerminateMonitor(ctx context.Context, monitorID string, reason string) error {
	if err := validation.ValidateOutboundURL(ctx, c.baseURL, true); err != nil {
		return fmt.Errorf("invalid internal callback url: %w", err)
	}
	url := fmt.Sprintf("%s/internal/v1/monitors/%s/terminate", c.baseURL, monitorID)

	body, err := json.Marshal(map[string]string{
		"reason": reason,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-API-Key", c.internalAPIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("gateway returned status %d", resp.StatusCode)
	}

	return nil
}
