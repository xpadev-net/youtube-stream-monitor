package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
	"github.com/xpadev-net/youtube-stream-tracker/internal/validation"
)

// EventType represents the type of webhook event.
type EventType string

const (
	EventStreamStarted          EventType = "stream.started"
	EventStreamEnded            EventType = "stream.ended"
	EventStreamDelayed          EventType = "stream.delayed"
	EventAlertBlackout          EventType = "alert.blackout"
	EventAlertBlackoutRecovered EventType = "alert.blackout_recovered"
	EventAlertSilence           EventType = "alert.silence"
	EventAlertSilenceRecovered  EventType = "alert.silence_recovered"
	EventAlertSegmentError      EventType = "alert.segment_error"
	EventMonitorError           EventType = "monitor.error"
)

// Payload represents a webhook payload.
type Payload struct {
	EventType EventType              `json:"event_type"`
	MonitorID string                 `json:"monitor_id"`
	StreamURL string                 `json:"stream_url"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Metadata  json.RawMessage        `json:"metadata,omitempty"`
}

// Sender handles webhook delivery.
type Sender struct {
	httpClient *http.Client
	signingKey string
	maxRetries int
}

// NewSender creates a new webhook sender.
func NewSender(signingKey string) *Sender {
	client := validation.NewSafeHTTPClient(10 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Cap redirects more strictly than the Go default (10) for defense in depth.
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if err := validation.ValidateOutboundURL(req.Context(), req.URL.String(), false); err != nil {
			return fmt.Errorf("redirect url not allowed: %w", err)
		}
		return nil
	}
	return &Sender{
		httpClient: client,
		signingKey: signingKey,
		maxRetries: 4, // total attempts (initial + 3 retries)
	}
}

// SendResult contains the result of sending a webhook.
type SendResult struct {
	Success    bool
	Attempts   int
	StatusCode int
	Error      string
}

// Send sends a webhook to the specified URL with retries.
func (s *Sender) Send(ctx context.Context, webhookURL string, payload *Payload) *SendResult {
	return s.sendValidated(ctx, webhookURL, payload)
}

func (s *Sender) sendValidated(ctx context.Context, webhookURL string, payload *Payload) *SendResult {
	if err := validation.ValidateOutboundURL(ctx, webhookURL, false); err != nil {
		return &SendResult{Error: fmt.Sprintf("invalid webhook url: %v", err)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &SendResult{Error: fmt.Sprintf("marshal payload: %v", err)}
	}

	return s.sendWithRetries(ctx, webhookURL, payload, body)
}

func (s *Sender) sendWithoutValidation(ctx context.Context, webhookURL string, payload *Payload) *SendResult {
	body, err := json.Marshal(payload)
	if err != nil {
		return &SendResult{Error: fmt.Sprintf("marshal payload: %v", err)}
	}

	return s.sendWithRetries(ctx, webhookURL, payload, body)
}

func (s *Sender) sendWithRetries(ctx context.Context, webhookURL string, payload *Payload, body []byte) *SendResult {
	result := &SendResult{}
	for attempt := 1; attempt <= s.maxRetries; attempt++ {
		result.Attempts = attempt

		// Wait before retry (skip first attempt)
		if delay := retryDelay(attempt); delay > 0 {
			select {
			case <-ctx.Done():
				result.Error = "context canceled"
				return result
			case <-time.After(delay):
			}
		}

		statusCode, err := s.sendOnce(ctx, webhookURL, body)
		result.StatusCode = statusCode

		if err == nil && statusCode >= 200 && statusCode < 300 {
			result.Success = true
			result.Error = ""
			log.Info("webhook sent successfully",
				zap.String("url", webhookURL),
				zap.String("event_type", string(payload.EventType)),
				zap.Int("attempt", attempt),
			)
			return result
		}

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else {
			errMsg = fmt.Sprintf("HTTP %d", statusCode)
		}

		log.Warn("webhook delivery failed",
			zap.String("url", webhookURL),
			zap.String("event_type", string(payload.EventType)),
			zap.Int("attempt", attempt),
			zap.String("error", errMsg),
		)

		result.Error = errMsg
	}

	log.Error("webhook delivery failed after all retries",
		zap.String("url", webhookURL),
		zap.String("event_type", string(payload.EventType)),
		zap.Int("total_attempts", result.Attempts),
		zap.String("last_error", result.Error),
	)

	return result
}

func retryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	shift := attempt - 2
	if shift < 0 {
		return 0
	}
	delay := time.Second * time.Duration(1<<shift)
	if delay > 10*time.Second {
		return 10 * time.Second
	}
	return delay
}

// sendOnce sends a single webhook request.
func (s *Sender) sendOnce(ctx context.Context, webhookURL string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	// Set headers
	timestamp := time.Now().Unix()
	signature := s.sign(timestamp, body)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Signature-256", "sha256="+signature)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Read and discard body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

// sign creates an HMAC-SHA256 signature for the webhook.
// Format: HMAC-SHA256(key, "{timestamp}.{body}")
func (s *Sender) sign(timestamp int64, body []byte) string {
	message := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(s.signingKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies a webhook signature.
// This is useful for implementing a webhook receiver.
func VerifySignature(signingKey, signature string, timestamp int64, body []byte) bool {
	// Check timestamp is within 5 minutes
	now := time.Now().Unix()
	if abs(now-timestamp) > 300 {
		return false
	}

	// Verify signature
	message := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expected))
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
