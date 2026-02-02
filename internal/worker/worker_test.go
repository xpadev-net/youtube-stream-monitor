package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xpadev-net/youtube-stream-tracker/internal/config"
	"github.com/xpadev-net/youtube-stream-tracker/internal/webhook"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ytdlp"
)

type stubYtDlpClient struct {
	isLive bool
	info   *ytdlp.StreamInfo
	err    error
}

func (s *stubYtDlpClient) IsStreamLive(ctx context.Context, streamURL string) (bool, *ytdlp.StreamInfo, error) {
	return s.isLive, s.info, s.err
}

func (s *stubYtDlpClient) GetManifestURL(ctx context.Context, streamURL string) (string, error) {
	return "", nil
}

type captureWebhookSender struct {
	calls []*webhook.Payload
	urls  []string
}

func (c *captureWebhookSender) Send(ctx context.Context, url string, payload *webhook.Payload) *webhook.SendResult {
	c.calls = append(c.calls, payload)
	c.urls = append(c.urls, url)
	return &webhook.SendResult{Success: true, Attempts: 1}
}

func TestWaitingModeSendsStreamEnded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.WorkerConfig{
		MonitorID:                  "mon-test",
		StreamURL:                  "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		CallbackURL:                server.URL,
		InternalAPIKey:             "internal-key",
		WebhookURL:                 "http://example.com",
		WebhookSigningKey:          "signing-key",
		WaitingModeInitialInterval: 1 * time.Millisecond,
		WaitingModeDelayedInterval: 1 * time.Millisecond,
		ManifestFetchTimeout:       1 * time.Second,
		ManifestRefreshInterval:    1 * time.Second,
		SegmentFetchTimeout:        1 * time.Second,
		SegmentMaxBytes:            1024,
		AnalysisInterval:           1 * time.Second,
		BlackoutThreshold:          1 * time.Second,
		SilenceThreshold:           1 * time.Second,
		SilenceDBThreshold:         -50,
		DelayThreshold:             1 * time.Second,
		FFmpegPath:                 "ffmpeg",
		FFprobePath:                "ffprobe",
		YtDlpPath:                  "yt-dlp",
		StreamlinkPath:             "streamlink",
	}

	ytdlpClient := &stubYtDlpClient{
		isLive: false,
		info: &ytdlp.StreamInfo{
			LiveStatus: "was_live",
		},
	}
	sender := &captureWebhookSender{}
	callbackClient := NewCallbackClient(server.URL, cfg.InternalAPIKey)
	worker := NewWorkerWithDeps(cfg, ytdlpClient, nil, nil, sender, callbackClient)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := worker.waitingMode(ctx); err != nil {
		t.Fatalf("waitingMode returned error: %v", err)
	}

	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 webhook call, got %d", len(sender.calls))
	}

	payload := sender.calls[0]
	if payload.EventType != webhook.EventStreamEnded {
		t.Fatalf("event_type = %v, want %v", payload.EventType, webhook.EventStreamEnded)
	}

	reason, ok := payload.Data["reason"]
	if !ok {
		t.Fatalf("expected reason in payload data")
	}
	if reason != "was_live" {
		t.Fatalf("reason = %v, want was_live", reason)
	}
}
