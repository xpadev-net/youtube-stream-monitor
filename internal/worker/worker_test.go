package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xpadev-net/youtube-stream-tracker/internal/config"
	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ffmpeg"
	"github.com/xpadev-net/youtube-stream-tracker/internal/manifest"
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
	return "https://example.com/manifest.m3u8", nil
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

type failingWebhookSender struct{}

func (f *failingWebhookSender) Send(ctx context.Context, url string, payload *webhook.Payload) *webhook.SendResult {
	return &webhook.SendResult{Success: false, Attempts: 4, Error: "failed"}
}

type spyCallbackClient struct {
	terminateCalled bool
	terminateReason string
}

func (s *spyCallbackClient) ReportStatus(ctx context.Context, monitorID string, status db.MonitorStatus, update *StatusUpdate) error {
	return nil
}

func (s *spyCallbackClient) TerminateMonitor(ctx context.Context, monitorID string, reason string) error {
	s.terminateCalled = true
	s.terminateReason = reason
	return nil
}

func (s *spyCallbackClient) ReportWebhookEvent(ctx context.Context, monitorID string, event *WebhookEventReport) error {
	return nil
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

func TestWebhookFailureDeletesJob(t *testing.T) {
	cfg := &config.WorkerConfig{
		MonitorID:                  "mon-test",
		StreamURL:                  "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		CallbackURL:                "http://example.com",
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

	spyCallback := &spyCallbackClient{}
	worker := NewWorkerWithDeps(cfg, &stubYtDlpClient{}, nil, nil, &failingWebhookSender{}, spyCallback)

	worker.sendWebhook(context.Background(), webhook.EventStreamStarted, nil)

	if !spyCallback.terminateCalled {
		t.Fatalf("expected terminate to be called")
	}
	if spyCallback.terminateReason != "webhook_delivery_failed" {
		t.Fatalf("terminate reason = %s, want webhook_delivery_failed", spyCallback.terminateReason)
	}
}

type stubManifestParser struct{}

func (s *stubManifestParser) GetLatestSegment(ctx context.Context, manifestURL string) (*manifest.Segment, error) {
	return &manifest.Segment{
		URL:       "http://example.com/segment.ts",
		Duration:  1.0,
		Sequence:  1,
		MediaType: "hls",
	}, nil
}

func (s *stubManifestParser) IsEndList(ctx context.Context, manifestURL string) (bool, error) {
	return false, nil
}

func (s *stubManifestParser) FetchSegment(ctx context.Context, segmentURL string) ([]byte, error) {
	return []byte("data"), nil
}

type stubAnalyzer struct{}

func (s *stubAnalyzer) EnsureTmpDir() error {
	return nil
}

func (s *stubAnalyzer) CleanupMonitor(monitorID string) error {
	return nil
}

func (s *stubAnalyzer) SaveSegment(monitorID string, data []byte) (string, error) {
	return "/tmp/segment.ts", nil
}

func (s *stubAnalyzer) CleanupSegment(segmentPath string) error {
	return nil
}

func (s *stubAnalyzer) AnalyzeSegment(ctx context.Context, segmentPath string) (*ffmpeg.AnalysisResult, error) {
	return &ffmpeg.AnalysisResult{
		Black:   &ffmpeg.BlackDetectResult{},
		Silence: &ffmpeg.SilenceDetectResult{},
	}, nil
}

type delayedAnalyzer struct {
	delay    time.Duration
	done     chan struct{}
	doneOnce sync.Once
}

func (d *delayedAnalyzer) EnsureTmpDir() error {
	return nil
}

func (d *delayedAnalyzer) CleanupMonitor(monitorID string) error {
	return nil
}

func (d *delayedAnalyzer) SaveSegment(monitorID string, data []byte) (string, error) {
	return "/tmp/segment.ts", nil
}

func (d *delayedAnalyzer) CleanupSegment(segmentPath string) error {
	return nil
}

func (d *delayedAnalyzer) AnalyzeSegment(ctx context.Context, segmentPath string) (*ffmpeg.AnalysisResult, error) {
	time.Sleep(d.delay)
	d.doneOnce.Do(func() {
		if d.done != nil {
			close(d.done)
		}
	})
	return &ffmpeg.AnalysisResult{
		Black:   &ffmpeg.BlackDetectResult{},
		Silence: &ffmpeg.SilenceDetectResult{},
	}, nil
}

func TestGracefulShutdownCompletesAnalysis(t *testing.T) {
	cfg := &config.WorkerConfig{
		MonitorID:                  "mon-test",
		StreamURL:                  "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		CallbackURL:                "http://example.com",
		InternalAPIKey:             "internal-key",
		WebhookURL:                 "http://example.com",
		WebhookSigningKey:          "signing-key",
		WaitingModeInitialInterval: 1 * time.Millisecond,
		WaitingModeDelayedInterval: 1 * time.Millisecond,
		ManifestFetchTimeout:       1 * time.Second,
		ManifestRefreshInterval:    1 * time.Second,
		SegmentFetchTimeout:        1 * time.Second,
		SegmentMaxBytes:            1024,
		AnalysisInterval:           1 * time.Millisecond,
		BlackoutThreshold:          1 * time.Second,
		SilenceThreshold:           1 * time.Second,
		SilenceDBThreshold:         -50,
		DelayThreshold:             1 * time.Second,
		FFmpegPath:                 "ffmpeg",
		FFprobePath:                "ffprobe",
		YtDlpPath:                  "yt-dlp",
		StreamlinkPath:             "streamlink",
	}

	parser := &stubManifestParser{}
	done := make(chan struct{})
	analyzer := &delayedAnalyzer{delay: 20 * time.Millisecond, done: done}
	spyCallback := &spyCallbackClient{}
	worker := NewWorkerWithDeps(cfg, &stubYtDlpClient{}, parser, analyzer, &captureWebhookSender{}, spyCallback)
	worker.setState(StateMonitoring)
	worker.lastLiveCheck = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("worker run error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("analysis did not complete before shutdown")
	}
}
