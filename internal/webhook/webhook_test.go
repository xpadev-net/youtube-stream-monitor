package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	sender := NewSender("test-secret-key")
	timestamp := int64(1705315000)
	body := []byte(`{"event_type":"test","monitor_id":"mon-123"}`)

	signature := sender.sign(timestamp, body)

	// Verify signature format
	if len(signature) != 64 { // SHA256 hex = 64 chars
		t.Errorf("signature length = %v, want 64", len(signature))
	}

	// Verify signature is hex
	_, err := hex.DecodeString(signature)
	if err != nil {
		t.Errorf("signature is not valid hex: %v", err)
	}

	// Verify signature is deterministic
	signature2 := sender.sign(timestamp, body)
	if signature != signature2 {
		t.Errorf("signature is not deterministic: %v != %v", signature, signature2)
	}
}

func TestVerifySignature(t *testing.T) {
	signingKey := "test-secret-key"
	timestamp := time.Now().Unix()
	body := []byte(`{"event_type":"test","monitor_id":"mon-123"}`)

	// Generate signature using the same method as the Sender
	message := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(message))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	// VerifySignature expects signature without "sha256=" prefix (it compares hex directly)
	signature := expectedSig

	// Test valid signature
	if !VerifySignature(signingKey, signature, timestamp, body) {
		t.Error("VerifySignature() = false, want true for valid signature")
	}

	// Test invalid signature
	wrongSig := hex.EncodeToString([]byte("wrong"))
	if VerifySignature(signingKey, wrongSig, timestamp, body) {
		t.Error("VerifySignature() = true, want false for invalid signature")
	}

	// Test wrong key
	if VerifySignature("wrong-key", signature, timestamp, body) {
		t.Error("VerifySignature() = true, want false for wrong key")
	}

	// Test expired timestamp (more than 5 minutes old)
	oldTimestamp := time.Now().Unix() - 400 // 400 seconds = more than 5 minutes
	oldMessage := fmt.Sprintf("%d.%s", oldTimestamp, string(body))
	oldMac := hmac.New(sha256.New, []byte(signingKey))
	oldMac.Write([]byte(oldMessage))
	oldSignature := hex.EncodeToString(oldMac.Sum(nil))
	if VerifySignature(signingKey, oldSignature, oldTimestamp, body) {
		t.Error("VerifySignature() = true, want false for expired timestamp")
	}

	// Test future timestamp (more than 5 minutes ahead)
	futureTimestamp := time.Now().Unix() + 400 // 400 seconds = more than 5 minutes
	futureMessage := fmt.Sprintf("%d.%s", futureTimestamp, string(body))
	futureMac := hmac.New(sha256.New, []byte(signingKey))
	futureMac.Write([]byte(futureMessage))
	futureSignature := hex.EncodeToString(futureMac.Sum(nil))
	if VerifySignature(signingKey, futureSignature, futureTimestamp, body) {
		t.Error("VerifySignature() = true, want false for future timestamp")
	}
}

func TestNewSender(t *testing.T) {
	sender := NewSender("test-key")

	if sender.signingKey != "test-key" {
		t.Errorf("NewSender().signingKey = %v, want test-key", sender.signingKey)
	}

	if sender.maxRetries != 4 {
		t.Errorf("NewSender().maxRetries = %v, want 4", sender.maxRetries)
	}

	if sender.httpClient.Timeout != 10*time.Second {
		t.Errorf("NewSender().httpClient.Timeout = %v, want 10s", sender.httpClient.Timeout)
	}
}

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: 0},
		{attempt: 2, want: 1 * time.Second},
		{attempt: 3, want: 2 * time.Second},
		{attempt: 4, want: 4 * time.Second},
		{attempt: 6, want: 10 * time.Second},
	}

	for _, tt := range tests {
		if got := retryDelay(tt.attempt); got != tt.want {
			t.Errorf("retryDelay(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func TestSender_Send_RetryTimestamp(t *testing.T) {
	sender := NewSender("test-secret")

	var requestBodies [][]byte
	var timestamps []string // X-Timestamp header

	mock := &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			// Capture body
			body, _ := io.ReadAll(req.Body)
			requestBodies = append(requestBodies, body)
			req.Body.Close()
			// Create a new body for the request in case it's used again (though here we just consumed it)
			// Actually, since we read it, if the code tries to read it again it might fail if we don't restore it.
			// But the Sender logic is: marshal body -> loop { sendOnce(body) }.
			// sendOnce makes a new request with bytes.NewReader(body).
			// So the body IS safe to read fully here as it is a fresh reader each time.

			timestamps = append(timestamps, req.Header.Get("X-Timestamp"))

			if len(requestBodies) == 1 {
				return nil, fmt.Errorf("network error")
			}
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString("{}")),
			}, nil
		},
	}
	sender.httpClient.Transport = mock
	sender.maxRetries = 2 // 2 attempts total (1 initial + 1 retry)

	payload := &Payload{
		EventType: "test_event",
		MonitorID: "mon-test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	result := sender.Send(ctx, "http://example.com", payload)

	if !result.Success {
		t.Errorf("Send failed: %v", result.Error)
	}
	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}

	if len(requestBodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requestBodies))
	}

	// Verify bodies are identical
	if string(requestBodies[0]) != string(requestBodies[1]) {
		t.Errorf("request bodies differ between retries:\n%s\nvs\n%s", requestBodies[0], requestBodies[1])
	}

	// Verify timestamp in body is consistent
	// We can decode to map to check specifically the timestamp field, or just string compare (which we did).

	first, err := strconv.ParseInt(timestamps[0], 10, 64)
	if err != nil {
		t.Fatalf("failed to parse first X-Timestamp: %v", err)
	}
	second, err := strconv.ParseInt(timestamps[1], 10, 64)
	if err != nil {
		t.Fatalf("failed to parse second X-Timestamp: %v", err)
	}
	if second < first {
		t.Errorf("X-Timestamp should be monotonic: first=%d second=%d", first, second)
	}
}
