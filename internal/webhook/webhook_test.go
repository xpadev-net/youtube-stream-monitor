package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	if sender.maxRetries != 3 {
		t.Errorf("NewSender().maxRetries = %v, want 3", sender.maxRetries)
	}

	if sender.httpClient.Timeout != 10*time.Second {
		t.Errorf("NewSender().httpClient.Timeout = %v, want 10s", sender.httpClient.Timeout)
	}
}
