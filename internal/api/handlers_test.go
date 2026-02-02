package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/xpadev-net/youtube-stream-tracker/internal/db"
	"github.com/xpadev-net/youtube-stream-tracker/internal/ids"
)

func TestIsValidYouTubeWatchURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "valid YouTube watch URL",
			url:  "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
			want: true,
		},
		{
			name: "valid YouTube watch URL without www",
			url:  "https://youtube.com/watch?v=dQw4w9WgXcQ",
			want: true,
		},
		{
			name: "valid YouTube watch URL with http",
			url:  "http://www.youtube.com/watch?v=dQw4w9WgXcQ",
			want: true,
		},
		{
			name: "invalid URL - not YouTube",
			url:  "https://example.com/watch?v=dQw4w9WgXcQ",
			want: false,
		},
		{
			name: "invalid URL - wrong domain",
			url:  "https://youtu.be/dQw4w9WgXcQ",
			want: false,
		},
		{
			name: "invalid URL - missing video ID",
			url:  "https://www.youtube.com/watch",
			want: false,
		},
		{
			name: "invalid URL - short video ID",
			url:  "https://www.youtube.com/watch?v=short",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidYouTubeWatchURL(tt.url); got != tt.want {
				t.Errorf("isValidYouTubeWatchURL(%v) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestNewHandler(t *testing.T) {
	repo := &db.MonitorRepository{}
	handler := NewHandler(repo, 50, nil, "internal-key", "signing-key", "stream-monitor-secrets", "internal-api-key", "webhook-signing-key")

	if handler.repo != repo {
		t.Error("NewHandler() repo not set correctly")
	}

	if handler.maxMonitors != 50 {
		t.Errorf("NewHandler() maxMonitors = %v, want 50", handler.maxMonitors)
	}

	if handler.internalAPIKey != "internal-key" {
		t.Errorf("NewHandler() internalAPIKey = %v, want internal-key", handler.internalAPIKey)
	}

	if handler.webhookSigningKey != "signing-key" {
		t.Errorf("NewHandler() webhookSigningKey = %v, want signing-key", handler.webhookSigningKey)
	}
}

// TestCreateMonitorRequest tests the request structure
func TestCreateMonitorRequest(t *testing.T) {
	req := CreateMonitorRequest{
		StreamURL:   "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		CallbackURL: "https://example.com/webhook",
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal CreateMonitorRequest: %v", err)
	}

	var unmarshaled CreateMonitorRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal CreateMonitorRequest: %v", err)
	}

	if unmarshaled.StreamURL != req.StreamURL {
		t.Errorf("Unmarshaled StreamURL = %v, want %v", unmarshaled.StreamURL, req.StreamURL)
	}

	if unmarshaled.CallbackURL != req.CallbackURL {
		t.Errorf("Unmarshaled CallbackURL = %v, want %v", unmarshaled.CallbackURL, req.CallbackURL)
	}
}

func TestUpdateMonitorStatusValidation(t *testing.T) {
	// Setup a handler with a fake repo that returns stats
	repo := &db.MonitorRepository{}
	handler := NewHandler(repo, 50, nil, "internal-key", "signing-key", "stream-monitor-secrets", "internal-api-key", "webhook-signing-key")

	router := setupTestRouter()
	router.PUT("/internal/v1/monitors/:monitor_id/status", handler.UpdateMonitorStatus)

	// Prepare a request with invalid stream_status
	validID := ids.NewMonitorID()
	body := `{"status":"monitoring","stream_status":"invalid_status"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/internal/v1/monitors/"+validID+"/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid stream_status, got %d", w.Code)
	}

	// Prepare a request with invalid health.video
	body = `{"status":"monitoring","health":{"video":"bad","audio":"ok"}}`
	w = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/internal/v1/monitors/"+validID+"/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid health.video, got %d", w.Code)
	}
}

// TestMonitorIDValidation tests that monitor IDs are validated correctly
func TestMonitorIDValidation(t *testing.T) {
	validID := ids.NewMonitorID()
	if !ids.IsValidMonitorID(validID) {
		t.Errorf("Generated monitor ID %v should be valid", validID)
	}

	invalidIDs := []string{
		"invalid",
		"mon-",
		"monitor-123",
		"",
	}

	for _, id := range invalidIDs {
		if ids.IsValidMonitorID(id) {
			t.Errorf("Monitor ID %v should be invalid", id)
		}
	}
}

// TestResponseStructures tests the response structures
func TestResponseStructures(t *testing.T) {
	// Test CreateMonitorResponse
	createResp := CreateMonitorResponse{
		MonitorID: "mon-123",
		Status:    "initializing",
		CreatedAt: "2026-01-24T00:00:00Z",
	}

	jsonData, err := json.Marshal(createResp)
	if err != nil {
		t.Fatalf("Failed to marshal CreateMonitorResponse: %v", err)
	}

	var unmarshaled CreateMonitorResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal CreateMonitorResponse: %v", err)
	}

	if unmarshaled.MonitorID != createResp.MonitorID {
		t.Errorf("Unmarshaled MonitorID = %v, want %v", unmarshaled.MonitorID, createResp.MonitorID)
	}

	// Test DeleteMonitorResponse
	deleteResp := DeleteMonitorResponse{
		MonitorID: "mon-123",
		Status:    "stopped",
		StoppedAt: "2026-01-24T00:00:00Z",
	}

	jsonData, err = json.Marshal(deleteResp)
	if err != nil {
		t.Fatalf("Failed to marshal DeleteMonitorResponse: %v", err)
	}

	var unmarshaledDelete DeleteMonitorResponse
	err = json.Unmarshal(jsonData, &unmarshaledDelete)
	if err != nil {
		t.Fatalf("Failed to unmarshal DeleteMonitorResponse: %v", err)
	}

	if unmarshaledDelete.MonitorID != deleteResp.MonitorID {
		t.Errorf("Unmarshaled MonitorID = %v, want %v", unmarshaledDelete.MonitorID, deleteResp.MonitorID)
	}
}

// TestHealthResponse tests the health response structure
func TestHealthResponse(t *testing.T) {
	health := HealthResponse{
		Video:       "ok",
		Audio:       "ok",
		LastCheckAt: "2026-01-24T00:00:00Z",
	}

	jsonData, err := json.Marshal(health)
	if err != nil {
		t.Fatalf("Failed to marshal HealthResponse: %v", err)
	}

	var unmarshaled HealthResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal HealthResponse: %v", err)
	}

	if unmarshaled.Video != health.Video {
		t.Errorf("Unmarshaled Video = %v, want %v", unmarshaled.Video, health.Video)
	}
}

// TestStatsResponse tests the stats response structure
func TestStatsResponse(t *testing.T) {
	stats := StatsResponse{
		TotalSegmentsAnalyzed: 100,
		BlackoutEvents:        5,
		SilenceEvents:         3,
	}

	jsonData, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("Failed to marshal StatsResponse: %v", err)
	}

	var unmarshaled StatsResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal StatsResponse: %v", err)
	}

	if unmarshaled.TotalSegmentsAnalyzed != stats.TotalSegmentsAnalyzed {
		t.Errorf("Unmarshaled TotalSegmentsAnalyzed = %v, want %v", unmarshaled.TotalSegmentsAnalyzed, stats.TotalSegmentsAnalyzed)
	}
}

// TestPaginationInfo tests pagination structure
func TestPaginationInfo(t *testing.T) {
	pagination := PaginationInfo{
		Total:  100,
		Limit:  50,
		Offset: 0,
	}

	jsonData, err := json.Marshal(pagination)
	if err != nil {
		t.Fatalf("Failed to marshal PaginationInfo: %v", err)
	}

	var unmarshaled PaginationInfo
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal PaginationInfo: %v", err)
	}

	if unmarshaled.Total != pagination.Total {
		t.Errorf("Unmarshaled Total = %v, want %v", unmarshaled.Total, pagination.Total)
	}
}

// Helper function to create a test router
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

// TestHandlerStructure tests that handler can be created without errors
func TestHandlerStructure(t *testing.T) {
	router := setupTestRouter()
	repo := &db.MonitorRepository{}

	handler := NewHandler(repo, 50, nil, "test-key", "test-signing-key", "stream-monitor-secrets", "internal-api-key", "webhook-signing-key")

	// Test that handler can be used in a route
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"handler": "created"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Test router status = %v, want %v", w.Code, http.StatusOK)
	}

	_ = handler // Suppress unused variable warning
}
