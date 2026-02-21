package manifest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetLatestSegmentHLSMediaPlaylist(t *testing.T) {
	m3u8 := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:100
#EXTINF:10.0,
segment100.ts
#EXTINF:10.0,
segment101.ts
#EXTINF:8.5,
segment102.ts
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m3u8))
	}))
	defer server.Close()

	parser := newTestParser()

	segment, err := parser.GetLatestSegment(context.Background(), server.URL+"/stream/playlist.m3u8")
	if err != nil {
		t.Fatalf("GetLatestSegment error: %v", err)
	}
	if segment.MediaType != "hls" {
		t.Fatalf("MediaType = %s, want hls", segment.MediaType)
	}
	expectedURL := server.URL + "/stream/segment102.ts"
	if segment.URL != expectedURL {
		t.Fatalf("segment URL = %s, want %s", segment.URL, expectedURL)
	}
	if segment.Duration != 8.5 {
		t.Fatalf("segment duration = %v, want 8.5", segment.Duration)
	}
	// Sequence = media sequence (100) + index of last segment (2) = 102
	if segment.Sequence != 102 {
		t.Fatalf("segment sequence = %d, want 102", segment.Sequence)
	}
}

func TestGetLatestSegmentHLSMasterPlaylist(t *testing.T) {
	master := `#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=1000000
media/720p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=500000
media/480p.m3u8
`
	media := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:50
#EXTINF:6.0,
seg50.ts
#EXTINF:6.0,
seg51.ts
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/master.m3u8":
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(master))
		case "/media/720p.m3u8":
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(media))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	parser := newTestParser()

	segment, err := parser.GetLatestSegment(context.Background(), server.URL+"/master.m3u8")
	if err != nil {
		t.Fatalf("GetLatestSegment error: %v", err)
	}
	if segment.MediaType != "hls" {
		t.Fatalf("MediaType = %s, want hls", segment.MediaType)
	}
	expectedURL := server.URL + "/media/seg51.ts"
	if segment.URL != expectedURL {
		t.Fatalf("segment URL = %s, want %s", segment.URL, expectedURL)
	}
	if segment.Duration != 6.0 {
		t.Fatalf("segment duration = %v, want 6.0", segment.Duration)
	}
	// Sequence = media sequence (50) + index of last segment (1) = 51
	if segment.Sequence != 51 {
		t.Fatalf("segment sequence = %d, want 51", segment.Sequence)
	}
}

func TestGetLatestSegmentHLSEmptyPlaylist(t *testing.T) {
	m3u8 := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m3u8))
	}))
	defer server.Close()

	parser := newTestParser()

	_, err := parser.GetLatestSegment(context.Background(), server.URL+"/empty.m3u8")
	if err == nil {
		t.Fatalf("expected error for empty playlist, got nil")
	}
}

func TestIsEndListHLSLive(t *testing.T) {
	m3u8 := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:1
#EXTINF:10.0,
segment1.ts
#EXTINF:10.0,
segment2.ts
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m3u8))
	}))
	defer server.Close()

	parser := newTestParser()

	ended, err := parser.IsEndList(context.Background(), server.URL+"/live.m3u8")
	if err != nil {
		t.Fatalf("IsEndList error: %v", err)
	}
	if ended {
		t.Fatalf("IsEndList = true, want false for live playlist")
	}
}

func TestIsEndListHLSEnded(t *testing.T) {
	m3u8 := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:1
#EXTINF:10.0,
segment1.ts
#EXTINF:10.0,
segment2.ts
#EXT-X-ENDLIST
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m3u8))
	}))
	defer server.Close()

	parser := newTestParser()

	ended, err := parser.IsEndList(context.Background(), server.URL+"/ended.m3u8")
	if err != nil {
		t.Fatalf("IsEndList error: %v", err)
	}
	if !ended {
		t.Fatalf("IsEndList = false, want true for ended playlist")
	}
}

func TestGetLatestSegmentHLSRelativeURL(t *testing.T) {
	m3u8 := `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
../segments/seg0.ts
#EXTINF:10.0,
../segments/seg1.ts
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m3u8))
	}))
	defer server.Close()

	parser := newTestParser()

	segment, err := parser.GetLatestSegment(context.Background(), server.URL+"/hls/playlist.m3u8")
	if err != nil {
		t.Fatalf("GetLatestSegment error: %v", err)
	}
	// ../segments/seg1.ts relative to /hls/playlist.m3u8 resolves to /segments/seg1.ts
	expectedURL := server.URL + "/segments/seg1.ts"
	if segment.URL != expectedURL {
		t.Fatalf("segment URL = %s, want %s", segment.URL, expectedURL)
	}
	if segment.Sequence != 1 {
		t.Fatalf("segment sequence = %d, want 1", segment.Sequence)
	}
}
