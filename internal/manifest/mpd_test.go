package manifest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetLatestSegmentDASHSegmentTimeline(t *testing.T) {
	mpd := `<?xml version="1.0" encoding="UTF-8"?>
<MPD mediaPresentationDuration="PT30S">
  <Period>
    <AdaptationSet>
      <Representation id="video" bandwidth="500000">
        <SegmentTemplate timescale="1" media="seg_$Number$.m4s" startNumber="1">
          <SegmentTimeline>
            <S t="0" d="10" r="2"/>
          </SegmentTimeline>
        </SegmentTemplate>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mpd))
	}))
	defer server.Close()

	parser := NewParserWithLimit(2*time.Second, 1024)
	// Use DefaultClient to allow httptest server (localhost) requests in tests.
	parser.httpClient = http.DefaultClient
	segment, err := parser.GetLatestSegment(context.Background(), server.URL+"/manifest.mpd")
	if err != nil {
		t.Fatalf("GetLatestSegment error: %v", err)
	}
	if segment.MediaType != "dash" {
		t.Fatalf("MediaType = %s, want dash", segment.MediaType)
	}
	if segment.URL != server.URL+"/seg_3.m4s" {
		t.Fatalf("segment URL = %s, want %s", segment.URL, server.URL+"/seg_3.m4s")
	}
	if segment.Duration != 10 {
		t.Fatalf("segment duration = %v, want 10", segment.Duration)
	}
}

func TestGetLatestSegmentDASHDuration(t *testing.T) {
	mpd := `<?xml version="1.0" encoding="UTF-8"?>
<MPD mediaPresentationDuration="PT20S">
  <Period>
    <AdaptationSet>
      <Representation id="video" bandwidth="500000">
        <SegmentTemplate timescale="1" duration="5" media="seg_$Number$.m4s" startNumber="1"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mpd))
	}))
	defer server.Close()

	parser := NewParserWithLimit(2*time.Second, 1024)
	// Use DefaultClient to allow httptest server (localhost) requests in tests.
	parser.httpClient = http.DefaultClient
	segment, err := parser.GetLatestSegment(context.Background(), server.URL+"/manifest.mpd")
	if err != nil {
		t.Fatalf("GetLatestSegment error: %v", err)
	}
	if segment.MediaType != "dash" {
		t.Fatalf("MediaType = %s, want dash", segment.MediaType)
	}
	if segment.URL != server.URL+"/seg_4.m4s" {
		t.Fatalf("segment URL = %s, want %s", segment.URL, server.URL+"/seg_4.m4s")
	}
	if segment.Duration != 5 {
		t.Fatalf("segment duration = %v, want 5", segment.Duration)
	}
}
