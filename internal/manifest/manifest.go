package manifest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grafov/m3u8"

	"github.com/xpadev-net/youtube-stream-tracker/internal/validation"
)

// Segment represents a media segment from the manifest.
type Segment struct {
	URL       string
	Duration  float64
	Sequence  uint64
	MediaType string // "hls" or "dash"
}

// Parser handles manifest parsing.
type Parser struct {
	httpClient      *http.Client
	maxSegmentBytes int64
}

// NewParser creates a new manifest parser.
func NewParser(timeout time.Duration) *Parser {
	return &Parser{
		httpClient:      validation.NewSafeHTTPClient(timeout),
		maxSegmentBytes: 10 * 1024 * 1024,
	}
}

// NewParserWithLimit creates a manifest parser with a segment size limit.
func NewParserWithLimit(timeout time.Duration, maxSegmentBytes int64) *Parser {
	if maxSegmentBytes <= 0 {
		maxSegmentBytes = 10 * 1024 * 1024
	}
	return &Parser{
		httpClient:      validation.NewSafeHTTPClient(timeout),
		maxSegmentBytes: maxSegmentBytes,
	}
}

// GetLatestSegment retrieves the latest segment from the manifest URL.
func (p *Parser) GetLatestSegment(ctx context.Context, manifestURL string) (*Segment, error) {
	// Determine manifest type from URL
	if strings.Contains(manifestURL, ".m3u8") || strings.Contains(manifestURL, "hls") {
		return p.getLatestHLSSegment(ctx, manifestURL)
	}
	if strings.Contains(manifestURL, ".mpd") || strings.Contains(manifestURL, "dash") {
		return p.getLatestDASHSegment(ctx, manifestURL)
	}

	// Default to HLS
	return p.getLatestHLSSegment(ctx, manifestURL)
}

// getLatestHLSSegment retrieves the latest segment from an HLS manifest.
func (p *Parser) getLatestHLSSegment(ctx context.Context, manifestURL string) (*Segment, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch failed with status %d", resp.StatusCode)
	}

	playlist, listType, err := m3u8.DecodeFrom(resp.Body, true)
	if err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	baseURL, err := url.Parse(manifestURL)
	if err != nil {
		return nil, fmt.Errorf("parse manifest URL: %w", err)
	}

	switch listType {
	case m3u8.MEDIA:
		mediapl := playlist.(*m3u8.MediaPlaylist)
		return p.extractLatestFromMediaPlaylist(mediapl, baseURL)
	case m3u8.MASTER:
		// For master playlist, we need to fetch the actual media playlist
		masterpl := playlist.(*m3u8.MasterPlaylist)
		if len(masterpl.Variants) == 0 {
			return nil, fmt.Errorf("no variants in master playlist")
		}

		// Pick the first variant (or could pick by bandwidth)
		variant := masterpl.Variants[0]
		mediaURL, err := resolveURL(baseURL, variant.URI)
		if err != nil {
			return nil, fmt.Errorf("resolve variant URL: %w", err)
		}

		return p.getLatestHLSSegment(ctx, mediaURL)
	default:
		return nil, fmt.Errorf("unknown playlist type")
	}
}

// extractLatestFromMediaPlaylist extracts the latest segment from a media playlist.
func (p *Parser) extractLatestFromMediaPlaylist(mediapl *m3u8.MediaPlaylist, baseURL *url.URL) (*Segment, error) {
	// Find the last non-nil segment
	var lastSeg *m3u8.MediaSegment
	var lastIdx int
	for i := uint(0); i < mediapl.Count(); i++ {
		seg := mediapl.Segments[i]
		if seg != nil {
			lastSeg = seg
			lastIdx = int(i)
		}
	}

	if lastSeg == nil {
		return nil, fmt.Errorf("no segments in playlist")
	}

	segmentURL, err := resolveURL(baseURL, lastSeg.URI)
	if err != nil {
		return nil, fmt.Errorf("resolve segment URL: %w", err)
	}

	return &Segment{
		URL:       segmentURL,
		Duration:  lastSeg.Duration,
		Sequence:  mediapl.SeqNo + uint64(lastIdx),
		MediaType: "hls",
	}, nil
}

// IsEndList returns true if the playlist is marked as ended (EXT-X-ENDLIST).
const maxIsEndListDepth = 4

func (p *Parser) IsEndList(ctx context.Context, manifestURL string) (bool, error) {
	return p.isEndListWithDepth(ctx, manifestURL, 0)
}

func (p *Parser) isEndListWithDepth(ctx context.Context, manifestURL string, depth int) (bool, error) {
	if depth > maxIsEndListDepth {
		return false, fmt.Errorf("max master->media recursion depth exceeded")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("manifest fetch failed with status %d", resp.StatusCode)
	}

	playlist, listType, err := m3u8.DecodeFrom(resp.Body, true)
	if err != nil {
		return false, fmt.Errorf("decode manifest: %w", err)
	}

	switch listType {
	case m3u8.MEDIA:
		mediapl := playlist.(*m3u8.MediaPlaylist)
		return mediapl.Closed, nil
	case m3u8.MASTER:
		masterpl := playlist.(*m3u8.MasterPlaylist)
		if len(masterpl.Variants) == 0 {
			return false, fmt.Errorf("master playlist has no variants")
		}
		baseURL, err := url.Parse(manifestURL)
		if err != nil {
			return false, fmt.Errorf("parse manifest URL: %w", err)
		}
		variant := masterpl.Variants[0]
		mediaURL, err := resolveURL(baseURL, variant.URI)
		if err != nil {
			return false, fmt.Errorf("resolve variant URL: %w", err)
		}
		return p.isEndListWithDepth(ctx, mediaURL, depth+1)
	default:
		return false, fmt.Errorf("unknown playlist type")
	}
}

// getLatestDASHSegment retrieves the latest segment from a DASH manifest.
// Note: This is a simplified implementation. Full DASH support would require
// a dedicated MPD parser library.
func (p *Parser) getLatestDASHSegment(ctx context.Context, manifestURL string) (*Segment, error) {
	// For now, return an error indicating DASH is not fully supported
	// A full implementation would need to parse the MPD XML and extract segments
	return nil, fmt.Errorf("DASH manifest parsing not yet implemented")
}

// FetchSegment downloads a segment from the given URL.
func (p *Parser) FetchSegment(ctx context.Context, segmentURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", segmentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch segment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("segment fetch failed with status %d", resp.StatusCode)
	}

	reader := io.LimitReader(resp.Body, p.maxSegmentBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read segment: %w", err)
	}
	if int64(len(data)) > p.maxSegmentBytes {
		return nil, fmt.Errorf("segment exceeds max size of %d bytes", p.maxSegmentBytes)
	}

	return data, nil
}

func resolveURL(base *url.URL, ref string) (string, error) {
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(refURL).String(), nil
}
