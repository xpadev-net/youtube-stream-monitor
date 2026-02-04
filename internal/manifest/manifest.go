package manifest

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
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
	if isDASHManifestURL(manifestURL) {
		return p.getLatestDASHSegment(ctx, manifestURL)
	}
	if strings.Contains(strings.ToLower(manifestURL), ".m3u8") {
		return p.getLatestHLSSegment(ctx, manifestURL)
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
	if isDASHManifestURL(manifestURL) {
		return false, nil
	}
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

	var mpd dashMPD
	if err := xml.NewDecoder(resp.Body).Decode(&mpd); err != nil {
		return nil, fmt.Errorf("decode mpd: %w", err)
	}

	segmentTemplate, representation, err := selectSegmentTemplate(&mpd)
	if err != nil {
		return nil, err
	}

	baseURL, err := resolveDASHBaseURL(&mpd, representation, manifestURL)
	if err != nil {
		return nil, err
	}

	segmentURL, duration, sequence, err := buildLatestDASHSegment(baseURL, segmentTemplate, representation, &mpd)
	if err != nil {
		return nil, err
	}

	return &Segment{
		URL:       segmentURL,
		Duration:  duration,
		Sequence:  sequence,
		MediaType: "dash",
	}, nil
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
	if refURL.IsAbs() {
		return refURL.String(), nil
	}
	resolved := *base
	if refURL.Path == "" {
		if refURL.RawQuery != "" || strings.HasPrefix(ref, "?") {
			resolved.RawQuery = refURL.RawQuery
		}
		if refURL.Fragment != "" || strings.Contains(ref, "#") {
			resolved.Fragment = refURL.Fragment
		}
		return resolved.String(), nil
	}
	if strings.HasPrefix(ref, "/") {
		resolved.Path = refURL.Path
	} else {
		resolved.Path = path.Join(path.Dir(base.Path), refURL.Path)
	}
	resolved.RawQuery = refURL.RawQuery
	resolved.Fragment = refURL.Fragment
	return resolved.String(), nil
}

type dashMPD struct {
	XMLName                   xml.Name   `xml:"MPD"`
	BaseURL                   string     `xml:"BaseURL"`
	MediaPresentationDuration string     `xml:"mediaPresentationDuration,attr"`
	Period                    dashPeriod `xml:"Period"`
}

type dashPeriod struct {
	AdaptationSets []dashAdaptationSet `xml:"AdaptationSet"`
}

type dashAdaptationSet struct {
	Representations []dashRepresentation `xml:"Representation"`
}

type dashRepresentation struct {
	ID              string               `xml:"id,attr"`
	Bandwidth       int64                `xml:"bandwidth,attr"`
	BaseURL         string               `xml:"BaseURL"`
	SegmentTemplate *dashSegmentTemplate `xml:"SegmentTemplate"`
}

type dashSegmentTemplate struct {
	Timescale       int64                `xml:"timescale,attr"`
	Duration        int64                `xml:"duration,attr"`
	StartNumber     int64                `xml:"startNumber,attr"`
	Media           string               `xml:"media,attr"`
	SegmentTimeline *dashSegmentTimeline `xml:"SegmentTimeline"`
}

type dashSegmentTimeline struct {
	Segments []dashSegmentTimelineS `xml:"S"`
}

type dashSegmentTimelineS struct {
	T int64 `xml:"t,attr"`
	D int64 `xml:"d,attr"`
	R int64 `xml:"r,attr"`
}

func selectSegmentTemplate(mpd *dashMPD) (*dashSegmentTemplate, *dashRepresentation, error) {
	if mpd == nil {
		return nil, nil, fmt.Errorf("mpd is nil")
	}
	var chosen *dashRepresentation
	for i := range mpd.Period.AdaptationSets {
		set := mpd.Period.AdaptationSets[i]
		for j := range set.Representations {
			rep := &set.Representations[j]
			if rep.SegmentTemplate == nil {
				continue
			}
			if chosen == nil || rep.Bandwidth > chosen.Bandwidth {
				chosen = rep
			}
		}
	}
	if chosen == nil {
		return nil, nil, fmt.Errorf("no representation with segment template")
	}
	if chosen.SegmentTemplate.Media == "" {
		return nil, nil, fmt.Errorf("segment template media is empty")
	}
	return chosen.SegmentTemplate, chosen, nil
}

func resolveDASHBaseURL(mpd *dashMPD, representation *dashRepresentation, manifestURL string) (string, error) {
	base, err := url.Parse(manifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest url: %w", err)
	}
	if representation != nil && representation.BaseURL != "" {
		return resolveRelativeBaseURL(base, representation.BaseURL)
	}
	if mpd != nil && mpd.BaseURL != "" {
		return resolveRelativeBaseURL(base, mpd.BaseURL)
	}
	base.Path = path.Dir(base.Path)
	if base.Path == "/" {
		// Root path already has trailing slash.
	} else if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func resolveRelativeBaseURL(base *url.URL, baseURL string) (string, error) {
	ref, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	return base.ResolveReference(ref).String(), nil
}

func buildLatestDASHSegment(baseURL string, template *dashSegmentTemplate, representation *dashRepresentation, mpd *dashMPD) (string, float64, uint64, error) {
	if template == nil {
		return "", 0, 0, fmt.Errorf("segment template is nil")
	}
	timescale := template.Timescale
	if timescale <= 0 {
		timescale = 1
	}
	startNumber := template.StartNumber
	if startNumber == 0 {
		startNumber = 1
	}

	number := startNumber
	var timeValue int64
	var duration int64
	var segmentsCount int64

	if template.SegmentTimeline != nil && len(template.SegmentTimeline.Segments) > 0 {
		var currentTime int64
		for i, seg := range template.SegmentTimeline.Segments {
			if seg.D == 0 {
				return "", 0, 0, fmt.Errorf("segment timeline duration missing")
			}
			if seg.T != 0 || i == 0 {
				currentTime = seg.T
			}
			repeat := seg.R
			// SegmentTimeline semantics: r=-1 repeats until the next S element, period end, or MPD update.
			// Clamp negative seg.R to 0 to avoid infinite repeats in offline/static parsing
			// (prevents infinite loops/counting); live MPDs should advance via periodic updates.
			if repeat < 0 {
				repeat = 0
			}
			duration = seg.D
			timeValue = currentTime + duration*repeat
			segmentsCount += 1 + repeat
			currentTime += duration * (repeat + 1)
		}
	} else {
		if template.Duration == 0 {
			return "", 0, 0, fmt.Errorf("segment duration missing")
		}
		duration = template.Duration
		segments, err := estimateSegmentCount(template, timescale, mpd)
		if err != nil {
			return "", 0, 0, err
		}
		segmentsCount = segments
		timeValue = (segmentsCount - 1) * duration
	}

	if segmentsCount <= 0 {
		segmentsCount = 1
	}
	number = startNumber + segmentsCount - 1
	if number < 1 {
		number = 1
	}

	urlStr, err := fillSegmentTemplate(baseURL, template.Media, representation, uint64(number), timeValue)
	if err != nil {
		return "", 0, 0, err
	}

	return urlStr, float64(duration) / float64(timescale), uint64(number), nil
}

func estimateSegmentCount(template *dashSegmentTemplate, timescale int64, mpd *dashMPD) (int64, error) {
	if template == nil {
		return 0, fmt.Errorf("segment template is nil")
	}
	if template.Duration <= 0 {
		return 0, fmt.Errorf("segment duration missing")
	}
	if timescale <= 0 {
		timescale = 1
	}
	totalSeconds, err := parseMPDDuration(mpd)
	if err != nil {
		return 0, err
	}
	segmentDuration := float64(template.Duration) / float64(timescale)
	if segmentDuration <= 0 {
		return 0, fmt.Errorf("segment duration missing")
	}
	segments := int64(math.Ceil(totalSeconds / segmentDuration))
	if segments < 1 {
		segments = 1
	}
	return segments, nil
}

var dashTemplatePattern = regexp.MustCompile(`\$(Number|Time|RepresentationID|Bandwidth)\$`)

func fillSegmentTemplate(baseURL string, media string, representation *dashRepresentation, number uint64, timeValue int64) (string, error) {
	replaced := dashTemplatePattern.ReplaceAllStringFunc(media, func(match string) string {
		switch match {
		case "$Number$":
			return strconv.FormatUint(number, 10)
		case "$Time$":
			return strconv.FormatInt(timeValue, 10)
		case "$RepresentationID$":
			if representation != nil {
				return representation.ID
			}
			return ""
		case "$Bandwidth$":
			if representation != nil {
				return strconv.FormatInt(representation.Bandwidth, 10)
			}
			return ""
		default:
			return match
		}
	})
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	return resolveURL(base, replaced)
}

// Supported subset: days + integer hours/minutes + fractional seconds.
// Weeks (PnW) and fractional hours/minutes are not supported.
var mpdDurationPattern = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)
var mpdDurationDaysOnlyPattern = regexp.MustCompile(`^P(\d+)D$`)

func parseMPDDuration(mpd *dashMPD) (float64, error) {
	if mpd == nil {
		return 0, fmt.Errorf("mpd is nil")
	}
	if mpd.MediaPresentationDuration == "" {
		return 0, fmt.Errorf("mediaPresentationDuration missing")
	}
	daysOnly := mpdDurationDaysOnlyPattern.FindStringSubmatch(mpd.MediaPresentationDuration)
	if daysOnly != nil {
		days, err := strconv.ParseFloat(daysOnly[1], 64)
		if err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		total := days * 24 * 3600
		if total <= 0 {
			return 0, fmt.Errorf("parsed duration is zero or negative")
		}
		return total, nil
	}
	match := mpdDurationPattern.FindStringSubmatch(mpd.MediaPresentationDuration)
	if match == nil {
		return 0, fmt.Errorf("invalid mediaPresentationDuration")
	}
	var total float64
	if match[1] != "" {
		days, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		total += days * 24 * 3600
	}
	if match[2] != "" {
		hours, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			return 0, fmt.Errorf("parse hours: %w", err)
		}
		total += hours * 3600
	}
	if match[3] != "" {
		minutes, err := strconv.ParseFloat(match[3], 64)
		if err != nil {
			return 0, fmt.Errorf("parse minutes: %w", err)
		}
		total += minutes * 60
	}
	if match[4] != "" {
		seconds, err := strconv.ParseFloat(match[4], 64)
		if err != nil {
			return 0, fmt.Errorf("parse seconds: %w", err)
		}
		total += seconds
	}
	if total <= 0 {
		return 0, fmt.Errorf("parsed duration is zero or negative")
	}
	return total, nil
}

func isDASHManifestURL(manifestURL string) bool {
	parsed, err := url.Parse(manifestURL)
	if err != nil {
		return strings.HasSuffix(strings.ToLower(manifestURL), ".mpd")
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), ".mpd")
}
