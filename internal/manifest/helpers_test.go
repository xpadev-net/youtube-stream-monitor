package manifest

import "net/http"

// newTestParser creates a parser that allows localhost requests for use with
// httptest.NewServer. This bypasses the SSRF-safe client used in production.
func newTestParser() *Parser {
	return &Parser{
		httpClient:      http.DefaultClient,
		maxSegmentBytes: 1024,
	}
}
