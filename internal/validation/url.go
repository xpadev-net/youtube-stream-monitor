package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ValidateOutboundURL validates that the URL is http/https and resolves to a public IP unless allowPrivate is true.
func ValidateOutboundURL(ctx context.Context, rawURL string, allowPrivate bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && isPrivateIP(ip) {
			return fmt.Errorf("private ip not allowed")
		}
		return nil
	}

	// Re-resolve at dial time by returning an error if host resolves only to private
	// addresses OR set up a transport that will enforce IP checks at dial time.
	// Here we perform an initial resolution check and also provide a helper to
	// create an http.Client with a DialContext that enforces the same checks.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no resolved ip")
	}
	if allowPrivate {
		return nil
	}
	for _, ipAddr := range ips {
		if isPrivateIP(ipAddr.IP) {
			return fmt.Errorf("private ip not allowed")
		}
	}
	return nil
}

// NewSafeHTTPClient returns an http.Client whose Transport resolves hostnames at
// dial time and enforces isPrivateIP checks to mitigate DNS rebinding/TOCTOU.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	return NewSafeHTTPClientWithPrivate(timeout, false)
}

// NewSafeHTTPClientWithPrivate allows optionally permitting private IPs for trusted endpoints.
func NewSafeHTTPClientWithPrivate(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipAddr := range ips {
				ip := ipAddr.IP
				if !allowPrivate && isPrivateIP(ip) {
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("no allowed ip to dial for host %s", host)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if !ip.IsGlobalUnicast() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}
