package validation

import (
	"context"
	"fmt"
	"net"
	"net/url"
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
