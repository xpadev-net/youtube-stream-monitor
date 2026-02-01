package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

const (
	// HeaderAPIKey is the header name for API key authentication.
	HeaderAPIKey = "X-API-Key"
	// HeaderInternalAPIKey is the header name for internal API key authentication.
	HeaderInternalAPIKey = "X-Internal-API-Key"
)

// APIKeyAuth returns a middleware that validates the API key.
func APIKeyAuth(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader(HeaderAPIKey)
		if key == "" {
			// Also check Authorization header
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if key == "" {
			RespondUnauthorized(c, "API key is required")
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) != 1 {
			RespondUnauthorized(c, "Invalid API key")
			c.Abort()
			return
		}

		c.Next()
	}
}

// InternalAPIKeyAuth returns a middleware that validates the internal API key.
func InternalAPIKeyAuth(internalAPIKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader(HeaderInternalAPIKey)
		if key == "" {
			RespondUnauthorized(c, "Internal API key is required")
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(internalAPIKey)) != 1 {
			RespondUnauthorized(c, "Invalid internal API key")
			c.Abort()
			return
		}

		c.Next()
	}
}

type rateLimiter struct {
	limit    rate.Limit
	burst    int
	window   time.Duration
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	lastSeen map[string]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	interval := window / time.Duration(limit)
	if interval <= 0 {
		interval = time.Second
	}
	return &rateLimiter{
		limit:    rate.Every(interval),
		burst:    limit,
		window:   window,
		visitors: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
	}
}

func (l *rateLimiter) cleanup() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-l.window)
		for key, seen := range l.lastSeen {
			if seen.Before(cutoff) {
				delete(l.lastSeen, key)
				delete(l.visitors, key)
			}
		}
		l.mu.Unlock()
	}
}

func (l *rateLimiter) getLimiter(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.visitors[key]
	if !exists {
		limiter = rate.NewLimiter(l.limit, l.burst)
		l.visitors[key] = limiter
	}
	l.lastSeen[key] = time.Now()
	return limiter
}

// RateLimit returns a middleware that enforces a fixed-window rate limit by key.
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	limiter := newRateLimiter(limit, window)
	go limiter.cleanup()
	return func(c *gin.Context) {
		key := c.GetHeader(HeaderAPIKey)
		if key == "" {
			key = c.ClientIP()
		}
		if !limiter.getLimiter(key).Allow() {
			RespondError(c, http.StatusTooManyRequests, ErrCodeRateLimitExceeded, "Rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}
