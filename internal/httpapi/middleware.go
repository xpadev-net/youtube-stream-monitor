package httpapi

import (
	"crypto/subtle"
	"fmt"
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

type limiterRegistry struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiter
	once     sync.Once
}

var sharedLimiters = &limiterRegistry{limiters: make(map[string]*rateLimiter)}

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

func (l *rateLimiter) cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	for key, seen := range l.lastSeen {
		if seen.Before(cutoff) {
			delete(l.lastSeen, key)
			delete(l.visitors, key)
		}
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

func (r *limiterRegistry) get(limit int, window time.Duration) *rateLimiter {
	key := fmt.Sprintf("%d/%s", limit, window)

	r.mu.Lock()
	limiter, exists := r.limiters[key]
	if !exists {
		limiter = newRateLimiter(limit, window)
		r.limiters[key] = limiter
		r.once.Do(func() {
			go r.cleanupLoop()
		})
	}
	r.mu.Unlock()

	return limiter
}

func (r *limiterRegistry) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for now := range ticker.C {
		r.mu.Lock()
		for _, limiter := range r.limiters {
			limiter.cleanup(now)
		}
		r.mu.Unlock()
	}
}

// RateLimit returns a middleware that enforces a token-bucket rate limit by key.
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	limiter := sharedLimiters.get(limit, window)
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
