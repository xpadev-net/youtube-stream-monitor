package httpapi

import (
	"container/heap"
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/xpadev-net/youtube-stream-tracker/internal/log"
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

const defaultMaxVisitors = 10000

// visitorEntry represents a visitor tracked in the heap.
type visitorEntry struct {
	key      string
	lastSeen time.Time
	index    int // position in the heap
}

// visitorHeap implements heap.Interface, ordered by lastSeen (oldest first).
type visitorHeap []*visitorEntry

func (h visitorHeap) Len() int            { return len(h) }
func (h visitorHeap) Less(i, j int) bool   { return h[i].lastSeen.Before(h[j].lastSeen) }
func (h visitorHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *visitorHeap) Push(x any) {
	entry := x.(*visitorEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *visitorHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*h = old[:n-1]
	return entry
}

type rateLimiter struct {
	limit       rate.Limit
	burst       int
	window      time.Duration
	maxVisitors int
	mu          sync.Mutex
	visitors    map[string]*rate.Limiter
	entries     map[string]*visitorEntry
	minHeap     visitorHeap
}

type limiterRegistry struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiter
	once     sync.Once
	cancel   context.CancelFunc
}

var sharedLimiters = &limiterRegistry{limiters: make(map[string]*rateLimiter)}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	interval := window / time.Duration(limit)
	if interval <= 0 {
		interval = time.Second
	}
	rl := &rateLimiter{
		limit:       rate.Every(interval),
		burst:       limit,
		window:      window,
		maxVisitors: defaultMaxVisitors,
		visitors:    make(map[string]*rate.Limiter),
		entries:     make(map[string]*visitorEntry),
		minHeap:     make(visitorHeap, 0),
	}
	heap.Init(&rl.minHeap)
	return rl
}

func (l *rateLimiter) cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	for l.minHeap.Len() > 0 && l.minHeap[0].lastSeen.Before(cutoff) {
		entry := heap.Pop(&l.minHeap).(*visitorEntry)
		delete(l.visitors, entry.key)
		delete(l.entries, entry.key)
	}
}

func (l *rateLimiter) getLimiter(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.visitors[key]
	now := time.Now()
	if !exists {
		// Invariant: len(l.visitors) == l.minHeap.Len() and every
		// insert/delete to l.visitors is paired with heap.Push/heap.Pop.
		if len(l.visitors) >= l.maxVisitors {
			if l.minHeap.Len() == 0 {
				// Invariant violated — log and evict an arbitrary visitor as fallback.
				log.Error("httpapi: rateLimiter invariant violated: visitors at capacity but minHeap is empty",
					zap.Int("visitors", len(l.visitors)),
					zap.Int("maxVisitors", l.maxVisitors),
				)
				for k := range l.visitors {
					delete(l.visitors, k)
					delete(l.entries, k)
					break
				}
			} else {
				entry := heap.Pop(&l.minHeap).(*visitorEntry)
				delete(l.visitors, entry.key)
				delete(l.entries, entry.key)
			}
		}
		limiter = rate.NewLimiter(l.limit, l.burst)
		l.visitors[key] = limiter
		entry := &visitorEntry{key: key, lastSeen: now}
		l.entries[key] = entry
		heap.Push(&l.minHeap, entry)
	} else {
		// Update lastSeen and fix heap position - O(log n)
		entry := l.entries[key]
		entry.lastSeen = now
		heap.Fix(&l.minHeap, entry.index)
	}
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
			ctx, cancel := context.WithCancel(context.Background())
			r.cancel = cancel
			go r.cleanupLoop(ctx)
		})
	}
	r.mu.Unlock()

	return limiter
}

// Stop cancels the background cleanup goroutine. It is safe to call
// multiple times; only the first call has any effect.
func (r *limiterRegistry) Stop() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *limiterRegistry) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.mu.Lock()
			snapshot := make([]*rateLimiter, 0, len(r.limiters))
			for _, limiter := range r.limiters {
				snapshot = append(snapshot, limiter)
			}
			r.mu.Unlock()
			for _, limiter := range snapshot {
				limiter.cleanup(now)
			}
		}
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
