package security

import (
    "net/http"
    "sync"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
    tokens     int
    capacity   int
    refillRate int
    lastRefill time.Time
    mu         sync.Mutex
    buckets    map[string]*tokenBucket
}

type tokenBucket struct {
    tokens     int
    lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter with specified capacity and refill rate
func NewRateLimiter(capacity, refillRate int) *RateLimiter {
    return &RateLimiter{
        capacity:   capacity,
        refillRate: refillRate,
        lastRefill: time.Now(),
        buckets:    make(map[string]*tokenBucket),
    }
}

// Allow checks if a request should be allowed based on rate limits
func (r *RateLimiter) Allow(key string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    bucket, exists := r.buckets[key]
    if !exists {
        bucket = &tokenBucket{
            tokens:     r.capacity,
            lastRefill: now,
        }
        r.buckets[key] = bucket
    }

    // Refill tokens based on time elapsed
    elapsed := now.Sub(bucket.lastRefill).Seconds()
    newTokens := int(elapsed * float64(r.refillRate))
    if newTokens > 0 {
        bucket.tokens = min(bucket.tokens+newTokens, r.capacity)
        bucket.lastRefill = now
    }

    if bucket.tokens > 0 {
        bucket.tokens--
        return true
    }

    return false
}

// WithRateLimit creates a middleware that enforces rate limiting
func WithRateLimit(limiter *RateLimiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Use IP address as the rate limit key
            key := r.RemoteAddr

            if !limiter.Allow(key) {
                console.Error("Rate limit exceeded from " + key)
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// WithSecurity adds security headers and CORS configuration
func WithSecurity(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Security headers
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")

        // CORS headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")

        // Handle preflight requests
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// WithRequestValidation adds request validation middleware
func WithRequestValidation(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Validate Content-Type for POST/PUT requests
        if r.Method == "POST" || r.Method == "PUT" {
            contentType := r.Header.Get("Content-Type")
            if contentType != "application/json" {
                console.Error("Invalid Content-Type: " + contentType)
                http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
                return
            }
        }

        // Add more request validation as needed
        next.ServeHTTP(w, r)
    })
}

// AuditLog adds audit logging middleware
func AuditLog(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Create a response wrapper to capture the status code
        rw := &responseWriter{ResponseWriter: w}
        
        // Process request
        next.ServeHTTP(rw, r)
        
        // Log the request details
        duration := time.Since(start).String()
        console.Info("Request: " + r.Method + " " + r.URL.Path + " [" + r.RemoteAddr + "] " + duration)
    })
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
    http.ResponseWriter
    status int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.status = code
    rw.ResponseWriter.WriteHeader(code)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
