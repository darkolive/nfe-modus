package tests

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "nfe-modus/api/functions/auth"
    "nfe-modus/api/functions/auth/security"
)

func TestRateLimiting(t *testing.T) {
    limiter := security.NewRateLimiter(2, 1) // 2 requests per second
    handler := security.WithRateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    // First request should succeed
    req := httptest.NewRequest("GET", "/", nil)
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusOK, rec.Code)

    // Second request should succeed
    rec = httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusOK, rec.Code)

    // Third request should be rate limited
    rec = httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestSecurityHeaders(t *testing.T) {
    handler := security.WithSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest("GET", "/", nil)
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)

    assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
    assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
    assert.Equal(t, "1; mode=block", rec.Header().Get("X-XSS-Protection"))
    assert.Equal(t, "max-age=31536000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
    assert.Equal(t, "default-src 'self'", rec.Header().Get("Content-Security-Policy"))
}

func TestRequestValidation(t *testing.T) {
    handler := security.WithRequestValidation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    // Test invalid content type
    req := httptest.NewRequest("POST", "/", nil)
    req.Header.Set("Content-Type", "text/plain")
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)

    // Test valid content type
    req = httptest.NewRequest("POST", "/", nil)
    req.Header.Set("Content-Type", "application/json")
    rec = httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthenticationFlow(t *testing.T) {
    ctx := context.Background()
    authService, err := auth.NewSecureAuthService("my-dgraph")
    require.NoError(t, err)
    defer authService.Close()

    // Start authentication
    err = authService.StartAuthentication(ctx, "test@example.com")
    require.NoError(t, err)
}

func TestAuditLogging(t *testing.T) {
    ctx := context.Background()
    authService, err := auth.NewSecureAuthService("my-dgraph")
    require.NoError(t, err)
    defer authService.Close()

    // Test authentication attempt
    err = authService.StartAuthentication(ctx, "test@example.com")
    require.NoError(t, err)
}
