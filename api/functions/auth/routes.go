package auth

import (
    "net/http"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// InitRoutes initializes all auth routes
func InitRoutes(mux *http.ServeMux, conn string) {
    // Register auth routes
    h := NewHandler(conn)

    // Registration endpoints
    mux.HandleFunc("/auth/register/start", h.HandleRegistrationStart)
    mux.HandleFunc("/auth/register/complete", h.HandleRegistrationComplete)

    // Authentication endpoints
    mux.HandleFunc("/auth/login/start", h.HandleAuthenticationStart)
    mux.HandleFunc("/auth/login/complete", h.HandleAuthenticationComplete)

    console.Debug("Auth routes initialized")
}
