package auth

import (
    "net/http"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// InitRoutes initializes all auth routes
func InitRoutes(mux *http.ServeMux, conn string) {
    // Register auth routes
    h := NewHandler(conn)

    // OTP endpoints
    mux.HandleFunc("/api/auth/otp/start", h.HandleOTPStart)
    mux.HandleFunc("/api/auth/otp/register", h.HandleOTPRegistration)
    mux.HandleFunc("/api/auth/otp/verify", h.HandleOTPVerification)

    // WebAuthn registration endpoints
    mux.HandleFunc("/api/auth/webauthn/register/start", h.HandleRegistrationStart)
    mux.HandleFunc("/api/auth/webauthn/register/finish", h.HandleRegistrationComplete)

    // WebAuthn authentication endpoints
    mux.HandleFunc("/api/auth/webauthn/authenticate/start", h.HandleAuthenticationStart)
    mux.HandleFunc("/api/auth/webauthn/authenticate/finish", h.HandleAuthenticationComplete)

    console.Debug("Auth routes initialized")
}
