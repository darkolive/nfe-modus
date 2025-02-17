package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"nfe-modus/api/functions/auth/crypto"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

type Handler struct {
	service *Service
}

func NewHandler(conn string) *Handler {
	return &Handler{
		service: NewService(conn),
	}
}

type registrationRequest struct {
	Email    string `json:"email"`
	DeviceID string `json:"deviceId"`
}

type registrationResponse struct {
	Challenge string `json:"challenge"`
}

// HandleRegistrationStart initiates the registration process
func (h *Handler) HandleRegistrationStart(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body: %v", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedEmail := crypto.HashEmail(req.Email)
	challenge, err := h.service.StartRegistration(r.Context(), hashedEmail, req.DeviceID)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to start registration: %v", err))
		http.Error(w, "Failed to start registration", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(registrationResponse{Challenge: challenge})
}

type registrationCompleteRequest struct {
	Email     string `json:"email"`
	DeviceID  string `json:"deviceId"`
	PublicKey string `json:"publicKey"`
}

// HandleRegistrationComplete completes the registration process
func (h *Handler) HandleRegistrationComplete(w http.ResponseWriter, r *http.Request) {
	var req registrationCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body: %v", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedEmail := crypto.HashEmail(req.Email)
	if err := h.service.CompleteRegistration(r.Context(), hashedEmail, req.DeviceID, req.PublicKey); err != nil {
		console.Error(fmt.Sprintf("Failed to complete registration: %v", err))
		http.Error(w, "Failed to complete registration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

type authenticationRequest struct {
	Email    string `json:"email"`
	DeviceID string `json:"deviceId"`
}

type authenticationResponse struct {
	Challenge string `json:"challenge"`
}

// HandleAuthenticationStart initiates the authentication process
func (h *Handler) HandleAuthenticationStart(w http.ResponseWriter, r *http.Request) {
	var req authenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body: %v", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedEmail := crypto.HashEmail(req.Email)
	challenge, err := h.service.StartAuthentication(r.Context(), hashedEmail, req.DeviceID)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to start authentication: %v", err))
		http.Error(w, "Failed to start authentication", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(authenticationResponse{Challenge: challenge})
}

type authenticationCompleteRequest struct {
	Email    string `json:"email"`
	DeviceID string `json:"deviceId"`
}

// HandleAuthenticationComplete completes the authentication process
func (h *Handler) HandleAuthenticationComplete(w http.ResponseWriter, r *http.Request) {
	var req authenticationCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body: %v", err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedEmail := crypto.HashEmail(req.Email)
	if err := h.service.CompleteAuthentication(r.Context(), hashedEmail, req.DeviceID); err != nil {
		console.Error(fmt.Sprintf("Failed to complete authentication: %v", err))
		http.Error(w, "Failed to complete authentication", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RegisterAuthRoutes registers all auth routes with the server
func RegisterAuthRoutes(mux *http.ServeMux, conn string) {
	h := NewHandler(conn)

	// Registration endpoints
	mux.HandleFunc("/auth/register/start", h.HandleRegistrationStart)
	mux.HandleFunc("/auth/register/complete", h.HandleRegistrationComplete)

	// Authentication endpoints
	mux.HandleFunc("/auth/login/start", h.HandleAuthenticationStart)
	mux.HandleFunc("/auth/login/complete", h.HandleAuthenticationComplete)
}
