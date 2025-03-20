package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"nfe-modus/api/functions/auth/crypto"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

type Handler struct {
	service    *Service
	otpService *OTPService
}

func NewHandler(conn string) *Handler {
	emailService := NewEmailService(conn)
	return &Handler{
		service:    NewService(conn),
		otpService: NewOTPService(conn, emailService),
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

// HandleOTPStart initiates the OTP generation process
func (h *Handler) HandleOTPStart(w http.ResponseWriter, r *http.Request) {
	console.Debug("Received OTP start request")
	
	if r.Method != http.MethodPost {
		console.Error("Method not allowed: " + r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Method not allowed",
		})
		return
	}

	var req struct {
		Email    string `json:"email"`
		DeviceID string `json:"deviceId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error("Failed to decode request: " + err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request body",
		})
		return
	}

	console.Debug("Generating OTP for email: " + req.Email)

	genReq := GenerateOTPRequest{
		Email: req.Email,
	}
	resp, err := h.otpService.GenerateOTP(&genReq)
	if err != nil {
		console.Error("Failed to generate OTP: " + err.Error())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// HandleOTPRegistration handles OTP-based registration
func (h *Handler) HandleOTPRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		DeviceID string `json:"deviceId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error("Failed to decode request: " + err.Error())
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	genReq := GenerateOTPRequest{
		Email: req.Email,
	}
	resp, err := h.otpService.GenerateOTP(&genReq)
	if err != nil {
		console.Error("Failed to generate OTP: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleOTPVerification verifies the provided OTP
func (h *Handler) HandleOTPVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OTP      string `json:"otp"`
		Cookie   string `json:"cookie"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error("Failed to decode request: " + err.Error())
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// If cookie is not provided, we can't proceed
	if req.Cookie == "" {
		console.Error("No cookie provided for OTP verification")
		http.Error(w, "Cookie required for verification", http.StatusBadRequest)
		return
	}

	verifyReq := VerifyOTPRequest{
		OTP:    req.OTP,
		Cookie: req.Cookie,
	}
	resp, err := h.otpService.VerifyOTP(&verifyReq)
	if err != nil {
		console.Error("Failed to verify OTP: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

	// OTP endpoints
	mux.HandleFunc("/auth/otp/start", h.HandleOTPStart)
	mux.HandleFunc("/auth/otp/register", h.HandleOTPRegistration)
	mux.HandleFunc("/auth/otp/verify", h.HandleOTPVerification)
}
