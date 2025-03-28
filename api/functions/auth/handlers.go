package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"nfe-modus/api/functions/audit"
	"nfe-modus/api/functions/auth/crypto"
	"nfe-modus/api/functions/email"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

type Handler struct {
	service    *Service
	otpService *OTPService
}

func NewHandler(conn string) *Handler {
	emailService := email.NewService(conn)
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

type recoveryRequest struct {
	Email              string `json:"email"`
	VerificationCookie string `json:"verificationCookie"`
	ClientIP           string `json:"clientIp,omitempty"`
	UserAgent          string `json:"userAgent,omitempty"`
	SessionID          string `json:"sessionId,omitempty"`
}

type resetRequest struct {
	ResetToken  string `json:"resetToken"`
	Email       string `json:"email"`
	Passphrase  string `json:"passphrase"`
	ClientIP    string `json:"clientIp,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
}

// HandlePasswordRecovery handles password recovery
func (h *Handler) HandlePasswordRecovery(w http.ResponseWriter, r *http.Request) {
	console.Debug("Handling password recovery request")
	
	// Only accept POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req recoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body for password recovery: %v", err))
		
		// Audit logging for invalid request
		// Using PASSPHRASE_RESET_REQUEST_INVALID_REQUEST for consistency with the audit memory
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_REQUEST_INVALID_REQUEST",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "recovery_initiate",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Invalid request body: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Create the recovery request for the service
	recoveryReq := &RecoveryPassphraseRequest{
		Email:              req.Email,
		VerificationCookie: req.VerificationCookie,
		ClientIP:           getClientIP(r, req.ClientIP),
		UserAgent:          getClientUserAgent(r, req.UserAgent),
		SessionID:          req.SessionID,
	}
	
	// Initialize services
	emailService := email.NewService(h.service.conn)
	otpService := NewOTPService(h.service.conn, emailService)
	roleService := NewRoleService(h.service.conn)
	emailEncryption := NewEmailEncryptionWithFallback()
	
	passphraseService, err := NewPassphraseService(h.service.conn, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to initialize passphrase service: %v", err))
		
		// Audit logging for service initialization error
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_REQUEST_UNHANDLED_ERROR",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "recovery_initiate",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Service initialization error: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Process the recovery request
	resp, err := passphraseService.RecoveryPassphrase(recoveryReq)
	if err != nil {
		console.Error(fmt.Sprintf("Error in recovery passphrase: %v", err))
		
		// Audit logging for unhandled error
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_REQUEST_UNHANDLED_ERROR",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "recovery_initiate",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Unhandled error: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Return the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandlePasswordReset handles password reset
func (h *Handler) HandlePasswordReset(w http.ResponseWriter, r *http.Request) {
	console.Debug("Handling password reset request")
	
	// Only accept POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req resetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		console.Error(fmt.Sprintf("Invalid request body for password reset: %v", err))
		
		// Audit logging for invalid request
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_INVALID_REQUEST",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "reset",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Invalid request body: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Validate the passphrase strength
	if len(req.Passphrase) < 8 {
		console.Warn("Passphrase too weak")
		
		// Audit logging for weak passphrase
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_INVALID_PASSPHRASE",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "reset",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        "Passphrase too weak",
			AuditTimestamp: time.Now().UTC(),
		})
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Passphrase too weak - must be at least 8 characters",
		})
		return
	}
	
	// Create the reset request for the service
	resetReq := &ResetPassphraseRequest{
		ResetToken: req.ResetToken,
		Email:      req.Email,
		Passphrase: req.Passphrase,
		ClientIP:   getClientIP(r, req.ClientIP),
		UserAgent:  getClientUserAgent(r, req.UserAgent),
		SessionID:  req.SessionID,
	}
	
	// Initialize services
	emailService := email.NewService(h.service.conn)
	otpService := NewOTPService(h.service.conn, emailService)
	roleService := NewRoleService(h.service.conn)
	emailEncryption := NewEmailEncryptionWithFallback()
	
	passphraseService, err := NewPassphraseService(h.service.conn, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to initialize passphrase service: %v", err))
		
		// Audit logging for service initialization error
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_UNHANDLED_ERROR",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "reset",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Service initialization error: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Process the reset request
	resp, err := passphraseService.ResetPassphrase(resetReq)
	if err != nil {
		console.Error(fmt.Sprintf("Error in reset passphrase: %v", err))
		
		// Audit logging for unhandled error
		auditService := audit.NewAuditService(h.service.conn)
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "PASSPHRASE_RESET_UNHANDLED_ERROR",
			ActorID:        "unknown",
			ActorType:      "user",
			OperationType:  "reset",
			ClientIP:       getClientIP(r, req.ClientIP),
			UserAgent:      getClientUserAgent(r, req.UserAgent),
			SessionID:      req.SessionID,
			Success:        false,
			RequestMethod:  r.Method,
			RequestPath:    r.URL.Path,
			Details:        fmt.Sprintf("Unhandled error: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Return the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Helper functions
func getClientIP(r *http.Request, fallback string) string {
	if r == nil {
		return fallback
	}
	
	// Try X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can be a comma-separated list, use the first value
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Try the RemoteAddr
	if r.RemoteAddr != "" {
		// Remove port if present
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return r.RemoteAddr
	}
	
	return fallback
}

func getClientUserAgent(r *http.Request, fallback string) string {
	if r == nil {
		return fallback
	}
	
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		return userAgent
	}
	
	return fallback
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
	
	// Password recovery endpoints
	mux.HandleFunc("/auth/recover", h.HandlePasswordRecovery)
	mux.HandleFunc("/auth/reset", h.HandlePasswordReset)
}
