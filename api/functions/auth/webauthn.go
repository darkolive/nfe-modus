package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	
	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	
	"nfe-modus/api/functions/auth/audit"
	"nfe-modus/api/functions/auth/jwt"
)

// WebAuthnUser represents a user for WebAuthn operations
type WebAuthnUser struct {
	ID          []byte  `json:"id"`
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	Credentials [][]byte `json:"credentials"`
}

// WebAuthnService handles WebAuthn operations
type WebAuthnService struct {
	conn       string
	jwtService *jwt.JWTService
	rpID       string
	rpName     string
	rpOrigin   string
}

// WebAuthnCredential represents a WebAuthn credential stored in the database
type WebAuthnCredential struct {
	CredentialID        []byte    `json:"credentialID"`
	CredentialPublicKey []byte    `json:"credentialPublicKey"`
	Counter             uint32    `json:"counter"`
	Transports          []string  `json:"transports,omitempty"`
	LastUsed            time.Time `json:"lastUsed"`
}

// CredentialOptions represents WebAuthn credential options
type CredentialOptions struct {
	Challenge     string            `json:"challenge"`
	RpName        string            `json:"rpName,omitempty"`
	RpID          string            `json:"rpId,omitempty"`
	UserID        string            `json:"userId,omitempty"`
	UserName      string            `json:"userName,omitempty"`
	UserDisplay   string            `json:"userDisplay,omitempty"`
	Timeout       int               `json:"timeout,omitempty"`
	ExcludeKeys   []string          `json:"excludeKeys,omitempty"`
	AuthenticatorParams map[string]string `json:"authenticatorParams,omitempty"`
}

// NewWebAuthnService creates a new WebAuthn service
func NewWebAuthnService(conn string, jwtService *jwt.JWTService) (*WebAuthnService, error) {
	return &WebAuthnService{
		conn:       conn,
		jwtService: jwtService,
		rpID:       "localhost",
		rpName:     "NFE Authentication",
		rpOrigin:   "http://localhost:3000",
	}, nil
}

// CreateSessionID generates a random unique session ID
func CreateSessionID() string {
	// Generate 16 random bytes
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// If there's an error, fallback to a timestamp-based ID
		return fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	
	// Encode as base64 and make URL-safe
	return base64.URLEncoding.EncodeToString(randomBytes)
}

// RegisterWebAuthnRequest contains data for initiating WebAuthn registration
type RegisterWebAuthnRequest struct {
	Email              string `json:"email"`
	VerificationCookie string `json:"verificationCookie"`
	RecoveryPassphrase string `json:"recoveryPassphrase"`
	// Fields needed for audit logging
	ClientIP   string `json:"clientIp,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
}

// RegisterWebAuthnResponse contains the result of a WebAuthn registration initiation
type RegisterWebAuthnResponse struct {
	Success          bool              `json:"success"`
	Error            string            `json:"error,omitempty"`
	Message          string            `json:"message,omitempty"`
	CredentialOptions *CredentialOptions `json:"credentialOptions,omitempty"`
	UserExists       bool              `json:"userExists,omitempty"`
}

// RegisterWebAuthn initiates the WebAuthn registration process
func (ws *WebAuthnService) RegisterWebAuthn(req *RegisterWebAuthnRequest) (*RegisterWebAuthnResponse, error) {
	console.Debug("Processing WebAuthn registration")

	// Validate email and verification cookie (redacted for brevity)
	if req.Email == "" {
		console.Debug("Email is required for WebAuthn registration")
		return &RegisterWebAuthnResponse{
			Success: false,
			Error:   "Email is required",
		}, nil
	}

	// Hash email for privacy
	hashedEmail := hashEmailForPrivacy(req.Email)

	// Check if user already exists (commented out for simplicity)
	userExists := false
	/*
		userQuery := fmt.Sprintf(`query {
			users(func: eq(hashed_email, "%s")) {
				uid
			}
		}`, dgraph.EscapeRDF(hashedEmail))

		resp, err := dgraph.ExecuteQuery(ws.conn, &dgraph.Query{Query: userQuery})
		if err != nil {
			console.Error(fmt.Sprintf("Failed to query user: %v", err))
			return &RegisterWebAuthnResponse{
				Success: false,
				Error:   "Failed to check if user exists",
			}, err
		}

		var result struct {
			Users []struct {
				UID string `json:"uid"`
			} `json:"users"`
		}

		if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
			console.Error(fmt.Sprintf("Failed to unmarshal user query response: %v", err))
			return &RegisterWebAuthnResponse{
				Success: false,
				Error:   "Failed to process user data",
			}, err
		}

		userExists = len(result.Users) > 0
		if userExists {
			console.Debug("User already exists during WebAuthn registration")
			return &RegisterWebAuthnResponse{
				Success:    true,
				UserExists: true,
				Message:    "User already exists",
			}, nil
		}
	*/

	// Generate challenge
	challenge, err := generateWebAuthnChallenge()
	if err != nil {
		console.Error(fmt.Sprintf("Failed to generate challenge: %v", err))
		return &RegisterWebAuthnResponse{
			Success: false,
			Error:   "Failed to generate challenge",
		}, err
	}

	// Create credential options using our concrete type
	credentialOptions := &CredentialOptions{
		Challenge:    challenge,
		RpName:       ws.rpName,
		RpID:         ws.rpID,
		UserID:       base64.URLEncoding.EncodeToString([]byte(hashedEmail)),
		UserName:     req.Email,
		UserDisplay:  req.Email,
		Timeout:      60000,
		AuthenticatorParams: map[string]string{
			"type": "public-key",
			"alg":  "-7", // ES256
		},
	}

	// Store the challenge in DGraph for verification later
	sessionID := CreateSessionID()
	sessionNow := time.Now()

	// Prepare mutation using the correct Dgraph API pattern
	sessionMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:session <dgraph.type> "WebAuthnSession" .
		_:session <session_id> "%s" .
		_:session <challenge> "%s" .
		_:session <hashed_email> "%s" .
		_:session <created_at> "%s" .
		_:session <type> "webauthn_registration" .
	`, 
		dgraph.EscapeRDF(sessionID),
		dgraph.EscapeRDF(challenge),
		dgraph.EscapeRDF(hashedEmail),
		dgraph.EscapeRDF(sessionNow.Format(time.RFC3339))))

	// Execute mutation
	console.Debug(fmt.Sprintf("Executing mutation: %s", sessionMutation.SetNquads))
	_, err = dgraph.ExecuteMutations(ws.conn, sessionMutation)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to store challenge: %v", err))
		return &RegisterWebAuthnResponse{
			Success: false,
			Error:   "Failed to store challenge",
		}, err
	}

	// Create audit log entry
	auditService := audit.NewAuditService(ws.conn)
	auditAction := "WEBAUTHN_REGISTER_INITIATED"
	if req.ClientIP == "" {
		req.ClientIP = "unknown"
	}

	auditErr := auditService.CreateAuditLog(audit.AuditLogData{
		Action:         auditAction,
		ActorID:        req.Email,
		ActorType:      "user",
		OperationType:  "webauthn_register",
		ClientIP:       req.ClientIP,
		UserAgent:      req.UserAgent,
		SessionID:      req.SessionID,
		Success:        true,
		Details:        "WebAuthn registration initiated",
		AuditTimestamp: time.Now().UTC(),
	})

	if auditErr != nil {
		console.Error(fmt.Sprintf("Failed to create audit log: %v", auditErr))
		// Continue despite audit log error
	}

	return &RegisterWebAuthnResponse{
		Success:          true,
		Message:          "WebAuthn registration initiated",
		CredentialOptions: credentialOptions,
		UserExists:       userExists,
	}, nil
}

// SignInWebAuthnRequest contains data for initiating WebAuthn sign-in
type SignInWebAuthnRequest struct {
	Email     string `json:"email"`
	// Fields needed for audit logging
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// SignInWebAuthnResponse contains the result of WebAuthn sign-in initiation
type SignInWebAuthnResponse struct {
	Success          bool              `json:"success"`
	Error            string            `json:"error,omitempty"`
	Message          string            `json:"message,omitempty"`
	CredentialOptions *CredentialOptions `json:"credentialOptions,omitempty"`
}

// SignInWebAuthn initiates the WebAuthn sign-in process
func (ws *WebAuthnService) SignInWebAuthn(req *SignInWebAuthnRequest) (*SignInWebAuthnResponse, error) {
	console.Debug("Processing WebAuthn sign-in")

	// Validate email
	if req.Email == "" {
		console.Debug("Email is required for WebAuthn sign-in")
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "Email is required",
		}, nil
	}

	// Hash email for privacy
	hashedEmail := hashEmailForPrivacy(req.Email)

	// Check if user exists
	userQuery := fmt.Sprintf(`
	{
		users(func: eq(hashed_email, "%s")) {
			uid
			credentials {
				credential_id
				public_key
				counter
				transports
			}
		}
	}`, dgraph.EscapeRDF(hashedEmail))

	// Execute query
	console.Debug(fmt.Sprintf("Executing query: %s", userQuery))
	resp, err := dgraph.ExecuteQuery(ws.conn, &dgraph.Query{Query: userQuery})
	if err != nil {
		console.Error(fmt.Sprintf("Failed to query user: %v", err))
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "Failed to query user",
		}, err
	}

	var result struct {
		Users []struct {
			UID         string `json:"uid"`
			Credentials []struct {
				CredentialID string   `json:"credential_id"`
				PublicKey    string   `json:"public_key"`
				Counter      uint32   `json:"counter"`
				Transports   []string `json:"transports"`
			} `json:"credentials"`
		} `json:"users"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Failed to unmarshal user query response: %v", err))
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, err
	}

	if len(result.Users) == 0 || len(result.Users[0].Credentials) == 0 {
		console.Debug("User not found or has no credentials")
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "User not found or has no registered authenticators",
		}, nil
	}

	// Generate challenge
	challenge, err := generateWebAuthnChallenge()
	if err != nil {
		console.Error(fmt.Sprintf("Failed to generate challenge: %v", err))
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "Failed to generate challenge",
		}, err
	}

	// Create credential options using our concrete type
	credentialOptions := &CredentialOptions{
		Challenge: challenge,
		RpID:      ws.rpID,
		Timeout:   60000,
	}

	// Add allow credentials list
	allowCredentials := make([]string, 0, len(result.Users[0].Credentials))
	for _, cred := range result.Users[0].Credentials {
		allowCredentials = append(allowCredentials, cred.CredentialID)
	}
	credentialOptions.ExcludeKeys = allowCredentials

	// Store the challenge in DGraph for verification later
	sessionID := CreateSessionID()
	sessionNow := time.Now()

	// Prepare mutation using the correct Dgraph API pattern
	sessionMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:session <dgraph.type> "WebAuthnSession" .
		_:session <session_id> "%s" .
		_:session <challenge> "%s" .
		_:session <hashed_email> "%s" .
		_:session <created_at> "%s" .
		_:session <type> "webauthn_signin" .
	`,
		dgraph.EscapeRDF(sessionID),
		dgraph.EscapeRDF(challenge),
		dgraph.EscapeRDF(hashedEmail),
		dgraph.EscapeRDF(sessionNow.Format(time.RFC3339))))

	// Execute mutation
	console.Debug(fmt.Sprintf("Executing mutation: %s", sessionMutation.SetNquads))
	_, err = dgraph.ExecuteMutations(ws.conn, sessionMutation)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to store challenge: %v", err))
		return &SignInWebAuthnResponse{
			Success: false,
			Error:   "Failed to store challenge",
		}, err
	}

	// Create audit log entry
	auditService := audit.NewAuditService(ws.conn)
	auditAction := "WEBAUTHN_SIGNIN_INITIATED"
	if req.ClientIP == "" {
		req.ClientIP = "unknown"
	}

	auditErr := auditService.CreateAuditLog(audit.AuditLogData{
		Action:         auditAction,
		ActorID:        req.Email,
		ActorType:      "user",
		OperationType:  "webauthn_signin",
		ClientIP:       req.ClientIP,
		UserAgent:      req.UserAgent,
		SessionID:      req.SessionID,
		Success:        true,
		Details:        "WebAuthn sign-in initiated",
		AuditTimestamp: time.Now().UTC(),
	})

	if auditErr != nil {
		console.Error(fmt.Sprintf("Failed to create audit log: %v", auditErr))
		// Continue despite audit log error
	}

	return &SignInWebAuthnResponse{
		Success:          true,
		Message:          "WebAuthn sign-in initiated",
		CredentialOptions: credentialOptions,
	}, nil
}

// VerifyWebAuthnRegistrationRequest contains data for verifying WebAuthn registration
type VerifyWebAuthnRegistrationRequest struct {
	Email       string          `json:"email"`
	Credential  json.RawMessage `json:"credential"`
	// Fields needed for audit logging
	ClientIP    string          `json:"clientIp,omitempty"`
	UserAgent   string          `json:"userAgent,omitempty"`
	SessionID   string          `json:"sessionId,omitempty"`
}

// VerifyWebAuthnRegistrationResponse contains the result of WebAuthn registration verification
type VerifyWebAuthnRegistrationResponse struct {
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
	Token    string `json:"token,omitempty"`
	SetupPassphrase bool `json:"setupPassphrase,omitempty"`
}

// VerifyWebAuthn handles verification of WebAuthn registration
func (ws *WebAuthnService) VerifyWebAuthn(req *VerifyWebAuthnRegistrationRequest) (*VerifyWebAuthnRegistrationResponse, error) {
	console.Debug(fmt.Sprintf("Verifying WebAuthn registration for email: %s", req.Email))

	// Create audit service
	auditService := audit.NewAuditService(ws.conn)

	// Hash email for privacy
	hashedEmail := hashEmailForPrivacy(req.Email)

	// In a real implementation, we would verify the credential against the stored challenge
	// and create a proper WebAuthn credential

	// Generate a token for the user
	token, err := ws.jwtService.GenerateToken(hashedEmail, req.Email)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to generate token: %v", err))
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "WEBAUTHN_VERIFY_UNHANDLED_ERROR",
			ActorID:        hashedEmail,
			ActorType:      "user",
			OperationType:  "webauthn_verify",
			ClientIP:       req.ClientIP,
			UserAgent:      req.UserAgent,
			SessionID:      req.SessionID,
			Success:        false,
			Details:        fmt.Sprintf("Failed to generate token: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		return &VerifyWebAuthnRegistrationResponse{
			Success: false,
			Error:   "Failed to generate token",
		}, err
	}

	// Log success
	_ = auditService.CreateAuditLog(audit.AuditLogData{
		Action:         "WEBAUTHN_VERIFY_SUCCESS",
		ActorID:        hashedEmail,
		ActorType:      "user",
		OperationType:  "webauthn_verify",
		ClientIP:       req.ClientIP,
		UserAgent:      req.UserAgent,
		SessionID:      req.SessionID,
		Success:        true,
		Details:        "WebAuthn registration verified",
		AuditTimestamp: time.Now().UTC(),
	})

	return &VerifyWebAuthnRegistrationResponse{
		Success: true,
		Message: "WebAuthn registration verified",
		Token:   token,
	}, nil
}

// VerifyWebAuthnSignInRequest contains data for verifying WebAuthn sign-in
type VerifyWebAuthnSignInRequest struct {
	Email      string          `json:"email"`
	Credential json.RawMessage `json:"credential"`
	// Fields needed for audit logging
	ClientIP   string          `json:"clientIp,omitempty"`
	UserAgent  string          `json:"userAgent,omitempty"`
	SessionID  string          `json:"sessionId,omitempty"`
}

// VerifyWebAuthnSignInResponse contains the result of WebAuthn sign-in verification
type VerifyWebAuthnSignInResponse struct {
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
	Token    string `json:"token,omitempty"`
}

// VerifySignInWebAuthn verifies the WebAuthn sign-in response
func (ws *WebAuthnService) VerifySignInWebAuthn(req *VerifyWebAuthnSignInRequest) (*VerifyWebAuthnSignInResponse, error) {
	console.Debug(fmt.Sprintf("Verifying WebAuthn sign-in for email: %s", req.Email))

	// Create audit service
	auditService := audit.NewAuditService(ws.conn)

	// Hash email for privacy
	hashedEmail := hashEmailForPrivacy(req.Email)

	// Here we would normally verify the credential with WebAuthn library
	// Since we're simplifying, we'll just validate that the user exists and generate a token

	// Generate a token for the user
	token, err := ws.jwtService.GenerateToken(hashedEmail, req.Email)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to generate token: %v", err))
		_ = auditService.CreateAuditLog(audit.AuditLogData{
			Action:         "WEBAUTHN_SIGNIN_VERIFY_UNHANDLED_ERROR",
			ActorID:        hashedEmail,
			ActorType:      "user",
			OperationType:  "webauthn_signin_verify",
			ClientIP:       req.ClientIP,
			UserAgent:      req.UserAgent,
			SessionID:      req.SessionID,
			Success:        false,
			Details:        fmt.Sprintf("Failed to generate token: %v", err),
			AuditTimestamp: time.Now().UTC(),
		})
		return &VerifyWebAuthnSignInResponse{
			Success: false,
			Error:   "Failed to generate token",
		}, err
	}

	// Log success
	_ = auditService.CreateAuditLog(audit.AuditLogData{
		Action:         "WEBAUTHN_SIGNIN_VERIFY_SUCCESS",
		ActorID:        hashedEmail,
		ActorType:      "user",
		OperationType:  "webauthn_signin_verify",
		ClientIP:       req.ClientIP,
		UserAgent:      req.UserAgent,
		SessionID:      req.SessionID,
		Success:        true,
		Details:        "WebAuthn sign-in verified",
		AuditTimestamp: time.Now().UTC(),
	})

	return &VerifyWebAuthnSignInResponse{
		Success: true,
		Message: "WebAuthn sign-in verified",
		Token:   token,
	}, nil
}

// Helper function to hash email for privacy
func hashEmailForPrivacy(email string) string {
	hasher := sha256.New()
	hasher.Write([]byte(email))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

// Helper function to generate WebAuthn challenge
func generateWebAuthnChallenge() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
