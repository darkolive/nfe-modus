package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

type OTPService struct {
	conn           string
	emailSender    EmailSender
	secretKey      []byte             // Secret key for HMAC operations
	verifiedEmails map[string]struct {
		verifiedAt time.Time
	}
	mu            sync.Mutex // Mutex for thread safety
	failedAttempts map[string]int // Store for tracking failed attempts
	verifiedEmailsMutex sync.Mutex // Mutex for thread safety
}

type EmailSender interface {
	SendOTP(to, otp string) error
}

// NewOTPService creates a new OTP service
func NewOTPService(conn string, emailSender EmailSender) *OTPService {
	// Get encryption key from environment
	encryptionKey := os.Getenv("MODUS_ENCRYPTION_KEY")
	var secretKey []byte
	
	if encryptionKey != "" {
		// Try to decode from base64 if it's in that format
		var err error
		secretKey, err = base64.StdEncoding.DecodeString(encryptionKey)
		if err != nil {
			// If not base64, use the string directly
			secretKey = []byte(encryptionKey)
			console.Info("Using MODUS_ENCRYPTION_KEY as raw bytes")
		} else {
			console.Info("Using MODUS_ENCRYPTION_KEY from environment (base64 decoded)")
		}
	} else {
		// Fallback to a static key if environment variable is not set
		console.Warn("MODUS_ENCRYPTION_KEY not found in environment, using fallback static key")
		secretKey = []byte("nfe-modus-static-key-for-hmac-operations-2025")
	}
	
	return &OTPService{
		conn:          conn,
		emailSender:   emailSender,
		secretKey:     secretKey,
		verifiedEmails: make(map[string]struct {
			verifiedAt time.Time
		}),
		mu: sync.Mutex{},
		failedAttempts: make(map[string]int),
		verifiedEmailsMutex: sync.Mutex{},
	}
}

// StoreVerifiedEmail stores a verified email in memory with the current timestamp
func (s *OTPService) StoreVerifiedEmail(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifiedEmails[email] = struct {
		verifiedAt time.Time
	}{
		verifiedAt: time.Now(),
	}
	console.Debug(fmt.Sprintf("Stored verified email in memory: %s", email))
}

// GetVerifiedEmail retrieves a verified email from memory along with its verification time
// Returns the email, verification time, and whether it exists
func (s *OTPService) GetVerifiedEmail(email string) (string, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	info, exists := s.verifiedEmails[email]
	if !exists {
		return "", time.Time{}, false
	}
	
	return email, info.verifiedAt, true
}

// ClearVerifiedEmail removes a verified email from memory
func (s *OTPService) ClearVerifiedEmail(verificationCookie string) {
	// If cookie is provided, try to get the email from it
	if verificationCookie != "" {
		verificationInfo, err := s.CheckVerificationCookie("", verificationCookie)
		if err == nil && verificationInfo != nil {
			email := verificationInfo.Email
			s.verifiedEmailsMutex.Lock()
			defer s.verifiedEmailsMutex.Unlock()
			delete(s.verifiedEmails, email)
			console.Debug(fmt.Sprintf("Cleared verified email from memory: %s", email))
			return
		}
	}
	
	console.Debug("No email provided in verification cookie, unable to clear verified email from memory")
}

type OTP struct {
	Email       string    `json:"email"`
	Code        string    `json:"code"`
	ExpiresAt   time.Time `json:"expiresAt"`
	CreatedAt   time.Time `json:"createdAt"`
	Attempts    int       `json:"attempts"`
	LastRequest time.Time `json:"lastRequest,omitempty"`
}

type GenerateOTPRequest struct {
	Email string `json:"email"`
}

type GenerateOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Cookie  string `json:"cookie,omitempty"` // Encrypted cookie value
}

type VerifyOTPRequest struct {
	OTP    string `json:"otp"`
	Cookie string `json:"cookie"` // Encrypted cookie value
}

type VerifyOTPResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	Token          string `json:"token,omitempty"`
	User           *UserData  `json:"user,omitempty"`
	VerificationCookie string `json:"verificationCookie,omitempty"`
}

const (
	otpLength   = 6
	maxAttempts = 5
	otpTimeout  = 10 * time.Minute
	otpCooldown = 1 * time.Minute  // Minimum time between OTP requests
	cookieName  = "nfe_otp_data"
)

// Error messages
const (
	errUserNotFound      = "user not found or account is not active"
	errTooManyAttempts   = "too many failed attempts, please request a new OTP"
	errOTPNotSet         = "OTP not set, please request a new OTP"
	errOTPExpired        = "OTP has expired (after 10 minutes), please request a new one"
	errInvalidOTP        = "invalid OTP"
	errInvalidCookie     = "invalid or missing cookie data"
	errRateLimited       = "please wait before requesting another OTP"
)

func (s *OTPService) GenerateOTP(req *GenerateOTPRequest) (*GenerateOTPResponse, error) {
	now := time.Now()
	email := strings.ToLower(strings.TrimSpace(req.Email))
	
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	
	// Generate new OTP
	otp, err := generateRandomOTP()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %v", err)
	}
	
	// Create new OTP data
	otpData := OTP{
		Email:       email,
		Code:        otp,
		ExpiresAt:   now.Add(otpTimeout),
		CreatedAt:   now,
		Attempts:    0,
		LastRequest: now,
	}
	
	// Encrypt OTP data for cookie
	cookieValue, err := s.encryptOTPData(&otpData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt OTP data: %v", err)
	}
	
	// Send OTP via email
	if err := s.emailSender.SendOTP(email, otp); err != nil {
		return nil, fmt.Errorf("failed to send OTP email: %v", err)
	}
	
	console.Info(fmt.Sprintf("OTP generated for %s: %s", email, otp))
	
	return &GenerateOTPResponse{
		Success: true,
		Message: "OTP sent successfully",
		Cookie:  cookieValue,
	}, nil
}

func (s *OTPService) VerifyOTP(req *VerifyOTPRequest) (*VerifyOTPResponse, error) {
	// Decrypt and validate OTP cookie first to get email if not provided
	var otpData OTP
	var err error
	
	if req.Cookie != "" {
		// If cookie provided, decrypt it
		otpDataPtr, decryptErr := s.decryptOTPData(req.Cookie)
		if decryptErr != nil {
			return &VerifyOTPResponse{
				Success: false,
				Message: "Invalid OTP cookie",
			}, nil
		}
		otpData = *otpDataPtr
		
		// If email is not provided in the request, use the one from the cookie
		// req.Email = otpData.Email
	} else {
		// If no cookie, we can't proceed
		return &VerifyOTPResponse{
			Success: false,
			Message: "OTP verification failed - no valid cookie",
		}, nil
	}
	
	// Now check if we have an email (either from request or cookie)
	if req.OTP == "" {
		return &VerifyOTPResponse{
			Success: false,
			Message: "OTP is required",
		}, nil
	}

	// Check if OTP has expired
	if time.Now().After(otpData.ExpiresAt) {
		return &VerifyOTPResponse{
			Success: false,
			Message: "OTP has expired",
		}, nil
	}

	// Check if OTP is valid
	if req.OTP != otpData.Code {
		// Increment failed attempts
		s.incrementFailedAttempts(otpData.Email)
		return &VerifyOTPResponse{
			Success: false,
			Message: "Invalid OTP",
		}, nil
	}

	// OTP verification successful!
	
	// Create verification timestamp
	now := time.Now().UTC()
	
	// Record verification in memory store
	s.StoreVerifiedEmail(otpData.Email)
	
	// Generate cookie for web client
	cookieString, cookieGenErr := s.generateVerificationCookieV2(VerificationInfo{
		Email:      otpData.Email,
		VerifiedAt: now,
		Method:     "OTP",
	})
	if cookieGenErr != nil {
		console.Error("Failed to generate verification cookie: " + cookieGenErr.Error())
		// Continue anyway, verification was successful
	}
	
	// Reset failed attempts counter
	s.resetFailedAttempts(otpData.Email)
	
	// Get or create user record
	userData, err := s.getUserByEmail(otpData.Email)
	if err != nil {
		// If user doesn't exist, create a new one
		userData, err = s.createUser(otpData.Email)
		if err != nil {
			console.Error("Failed to create user record: " + err.Error())
			return &VerifyOTPResponse{
				Success: false,
				Message: "Failed to create user record",
			}, nil
		}
	}
	
	// Generate token and user object for response
	tokenString := generateSessionToken()
	userObj := &UserData{
		UID: userData.UID,
	}
	
	// Return success response
	return &VerifyOTPResponse{
		Success: true,
		Message: "OTP verification successful",
		Token: tokenString,
		VerificationCookie: cookieString,
		User: userObj,
	}, nil
}

// Helper functions

// Encrypt OTP data for cookie
func (s *OTPService) encryptOTPData(otpData *OTP) (string, error) {
	// Serialize OTP data to JSON
	data, err := json.Marshal(otpData)
	if err != nil {
		return "", fmt.Errorf("failed to serialize OTP data: %v", err)
	}
	
	// Generate HMAC for data integrity
	h := hmac.New(sha256.New, s.secretKey)
	h.Write(data)
	hmacSum := h.Sum(nil)
	
	// Combine HMAC and data, then base64 encode
	combined := append(hmacSum, data...)
	encoded := base64.StdEncoding.EncodeToString(combined)
	
	return encoded, nil
}

// Decrypt and validate OTP data from cookie
func (s *OTPService) decryptOTPData(cookieValue string) (*OTP, error) {
	// Decode base64
	combined, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie: %v", err)
	}
	
	// Split HMAC and data
	if len(combined) < sha256.Size {
		return nil, fmt.Errorf("invalid cookie format")
	}
	
	hmacSum := combined[:sha256.Size]
	data := combined[sha256.Size:]
	
	// Verify HMAC
	h := hmac.New(sha256.New, s.secretKey)
	h.Write(data)
	expectedHMAC := h.Sum(nil)
	
	if !hmac.Equal(hmacSum, expectedHMAC) {
		return nil, fmt.Errorf("invalid cookie signature")
	}
	
	// Deserialize OTP data
	var otpData OTP
	if err := json.Unmarshal(data, &otpData); err != nil {
		return nil, fmt.Errorf("failed to deserialize OTP data: %v", err)
	}
	
	return &otpData, nil
}

// User data type for consistent response
type UserData struct {
	UID string
}

// Get user by email from database
func (s *OTPService) getUserByEmail(email string) (*UserData, error) {
	query := &dgraph.Query{
		Query: `query userExists($email: string) {
			user(func: eq(email, $email)) {
				uid
			}
		}`,
		Variables: map[string]string{
			"$email": email,
		},
	}
	
	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return nil, err
	}
	
	var result struct {
		User []struct {
			UID string `json:"uid"`
		} `json:"user"`
	}
	
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, err
	}
	
	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	
	return &UserData{UID: result.User[0].UID}, nil
}

// Create a new user in the database
func (s *OTPService) createUser(email string) (*UserData, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	
	// Try to encrypt the email for database storage
	emailToStore := email // Default to plaintext email
	
	// Use the more reliable method with fallback for email encryption
	emailEncryption := NewEmailEncryptionWithFallback()
	encryptedEmail, encryptErr := emailEncryption.EncryptEmail(email)
	if encryptErr == nil {
		emailToStore = encryptedEmail // Use encrypted email for storage
		console.Info("Email encrypted successfully for database storage")
	} else {
		console.Warn("Failed to encrypt email, using plaintext: " + encryptErr.Error())
	}
	
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			_:user <dgraph.type> "User" .
			_:user <email> "%s" .
			_:user <status> "active" .
			_:user <dateJoined> "%s" .
			_:user <verified> "true" .
			_:user <failedLoginAttempts> "0" .
		`, dgraph.EscapeRDF(emailToStore), now),
	}
	
	resp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		return nil, err
	}
	
	// Extract the UID of the new user
	var userUID string
	for _, uid := range resp.Uids {
		userUID = uid
		break
	}
	
	if userUID == "" {
		return nil, fmt.Errorf("failed to create user")
	}
	
	// Create a RoleService and ensure roles exist before assigning them
	roleService := NewRoleService(s.conn)
	
	// Ensure the roles exist before assignment
	ensureErr := roleService.EnsureRolesExist()
	if ensureErr != nil {
		console.Error("Failed to ensure roles exist: " + ensureErr.Error())
		// This is non-fatal, continue with role assignment attempt
	}
	
	// Assign the registered role to the new user
	roleErr := roleService.AssignRoleToUser(userUID, "registered")
	if roleErr != nil {
		console.Error("Failed to assign registered role to new user: " + roleErr.Error())
		// This is non-fatal, continue with user creation
	} else {
		console.Info(fmt.Sprintf("Successfully assigned 'registered' role to new user with email: %s", email))
	}
	
	return &UserData{UID: userUID}, nil
}

// updateUserVerification updates a user's verification status
// Note: Currently unused but kept for API compatibility and future use
func (s *OTPService) updateUserVerification(user *UserData, now time.Time) error {
	// Update verification status in Dgraph
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			<%s> <verified> "true" .
			<%s> <emailVerified> "%s" .
			<%s> <lastAuthTime> "%s" .
		`, user.UID, user.UID, now.Format(time.RFC3339), user.UID, now.Format(time.RFC3339)),
	}
	
	_, err := dgraph.ExecuteMutations(s.conn, mutation)
	return err
}

// GenerateOTP creates a cryptographically secure OTP
func generateRandomOTP() (string, error) {
	// Generate a random integer between 100000 and 999999
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	
	// Add 100000 to ensure we get a 6-digit number
	otp := n.Int64() + 100000
	
	return fmt.Sprintf("%d", otp), nil
}

// ValidateOTPInput checks if the OTP meets security requirements
func ValidateOTPInput(otp string) error {
	if len(otp) != otpLength {
		return fmt.Errorf("invalid OTP length: expected %d, got %d", otpLength, len(otp))
	}

	// Check if OTP contains only digits
	for _, c := range otp {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid OTP format: must contain only digits")
		}
	}

	return nil
}

// IsOTPExpired checks if the OTP has expired
func IsOTPExpired(createdAt time.Time) bool {
	return time.Since(createdAt) > otpTimeout
}

// ShouldAllowNewOTP checks if enough time has passed since the last OTP request
func ShouldAllowNewOTP(lastOTPTime time.Time) bool {
	return time.Since(lastOTPTime) > otpCooldown
}

// HasExceededMaxAttempts checks if the user has exceeded maximum failed attempts
func HasExceededMaxAttempts(attempts int) bool {
	return attempts >= maxAttempts
}

// LogAuthAttempt logs authentication attempts for audit purposes
func LogAuthAttempt(email, action string, success bool, metadata map[string]string) {
	// For now, just log to console
	// In production, this should be logged to a proper audit system
	if success {
		console.Info(fmt.Sprintf("Auth %s succeeded for %s", action, email))
	} else {
		console.Error(fmt.Sprintf("Auth %s failed for %s", action, email))
	}
}

// generateSessionToken generates a random session token
func generateSessionToken() string {
	// Generate 32 random bytes
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		console.Error("Failed to generate session token: " + err.Error())
		return ""
	}
	
	// Convert to base64
	return base64.URLEncoding.EncodeToString(b)
}

// GetVerificationInfo returns detailed verification information for an email
func (s *OTPService) GetVerificationInfo(email string) *VerificationInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if data, exists := s.verifiedEmails[email]; exists {
		return &VerificationInfo{
			Email:      email,
			VerifiedAt: data.verifiedAt,
			Method:     "OTP",
		}
	}
	
	return nil
}

// CheckVerification checks if an email has been verified recently
func (s *OTPService) CheckVerification(email string) (bool, error) {
	// First check in-memory store
	if _, exists := s.verifiedEmails[email]; exists {
		return true, nil
	}
	
	return false, fmt.Errorf("email not verified or verification expired")
}

// ClearVerification removes verification data for an email
func (s *OTPService) ClearVerification(verificationCookie string) {
	s.ClearVerifiedEmail(verificationCookie)
}

// ClearEmailVerification is an alias for ClearVerification
func (s *OTPService) ClearEmailVerification(verificationCookie string) {
	s.ClearVerifiedEmail(verificationCookie)
}

// VerificationInfo represents data about a verified email
type VerificationInfo struct {
	Email      string    `json:"email"`
	VerifiedAt time.Time `json:"verifiedAt"`
	Method     string    `json:"method"`
}

// generateVerificationCookie creates a cookie for email verification
func (s *OTPService) generateVerificationCookieV2(info VerificationInfo) (string, error) {
	// Create the verification data
	data, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to serialize verification data: %v", err)
	}

	// Create HMAC
	h := hmac.New(sha256.New, s.secretKey)
	h.Write(data)
	hmacSum := h.Sum(nil)

	// Combine HMAC and data
	combined := append(hmacSum, data...)

	// Encode as base64 with URL-safe encoding
	cookie := base64.URLEncoding.EncodeToString(combined)
	return cookie, nil
}

// CheckVerification verifies the cookie and returns the verification info
func (s *OTPService) CheckVerificationCookie(email string, cookie string) (*VerificationInfo, error) {
	// If cookie is missing, we can't proceed
	if cookie == "" {
		return nil, fmt.Errorf("no verification cookie provided")
	}

	// First extract information from the cookie, since it's our authoritative source
	// Decode cookie
	combined, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		return nil, fmt.Errorf("invalid verification cookie format")
	}

	if len(combined) <= sha256.Size {
		return nil, fmt.Errorf("invalid verification cookie data")
	}

	hmacSum := combined[:sha256.Size]
	data := combined[sha256.Size:]

	// Verify HMAC
	h := hmac.New(sha256.New, s.secretKey)
	h.Write(data)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(hmacSum, expectedHMAC) {
		return nil, fmt.Errorf("invalid verification cookie signature")
	}

	// Deserialize verification data
	var verificationInfo VerificationInfo
	if err := json.Unmarshal(data, &verificationInfo); err != nil {
		return nil, fmt.Errorf("failed to deserialize verification data: %v", err)
	}
	
	// If email wasn't provided, use the one from the cookie
	if email == "" {
		email = verificationInfo.Email
	} else if verificationInfo.Email != email {
		// If an email was provided but doesn't match the cookie, that's an error
		return nil, fmt.Errorf("email mismatch in verification cookie")
	}
	
	// As a backup, check the in-memory cache using the email from the cookie
	if verifiedInfo, exists := s.verifiedEmails[email]; exists {
		// Use the most recent verification timestamp between cookie and memory
		if verifiedInfo.verifiedAt.After(verificationInfo.VerifiedAt) {
			verificationInfo.VerifiedAt = verifiedInfo.verifiedAt
		}
	}

	return &verificationInfo, nil
}

// incrementFailedAttempts increments the failed attempts for an email
func (s *OTPService) incrementFailedAttempts(email string) {
	s.failedAttempts[email]++
}

// resetFailedAttempts resets the failed attempts for an email
func (s *OTPService) resetFailedAttempts(email string) {
	s.failedAttempts[email] = 0
}
