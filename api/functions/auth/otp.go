package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

type OTPService struct {
	conn        string
	emailSender EmailSender
}

type EmailSender interface {
	SendOTP(to, otp string) error
}

func NewOTPService(conn string, emailSender EmailSender) *OTPService {
	return &OTPService{
		conn:        conn,
		emailSender: emailSender,
	}
}

type OTP struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type GenerateOTPRequest struct {
	Email string `json:"email"`
}

type GenerateOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type VerifyOTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type VerifyOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	User    *User  `json:"user,omitempty"`
}

const (
	otpLength   = 6
	maxAttempts = 5
	otpTimeout  = 10 * time.Minute
	otpCooldown = 1 * time.Minute  // Minimum time between OTP requests
)

// Error messages
const (
	errUserNotFound      = "user not found or account is not active"
	errTooManyAttempts   = "too many failed attempts, please request a new OTP"
	errOTPNotSet         = "OTP creation time not set, please request a new OTP"
	errOTPExpired        = "OTP has expired (after 10 minutes), please request a new one"
	errInvalidOTP        = "invalid OTP"
	errInvalidOTPTime    = "invalid OTP creation time: %v"
	errFailedAttempts    = "failed to increment failed attempts: %v"
)

func (s *OTPService) GenerateOTP(req *GenerateOTPRequest) (*GenerateOTPResponse, error) {
	now := time.Now()
	otp, err := GenerateOTP()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %v", err)
	}

	// Check if user exists
	query := &dgraph.Query{
		Query: `query userExists($email: string) {
			user(func: eq(email, $email)) {
				uid
				status
				otpCreatedAt
				lastOTPRequestTime
			}
		}`,
		Variables: map[string]string{
			"$email": req.Email,
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		console.Error("Failed to query user - email: " + req.Email + ", error: " + err.Error())
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID               string `json:"uid"`
			Status           string `json:"status"`
			OTPCreatedAt     string `json:"otpCreatedAt"`
			LastOTPRequestTime string `json:"lastOTPRequestTime"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to parse response - email: " + req.Email + ", error: " + err.Error())
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// If user exists, check status and rate limiting
	if len(result.User) > 0 {
		user := result.User[0]
		
		// Check account status
		if user.Status != "active" {
			console.Error("Account is not active - email: " + req.Email)
			return &GenerateOTPResponse{
				Success: false,
				Message: "account is not active",
			}, nil
		}

		// Check rate limiting if last OTP request time exists
		if user.LastOTPRequestTime != "" {
			lastRequest, err := time.Parse(time.RFC3339, user.LastOTPRequestTime)
			if err == nil && time.Since(lastRequest) < otpCooldown {
				console.Error("Rate limited - email: " + req.Email + ", last request: " + lastRequest.String())
				return &GenerateOTPResponse{
					Success: false,
					Message: "please wait before requesting another OTP",
				}, nil
			}
		}

		// Update existing user with new OTP
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`
				<%s> <otp> "%s" .
				<%s> <otpCreatedAt> "%s" .
				<%s> <lastOTPRequestTime> "%s" .
				<%s> <failedAttempts> "0" .
			`, user.UID, otp, user.UID, now.Format(time.RFC3339), 
			   user.UID, now.Format(time.RFC3339), user.UID),
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return nil, fmt.Errorf("failed to update user OTP: %v", err)
		}
	} else {
		// Create new user
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`
				_:user <dgraph.type> "User" .
				_:user <email> "%s" .
				_:user <otp> "%s" .
				_:user <otpCreatedAt> "%s" .
				_:user <lastOTPRequestTime> "%s" .
				_:user <status> "active" .
				_:user <dateJoined> "%s" .
				_:user <failedAttempts> "0" .
				_:user <verified> "false" .
			`, req.Email, otp, now.Format(time.RFC3339), 
			   now.Format(time.RFC3339), now.Format(time.RFC3339)),
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return nil, fmt.Errorf("failed to create user: %v", err)
		}
	}

	if err := s.emailSender.SendOTP(req.Email, otp); err != nil {
		return nil, fmt.Errorf("failed to send OTP email: %v", err)
	}

	return &GenerateOTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *OTPService) VerifyOTP(req *VerifyOTPRequest) (*VerifyOTPResponse, error) {
	now := time.Now()

	console.Info("Verifying OTP for email: " + req.Email)

	query := &dgraph.Query{
		Query: `query verifyOTP($email: string, $otp: string) {
			user(func: eq(email, $email), first: 1) {
				uid
				email
				otp
				otpCreatedAt
				failedAttempts
				status
			}
		}`,
		Variables: map[string]string{
			"$email": req.Email,
			"$otp":   req.OTP,
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		console.Error("Failed to query user - email: " + req.Email + ", error: " + err.Error())
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID           string `json:"uid"`
			Email         string `json:"email"`
			OTP           string `json:"otp"`
			OTPCreatedAt  string `json:"otpCreatedAt"`
			FailedAttempts int    `json:"failedAttempts"`
			Status        string `json:"status"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to parse response - email: " + req.Email + ", error: " + err.Error())
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 {
		console.Error("User not found - email: " + req.Email)
		return nil, fmt.Errorf("invalid email or OTP")
	}

	user := result.User[0]

	// Check account status
	if user.Status != "active" {
		console.Error("Account is not active - email: " + req.Email)
		return nil, fmt.Errorf("account is not active")
	}

	// Check failed attempts
	if HasExceededMaxAttempts(user.FailedAttempts) {
		console.Error("Too many failed attempts - email: " + req.Email + ", attempts: " + fmt.Sprint(user.FailedAttempts))
		return nil, fmt.Errorf("too many failed attempts")
	}

	// Check OTP expiry
	otpCreatedAt, err := time.Parse(time.RFC3339, user.OTPCreatedAt)
	if err != nil {
		console.Error("Invalid OTP creation time - email: " + req.Email + ", time: " + user.OTPCreatedAt + ", error: " + err.Error())
		return nil, fmt.Errorf("invalid OTP")
	}

	if IsOTPExpired(otpCreatedAt) {
		console.Error("OTP expired - email: " + req.Email + ", created: " + otpCreatedAt.String())
		return nil, fmt.Errorf("OTP has expired")
	}

	// Verify OTP
	if user.OTP != req.OTP {
		// Increment failed attempts
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf("<%s> <failedAttempts> \"%d\" .", user.UID, user.FailedAttempts+1),
		}
		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			console.Error("Failed to increment attempts - email: " + req.Email + ", error: " + err.Error())
			return nil, fmt.Errorf("failed to update attempts")
		}
		console.Error("Invalid OTP - email: " + req.Email + ", attempts: " + fmt.Sprint(user.FailedAttempts+1))
		LogAuthAttempt(req.Email, "verify", false, map[string]string{"otp": req.OTP})
		return nil, fmt.Errorf("invalid OTP")
	}

	// Clear OTP and update verification status
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			<%s> <otp> "" .
			<%s> <verified> "true" .
			<%s> <failedAttempts> "0" .
			<%s> <lastAuthTime> "%s" .
		`, user.UID, user.UID, user.UID, user.UID, now.Format(time.RFC3339)),
	}

	if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
		console.Error("Failed to update user - email: " + req.Email + ", error: " + err.Error())
		return nil, fmt.Errorf("failed to update user")
	}

	console.Info("OTP verified successfully - email: " + req.Email)
	LogAuthAttempt(req.Email, "verify", true, map[string]string{"otp": req.OTP})

	return &VerifyOTPResponse{
		Success: true,
		Message: "OTP verified successfully",
		Token:   generateSessionToken(),
		User: &User{
			ID:    user.UID,
			Email: user.Email,
		},
	}, nil
}

// GenerateOTP creates a cryptographically secure OTP
func GenerateOTP() (string, error) {
	var otp strings.Builder
	otp.Grow(otpLength)

	// Use crypto/rand for secure random numbers
	for i := 0; i < otpLength; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate secure random number: %v", err)
		}
		otp.WriteString(num.String())
	}

	return otp.String(), nil
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
	logData := "Auth attempt - email: " + email + 
		", action: " + action + 
		", success: " + fmt.Sprint(success) + 
		", metadata: " + fmt.Sprint(metadata)

	if success {
		console.Info(logData)
	} else {
		console.Error(logData)
	}
}

// generateSessionToken generates a random session token
func generateSessionToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
