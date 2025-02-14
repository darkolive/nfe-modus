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

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

const (
	otpLength = 6
	maxAttempts = 5
	otpTimeout = 10 * time.Minute
	otpCooldown = 1 * time.Minute
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
	otp, err := GenerateOTP()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %v", err)
	}

	if err := ValidateOTPInput(otp); err != nil {
		return nil, fmt.Errorf("invalid OTP: %v", err)
	}

	now := time.Now().UTC()
	// First query to check existing user and status
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
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID          string    `json:"uid"`
			Status       string    `json:"status"`
			OTPCreatedAt time.Time `json:"otpCreatedAt,omitempty"`
			LastOTPRequestTime time.Time `json:"lastOTPRequestTime,omitempty"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Handle existing user
	if len(result.User) > 0 {
		user := result.User[0]
		
		// Check if user is active
		if user.Status != "" && user.Status != "active" {
			return nil, fmt.Errorf("account is not active")
		}

		// Check rate limiting
		if !user.LastOTPRequestTime.IsZero() {
			if !ShouldAllowNewOTP(user.LastOTPRequestTime) {
				return nil, fmt.Errorf("please wait %d seconds before requesting another OTP", int(otpCooldown.Seconds()-time.Since(user.LastOTPRequestTime).Seconds()))
			}
		}

		// Update existing user with new OTP using RDF format
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`
				<%s> <otp> "%s" .
				<%s> <otpCreatedAt> "%s" .
				<%s> <lastOTPRequestTime> "%s" .
				<%s> <failedAttempts> "0" .
			`, user.UID, otp, user.UID, now.Format(time.RFC3339), user.UID, now.Format(time.RFC3339), user.UID),
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return nil, fmt.Errorf("failed to update user OTP: %v", err)
		}

		if err := s.emailSender.SendOTP(req.Email, otp); err != nil {
			return nil, fmt.Errorf("failed to send OTP email: %v", err)
		}

		return &GenerateOTPResponse{
			Success: true,
			Message: "OTP sent successfully",
		}, nil
	}

	// Create new user using RDF format
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
		`, req.Email, otp, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339)),
	}

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Check if user was created successfully
	if len(mutResp.Uids) == 0 {
		return nil, fmt.Errorf("failed to create user: no uid returned")
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

	console.Info(fmt.Sprintf("Verifying OTP for email: %s", req.Email))

	query := &dgraph.Query{
		Query: `query verifyOTP($email: string, $otp: string) {
			user(func: eq(email, $email)) @filter(has(email) AND eq(status, "active")) {
				uid
				email
				status
				otp @filter(eq(otp, $otp))
				otpCreatedAt
				failedAttempts
				verified
				dateJoined
				lastAuthTime
			}
		}`,
		Variables: map[string]string{
			"$email": req.Email,
			"$otp":   req.OTP,
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to query user - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID           string    `json:"uid"`
			Email         string    `json:"email"`
			Status        string    `json:"status"`
			OTP          string    `json:"otp"`
			OTPCreatedAt string    `json:"otpCreatedAt"`
			FailedAttempts int     `json:"failedAttempts"`
			Verified     bool      `json:"verified"`
			DateJoined   time.Time `json:"dateJoined"`
			LastAuthTime time.Time `json:"lastAuthTime"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Failed to parse response - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 {
		console.Error(fmt.Sprintf("User not found - email: %s", req.Email))
		return nil, fmt.Errorf(errUserNotFound)
	}

	user := result.User[0]

	// Check failed attempts
	if HasExceededMaxAttempts(user.FailedAttempts) {
		console.Error(fmt.Sprintf("Too many failed attempts - email: %s, attempts: %d", req.Email, user.FailedAttempts))
		return nil, fmt.Errorf(errTooManyAttempts)
	}

	// Handle empty OTP creation time
	if user.OTPCreatedAt == "" {
		console.Error(fmt.Sprintf("OTP creation time not set - email: %s", req.Email))
		return nil, fmt.Errorf(errOTPNotSet)
	}

	// Parse OTP creation time
	otpCreatedAt, err := time.Parse(time.RFC3339Nano, user.OTPCreatedAt)
	if err != nil {
		console.Error(fmt.Sprintf("Invalid OTP creation time - email: %s, time: %s, error: %v", req.Email, user.OTPCreatedAt, err))
		return nil, fmt.Errorf(errInvalidOTPTime, err)
	}

	// Check OTP expiry
	if IsOTPExpired(otpCreatedAt) {
		console.Error(fmt.Sprintf("OTP expired - email: %s, created: %v, age: %.2f minutes", req.Email, otpCreatedAt, time.Since(otpCreatedAt).Minutes()))
		return nil, fmt.Errorf(errOTPExpired)
	}

	// Check OTP match
	if user.OTP == "" {
		// Increment failed attempts
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`<%s> <failedAttempts> "%d" .`, user.UID, user.FailedAttempts+1),
		}
		mutations := []*dgraph.Mutation{mutation}
		if _, err := dgraph.ExecuteMutations(s.conn, mutations...); err != nil {
			console.Error(fmt.Sprintf("Failed to increment attempts - email: %s, error: %v", req.Email, err))
			return nil, fmt.Errorf(errFailedAttempts, err)
		}
		console.Error(fmt.Sprintf("Invalid OTP - email: %s, attempts: %d", req.Email, user.FailedAttempts+1))
		LogAuthAttempt(req.Email, "verify", false, map[string]string{"otp": req.OTP})
		return nil, fmt.Errorf(errInvalidOTP)
	}

	// OTP is valid, update user
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			<%s> <verified> "true" .
			<%s> <lastAuthTime> "%s"^^<xs:dateTime> .
			<%s> <failedAttempts> "0" .
		`, user.UID, user.UID, now.UTC().Format(time.RFC3339Nano), user.UID),
	}

	if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
		console.Error(fmt.Sprintf("Failed to update user - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to update user: %v", err)
	}

	console.Info(fmt.Sprintf("OTP verified successfully - email: %s", req.Email))
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
	logData := fmt.Sprintf("Auth attempt - email: %s, action: %s, success: %v, metadata: %v",
		email, action, success, metadata)

	if success {
		console.Info(logData)
	} else {
		console.Warn(logData)
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
