package auth

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

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

func (s *OTPService) GenerateOTP(req *GenerateOTPRequest) (*GenerateOTPResponse, error) {
	otp, err := s.generateOTP(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %v", err)
	}

	if err := s.emailSender.SendOTP(req.Email, otp); err != nil {
		return nil, fmt.Errorf("failed to send OTP email: %v", err)
	}

	return &GenerateOTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *OTPService) generateOTP(email string) (string, error) {
	now := time.Now()
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Using DQL upsert to handle both new and existing users
	query := &dgraph.Query{
		Query: `query userExists($email: string) {
			user(func: eq(email, $email)) {
				uid
				email
				status
				otpCreatedAt
			}
		}`,
		Variables: map[string]string{
			"$email": email,
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return "", fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID          string    `json:"uid"`
			Email        string    `json:"email"`
			Status       string    `json:"status"`
			OTPCreatedAt time.Time `json:"otpCreatedAt,omitempty"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// Handle existing user
	if len(result.User) > 0 {
		user := result.User[0]

		// Check if user is active
		if user.Status != "" && user.Status != "active" {
			return "", fmt.Errorf("account is not active")
		}

		// Check rate limiting
		if !user.OTPCreatedAt.IsZero() {
			timeSince := now.Sub(user.OTPCreatedAt)
			if timeSince.Minutes() < 1 {
				return "", fmt.Errorf("please wait %d seconds before requesting another OTP", int(60-timeSince.Seconds()))
			}
		}

		// Update existing user with new OTP
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`
				<%s> <otp> "%s" .
				<%s> <otpCreatedAt> "%s"^^<xs:dateTime> .
				<%s> <failedAttempts> "0" .
			`, user.UID, otp, user.UID, now.Format(time.RFC3339), user.UID),
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return "", fmt.Errorf("failed to update user OTP: %v", err)
		}

		return otp, nil
	}

	// Create new user with DQL
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			_:user <dgraph.type> "User" .
			_:user <email> "%s" .
			_:user <otp> "%s" .
			_:user <otpCreatedAt> "%s"^^<xs:dateTime> .
			_:user <status> "active" .
			_:user <dateJoined> "%s"^^<xs:dateTime> .
			_:user <failedAttempts> "0" .
			_:user <verified> "false" .
		`, email, otp, now.Format(time.RFC3339), now.Format(time.RFC3339)),
	}

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %v", err)
	}

	// Check if user was created successfully
	if len(mutResp.Uids) == 0 {
		return "", fmt.Errorf("failed to create user: no uid returned")
	}

	return otp, nil
}

func (s *OTPService) VerifyOTP(req *VerifyOTPRequest) (*VerifyOTPResponse, error) {
	now := time.Now()

	query := &dgraph.Query{
		Query: `query verifyOTP($email: string, $otp: string) {
			user(func: eq(email, $email), first: 1) {
				uid
				email
				status
				otp
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
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			UID           string    `json:"uid"`
			Email         string    `json:"email"`
			Status        string    `json:"status"`
			OTP          string    `json:"otp"`
			OTPCreatedAt time.Time `json:"otpCreatedAt"`
			FailedAttempts int    `json:"failedAttempts"`
			Verified     bool      `json:"verified"`
			DateJoined   time.Time `json:"dateJoined"`
			LastAuthTime time.Time `json:"lastAuthTime"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	user := result.User[0]

	// Check user status
	if user.Status != "active" {
		return nil, fmt.Errorf("account is %s", user.Status)
	}

	// Check failed attempts
	if user.FailedAttempts >= 5 {
		return nil, fmt.Errorf("too many failed attempts, please request a new OTP")
	}

	// Check OTP expiry
	if time.Since(user.OTPCreatedAt) > 5*time.Minute {
		return nil, fmt.Errorf("OTP has expired, please request a new one")
	}

	// Check OTP match
	if user.OTP != req.OTP {
		// Increment failed attempts
		mutation := &dgraph.Mutation{
			SetNquads: fmt.Sprintf(`
				<%s> <failedAttempts> "%d" .
			`, user.UID, user.FailedAttempts+1),
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return nil, fmt.Errorf("failed to update failed attempts: %v", err)
		}

		return nil, fmt.Errorf("invalid OTP")
	}

	// OTP is valid, update user
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			<%s> <verified> "true" .
			<%s> <lastAuthTime> "%s"^^<xs:dateTime> .
			<%s> <failedAttempts> "0" .
		`, user.UID, user.UID, now.Format(time.RFC3339), user.UID),
	}

	if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
		return nil, fmt.Errorf("failed to update user: %v", err)
	}

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

// generateSessionToken generates a random session token
func generateSessionToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, 32)
	for i := range token {
		token[i] = charset[rand.Intn(len(charset))]
	}
	return string(token)
}
