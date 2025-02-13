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
	query := &dgraph.Query{
		Query: `query userExists($email: string) {
			user(func: eq(email, $email), first: 1) {
				uid
				email
				status
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
			UID    string `json:"uid"`
			Email  string `json:"email"`
			Status string `json:"status"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	now := time.Now()

	var setNquads string
	var delNquads string
	if len(result.User) > 0 {
		user := result.User[0]
		
		switch user.Status {
		case "suspended":
			return "", fmt.Errorf("account is suspended")
		case "deactivated":
			return "", fmt.Errorf("account is deactivated")
		}

		setNquads = fmt.Sprintf(`
			<%s> <otp> "%s" .
			<%s> <otpCreatedAt> "%s" .
		`, user.UID, otp, user.UID, now.Format(time.RFC3339))

		delNquads = fmt.Sprintf(`
			<%s> <sessionToken> * .
			<%s> <sessionExpiry> * .
		`, user.UID, user.UID)
	} else {
		setNquads = fmt.Sprintf(`
			_:user <dgraph.type> "User" .
			_:user <email> "%s" .
			_:user <otp> "%s" .
			_:user <otpCreatedAt> "%s" .
			_:user <status> "active" .
			_:user <dateJoined> "%s" .
			_:user <failedAttempts> "0" .
		`, email, otp, now.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	mutation := &dgraph.Mutation{
		SetNquads: setNquads,
		DelNquads: delNquads,
	}

	if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
		return "", fmt.Errorf("failed to update user: %v", err)
	}

	return otp, nil
}

func (s *OTPService) VerifyOTP(req *VerifyOTPRequest) (*VerifyOTPResponse, error) {
	query := &dgraph.Query{
		Query: `query getUser($email: string) {
			user(func: eq(email, $email), first: 1) {
				uid
				email
				otp
				otpCreatedAt
				status
				failedAttempts
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
			UID            string    `json:"uid"`
			Email          string    `json:"email"`
			OTP            string    `json:"otp"`
			OTPCreatedAt   time.Time `json:"otpCreatedAt"`
			Status         string    `json:"status"`
			FailedAttempts int       `json:"failedAttempts"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	user := result.User[0]

	// Check account status
	switch user.Status {
	case "suspended":
		return nil, fmt.Errorf("account is suspended")
	case "deactivated":
		return nil, fmt.Errorf("account is deactivated")
	}

	// Check if OTP is expired (10 minutes)
	if time.Since(user.OTPCreatedAt) > 10*time.Minute {
		return nil, fmt.Errorf("OTP has expired")
	}

	// Check if OTP matches
	if user.OTP != req.OTP {
		// Increment failed attempts
		failedAttempts := user.FailedAttempts + 1

		setNquads := fmt.Sprintf(`<%s> <failedAttempts> "%d" .`, user.UID, failedAttempts)
		
		// If too many failed attempts, suspend the account
		if failedAttempts >= 5 {
			setNquads += fmt.Sprintf(`
				<%s> <status> "suspended" .
			`, user.UID)
		}

		mutation := &dgraph.Mutation{
			SetNquads: setNquads,
		}

		if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
			return nil, fmt.Errorf("failed to update failed attempts: %v", err)
		}

		if failedAttempts >= 5 {
			return nil, fmt.Errorf("account has been suspended due to too many failed attempts")
		}

		return nil, fmt.Errorf("invalid OTP")
	}

	// Generate session token
	sessionToken := generateSessionToken()
	sessionExpiry := time.Now().Add(24 * time.Hour)

	// Update user with session token and clear OTP
	mutation := &dgraph.Mutation{
		SetNquads: fmt.Sprintf(`
			<%s> <sessionToken> "%s" .
			<%s> <sessionExpiry> "%s" .
			<%s> <failedAttempts> "0" .
		`, user.UID, sessionToken, user.UID, sessionExpiry.Format(time.RFC3339), user.UID),
		DelNquads: fmt.Sprintf(`
			<%s> <otp> * .
			<%s> <otpCreatedAt> * .
		`, user.UID, user.UID),
	}

	if _, err := dgraph.ExecuteMutations(s.conn, mutation); err != nil {
		return nil, fmt.Errorf("failed to update user session: %v", err)
	}

	return &VerifyOTPResponse{
		Success: true,
		Message: "OTP verified successfully",
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
