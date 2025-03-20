package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	"golang.org/x/crypto/pbkdf2"
	"nfe-modus/api/functions/email"
)

// Constants for PBKDF2
const (
	iterations = 100000 // Number of iterations
	keyLength  = 64     // Length of the derived key in bytes
	saltLength = 32     // Length of the salt in bytes
)

// PassphraseService handles passphrase operations like setting and verifying
type PassphraseService struct {
	conn            string
	otpService      *OTPService     // For email verification checks
	roleService     *RoleService    // For role management
	emailEncryption *EmailEncryption // For email encryption
	emailService    *email.Service   // For sending emails
	didService      *DIDService     // For passwordless authentication
}

// NewPassphraseService creates a new passphrase service
func NewPassphraseService(conn string, otpService *OTPService, roleService *RoleService, emailEncryption *EmailEncryption, emailService *email.Service) (*PassphraseService, error) {
	if otpService == nil {
		return nil, fmt.Errorf("OTP service is required")
	}
	
	didService, err := NewDIDService(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID service: %v", err)
	}
	
	return &PassphraseService{
		conn:            conn,
		otpService:      otpService,
		roleService:     roleService,
		emailEncryption: emailEncryption,
		emailService:    emailService,
		didService:      didService,
	}, nil
}

// NewPassphraseServiceWithoutEncryption creates a new passphrase service without email encryption
// This is used when we already have a verified email from a cookie and don't need to encrypt it
func NewPassphraseServiceWithoutEncryption(conn string, otpService *OTPService, roleService *RoleService, emailService *email.Service) (*PassphraseService, error) {
	if otpService == nil {
		return nil, fmt.Errorf("OTP service is required")
	}
	
	didService, err := NewDIDService(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID service: %v", err)
	}
	
	return &PassphraseService{
		conn:            conn,
		otpService:      otpService,
		roleService:     roleService,
		emailService:    emailService,
		didService:      didService,
		// No email encryption, we'll use the verified email from cookie
	}, nil
}

// RegisterPassphraseRequest contains data for registering a new passphrase
type RegisterPassphraseRequest struct {
	Passphrase         string `json:"passphrase"`
	VerificationCookie string `json:"verificationCookie"`
}

// SigninPassphraseRequest contains data for signing in with a passphrase
type SigninPassphraseRequest struct {
	Passphrase string `json:"passphrase"`
	Cookie     string `json:"cookie"`
}

// RecoveryPassphraseRequest contains data for initiating passphrase recovery
type RecoveryPassphraseRequest struct {
	Cookie string `json:"cookie"`
}

// ResetPassphraseRequest contains data for resetting a passphrase
type ResetPassphraseRequest struct {
	NewPassphrase      string `json:"newPassphrase"`
	VerificationCookie string `json:"verificationCookie"`
}

// RegisterPassphraseResponse contains the result of registering a passphrase
type RegisterPassphraseResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// SigninPassphraseResponse contains the result of a signin passphrase operation
type SigninPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	UserDID string `json:"did,omitempty"`
}

// RecoveryPassphraseResponse contains the result of a recovery passphrase operation
type RecoveryPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ResetPassphraseResponse contains the result of a reset passphrase operation
type ResetPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// UserDetailsRequest contains data for updating user details
type UserDetailsRequest struct {
	Name             string `json:"name,omitempty"`
	MarketingConsent *bool  `json:"marketingConsent,omitempty"`
	Cookie           string `json:"cookie,omitempty"`
}

// UserDetailsResponse contains the response for a user details update
type UserDetailsResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Uid     string `json:"uid,omitempty"`
}

// RegisterUserDetailsRequest is for initial user registration with OTP verification
type RegisterUserDetailsRequest struct {
	VerificationCookie string `json:"verificationCookie"`
	Name               string `json:"name,omitempty"`
	MarketingConsent   *bool  `json:"marketingConsent,omitempty"`
}

// passphraseHashInfo contains the hash and salt for a passphrase
type passphraseHashInfo struct {
	Hash string
	Salt string
}

// generateSalt creates a random salt for passphrase hashing
func generateSalt() (string, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// hashPassphrase hashes a passphrase using PBKDF2
func hashPassphrase(passphrase string, salt string) (string, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %v", err)
	}

	hash := pbkdf2.Key([]byte(passphrase), saltBytes, iterations, keyLength, sha512.New)
	return base64.StdEncoding.EncodeToString(hash), nil
}

// verifyPassphrase verifies a passphrase against a stored hash
// This is a helper function used by the PassphraseService.VerifyPassphrase method
func verifyPassphrase(passphrase, storedHash, storedSalt string) (bool, error) {
	// Hash the provided passphrase with the stored salt
	hash, err := hashPassphrase(passphrase, storedSalt)
	if err != nil {
		return false, err
	}

	// Constant-time comparison to prevent timing attacks
	hashBytes, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false, err
	}

	storedHashBytes, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil {
		return false, err
	}

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(hashBytes, storedHashBytes) == 1, nil
}

// generateUUID generates a UUID v4 compatible string
func generateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", err
	}
	// Set version to 4 (random UUID)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant to RFC4122
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	
	return fmt.Sprintf("%x-%x-%x-%x-%x", 
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// RegisterPassphrase sets a passphrase for a user
func (ps *PassphraseService) RegisterPassphrase(req *RegisterPassphraseRequest) (*RegisterPassphraseResponse, error) {
	// Get email from verification cookie
	verificationInfo, err := ps.otpService.CheckVerificationCookie("", req.VerificationCookie)
	if err != nil {
		console.Error("Failed to verify cookie: " + err.Error())
		return &RegisterPassphraseResponse{Success: false, Error: "Invalid verification cookie"}, nil
	}
	
	email := verificationInfo.Email
	console.Debug(fmt.Sprintf("Setting passphrase for email: %s", email))

	// Validate input
	if email == "" {
		return &RegisterPassphraseResponse{Success: false, Error: "Email is required. Provide it via verification cookie."}, nil
	}
	if req.Passphrase == "" {
		return &RegisterPassphraseResponse{Success: false, Error: "Passphrase is required"}, nil
	}

	// Basic passphrase validation
	if len(req.Passphrase) < 12 {
		return &RegisterPassphraseResponse{
			Success: false, Error: "Passphrase must be at least 12 characters long",
		}, nil
	}

	// Check verification time to ensure it's fresh (within 5 minutes)
	if time.Since(verificationInfo.VerifiedAt) > 5*time.Minute {
		console.Error("Email verification has expired")
		return &RegisterPassphraseResponse{
			Success: false,
			Error:   "Email verification has expired",
		}, nil
	}

	// Encrypt the email for storage and searching
	var encryptedEmail string
	if ps.emailEncryption != nil {
		var encryptErr error
		encryptedEmail, encryptErr = ps.emailEncryption.EncryptEmail(email)
		if encryptErr != nil {
			console.Error("Failed to encrypt email: " + encryptErr.Error())
			return &RegisterPassphraseResponse{
				Success: false,
				Error:   "Failed to process user data",
			}, nil
		}
	} else {
		console.Warn("Email encryption not available, using plaintext")
		encryptedEmail = email
	}

	// Query the user by encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			email
		}
	}`,
		dgraph.EscapeRDF(encryptedEmail))

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &RegisterPassphraseResponse{
		Success: false,
		Error:   "Failed to query user",
	}, nil
	}

	type QueryResult struct {
		User []struct {
			Uid   string `json:"uid"`
			Email string `json:"email"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to parse user response: " + err.Error())
		return &RegisterPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// If user doesn't exist, create a new user
	if len(result.User) == 0 {
		console.Debug("User not found, creating new user")
		
		// Generate a DID (Decentralized Identifier) based on email and passphrase
		// This creates a deterministic but secure identifier for passwordless auth
		_, err := ps.didService.RegisterUserWithPasswordlessDID(context.Background(), email, req.Passphrase)
		if err != nil {
			console.Error("Failed to create user with passwordless DID: " + err.Error())
			return &RegisterPassphraseResponse{
				Success: false,
				Error:   "Internal server error",
			}, nil
		}

		// User ID is available but roles are now assigned during OTP verification
		console.Debug("New user created with role assigned during OTP verification and passwordless authentication")
	} else {
		// Update existing user's passphrase
		console.Debug("User found, updating passphrase")
		user := result.User[0]

		// Update the user with new passphrase and DID
		err := ps.didService.UpdateUserWithPasswordlessDID(context.Background(), user.Uid, email, req.Passphrase)
		if err != nil {
			console.Error("Failed to update user with passwordless DID: " + err.Error())
			return &RegisterPassphraseResponse{
				Success: false,
				Error:   "Failed to update user",
			}, nil
		}
		
		console.Debug("Updated user with passwordless DID authentication")
	}

	// Clear the verified email from memory
	ps.otpService.ClearVerifiedEmail(req.VerificationCookie)

	return &RegisterPassphraseResponse{
		Success: true,
		Message: "Passphrase set successfully",
	}, nil
}

// SigninPassphrase verifies a user's passphrase
func (ps *PassphraseService) SigninPassphrase(req *SigninPassphraseRequest) (*SigninPassphraseResponse, error) {
	// Get email from cookie
	otpData, err := ps.otpService.decryptOTPData(req.Cookie)
	if err != nil {
		console.Error("Failed to decrypt cookie: " + err.Error())
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Invalid cookie",
		}, nil
	}
	
	email := otpData.Email
	console.Debug(fmt.Sprintf("Verifying passphrase for email: %s", email))

	if email == "" || req.Passphrase == "" {
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Email and passphrase are required",
		}, nil
	}

	// Encrypt the email for searching
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
	if err != nil {
		console.Error("Failed to encrypt email for search: " + err.Error())
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// Check if user exists using encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			did
			status
			failedLoginAttempts
			lockedUntil
		}
	}`, encryptedEmail)

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Failed to query user",
		}, err
	}

	type QueryResult struct {
		User []struct {
			Uid               string `json:"uid"`
			Did               string `json:"did"`
			Status            string `json:"status"`
			FailedLoginAttempts int  `json:"failedLoginAttempts"`
			LockedUntil       string `json:"lockedUntil"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal user query result: " + err.Error())
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, err
	}

	if len(result.User) == 0 {
		console.Debug("User not found")
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Invalid email or passphrase",
		}, nil
	}

	user := result.User[0]

	// Verify the account status
	if user.Status != "active" {
		console.Debug("User account is not active")
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Account is not active",
		}, nil
	}

	// Check if account is locked
	if user.LockedUntil != "" {
		lockedUntil, err := time.Parse(time.RFC3339, user.LockedUntil)
		if err == nil && lockedUntil.After(time.Now()) {
			console.Debug("User account is locked")
			return &SigninPassphraseResponse{
				Success: false,
				Error:   "Account is locked due to too many failed login attempts. Please try again later.",
			}, nil
		}
	}

	// Use passwordless authentication
	isValid := ps.didService.VerifyPasswordlessDID(email, req.Passphrase, user.Did)
	if !isValid {
		console.Debug("Invalid passphrase")
		
		// Update failed login attempts
		failedAttempts := user.FailedLoginAttempts + 1
		var lockUntil string
		
		// Lock account after 5 failed attempts
		if failedAttempts >= 5 {
			// Lock for 30 minutes
			lockTime := time.Now().Add(30 * time.Minute)
			lockUntil = lockTime.Format(time.RFC3339)
		}
		
		// Update the failed login attempts in the database
		updateMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			<%s> <failedLoginAttempts> "%d" .
		`, dgraph.EscapeRDF(user.Uid), failedAttempts))
		
		if lockUntil != "" {
			updateMutation = dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
				<%s> <failedLoginAttempts> "%d" .
				<%s> <lockedUntil> "%s" .
			`, dgraph.EscapeRDF(user.Uid), failedAttempts, 
			   dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(lockUntil)))
		}
		
		_, _ = dgraph.ExecuteMutations(ps.conn, updateMutation) // Ignore errors here
		
		return &SigninPassphraseResponse{
			Success: false,
			Error:   "Invalid email or passphrase",
		}, nil
	}

	// Reset failed login attempts on successful login
	if user.FailedLoginAttempts > 0 {
		resetMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			<%s> <failedLoginAttempts> "0" .
			<%s> <lockedUntil> "" .
		`, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(user.Uid)))
		
		_, _ = dgraph.ExecuteMutations(ps.conn, resetMutation) // Ignore errors here
	}

	// Update last auth time
	now := time.Now().UTC().Format(time.RFC3339)
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		<%s> <lastAuthTime> "%s" .
	`, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))

	console.Debug(fmt.Sprintf("Updating last auth time: %s", mutation.SetNquads))
	_, err = dgraph.ExecuteMutations(ps.conn, mutation)
	if err != nil {
		console.Error("Failed to update last auth time: " + err.Error())
		// Non-fatal error, continue with login
		console.Info("User authenticated but failed to update last auth time")
	}

	// Return success with DID for session creation
	return &SigninPassphraseResponse{
		Success: true,
		UserDID: user.Did,
	}, nil
}

// RecoveryPassphrase initiates passphrase recovery for a user
func (ps *PassphraseService) RecoveryPassphrase(req *RecoveryPassphraseRequest) (*RecoveryPassphraseResponse, error) {
	// Get email from cookie
	otpData, err := ps.otpService.decryptOTPData(req.Cookie)
	if err != nil {
		console.Error("Failed to decrypt cookie: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Invalid cookie",
		}, nil
	}
	
	email := otpData.Email
	console.Debug(fmt.Sprintf("Initiating passphrase recovery for email: %s", email))

	if email == "" {
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Email is required. Provide it via cookie.",
		}, nil
	}

	// Encrypt the email for searching
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
	if err != nil {
		console.Error("Failed to encrypt email for search: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// Check if user exists using encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			did
			verified
			hasPassphrase
		}
	}`, encryptedEmail)

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Failed to query user",
		}, err
	}

	type QueryResult struct {
		User []struct {
			Uid          string `json:"uid"`
			Did          string `json:"did"`
			Verified     bool   `json:"verified"`
			HasPassphrase bool  `json:"hasPassphrase"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal user query result: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, err
	}

	if len(result.User) == 0 {
		console.Debug("User not found")
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Invalid email",
		}, nil
	}

	user := result.User[0]

	// Verify that user has a passphrase set
	if !user.HasPassphrase {
		console.Debug("User does not have a passphrase")
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Passphrase not set for user",
		}, nil
	}

	// Generate verification cookie for password reset
	verificationInfo := VerificationInfo{
		Email:      email,
		VerifiedAt: time.Now().UTC(),
		Method:     "RecoveryEmail",
	}
	
	resetToken, err := ps.otpService.generateVerificationCookieV2(verificationInfo)
	if err != nil {
		console.Error("Failed to generate reset token: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Failed to generate reset token",
		}, nil
	}
	
	// Send password reset email using the service's email service
	err = ps.emailService.SendPasswordReset(email, resetToken)
	if err != nil {
		console.Error("Failed to send password reset email: " + err.Error())
		return &RecoveryPassphraseResponse{
			Success: false,
			Error:   "Failed to send password reset email",
		}, nil
	}
	
	console.Info(fmt.Sprintf("Password reset email sent to %s with token", email))

	return &RecoveryPassphraseResponse{
		Success: true,
	}, nil
}

// ResetPassphrase resets a user's passphrase
func (ps *PassphraseService) ResetPassphrase(req *ResetPassphraseRequest) (*ResetPassphraseResponse, error) {
	// Get email from verification cookie
	verificationInfo, err := ps.otpService.CheckVerificationCookie("", req.VerificationCookie)
	if err != nil {
		console.Error("Failed to verify cookie: " + err.Error())
		return &ResetPassphraseResponse{Success: false, Error: "Invalid verification cookie"}, nil
	}
	
	email := verificationInfo.Email
	console.Debug(fmt.Sprintf("Resetting passphrase for email: %s", email))

	// Validate input
	if email == "" {
		return &ResetPassphraseResponse{Success: false, Error: "Email is required. Provide it via verification cookie."}, nil
	}
	if req.NewPassphrase == "" {
		return &ResetPassphraseResponse{Success: false, Error: "New passphrase is required"}, nil
	}

	// Basic passphrase validation
	if len(req.NewPassphrase) < 12 {
		return &ResetPassphraseResponse{
			Success: false, Error: "Passphrase must be at least 12 characters long",
		}, nil
	}

	// Check if email was verified recently via OTP
	verifiedEmail, verificationTime, exists := ps.otpService.GetVerifiedEmail(email)
	if !exists {
		console.Error("Email verification not found")
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Email verification required before resetting passphrase",
		}, nil
	}

	// Ensure the email matches what was verified
	if verifiedEmail != email {
		console.Error("Email mismatch")
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Email mismatch",
		}, nil
	}

	// Ensure the verification is fresh (within 5 minutes)
	if time.Since(verificationTime) > 5*time.Minute {
		console.Error("Email verification has expired")
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Email verification has expired",
		}, nil
	}

	// Encrypt the email for storage and searching
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
	if err != nil {
		console.Error("Failed to encrypt email: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// Query the user by encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			email
		}
	}`, encryptedEmail)

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Failed to query user",
		}, nil
	}

	type QueryResult struct {
		User []struct {
			Uid   string `json:"uid"`
			Email string `json:"email"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to parse user response: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// If user doesn't exist, return error
	if len(result.User) == 0 {
		console.Error("User not found")
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "User not found",
		}, nil
	}

	user := result.User[0]

	// Hash the new passphrase
	salt, err := generateSalt()
	if err != nil {
		console.Error("Failed to generate salt: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Internal server error",
		}, nil
	}
	hash, err := hashPassphrase(req.NewPassphrase, salt)
	if err != nil {
		console.Error("Failed to hash passphrase: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Internal server error",
		}, nil
	}

	// Update the user with new passphrase
	now := time.Now().UTC().Format(time.RFC3339)
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		<%s> <hasPassphrase> "true" .
		<%s> <passwordHash> "%s" .
		<%s> <passwordSalt> "%s" .
		<%s> <verified> "true" .
		<%s> <status> "active" .
		<%s> <updatedAt> "%s" .
		<%s> <lastAuthTime> "%s" .
	`, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(hash), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(salt), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now), dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))

	console.Debug(fmt.Sprintf("Updating user: %s", mutation.SetNquads))
	_, err = dgraph.ExecuteMutations(ps.conn, mutation)
	if err != nil {
		console.Error("Failed to update user: " + err.Error())
		return &ResetPassphraseResponse{
			Success: false,
			Error:   "Failed to update user",
		}, nil
	}

	return &ResetPassphraseResponse{
		Success: true,
	}, nil
}

// UpdateUserDetails updates a user's profile information such as name and marketing consent
func (ps *PassphraseService) UpdateUserDetails(req *UserDetailsRequest) (*UserDetailsResponse, error) {
	// Get email from cookie
	otpData, err := ps.otpService.decryptOTPData(req.Cookie)
	if err != nil {
		console.Error("Failed to decrypt cookie: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Invalid cookie",
		}, nil
	}
	
	email := otpData.Email
	console.Debug(fmt.Sprintf("Updating user details for email: %s", email))
	
	if email == "" {
		return &UserDetailsResponse{
			Success: false,
			Error:   "Email is required. Provide it via cookie.",
		}, nil
	}
	
	// Encrypt the email for lookup
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
	if err != nil {
		console.Error("Failed to encrypt email: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Failed to process email",
		}, nil
	}
	
	// Check if user exists using encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			did
			email
			name
			marketingConsent
		}
	}`, strings.Replace(encryptedEmail, `"`, `\"`, -1))
	
	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Database error while searching for user",
		}, nil
	}
	
	var result struct {
		User []struct {
			Uid              string `json:"uid"`
			Did              string `json:"did"`
			Email            string `json:"email"`
			Name             string `json:"name"`
			MarketingConsent bool   `json:"marketingConsent"`
		} `json:"user"`
	}
	
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal user query result: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Failed to process database response",
		}, nil
	}
	
	// Check if user exists
	if len(result.User) == 0 {
		console.Error("User not found with email: " + email)
		return &UserDetailsResponse{
			Success: false,
			Error:   "User not found",
		}, nil
	}
	
	user := result.User[0]
	
	// Build mutation for user details
	// Only include fields that are provided in the request
	var nquads []string
	
	// Update name if provided
	if req.Name != "" {
		nquads = append(nquads, fmt.Sprintf(`<%s> <name> "%s" .`, 
			dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(req.Name)))
	}
	
	// Update marketing consent if provided
	if req.MarketingConsent != nil {
		nquads = append(nquads, fmt.Sprintf(`<%s> <marketingConsent> "%t" .`, 
			dgraph.EscapeRDF(user.Uid), *req.MarketingConsent))
	}
	
	// Add updatedAt timestamp
	now := time.Now().UTC().Format(time.RFC3339)
	nquads = append(nquads, fmt.Sprintf(`<%s> <updatedAt> "%s" .`, 
		dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))
	
	// Create and execute mutation
	mutation := dgraph.NewMutation().WithSetNquads(strings.Join(nquads, "\n"))
	_, err = dgraph.ExecuteMutations(ps.conn, mutation)
	if err != nil {
		console.Error("Failed to update user details: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Failed to update user details",
		}, nil
	}
	
	console.Info(fmt.Sprintf("Updated user details for user %s", user.Uid))
	return &UserDetailsResponse{
		Success: true,
		Uid:     user.Uid,
	}, nil
}

// RegisterUserDetails updates user details during initial registration
// This uses the email verification cookie to identify the user
func (ps *PassphraseService) RegisterUserDetails(req *RegisterUserDetailsRequest) (*UserDetailsResponse, error) {
	console.Debug("Processing RegisterUserDetails request")

	// Verify the cookie to get the email
	verificationInfo, err := ps.otpService.CheckVerificationCookie("", req.VerificationCookie)
	if err != nil {
		console.Error("Failed to verify cookie: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Invalid or expired verification",
		}, nil
	}

	email := verificationInfo.Email
	if email == "" {
		console.Error("No email found in verification cookie")
		return &UserDetailsResponse{
			Success: false,
			Error:   "Invalid verification data",
		}, nil
	}

	// Ensure the verification is fresh (within 5 minutes)
	if time.Since(verificationInfo.VerifiedAt) > 5*time.Minute {
		console.Error("Email verification has expired")
		return &UserDetailsResponse{
			Success: false,
			Error:   "Email verification has expired",
		}, nil
	}
	
	var encryptedEmail string
	var searchEmail string // Email to use for database search
	
	// Check if we have email encryption enabled
	if ps.emailEncryption != nil {
		// Encrypt the email for storage and searching
		encryptedEmail, err = ps.emailEncryption.EncryptEmail(email)
		if err != nil {
			console.Error("Failed to encrypt email: " + err.Error())
			return &UserDetailsResponse{
				Success: false,
				Error:   "Failed to process user data",
			}, nil
		}
		searchEmail = encryptedEmail // Use encrypted email for search when encryption is available
	} else {
		// If no encryption, use the plaintext email for searching
		// The OTP verification process stored the email in plaintext
		searchEmail = email
	}
	
	// Query the user by email (encrypted or plaintext based on availability of encryption)
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			did
			email
			name
			marketingConsent
		}
	}`, strings.Replace(searchEmail, `"`, `\"`, -1))
	
	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Database error while searching for user",
		}, nil
	}
	
	var result struct {
		User []struct {
			Uid              string `json:"uid"`
			Did              string `json:"did"`
			Email            string `json:"email"`
			Name             string `json:"name"`
			MarketingConsent bool   `json:"marketingConsent"`
		} `json:"user"`
	}
	
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal user query result: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Failed to process database response",
		}, nil
	}
	
	// Check if user exists
	if len(result.User) == 0 {
		console.Error("User not found with email: " + email)
		return &UserDetailsResponse{
			Success: false,
			Error:   "User not found",
		}, nil
	}
	
	user := result.User[0]
	
	// Build mutation for user details
	var nquads []string
	
	// Update name if provided
	if req.Name != "" {
		nquads = append(nquads, fmt.Sprintf(`<%s> <name> "%s" .`, 
			dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(req.Name)))
	}
	
	// Update marketing consent if provided
	if req.MarketingConsent != nil {
		nquads = append(nquads, fmt.Sprintf(`<%s> <marketingConsent> "%t" .`, 
			dgraph.EscapeRDF(user.Uid), *req.MarketingConsent))
	}
	
	// Add dateJoined field if not already set
	now := time.Now().UTC().Format(time.RFC3339)
	nquads = append(nquads, fmt.Sprintf(`<%s> <dateJoined> "%s" .`, 
		dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))
	
	// Update timestamp
	nquads = append(nquads, fmt.Sprintf(`<%s> <updatedAt> "%s" .`, 
		dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))
	
	// Create and execute mutation
	mutation := dgraph.NewMutation().WithSetNquads(strings.Join(nquads, "\n"))
	_, err = dgraph.ExecuteMutations(ps.conn, mutation)
	if err != nil {
		console.Error("Failed to update user details: " + err.Error())
		return &UserDetailsResponse{
			Success: false,
			Error:   "Failed to update user details",
		}, nil
	}
	
	// Registration successful, clear verification
	ps.otpService.ClearVerification(email)
	
	console.Info(fmt.Sprintf("Registered user details for user %s", user.Uid))
	return &UserDetailsResponse{
		Success: true,
		Uid:     user.Uid,
	}, nil
}
