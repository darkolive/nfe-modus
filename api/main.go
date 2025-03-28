package main

import (
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	
	"nfe-modus/api/functions/auth"
	"nfe-modus/api/functions/auth/jwt"
	"nfe-modus/api/functions/email"
	"nfe-modus/api/functions/user"
	"fmt"
)

var (
	connection = "my-dgraph"
)

func main() {
	console.Info("Initializing WebAssembly module")
	console.Debug("Running API server")
}

// @modus:function
func GenerateOTP(req *auth.GenerateOTPRequest) (*auth.GenerateOTPResponse, error) {
	console.Debug("Processing Generate OTP request")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.GenerateOTP(req)
}

// @modus:function
func VerifyOTP(req *auth.VerifyOTPRequest) (*auth.VerifyOTPResponse, error) {
	console.Debug("Processing Verify OTP request")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.VerifyOTP(req)
}

// @modus:function
func GetUserTimestamps(req *user.GetUserTimestampsInput) (*user.UserTimestamps, error) {
	return user.GetUserTimestamps(connection, req)
}

// @modus:mutation
func RegisterWebAuthn(req *auth.RegisterWebAuthnRequest) (*auth.RegisterWebAuthnResponse, error) {
	console.Debug("Processing WebAuthn registration")
	
	// Validate recovery passphrase if provided
	if req.RecoveryPassphrase == "" {
		console.Debug("Recovery passphrase is required for WebAuthn registration")
		return &auth.RegisterWebAuthnResponse{
			Success: false,
			Error:   "Recovery passphrase is required as a backup authentication method",
		}, nil
	}
	
	// Create JWT service with required parameters
	jwtService := jwt.NewJWTService("your-secret-key", "nfe-modus", 24)
	
	// Create OTP service to verify the email cookie
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	
	// Try to get email from verification cookie if email not directly provided
	if req.Email == "" && req.VerificationCookie != "" {
		email, verifiedAt, verified := otpService.GetVerifiedEmail(req.VerificationCookie)
		if !verified {
			console.Error("Email verification required before WebAuthn registration")
			return &auth.RegisterWebAuthnResponse{
				Success: false,
				Error:   "Email verification required before WebAuthn registration",
			}, nil
		}
		
		// Check if verification is recent (within last 5 minutes)
		if time.Since(verifiedAt) > 5*time.Minute {
			console.Error("Email verification has expired, please verify your email again")
			return &auth.RegisterWebAuthnResponse{
				Success: false,
				Error:   "Email verification has expired, please verify your email again",
			}, nil
		}
		
		// Update the request with the verified email
		req.Email = email
		console.Debug(fmt.Sprintf("Using verified email from OTP cookie: %s", email))
	}
	
	// Validate email is present after potential cookie extraction
	if req.Email == "" {
		console.Debug("Email is required for WebAuthn registration")
		return &auth.RegisterWebAuthnResponse{
			Success: false,
			Error:   "Email is required",
		}, nil
	}
	
	// Create WebAuthn service
	webAuthnService, err := auth.NewWebAuthnService(connection, jwtService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to create WebAuthn service: %v", err))
		return &auth.RegisterWebAuthnResponse{
			Success: false,
			Error:   "Internal server error",
		}, err
	}
	
	// Create services for storing recovery passphrase
	roleService := auth.NewRoleService(connection)
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	// Initialize passphrase service for future recovery passphrase storage
	// Note: We're not using this service yet, but will in a future implementation
	// to properly store the recovery passphrase
	_, passphraseErr := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if passphraseErr != nil {
		console.Error(fmt.Sprintf("Warning: Failed to initialize passphrase service: %v", passphraseErr))
		// Continue despite this error, as we're not using the service yet
	}
	
	// TODO: In a future implementation, we will:
	// 1. Hash and store the recovery passphrase
	// 2. Associate it with the user account
	// 3. Implement recovery flows for WebAuthn authenticators
	
	// Proceed with WebAuthn registration
	return webAuthnService.RegisterWebAuthn(req)
}

// @modus:function
func VerifyWebAuthn(req *auth.VerifyWebAuthnRegistrationRequest) (*auth.VerifyWebAuthnRegistrationResponse, error) {
	console.Debug("Processing WebAuthn verification")
	
	// Create JWT service with required parameters
	jwtService := jwt.NewJWTService("your-secret-key", "nfe-modus", 24)
	
	// Create WebAuthn service
	webAuthnService, err := auth.NewWebAuthnService(connection, jwtService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to create WebAuthn service: %v", err))
		return &auth.VerifyWebAuthnRegistrationResponse{
			Success: false,
			Error:   "Internal server error",
		}, err
	}
	
	// If email is not provided directly but we have a verification cookie
	if req.Email == "" {
		console.Debug("Email is required for WebAuthn verification")
		return &auth.VerifyWebAuthnRegistrationResponse{
			Success: false,
			Error:   "Email is required",
		}, nil
	}
	
	// Proceed with WebAuthn verification
	return webAuthnService.VerifyWebAuthn(req)
}

// @modus:function
func SignInWebAuthn(req *auth.SignInWebAuthnRequest) (*auth.SignInWebAuthnResponse, error) {
	console.Debug("Processing WebAuthn sign-in")
	
	// Create JWT service with required parameters
	jwtService := jwt.NewJWTService("your-secret-key", "nfe-modus", 24)
	
	// Create WebAuthn service
	webAuthnService, err := auth.NewWebAuthnService(connection, jwtService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to create WebAuthn service: %v", err))
		return &auth.SignInWebAuthnResponse{
			Success: false,
			Error:   "Internal server error",
		}, err
	}
	
	return webAuthnService.SignInWebAuthn(req)
}

// @modus:function
func VerifySignInWebAuthn(req *auth.VerifyWebAuthnSignInRequest) (*auth.VerifyWebAuthnSignInResponse, error) {
	console.Debug("Processing WebAuthn sign-in verification")
	
	// Create JWT service with required parameters
	jwtService := jwt.NewJWTService("your-secret-key", "nfe-modus", 24)
	
	// Create WebAuthn service
	webAuthnService, err := auth.NewWebAuthnService(connection, jwtService)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to create WebAuthn service: %v", err))
		return &auth.VerifyWebAuthnSignInResponse{
			Success: false,
			Error:   "Internal server error",
		}, err
	}
	
	return webAuthnService.VerifySignInWebAuthn(req)
}

// @modus:function
func RegisterPassphrase(req *auth.RegisterPassphraseRequest) (*auth.RegisterPassphraseResponse, error) {
	console.Debug("Processing Register Passphrase request - using verification cookie for email retrieval")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the new fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.RegisterPassphraseResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.RegisterPassphrase(req)
}

// @modus:function
func SigninPassphrase(req *auth.SigninPassphraseRequest) (*auth.SigninPassphraseResponse, error) {
	console.Debug("Processing Signin Passphrase request - using cookie for email retrieval")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.SigninPassphraseResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.SigninPassphrase(req)
}

// @modus:function
func RecoveryPassphrase(req *auth.RecoveryPassphraseRequest) (*auth.RecoveryPassphraseResponse, error) {
	console.Debug("Processing Recovery Passphrase request - using cookie for email retrieval")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.RecoveryPassphraseResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.RecoveryPassphrase(req)
}

// @modus:function
func ResetPassphrase(req *auth.ResetPassphraseRequest) (*auth.ResetPassphraseResponse, error) {
	console.Debug("Processing Reset Passphrase request - using reset token for password reset")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.ResetPassphraseResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.ResetPassphrase(req)
}

// @modus:function
func UpdateUserDetails(req *auth.UserDetailsRequest) (*auth.UserDetailsResponse, error) {
	console.Debug("Processing Update User Details request - using cookie for email retrieval")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.UserDetailsResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.UpdateUserDetails(req)
}

// @modus:function
func RegisterUserDetails(req *auth.RegisterUserDetailsRequest) (*auth.UserDetailsResponse, error) {
	console.Debug("Processing Register User Details request")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	roleService := auth.NewRoleService(connection)
	
	// Use the fallback encryption that won't fail if the environment variable is missing
	emailEncryption := auth.NewEmailEncryptionWithFallback()
	
	passphraseService, err := auth.NewPassphraseService(connection, otpService, roleService, emailEncryption, emailService)
	if err != nil {
		console.Error("Failed to initialize passphrase service: " + err.Error())
		return &auth.UserDetailsResponse{
			Success: false,
			Error:   "Internal server error initializing passphrase service",
		}, err
	}
	
	return passphraseService.RegisterUserDetails(req)
}

// getUserTimestamps retrieves user timestamps for analytics and activity tracking
// Note: Currently unused but retained for future reporting functionality
func getUserTimestamps(email string) (*dgraph.Query, error) {
	vars := map[string]string{
		"$email": email,
		"$now":   time.Now().UTC().Format(time.RFC3339),
	}

	q := &dgraph.Query{
		Query: `query getUser($email: string, $now: string) {
			var(func: eq(email, $email), first: 1) {
				# Calculate days since joined
				joined as math(since(dateJoined)/(24*60*60))
				
				# Calculate hours since last auth
				hoursSinceAuth as math(since(lastAuthTime)/(60*60))
			}

			user(func: eq(email, $email), first: 1) {
				dateJoined
				lastAuthTime
				daysSinceJoined: val(joined)
				hoursSinceAuth: val(hoursSinceAuth)
				
				# Check if user is active (logged in within last 30 days)
				isActive: lt(since(lastAuthTime), 2592000)
				
				# Validate user exists
				userExists: uid
			}
		}`,
		Variables: vars,
	}

	return q, nil
}