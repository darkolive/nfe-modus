package main

import (
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	"nfe-modus/api/functions/auth"
	"nfe-modus/api/functions/email"
	"nfe-modus/api/functions/user"
)

var (
	connection = "my-dgraph"
)

func main() {
	console.Info("Initializing WebAssembly module")
	// WebAssembly initialization code here
}

// @modus:function
func GenerateOTP(req *auth.GenerateOTPRequest) (*auth.GenerateOTPResponse, error) {
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.GenerateOTP(req)
}

// @modus:function
func VerifyOTP(req *auth.VerifyOTPRequest) (*auth.VerifyOTPResponse, error) {
	console.Debug("Processing OTP verification - email may be provided in request or extracted from cookie")
	emailService := email.NewService(connection)
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.VerifyOTP(req)
}

// @modus:function
func GetUserTimestamps(req *user.GetUserTimestampsInput) (*user.UserTimestamps, error) {
	return user.GetUserTimestamps(connection, req)
}

// @modus:mutation
func RegisterWebAuthn(req *auth.WebAuthnRegistrationRequest) (*auth.WebAuthnRegistrationResponse, error) {
	console.Debug("Processing WebAuthn registration")
	webAuthnService := auth.NewWebAuthnService(connection)
	return webAuthnService.RegisterWebAuthn(req)
}

// @modus:function
func VerifyWebAuthn(req *auth.WebAuthnVerificationRequest) (*auth.WebAuthnVerificationResponse, error) {
	console.Debug("Processing WebAuthn verification")
	webAuthnService := auth.NewWebAuthnService(connection)
	return webAuthnService.VerifyWebAuthn(req)
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
	console.Debug("Processing Reset Passphrase request - using verification cookie for email retrieval")
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