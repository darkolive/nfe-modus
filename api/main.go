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