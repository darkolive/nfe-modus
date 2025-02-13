package main

import (
	"log"
	"math/rand"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"

	"nfe-modus/api/functions/auth"
	"nfe-modus/api/functions/email"
	"nfe-modus/api/functions/user"
)

const (
	connection = "my-dgraph"
)

func init() {
	rand.Seed(time.Now().UnixNano())

	// Drop old attributes first
	dropSchema := `
		<sessionToken>: * .
		<sessionExpiry>: * .
	`
	if err := dgraph.AlterSchema(connection, dropSchema); err != nil {
		log.Printf("Failed to drop old attributes: %v", err)
	}

	// Update User type without session fields
	typeSchema := `
		<dateJoined>: datetime @index(hour) .
		<email>: string @index(exact) @upsert .
		<failedAttempts>: int @index(int) .
		<lastAuthTime>: datetime @index(hour) .
		<otp>: string .
		<otpCreatedAt>: datetime @index(hour) .
		<status>: string @index(exact) .
		<verified>: bool @index(bool) .

		type User {
			email
			otp
			otpCreatedAt
			failedAttempts
			verified
			lastAuthTime
			status
			dateJoined
		}
	`

	if err := dgraph.AlterSchema(connection, typeSchema); err != nil {
		log.Printf("Failed to update User type: %v", err)
	}
}

// @modus:function
func GenerateOTP(req *auth.GenerateOTPRequest) (*auth.GenerateOTPResponse, error) {
	emailService := email.NewService()
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.GenerateOTP(req)
}

// @modus:function
func VerifyOTP(req *auth.VerifyOTPRequest) (*auth.VerifyOTPResponse, error) {
	emailService := email.NewService()
	otpService := auth.NewOTPService(connection, emailService)
	return otpService.VerifyOTP(req)
}

// @modus:function
func GetUserTimestamps(req *user.GetUserTimestampsInput) (*user.UserTimestamps, error) {
	return user.GetUserTimestamps(req)
}