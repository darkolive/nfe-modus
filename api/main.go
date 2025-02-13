package main

import (
	"context"
	"log"
	"math/rand"
	"os"
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

	// Read and apply schema from file
	schemaBytes, err := os.ReadFile("/Users/darrenknipe/Hypermode/nfe-modus/schema.dgraph")
	if err != nil {
		log.Printf("Failed to read schema file: %v", err)
		return
	}

	if err := dgraph.AlterSchema(connection, string(schemaBytes)); err != nil {
		log.Printf("Failed to update schema: %v", err)
	}
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
	userService := user.NewUserService(connection)
	return userService.GetUserTimestamps(context.Background(), req)
}