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

	// First migrate existing users to have status field using their createdDate
	migration := &dgraph.Mutation{
		SetNquads: `
			upsert {
				query {
					var(func: type(User)) @filter(not has(status)) {
						u as uid
						c as createdDate
					}
				}
				mutation {
					set {
						uid(u) <status> "active" .
						uid(u) <dateJoined> val(c) .
					}
				}
			}
		`,
	}

	if _, err := dgraph.ExecuteMutations(connection, migration); err != nil {
		log.Printf("Failed to migrate users: %v", err)
	}

	// Drop operations for old schema
	dropOps := []string{
		"drop attr: createdDate .",
		"drop attr: isActive .",
	}

	for _, op := range dropOps {
		if err := dgraph.AlterSchema(connection, op); err != nil {
			log.Printf("Failed to execute drop operation %s: %v", op, err)
		}
	}

	// Update schema with new fields
	newSchema := []string{
		"status: string @index(exact) .",
		"dateJoined: datetime @index(hour) .",
	}

	for _, s := range newSchema {
		if err := dgraph.AlterSchema(connection, s); err != nil {
			log.Printf("Failed to add new schema %s: %v", s, err)
		}
	}

	// Update User type
	typeSchema := `
		type User {
			email
			otp
			otpCreatedAt
			failedAttempts
			verified
			sessionToken
			sessionExpiry
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