package user

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

type UserService struct {
	conn string
}

func NewUserService(conn string) *UserService {
	return &UserService{conn: conn}
}

type UserTimestamps struct {
	DateJoined      time.Time `json:"dateJoined"`
	LastAuthTime    time.Time `json:"lastAuthTime"`
	DaysSinceJoined int       `json:"daysSinceJoined"`
	LastSeenStatus  string    `json:"lastSeenStatus"`
	IsActive        bool      `json:"isActive"`
	FailedAttempts  int       `json:"failedAttempts"`
	LastOTPTime     time.Time `json:"lastOTPTime"`
}

type GetUserTimestampsInput struct {
	Email string `json:"email"`
}

// @modus:function
func GetUserTimestamps(conn string, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	console.Info(fmt.Sprintf("Getting user timestamps for email: %s", req.Email))

	vars := map[string]string{
		"$email": req.Email,
	}

	query := &dgraph.Query{
		Query: `query getUser($email: string) {
			var(func: eq(email, $email)) {
				dj as dateJoined
				la as lastAuthTime
				
				# Calculate days since joined
				daysSinceJoined as math(since(dj)/(24*60*60))
				
				# Calculate hours since last auth
				hoursSinceAuth as math(since(la)/(60*60))

				# Calculate if user is active (logged in within last 30 days)
				isActive as math(since(la) < 2592000)
			}

			user(func: eq(email, $email)) {
				dateJoined
				lastAuthTime
				daysSinceJoined: val(daysSinceJoined)
				hoursSinceAuth: val(hoursSinceAuth)
				isActive: val(isActive)
				
				# Validate user exists
				userExists: uid
			}
		}`,
		Variables: vars,
	}

	service := NewUserService(conn)
	resp, err := dgraph.ExecuteQuery(service.conn, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			DateJoined      time.Time `json:"dateJoined"`
			LastAuthTime    time.Time `json:"lastAuthTime"`
			DaysSinceJoined float64   `json:"daysSinceJoined"`
			HoursSinceAuth  float64   `json:"hoursSinceAuth"`
			IsActive        bool      `json:"isActive"`
			UserExists      string    `json:"userExists"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 || result.User[0].UserExists == "" {
		return nil, fmt.Errorf("user not found")
	}

	user := result.User[0]

	// Determine last seen status based on hours since last auth
	var lastSeenStatus string
	switch {
	case user.HoursSinceAuth < 1:
		lastSeenStatus = "Online"
	case user.HoursSinceAuth < 24:
		lastSeenStatus = "Today"
	case user.HoursSinceAuth < 168:
		lastSeenStatus = "This Week"
	default:
		lastSeenStatus = "Away"
	}

	timestamps := &UserTimestamps{
		DateJoined:      user.DateJoined,
		LastAuthTime:    user.LastAuthTime,
		DaysSinceJoined: int(user.DaysSinceJoined),
		LastSeenStatus:  lastSeenStatus,
		IsActive:        user.IsActive,
	}

	console.Info(fmt.Sprintf("User timestamps retrieved - email: %s, joined: %v, lastAuth: %v, status: %s, days: %d",
		req.Email, timestamps.DateJoined, timestamps.LastAuthTime, timestamps.LastSeenStatus, timestamps.DaysSinceJoined))

	return timestamps, nil
}
