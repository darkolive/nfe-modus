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

	// Combine queries for better performance
	query := `query getUser($email: string) {
		user(func: eq(email, $email)) {
			uid
			dateJoined
			lastAuthTime
			failedAttempts
			lastOTPTime
		}
	}`

	vars := map[string]string{"$email": req.Email}
	resp, err := dgraph.ExecuteQuery(conn, &dgraph.Query{Query: query, Variables: vars})
	if err != nil {
		console.Error(fmt.Sprintf("Failed to get user timestamps - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to get user timestamps: %v", err)
	}

	var result struct {
		User []struct {
			UID           string    `json:"uid"`
			DateJoined   time.Time `json:"dateJoined"`
			LastAuthTime time.Time `json:"lastAuthTime"`
			FailedAttempts int     `json:"failedAttempts"`
			LastOTPTime time.Time  `json:"lastOTPTime"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Failed to unmarshal user data - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to unmarshal user data: %v", err)
	}

	if len(result.User) == 0 {
		console.Error(fmt.Sprintf("User not found - email: %s", req.Email))
		return nil, fmt.Errorf("user not found: %s", req.Email)
	}

	user := result.User[0]
	now := time.Now().UTC()
	daysSinceJoined := int(now.Sub(user.DateJoined).Hours() / 24)

	// Calculate user status with more precision
	var status string
	hoursSinceAuth := now.Sub(user.LastAuthTime).Hours()
	switch {
	case hoursSinceAuth < 0.25: // 15 minutes
		status = "Online"
	case hoursSinceAuth < 24:
		status = "Today"
	case hoursSinceAuth < 168: // 7 days
		status = "ThisWeek"
	default:
		status = "Offline"
	}

	// Log for security monitoring
	// auth.LogAuthAttempt(req.Email, "GetUserTimestamps", true, map[string]string{
	// 	"status": status,
	// 	"daysSinceJoined": fmt.Sprintf("%d", daysSinceJoined),
	// })

	// Check if active in last 30 days
	isActive := !user.LastAuthTime.IsZero() && user.LastAuthTime.After(now.AddDate(0, 0, -30))

	timestamps := &UserTimestamps{
		DateJoined:      user.DateJoined,
		LastAuthTime:    user.LastAuthTime,
		DaysSinceJoined: daysSinceJoined,
		LastSeenStatus:  status,
		IsActive:        isActive,
		FailedAttempts:  user.FailedAttempts,
		LastOTPTime:     user.LastOTPTime,
	}

	console.Info(fmt.Sprintf("User timestamps retrieved - email: %s, joined: %v, lastAuth: %v, status: %s, days: %d",
		req.Email, timestamps.DateJoined, timestamps.LastAuthTime, timestamps.LastSeenStatus, timestamps.DaysSinceJoined))

	return timestamps, nil
}
