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
}

type GetUserTimestampsInput struct {
	Email string `json:"email"`
}

// @modus:function
func GetUserTimestamps(conn string, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	console.Info(fmt.Sprintf("Getting user timestamps for email: %s", req.Email))

	now := time.Now().UTC()
	thirtyDaysAgo := now.Add(-30 * 24 * time.Hour)

	vars := map[string]string{
		"$email": req.Email,
	}

	query := &dgraph.Query{
		Query: `query getUser($email: string) {
			user(func: eq(email, $email)) {
				dateJoined
				lastAuthTime
				userExists: uid
			}
		}`,
		Variables: vars,
	}

	service := NewUserService(conn)
	resp, err := dgraph.ExecuteQuery(service.conn, query)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to query user timestamps - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			DateJoined   time.Time `json:"dateJoined"`
			LastAuthTime time.Time `json:"lastAuthTime"`
			UserExists   string    `json:"userExists"`
		} `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Failed to parse user timestamps - email: %s, error: %v", req.Email, err))
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.User) == 0 || result.User[0].UserExists == "" {
		console.Error(fmt.Sprintf("User not found - email: %s", req.Email))
		return nil, fmt.Errorf("user not found")
	}

	user := result.User[0]

	// Calculate time differences in Go
	daysSinceJoined := int(now.Sub(user.DateJoined).Hours() / 24)
	
	// Determine if user is active (logged in within last 30 days)
	isActive := !user.LastAuthTime.IsZero() && user.LastAuthTime.After(thirtyDaysAgo)

	// Calculate last seen status
	hoursSinceAuth := now.Sub(user.LastAuthTime).Hours()
	var lastSeenStatus string
	switch {
	case hoursSinceAuth < 1:
		lastSeenStatus = "Online"
	case hoursSinceAuth < 24:
		lastSeenStatus = "Today"
	case hoursSinceAuth < 168:
		lastSeenStatus = "This Week"
	default:
		lastSeenStatus = "Inactive"
	}

	timestamps := &UserTimestamps{
		DateJoined:      user.DateJoined,
		LastAuthTime:    user.LastAuthTime,
		DaysSinceJoined: daysSinceJoined,
		LastSeenStatus:  lastSeenStatus,
		IsActive:        isActive,
	}

	console.Info(fmt.Sprintf("User timestamps retrieved - email: %s, joined: %v, lastAuth: %v, status: %s, days: %d", 
		req.Email,
		timestamps.DateJoined.Format(time.RFC3339),
		timestamps.LastAuthTime.Format(time.RFC3339),
		timestamps.LastSeenStatus,
		timestamps.DaysSinceJoined))

	return timestamps, nil
}
