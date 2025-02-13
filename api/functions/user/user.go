package user

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

type UserService struct {
	conn string
}

func NewUserService(conn string) *UserService {
	return &UserService{
		conn: conn,
	}
}

type UserTimestamps struct {
	DateJoined      time.Time `json:"dateJoined"`
	LastAuthTime    time.Time `json:"lastAuthTime"`
	DaysSinceJoined int      `json:"daysSinceJoined"`
	LastSeenStatus  string   `json:"lastSeenStatus"`
	IsActive        bool     `json:"isActive"`
}

type GetUserTimestampsInput struct {
	Email string `json:"email"`
}

// GetUserTimestamps retrieves the dateJoined and lastAuthTime for a user along with computed fields
func (s *UserService) GetUserTimestamps(ctx context.Context, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	now := time.Now()

	query := &dgraph.Query{
		Query: `query getUser($email: string, $now: string) {
			var(func: eq(email, $email), first: 1) {
				# Calculate days since joined using built-in math functions
				joined as math(since(dateJoined)/(24*60*60))
				
				# Determine last seen status
				lastSeen as math(since(lastAuthTime)/(60*60))
			}

			user(func: eq(email, $email), first: 1) {
				dateJoined
				lastAuthTime
				
				# Computed fields using DQL functions
				daysSinceJoined: val(joined)
				lastSeenStatus: cond(
					lt(val(lastSeen), 1), "Online",
					lt(val(lastSeen), 24), "Today",
					lt(val(lastSeen), 168), "This Week",
					"Away"
				)
				
				# Check if user is active (logged in within last 30 days)
				isActive: lt(since(lastAuthTime), 2592000)
				
				# Validate user exists
				userExists: uid
			}
		}`,
		Variables: map[string]string{
			"$email": req.Email,
			"$now":   now.Format(time.RFC3339),
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []struct {
			DateJoined      time.Time `json:"dateJoined"`
			LastAuthTime    time.Time `json:"lastAuthTime"`
			DaysSinceJoined float64   `json:"daysSinceJoined"`
			LastSeenStatus  string    `json:"lastSeenStatus"`
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
	return &UserTimestamps{
		DateJoined:      user.DateJoined,
		LastAuthTime:    user.LastAuthTime,
		DaysSinceJoined: int(user.DaysSinceJoined),
		LastSeenStatus:  user.LastSeenStatus,
		IsActive:        user.IsActive,
	}, nil
}

// @modus:function
func GetUserTimestamps(conn string, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	return NewUserService(conn).GetUserTimestamps(context.Background(), req)
}
