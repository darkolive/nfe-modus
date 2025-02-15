package user

import (
	"crypto/sha256"
	"encoding/hex"
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




// hashEmail creates a secure hash of an email address
func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// CreateUser creates a new user with hashed email
func (s *UserService) CreateUser(email string) (*User, error) {
	hashedEmail := hashEmail(email)

	user := &User{
		HashedEmail:  hashedEmail,
		Status:      "UNVERIFIED",
		DateJoined:  time.Now().UTC(),
	}

	mutation := fmt.Sprintf(`
        mutation {
            set {
                _:user <hashedEmail> %q .
                _:user <status> %q .
                _:user <dateJoined> %q .
                _:user <dgraph.type> "User" .
            }
        }
    `, user.HashedEmail, user.Status, user.DateJoined.Format(time.RFC3339))

	_, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: mutation,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return user, nil
}

// UpdateUserStatus updates a user's status
func (s *UserService) UpdateUserStatus(userHash string, newStatus string) error {
	mutation := fmt.Sprintf(`
        mutation {
            set {
                uid(func: eq(hashedEmail, %q)) {
                    status as var(val(status))
                }
                uid(func: eq(hashedEmail, %q)) @filter(not(eq(val(status), %q))) {
                    status %q .
                }
            }
        }
    `, userHash, userHash, newStatus, newStatus)

	_, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: mutation,
	})
	if err != nil {
		return fmt.Errorf("failed to update user status: %v", err)
	}

	return nil
}

// GetUserTimestamps retrieves user timestamp information
func (s *UserService) GetUserTimestamps(email string) (*User, error) {
	hashedEmail := hashEmail(email)

	query := fmt.Sprintf(`
        query {
            user(func: eq(hashedEmail, %q)) {
                uid
                hashedEmail
                status
                dateJoined
                lastAuthTime
            }
        }
    `, hashedEmail)

	resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	var result struct {
		User []User `json:"user"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return &result.User[0], nil
}

// @modus:function
func GetUserTimestamps(conn string, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	console.Info(fmt.Sprintf("Getting user timestamps for email: %s", req.Email))
	hashedEmail := hashEmail(req.Email)

	query := fmt.Sprintf(`
        query {
            user(func: eq(hashedEmail, %q)) {
                dateJoined
                lastAuthTime
            }
        }
    `, hashedEmail)

	resp, err := dgraph.ExecuteQuery(conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []User `json:"user"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	user := result.User[0]

	// Determine last seen status based on hours since last auth
	var lastSeenStatus string
	switch {
	case user.LastAuthTime.After(time.Now().Add(-1 * time.Hour)):
		lastSeenStatus = "Online"
	case user.LastAuthTime.After(time.Now().Add(-24 * time.Hour)):
		lastSeenStatus = "Today"
	case user.LastAuthTime.After(time.Now().Add(-168 * time.Hour)):
		lastSeenStatus = "This Week"
	default:
		lastSeenStatus = "Away"
	}

	timestamps := &UserTimestamps{
		DateJoined:      user.DateJoined,
		LastAuthTime:    user.LastAuthTime,
		DaysSinceJoined: int(time.Since(user.DateJoined).Hours() / 24),
		LastSeenStatus:  lastSeenStatus,
		IsActive:        user.LastAuthTime.After(time.Now().Add(-30 * 24 * time.Hour)),
	}

	console.Info(fmt.Sprintf("User timestamps retrieved - email: %s, joined: %v, lastAuth: %v, status: %s, days: %d",
		req.Email, timestamps.DateJoined, timestamps.LastAuthTime, timestamps.LastSeenStatus, timestamps.DaysSinceJoined))

	return timestamps, nil
}
