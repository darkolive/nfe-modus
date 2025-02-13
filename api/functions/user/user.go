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
	DateJoined   time.Time `json:"dateJoined"`
	LastAuthTime time.Time `json:"lastAuthTime"`
}

type GetUserTimestampsInput struct {
	Email string `json:"email"`
}

// GetUserTimestamps retrieves the dateJoined and lastAuthTime for a user
func (s *UserService) GetUserTimestamps(ctx context.Context, req *GetUserTimestampsInput) (*UserTimestamps, error) {
	query := &dgraph.Query{
		Query: `query getUser($email: string) {
			user(func: eq(email, $email), first: 1) {
				dateJoined
				lastAuthTime
			}
		}`,
		Variables: map[string]string{
			"$email": req.Email,
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}

	var result struct {
		User []UserTimestamps `json:"user"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if len(result.User) == 0 {
		return nil, fmt.Errorf("user not found: %s", req.Email)
	}

	return &result.User[0], nil
}

var userService *UserService

func init() {
	userService = NewUserService("my-dgraph")
}

// @modus:function
func GetUserTimestamps(req *GetUserTimestampsInput) (*UserTimestamps, error) {
	return userService.GetUserTimestamps(context.Background(), req)
}
