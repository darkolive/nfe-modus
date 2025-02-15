package auth

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
    "nfe-modus/api/functions/user"
)

type AuthAttemptService struct {
    conn string
}

func NewAuthAttemptService(conn string) *AuthAttemptService {
    return &AuthAttemptService{conn: conn}
}

// CreateAuthAttempt creates a new authentication attempt for a user
func (s *AuthAttemptService) CreateAuthAttempt(userHash string, otp string) (*user.AuthenticationAttempt, error) {
    attempt := &user.AuthenticationAttempt{
        UserHash:          userHash,
        OTP:              otp,
        OTPCreatedAt:     time.Now().UTC(),
        FailedAttempts:   0,
        VerificationStatus: "PENDING",
    }

    mutation := fmt.Sprintf(`
        mutation {
            set {
                _:attempt <userHash> %q .
                _:attempt <otp> %q .
                _:attempt <otpCreatedAt> %q .
                _:attempt <failedAttempts> "0" .
                _:attempt <verificationStatus> %q .
                _:attempt <dgraph.type> "AuthenticationAttempt" .
            }
        }
    `, attempt.UserHash, attempt.OTP, attempt.OTPCreatedAt.Format(time.RFC3339), attempt.VerificationStatus)

    _, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: mutation,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create auth attempt: %v", err)
    }

    return attempt, nil
}

// GetLatestAttempt retrieves the latest authentication attempt for a user
func (s *AuthAttemptService) GetLatestAttempt(userHash string) (*user.AuthenticationAttempt, error) {
    query := fmt.Sprintf(`
        query {
            attempt(func: eq(userHash, %q), orderdesc: otpCreatedAt, first: 1) {
                uid
                userHash
                otp
                otpCreatedAt
                failedAttempts
                verificationStatus
            }
        }
    `, userHash)

    resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: query,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to query auth attempt: %v", err)
    }

    var result struct {
        Attempts []user.AuthenticationAttempt `json:"attempt"`
    }
    if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %v", err)
    }

    if len(result.Attempts) == 0 {
        return nil, fmt.Errorf("no authentication attempts found")
    }

    return &result.Attempts[0], nil
}

// UpdateAttemptStatus updates the status of an authentication attempt
func (s *AuthAttemptService) UpdateAttemptStatus(uid string, status string) error {
    mutation := fmt.Sprintf(`
        mutation {
            set {
                <%s> <verificationStatus> %q .
            }
        }
    `, uid, status)

    _, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: mutation,
    })
    if err != nil {
        return fmt.Errorf("failed to update attempt status: %v", err)
    }

    return nil
}

// IncrementFailedAttempts increments the failed attempts counter for an authentication attempt
func (s *AuthAttemptService) IncrementFailedAttempts(uid string) error {
    mutation := fmt.Sprintf(`
        mutation {
            set {
                var(func: uid(%s)) {
                    fa as failedAttempts
                }
                uid(%s) {
                    failedAttempts val(fa + 1) .
                }
            }
        }
    `, uid, uid)

    _, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: mutation,
    })
    if err != nil {
        return fmt.Errorf("failed to increment failed attempts: %v", err)
    }

    return nil
}
