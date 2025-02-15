package audit

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
    "nfe-modus/api/functions/user"
)

type AuditService struct {
    conn string
}

func NewAuditService(conn string) *AuditService {
    return &AuditService{conn: conn}
}

// CreateAuditLog creates a new audit log entry
func (s *AuditService) CreateAuditLog(userHash string, eventType string, ipAddress, userAgent, details string) (*user.AuditLog, error) {
    log := &user.AuditLog{
        UserHash:  userHash,
        EventType: eventType,
        Timestamp: time.Now().UTC(),
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Details:   details,
    }

    mutation := fmt.Sprintf(`
        mutation {
            set {
                _:log <userHash> %q .
                _:log <eventType> %q .
                _:log <timestamp> %q .
                _:log <ipAddress> %q .
                _:log <userAgent> %q .
                _:log <details> %q .
                _:log <dgraph.type> "AuditLog" .
            }
        }
    `, log.UserHash, log.EventType, log.Timestamp.Format(time.RFC3339), log.IPAddress, log.UserAgent, log.Details)

    _, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: mutation,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create audit log: %v", err)
    }

    return log, nil
}

// GetUserAuditLogs retrieves audit logs for a specific user
func (s *AuditService) GetUserAuditLogs(userHash string, limit int) ([]user.AuditLog, error) {
    query := fmt.Sprintf(`
        query {
            logs(func: eq(userHash, %q), orderdesc: timestamp, first: %d) {
                uid
                userHash
                eventType
                timestamp
                ipAddress
                userAgent
                details
            }
        }
    `, userHash, limit)

    resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
        Query: query,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to query audit logs: %v", err)
    }

    var result struct {
        Logs []user.AuditLog `json:"logs"`
    }
    if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %v", err)
    }

    return result.Logs, nil
}
