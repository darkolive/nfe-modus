package logging

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
    "nfe-modus/api/functions/auth/dgraph"
)

// AuditLogger handles audit logging to DGraph
type AuditLogger struct {
    conn string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(conn string) *AuditLogger {
    return &AuditLogger{conn: conn}
}

// LogEvent logs an audit event
func (l *AuditLogger) LogEvent(ctx context.Context, event AuditEvent) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    event.Timestamp = t.Format(time.RFC3339)

    mutation := map[string]interface{}{
        "set": []interface{}{event},
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    txn, err := dgraph.NewTransaction(l.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    if err := txn.Mutate(ctx, string(mutationJSON)); err != nil {
        console.Error("Failed to log audit event: " + err.Error())
        return fmt.Errorf("failed to log audit event: %v", err)
    }

    return nil
}

// QueryAuditTrail retrieves audit events for a user
func (l *AuditLogger) QueryAuditTrail(ctx context.Context, userHash string) ([]AuditEvent, error) {
    query := fmt.Sprintf(`{
        audit(func: eq(userHash, "%s")) {
            eventType
            timestamp
            details
            metadata
        }
    }`, userHash)

    txn, err := dgraph.NewTransaction(l.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return nil, fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    resp, err := txn.Query(ctx, query)
    if err != nil {
        console.Error("Failed to query audit trail: " + err.Error())
        return nil, fmt.Errorf("failed to query audit trail: %v", err)
    }

    var result struct {
        Audit []AuditEvent `json:"audit"`
    }

    if err := json.Unmarshal(resp, &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    return result.Audit, nil
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
    Type      string                 `json:"eventType"`
    Timestamp string                 `json:"timestamp"`
    UserHash  string                 `json:"userHash"`
    Details   string                 `json:"details"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
