package audit

import (
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// AuditService handles audit logging
type AuditService struct {
	conn string
}

// NewAuditService creates a new audit service
func NewAuditService(conn string) *AuditService {
	return &AuditService{
		conn: conn,
	}
}

// AuditLogData represents audit log data to be recorded
type AuditLogData struct {
	Action         string                 `json:"action"`
	ActorID        string                 `json:"actorId"`
	ActorType      string                 `json:"actorType"`
	OperationType  string                 `json:"operationType"`
	ClientIP       string                 `json:"clientIp,omitempty"`
	UserAgent      string                 `json:"userAgent,omitempty"`
	SessionID      string                 `json:"sessionId,omitempty"`
	Success        bool                   `json:"success"`
	Details        string                 `json:"details,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	AuditTimestamp time.Time              `json:"auditTimestamp"`
}

// CreateAuditLog logs an audit event
func (s *AuditService) CreateAuditLog(data AuditLogData) error {
	// Create a new mutation for the audit log
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:audit <dgraph.type> "AuditLog" .
		_:audit <audit.action> "%s" .
		_:audit <audit.actorId> "%s" .
		_:audit <audit.actorType> "%s" .
		_:audit <audit.operationType> "%s" .
		_:audit <audit.success> "%t" .
		_:audit <audit.timestamp> "%s" .
	`, dgraph.EscapeRDF(data.Action),
		dgraph.EscapeRDF(data.ActorID),
		dgraph.EscapeRDF(data.ActorType),
		dgraph.EscapeRDF(data.OperationType),
		data.Success,
		dgraph.EscapeRDF(data.AuditTimestamp.UTC().Format(time.RFC3339))))

	// Add optional fields if present
	if data.ClientIP != "" {
		mutation.WithSetNquads(fmt.Sprintf(`
			_:audit <audit.clientIp> "%s" .
		`, dgraph.EscapeRDF(data.ClientIP)))
	}

	if data.UserAgent != "" {
		mutation.WithSetNquads(fmt.Sprintf(`
			_:audit <audit.userAgent> "%s" .
		`, dgraph.EscapeRDF(data.UserAgent)))
	}

	if data.SessionID != "" {
		mutation.WithSetNquads(fmt.Sprintf(`
			_:audit <audit.sessionId> "%s" .
		`, dgraph.EscapeRDF(data.SessionID)))
	}

	if data.Details != "" {
		mutation.WithSetNquads(fmt.Sprintf(`
			_:audit <audit.details> "%s" .
		`, dgraph.EscapeRDF(data.Details)))
	}

	console.Debug(fmt.Sprintf("Executing audit log mutation for action: %s", data.Action))

	// Execute the mutation
	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Audit log mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Audit log mutation response: %s", mutResp.Json))
		}
		return fmt.Errorf("failed to create audit log: %v", err)
	}

	return nil
}
