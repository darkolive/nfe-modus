package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// AuditLogData represents audit log data according to ISO standards
type AuditLogData struct {
	Action              string    `json:"action"`
	ActorID             string    `json:"actorId"`
	ActorType           string    `json:"actorType"`
	ResourceID          string    `json:"resourceId,omitempty"`
	ResourceType        string    `json:"resourceType,omitempty"`
	OperationType       string    `json:"operationType"`
	RequestPath         string    `json:"requestPath,omitempty"`
	RequestMethod       string    `json:"requestMethod,omitempty"`
	RequestParams       string    `json:"requestParams,omitempty"`
	ResponseStatus      int       `json:"responseStatus,omitempty"`
	ClientIP            string    `json:"clientIp"`
	AuditTimestamp      time.Time `json:"auditTimestamp"`
	SessionID           string    `json:"sessionId,omitempty"`
	UserAgent           string    `json:"userAgent"`
	Success             bool      `json:"success"`
	SensitiveOperation  bool      `json:"sensitiveOperation,omitempty"`
	ComplianceFlags     []string  `json:"complianceFlags,omitempty"`
	Details             string    `json:"details,omitempty"`
}

// AuditService provides audit logging functionality
type AuditService struct {
	conn string
}

// NewAuditService creates a new audit service
func NewAuditService(conn string) *AuditService {
	return &AuditService{conn: conn}
}

// CreateAuditLog creates a new audit log entry that conforms to ISO standard
func (s *AuditService) CreateAuditLog(log AuditLogData) error {
	// Ensure timestamp is set
	if log.AuditTimestamp.IsZero() {
		log.AuditTimestamp = time.Now().UTC()
	}

	// Sanitize potential sensitive data in details
	// Mask any emails with ***
	// This is a simple example; more sophisticated masking might be needed
	// sanitizedDetails := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`).
	//    ReplaceAllString(log.Details, "***@***")
	// log.Details = sanitizedDetails

	// Create the mutation using Dgraph's preferred method with nquads
	nquads := []string{
		fmt.Sprintf(`_:log <action> %q .`, log.Action),
		fmt.Sprintf(`_:log <actorId> %q .`, log.ActorID),
		fmt.Sprintf(`_:log <actorType> %q .`, log.ActorType),
		fmt.Sprintf(`_:log <operationType> %q .`, log.OperationType),
		fmt.Sprintf(`_:log <clientIp> %q .`, log.ClientIP),
		fmt.Sprintf(`_:log <auditTimestamp> %q .`, log.AuditTimestamp.Format(time.RFC3339)),
		fmt.Sprintf(`_:log <userAgent> %q .`, log.UserAgent),
		fmt.Sprintf(`_:log <success> %q .`, fmt.Sprintf("%t", log.Success)),
	}

	// Add optional fields if they are provided
	if log.ResourceID != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <resourceId> %q .`, log.ResourceID))
	}

	if log.ResourceType != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <resourceType> %q .`, log.ResourceType))
	}

	if log.RequestPath != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <requestPath> %q .`, log.RequestPath))
	}

	if log.RequestMethod != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <requestMethod> %q .`, log.RequestMethod))
	}

	if log.RequestParams != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <requestParams> %q .`, log.RequestParams))
	}

	if log.ResponseStatus != 0 {
		nquads = append(nquads, fmt.Sprintf(`_:log <responseStatus> %q .`, fmt.Sprintf("%d", log.ResponseStatus)))
	}

	if log.SessionID != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <sessionId> %q .`, log.SessionID))
	}

	if log.SensitiveOperation {
		nquads = append(nquads, fmt.Sprintf(`_:log <sensitiveOperation> %q .`, "true"))
	}

	if len(log.ComplianceFlags) > 0 {
		complianceFlagsJSON, err := json.Marshal(log.ComplianceFlags)
		if err == nil {
			nquads = append(nquads, fmt.Sprintf(`_:log <complianceFlags> %q .`, string(complianceFlagsJSON)))
		}
	}

	if log.Details != "" {
		nquads = append(nquads, fmt.Sprintf(`_:log <details> %q .`, log.Details))
	}

	// Add type information
	nquads = append(nquads, `_:log <dgraph.type> "AuditLog" .`)

	// Join all nquads
	nquadsStr := strings.Join(nquads, "\n")

	// Create and execute the mutation
	mutation := dgraph.NewMutation().WithSetNquads(nquadsStr)

	// Execute the mutation
	_, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to create audit log: %v", err))
		return fmt.Errorf("failed to create audit log: %v", err)
	}

	console.Debug(fmt.Sprintf("Audit log created successfully: %s", log.Action))
	return nil
}

// GetAuditLogs retrieves audit logs with various filter options
func (s *AuditService) GetAuditLogs(filters map[string]interface{}, limit int) ([]AuditLogData, error) {
	// Build query filters
	filterClauses := []string{}

	for key, value := range filters {
		// Handle different value types
		switch v := value.(type) {
		case string:
			filterClauses = append(filterClauses, fmt.Sprintf("eq(%s, %q)", key, v))
		case int:
			filterClauses = append(filterClauses, fmt.Sprintf("eq(%s, %d)", key, v))
		case bool:
			filterClauses = append(filterClauses, fmt.Sprintf("eq(%s, %t)", key, v))
		}
	}

	// Combine filters with AND
	var filterClause string
	if len(filterClauses) > 0 {
		filterClause = fmt.Sprintf("@filter(%s)", strings.Join(filterClauses, " AND "))
	}

	query := fmt.Sprintf(`
		query {
			logs(func: type(AuditLog), orderdesc: auditTimestamp, first: %d) %s {
				uid
				action
				actorId
				actorType
				resourceId
				resourceType
				operationType
				requestPath
				requestMethod
				requestParams
				responseStatus
				clientIp
				auditTimestamp
				sessionId
				userAgent
				success
				sensitiveOperation
				complianceFlags
				details
			}
		}
	`, limit, filterClause)

	resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error(fmt.Sprintf("Failed to query audit logs: %v", err))
		return nil, fmt.Errorf("failed to query audit logs: %v", err)
	}

	var result struct {
		Logs []AuditLogData `json:"logs"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Failed to unmarshal audit logs: %v", err))
		return nil, fmt.Errorf("failed to unmarshal audit logs: %v", err)
	}

	return result.Logs, nil
}
