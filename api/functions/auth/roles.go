package auth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// RoleService handles role operations like creating and assigning roles
type RoleService struct {
	conn string
}

// NewRoleService creates a new role service
func NewRoleService(conn string) *RoleService {
	return &RoleService{
		conn: conn,
	}
}

// Role represents a user role in the system
type Role struct {
	UID         string   `json:"uid,omitempty"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

// EnsureRolesExist checks if admin and registered roles exist, creates them if not
func (rs *RoleService) EnsureRolesExist() error {
	// Query existing roles
	query := `
	{
		roles(func: type(Role)) {
			uid
			name
			permissions
			createdAt
			updatedAt
		}
	}`

	console.Debug(fmt.Sprintf("Executing roles query: %s", query))
	resp, err := dgraph.ExecuteQuery(rs.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query roles: " + err.Error())
		return err
	}

	type QueryResult struct {
		Roles []Role `json:"roles"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal roles query result: " + err.Error())
		return err
	}

	// Check if admin role exists
	adminExists := false
	registeredExists := false

	for _, role := range result.Roles {
		if role.Name == "admin" {
			adminExists = true
		}
		if role.Name == "registered" {
			registeredExists = true
		}
	}

	// Get current time in UTC
	now := time.Now().UTC().Format(time.RFC3339)
	
	// Create admin role if it doesn't exist
	if !adminExists {
		adminMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			_:admin <dgraph.type> "Role" .
			_:admin <name> "admin" .
			_:admin <permissions> "admin:*" .
			_:admin <createdAt> "%s" .
			_:admin <updatedAt> "%s" .
		`, dgraph.EscapeRDF(now), dgraph.EscapeRDF(now)))

		console.Debug(fmt.Sprintf("Creating admin role: %s", adminMutation.SetNquads))
		_, err := dgraph.ExecuteMutations(rs.conn, adminMutation)
		if err != nil {
			console.Error("Failed to create admin role: " + err.Error())
			return err
		}
		console.Info("Successfully created admin role")
	}

	// Create registered role if it doesn't exist
	if !registeredExists {
		regMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			_:registered <dgraph.type> "Role" .
			_:registered <name> "registered" .
			_:registered <permissions> "user:read" .
			_:registered <permissions> "user:write" .
			_:registered <createdAt> "%s" .
			_:registered <updatedAt> "%s" .
		`, dgraph.EscapeRDF(now), dgraph.EscapeRDF(now)))

		console.Debug(fmt.Sprintf("Creating registered role: %s", regMutation.SetNquads))
		_, err := dgraph.ExecuteMutations(rs.conn, regMutation)
		if err != nil {
			console.Error("Failed to create registered role: " + err.Error())
			return err
		}
		console.Info("Successfully created registered role")
	}

	return nil
}

// GetRoleByName retrieves a role by its name
func (rs *RoleService) GetRoleByName(name string) (*Role, error) {
	query := fmt.Sprintf(`
	{
		role(func: eq(name, %q)) @filter(type(Role)) {
			uid
			name
			permissions
			createdAt
			updatedAt
		}
	}`, name)

	console.Debug(fmt.Sprintf("Executing role query: %s", query))
	resp, err := dgraph.ExecuteQuery(rs.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query role: " + err.Error())
		return nil, err
	}

	type QueryResult struct {
		Role []Role `json:"role"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal role query result: " + err.Error())
		return nil, err
	}

	if len(result.Role) == 0 {
		return nil, fmt.Errorf("role '%s' not found", name)
	}

	return &result.Role[0], nil
}

// AssignRoleToUser assigns a role to a user
func (rs *RoleService) AssignRoleToUser(userUID, roleName string) error {
	// Get the role UID first
	role, err := rs.GetRoleByName(roleName)
	if err != nil {
		return err
	}

	// Assign role to user
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		<%s> <roles> <%s> .
	`, dgraph.EscapeRDF(userUID), dgraph.EscapeRDF(role.UID)))

	console.Debug(fmt.Sprintf("Assigning role to user: %s", mutation.SetNquads))
	_, err = dgraph.ExecuteMutations(rs.conn, mutation)
	if err != nil {
		console.Error("Failed to assign role to user: " + err.Error())
		return err
	}

	console.Info(fmt.Sprintf("Successfully assigned role '%s' to user", roleName))
	return nil
}
