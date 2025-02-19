package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	"github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
)

// Store handles database operations
type Store struct {
	conn string
}

// PasskeyCredential represents a WebAuthn credential
type PasskeyCredential struct {
	ID            string   `json:"id"`
	PublicKey     string   `json:"publicKey"`
	SignCount     uint32   `json:"signCount"`
	UserHandle    string   `json:"userHandle"`
	TransportsRaw []string `json:"transportsRaw,omitempty"`
}

// New creates a new store instance
func New(conn string) *Store {
	return &Store{conn: conn}
}

// CreateUser creates a new user with device credentials
func (s *Store) CreateUser(ctx context.Context, hashedEmail, deviceId, publicKey string) error {
	t, err := localtime.Now()
	if err != nil {
		return fmt.Errorf("failed to get current time: %v", err)
	}

	// Create user record
	mutation := fmt.Sprintf(`
		{
			set {
				_:user <dgraph.type> "User" .
				_:user <iD> "%s" .
				_:user <status> "active" .
				_:user <dateJoined> "%s" .
				_:user <lastAuthTime> "%s" .
			}
		}
	`, hashedEmail, t.Format(time.RFC3339), t.Format(time.RFC3339))

	query := &dgraph.Query{
		Query: mutation,
	}

	_, err = dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Create device record
	mutation = fmt.Sprintf(`
		mutation {
		  set {
			_:device <dgraph.type> "DeviceCredential" .
			_:device <did> "%s" .
			_:device <userHash> "%s" .
			_:device <deviceId> "%s" .
			_:device <publicKey> "%s" .
			_:device <lastSyncTime> "%s" .
			_:device <isVerified> "%t" .
			_:device <isRevoked> "%t" .
		  }
		}
	`, fmt.Sprintf("did:nfe:%s", hashedEmail), hashedEmail, deviceId, publicKey, t.Format(time.RFC3339), false, false)

	deviceQuery := &dgraph.Query{
		Query: mutation,
	}

	_, err = dgraph.ExecuteQuery(s.conn, deviceQuery)
	if err != nil {
		return fmt.Errorf("failed to create device: %v", err)
	}

	return nil
}

// GetUserDevices retrieves all devices for a user
func (s *Store) GetUserDevices(ctx context.Context, hashedEmail string) ([]map[string]interface{}, error) {
	query := &dgraph.Query{
		Query: `query getDevices($userDID: string) {
			device(func: eq(device.userDID, $userDID)) {
				device.id
				device.credentialID
				device.publicKey
				device.lastUsed
				device.createdAt
			}
		}`,
		Variables: map[string]string{
			"$userDID": fmt.Sprintf("did:nfe:%s", hashedEmail),
		},
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %v", err)
	}

	var result struct {
		Device []map[string]interface{} `json:"device"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return result.Device, nil
}

// LogAuthAttempt records an authentication attempt
func (s *Store) LogAuthAttempt(ctx context.Context, hashedEmail, deviceId, status, ipAddress string) error {
	t, err := localtime.Now()
	if err != nil {
		return fmt.Errorf("failed to get current time: %v", err)
	}

	// Create auth attempt record
	mutation := fmt.Sprintf(`
		{
			set {
				_:auth <dgraph.type> "AuthenticationSession" .
				_:auth <authenticationSession.id> "%s-%s-%d" .
				_:auth <authenticationSession.userDID> "%s" .
				_:auth <authenticationSession.deviceID> "%s" .
				_:auth <authenticationSession.createdAt> "%s" .
				_:auth <authenticationSession.expiresAt> "%s" .
			}
		}
	`, hashedEmail, deviceId, t.Unix(), fmt.Sprintf("did:nfe:%s", hashedEmail), deviceId, t.Format(time.RFC3339), t.Add(24*time.Hour).Format(time.RFC3339))

	query := &dgraph.Query{
		Query: mutation,
	}

	_, err = dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to log auth attempt: %v", err))
		return fmt.Errorf("failed to log auth attempt: %v", err)
	}

	return nil
}

// LogAudit records an audit event
func (s *Store) LogAudit(ctx context.Context, hashedEmail, eventType, details string, metadata map[string]interface{}) error {
	t, err := localtime.Now()
	if err != nil {
		return fmt.Errorf("failed to get current time: %v", err)
	}

	// Convert metadata to string map
	metadataStr := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			metadataStr[k] = str
		} else {
			bytes, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("failed to marshal metadata value: %v", err)
			}
			metadataStr[k] = string(bytes)
		}
	}

	// Update user record
	mutation := fmt.Sprintf(`
		{
			set {
				uid(did:nfe:%s) <lastAuthTime> "%s" .
				uid(did:nfe:%s) <status> "%s" .
			}
		}
	`, hashedEmail, t.Format(time.RFC3339), hashedEmail, eventType)

	query := &dgraph.Query{
		Query: mutation,
	}

	_, err = dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to log audit: %v", err))
		return fmt.Errorf("failed to log audit: %v", err)
	}

	return nil
}

// SavePasskey saves a passkey credential for a user
func (s *Store) SavePasskey(userHash string, cred *PasskeyCredential) error {
	t := time.Now().UTC()

	// First query to check if device already exists
	query := fmt.Sprintf(`
		query {
			device(func: eq(device.id, "%s")) {
				uid
			}
		}
	`, cred.ID)

	console.Debug(fmt.Sprintf("Executing query: %s", query))
	resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: query})
	if err != nil {
		console.Error(fmt.Sprintf("Query error: %v", err))
		return fmt.Errorf("failed to query device: %v", err)
	}
	console.Debug(fmt.Sprintf("Query response: %s", resp.Json))

	var result struct {
		Device []struct {
			UID string `json:"uid"`
		} `json:"device"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error(fmt.Sprintf("Unmarshal error: %v", err))
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	var mutation string
	if len(result.Device) > 0 {
		// Update existing device
		mutation = fmt.Sprintf(`
			{
				set {
					<%s> <device.publicKey> "%s" .
					<%s> <device.lastUsed> "%s" .
				}
			}
		`, result.Device[0].UID, cred.PublicKey, result.Device[0].UID, t.Format(time.RFC3339))
	} else {
		// Create new device
		mutation = fmt.Sprintf(`
			{
				set {
					_:device <dgraph.type> "Device" .
					_:device <device.id> "%s" .
					_:device <device.userDID> "%s" .
					_:device <device.credentialID> "%s" .
					_:device <device.publicKey> "%s" .
					_:device <device.lastUsed> "%s" .
					_:device <device.createdAt> "%s" .
				}
			}
		`, cred.ID, fmt.Sprintf("did:nfe:%s", userHash), cred.ID, cred.PublicKey, t.Format(time.RFC3339), t.Format(time.RFC3339))
	}

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation))

	mutResp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: mutation,
	})
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		return fmt.Errorf("failed to save passkey: %v", err)
	}

	console.Debug(fmt.Sprintf("Mutation response: %s", mutResp.Json))
	return nil
}

// GetPasskey retrieves a passkey credential from the database
func (s *Store) GetPasskey(ctx context.Context, userHash string) ([]byte, error) {
	query := &dgraph.Query{
		Query: fmt.Sprintf(`
			{
				device(func: eq(userHash, "%s")) {
					deviceId
					publicKey
					lastSyncTime
				}
			}
		`, userHash),
	}

	resp, err := dgraph.ExecuteQuery(s.conn, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get passkey: %v", err)
	}

	var result struct {
		Device []struct {
			DeviceID     string `json:"deviceId"`
			PublicKey    string `json:"publicKey"`
			LastSyncTime string `json:"lastSyncTime"`
		} `json:"device"`
	}

	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if len(result.Device) == 0 {
		return nil, fmt.Errorf("no device found for user")
	}

	device := result.Device[0]
	cred := map[string]interface{}{
		"id":            device.DeviceID,
		"publicKey":     device.PublicKey,
		"signCount":     uint32(0), // We don't store this yet
		"userHandle":    userHash,
		"transportsRaw": []string{},
	}

	return json.Marshal(cred)
}
