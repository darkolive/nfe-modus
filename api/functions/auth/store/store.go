package store

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
    "nfe-modus/api/functions/auth/dgraph"
)

type Store struct {
    conn string
}

func New(conn string) *Store {
    return &Store{conn: conn}
}

// CreateUser creates a new user with device credentials
func (s *Store) CreateUser(ctx context.Context, hashedEmail, deviceId, publicKey string) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "dgraph.type": "User",
                "hashedEmail": hashedEmail,
                "status": "active",
                "dateJoined": t.Format("2006-01-02T15:04:05Z"),
                "lastAuthTime": t.Format("2006-01-02T15:04:05Z"),
                "deviceCredentials": []map[string]interface{}{
                    {
                        "dgraph.type": "DeviceCredential",
                        "did": fmt.Sprintf("did:nfe:%s", deviceId),
                        "userHash": hashedEmail,
                        "deviceId": deviceId,
                        "publicKey": publicKey,
                        "lastSyncTime": t.Format("2006-01-02T15:04:05Z"),
                        "isVerified": false,
                        "isRevoked": false,
                    },
                },
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    txn, err := dgraph.NewTransaction(s.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    if err := txn.Mutate(ctx, string(mutationJSON)); err != nil {
        console.Error("Failed to create user: " + err.Error())
        return fmt.Errorf("failed to create user: %v", err)
    }

    return nil
}

// GetUserDevices retrieves all devices for a user
func (s *Store) GetUserDevices(ctx context.Context, hashedEmail string) ([]map[string]interface{}, error) {
    query := fmt.Sprintf(`{
        devices(func: eq(hashedEmail, "%s")) {
            deviceCredentials {
                did
                deviceId
                publicKey
                lastSyncTime
                isVerified
                isRevoked
            }
        }
    }`, hashedEmail)

    txn, err := dgraph.NewTransaction(s.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return nil, fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    resp, err := txn.Query(ctx, query)
    if err != nil {
        console.Error("Failed to query devices: " + err.Error())
        return nil, fmt.Errorf("failed to query devices: %v", err)
    }

    var result struct {
        Devices []struct {
            DeviceCredentials []map[string]interface{} `json:"deviceCredentials"`
        } `json:"devices"`
    }

    if err := json.Unmarshal(resp, &result); err != nil {
        return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    if len(result.Devices) == 0 {
        return nil, nil
    }

    return result.Devices[0].DeviceCredentials, nil
}

// LogAuthAttempt records an authentication attempt
func (s *Store) LogAuthAttempt(ctx context.Context, hashedEmail, deviceId, status, ipAddress string) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "dgraph.type": "AuthAttempt",
                "userHash": hashedEmail,
                "deviceId": deviceId,
                "timestamp": t.Format("2006-01-02T15:04:05Z"),
                "status": status,
                "ipAddress": ipAddress,
                "failedAttempts": 0,
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    txn, err := dgraph.NewTransaction(s.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    if err := txn.Mutate(ctx, string(mutationJSON)); err != nil {
        console.Error("Failed to log auth attempt: " + err.Error())
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

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "dgraph.type": "AuditLog",
                "userHash": hashedEmail,
                "eventType": eventType,
                "timestamp": t.Format("2006-01-02T15:04:05Z"),
                "details": details,
                "metadata": metadata,
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    txn, err := dgraph.NewTransaction(s.conn)
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

// SavePasskey stores an encrypted passkey for a user
func (s *Store) SavePasskey(ctx context.Context, hashedEmail string, encryptedCredential []byte) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "dgraph.type": "PasskeyCredential",
                "userHash": hashedEmail,
                "encryptedData": base64.StdEncoding.EncodeToString(encryptedCredential),
                "createdAt": t.Format("2006-01-02T15:04:05Z"),
                "isRevoked": false,
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    txn, err := dgraph.NewTransaction(s.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    if err := txn.Mutate(ctx, string(mutationJSON)); err != nil {
        console.Error("Failed to save passkey: " + err.Error())
        return fmt.Errorf("failed to save passkey: %v", err)
    }

    return nil
}

// GetPasskey retrieves the encrypted passkey for a user
func (s *Store) GetPasskey(ctx context.Context, hashedEmail string) ([]byte, error) {
    query := fmt.Sprintf(`{
        passkey(func: eq(userHash, "%s")) @filter(eq(dgraph.type, "PasskeyCredential") AND eq(isRevoked, false)) {
            encryptedData
        }
    }`, hashedEmail)

    txn, err := dgraph.NewTransaction(s.conn)
    if err != nil {
        console.Error("Failed to create transaction: " + err.Error())
        return nil, fmt.Errorf("failed to create transaction: %v", err)
    }
    defer txn.Close()

    resp, err := txn.Query(ctx, query)
    if err != nil {
        console.Error("Failed to query passkey: " + err.Error())
        return nil, fmt.Errorf("failed to query passkey: %v", err)
    }

    var result struct {
        Passkey []struct {
            EncryptedData string `json:"encryptedData"`
        } `json:"passkey"`
    }

    if err := json.Unmarshal([]byte(resp), &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %v", err)
    }

    if len(result.Passkey) == 0 {
        return nil, fmt.Errorf("no passkey found for user")
    }

    return base64.StdEncoding.DecodeString(result.Passkey[0].EncryptedData)
}
