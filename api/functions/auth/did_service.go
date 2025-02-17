package auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
    "nfe-modus/api/functions/auth/dgraph"
    "nfe-modus/api/functions/auth/types"
)

type DIDService struct {
    store *dgraph.Transaction
}

func NewDIDService(conn string) (*DIDService, error) {
    store, err := dgraph.NewTransaction(conn)
    if err != nil {
        return nil, fmt.Errorf("failed to create DGraph transaction: %v", err)
    }
    return &DIDService{store: store}, nil
}

func (s *DIDService) GenerateDID() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %v", err)
    }
    return fmt.Sprintf("did:nfe:%s", base64.URLEncoding.EncodeToString(bytes)), nil
}

func (s *DIDService) RegisterDevice(ctx context.Context, userHash, deviceId, publicKey string) (*types.DeviceCredential, error) {
    t, err := localtime.Now()
    if err != nil {
        return nil, fmt.Errorf("failed to get current time: %v", err)
    }

    did, err := s.GenerateDID()
    if err != nil {
        return nil, fmt.Errorf("failed to generate DID: %v", err)
    }

    cred := &types.DeviceCredential{
        DID:          did,
        UserHash:     userHash,
        DeviceID:     deviceId,
        PublicKey:    publicKey,
        LastSyncTime: t,
        IsVerified:   false,
        IsRevoked:    false,
    }

    mutation := map[string]interface{}{
        "set": []interface{}{cred},
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal mutation: %v", err)
    }

    if err := s.store.Mutate(ctx, string(mutationJSON)); err != nil {
        return nil, fmt.Errorf("failed to store device credential: %v", err)
    }

    return cred, nil
}

func (s *DIDService) GetDeviceCredential(ctx context.Context, userHash, deviceId string) (*types.DeviceCredential, error) {
    query := fmt.Sprintf(`{
        device(func: eq(deviceId, "%s")) @filter(eq(userHash, "%s")) {
            did
            userHash
            deviceId
            publicKey
            lastSyncTime
            isVerified
            isRevoked
        }
    }`, deviceId, userHash)

    resp, err := s.store.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to query device: %v", err)
    }

    var result struct {
        Device []types.DeviceCredential `json:"device"`
    }

    if err := json.Unmarshal(resp, &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal response: %v", err)
    }

    if len(result.Device) == 0 {
        return nil, fmt.Errorf("device not found")
    }

    return &result.Device[0], nil
}

func (s *DIDService) VerifyDevice(ctx context.Context, did string) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "uid": fmt.Sprintf("_:%s", did),
                "isVerified": true,
                "verifiedAt": t.Format(time.RFC3339),
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    if err := s.store.Mutate(ctx, string(mutationJSON)); err != nil {
        return fmt.Errorf("failed to verify device: %v", err)
    }

    return nil
}

func (s *DIDService) RevokeDevice(ctx context.Context, did string) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    mutation := map[string]interface{}{
        "set": []map[string]interface{}{
            {
                "uid": fmt.Sprintf("_:%s", did),
                "isRevoked": true,
                "revokedAt": t.Format(time.RFC3339),
            },
        },
    }

    mutationJSON, err := json.Marshal(mutation)
    if err != nil {
        return fmt.Errorf("failed to marshal mutation: %v", err)
    }

    if err := s.store.Mutate(ctx, string(mutationJSON)); err != nil {
        return fmt.Errorf("failed to revoke device: %v", err)
    }

    return nil
}

// Close closes the underlying DGraph transaction
func (s *DIDService) Close() error {
    return s.store.Close()
}
