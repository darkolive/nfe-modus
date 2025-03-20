package auth

import (
    "context"
    "crypto/rand"
    "crypto/sha512"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "time"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
    "github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
    "nfe-modus/api/functions/auth/types"
)

type DIDService struct {
    conn string
}

func NewDIDService(conn string) (*DIDService, error) {
    return &DIDService{conn: conn}, nil
}

// GenerateDID generates a random DID
func (s *DIDService) GenerateDID() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %v", err)
    }
    return fmt.Sprintf("did:nfe:%s", base64.URLEncoding.EncodeToString(bytes)), nil
}

// RegisterDevice registers a device with a DID
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

    mutation := fmt.Sprintf(`
        _:cred <dgraph.type> "DeviceCredential" .
        _:cred <did> "%s" .
        _:cred <userHash> "%s" .
        _:cred <deviceId> "%s" .
        _:cred <publicKey> "%s" .
        _:cred <lastSyncTime> "%s" .
        _:cred <isVerified> "%t" .
        _:cred <isRevoked> "%t" .
    `, dgraph.EscapeRDF(cred.DID), dgraph.EscapeRDF(cred.UserHash), dgraph.EscapeRDF(cred.DeviceID), 
       dgraph.EscapeRDF(cred.PublicKey), t.Format(time.RFC3339), cred.IsVerified, cred.IsRevoked)

    // We don't need the response, so we use _
    _, err = dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
    if err != nil {
        return nil, fmt.Errorf("failed to register device: %v", err)
    }

    console.Debug(fmt.Sprintf("Registered device credential with DID: %s", cred.DID))
    
    return cred, nil
}

// GetDeviceCredential gets a device credential by user hash and device ID
func (s *DIDService) GetDeviceCredential(ctx context.Context, userHash, deviceId string) (*types.DeviceCredential, error) {
    query := fmt.Sprintf(`
        query {
            cred(func: type(DeviceCredential)) @filter(eq(userHash, "%s") AND eq(deviceId, "%s")) {
                did
                userHash
                deviceId
                publicKey
                lastSyncTime
                isVerified
                isRevoked
            }
        }
    `, dgraph.EscapeRDF(userHash), dgraph.EscapeRDF(deviceId))

    res, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: query})
    if err != nil {
        return nil, fmt.Errorf("failed to query device credential: %v", err)
    }

    var result struct {
        Cred []types.DeviceCredential `json:"cred"`
    }

    if err := json.Unmarshal([]byte(res.Json), &result); err != nil {
        return nil, fmt.Errorf("failed to unmarshal credential: %v", err)
    }

    if len(result.Cred) == 0 {
        return nil, fmt.Errorf("device credential not found")
    }

    return &result.Cred[0], nil
}

// VerifyDevice marks a device as verified
func (s *DIDService) VerifyDevice(ctx context.Context, did string) error {
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }

    query := fmt.Sprintf(`
        query {
            cred(func: type(DeviceCredential)) @filter(eq(did, "%s")) {
                uid
            }
        }
    `, dgraph.EscapeRDF(did))

    res, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: query})
    if err != nil {
        return fmt.Errorf("failed to query device credential: %v", err)
    }

    var result struct {
        Cred []struct {
            UID string `json:"uid"`
        } `json:"cred"`
    }

    if err := json.Unmarshal([]byte(res.Json), &result); err != nil {
        return fmt.Errorf("failed to unmarshal credential: %v", err)
    }

    if len(result.Cred) == 0 {
        return fmt.Errorf("device credential not found")
    }

    mutation := fmt.Sprintf(`
        <%s> <lastVerifiedAt> "%s" .
    `, result.Cred[0].UID, dgraph.EscapeRDF(t.Format(time.RFC3339)))

    _, err = dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
    if err != nil {
        return fmt.Errorf("failed to update device verification: %v", err)
    }

    return nil
}

// RevokeDevice revokes a device credential
func (s *DIDService) RevokeDevice(ctx context.Context, did string) error {
    query := fmt.Sprintf(`
        query {
            cred(func: type(DeviceCredential)) @filter(eq(did, "%s")) {
                uid
            }
        }
    `, dgraph.EscapeRDF(did))

    res, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: query})
    if err != nil {
        return fmt.Errorf("failed to query device credential: %v", err)
    }

    var result struct {
        Cred []struct {
            UID string `json:"uid"`
        } `json:"cred"`
    }

    if err := json.Unmarshal([]byte(res.Json), &result); err != nil {
        return fmt.Errorf("failed to unmarshal credential: %v", err)
    }

    if len(result.Cred) == 0 {
        return fmt.Errorf("device credential not found")
    }

    mutation := fmt.Sprintf(`
        <%s> <status> "revoked" .
    `, result.Cred[0].UID)

    _, err = dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
    if err != nil {
        return fmt.Errorf("failed to revoke device: %v", err)
    }

    return nil
}

// GeneratePasswordlessDID creates a deterministic DID from an email and passphrase
// This enables passwordless authentication by having both client and server
// independently generate the same DID without storing password data
func (s *DIDService) GeneratePasswordlessDID(email, passphrase string) string {
    // Create material for the DID by combining email and passphrase
    didMaterial := email + ":" + passphrase
    
    // Hash the material with SHA-512
    didHash := sha512.Sum512([]byte(didMaterial))
    
    // Create a standardized DID using a prefix and the first 16 bytes of the hash
    did := fmt.Sprintf("did:nfe:%s", hex.EncodeToString(didHash[:16]))
    
    console.Debug(fmt.Sprintf("Generated passwordless DID using email and passphrase"))
    return did
}

// VerifyPasswordlessDID checks if a provided email and passphrase match the stored DID
// This is the core of passwordless verification
func (s *DIDService) VerifyPasswordlessDID(storedDID, email, passphrase string) bool {
    // Generate a DID with the provided credentials
    generatedDID := s.GeneratePasswordlessDID(email, passphrase)
    
    // Compare the generated DID with the stored DID
    return storedDID == generatedDID
}

// RegisterUserWithPasswordlessDID creates a new user entry with a passwordless DID
// This replaces the traditional password storage approach
func (s *DIDService) RegisterUserWithPasswordlessDID(ctx context.Context, email, passphrase string) (string, error) {
    // Generate the DID
    did := s.GeneratePasswordlessDID(email, passphrase)
    
    // Get current time
    t, err := localtime.Now()
    if err != nil {
        return "", fmt.Errorf("failed to get current time: %v", err)
    }
    
    // Create the user entry with DID but no password hash/salt
    mutation := fmt.Sprintf(`
        _:user <dgraph.type> "User" .
        _:user <email> "%s" .
        _:user <did> "%s" .
        _:user <hasPassphrase> "true" .
        _:user <verified> "true" .
        _:user <dateJoined> "%s" .
        _:user <status> "active" .
    `, dgraph.EscapeRDF(email), dgraph.EscapeRDF(did), t.Format(time.RFC3339))
    
    res, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
    if err != nil {
        return "", fmt.Errorf("failed to create user: %v", err)
    }
    
    // Extract the UID of the new user
    var userUID string
    for _, uid := range res.Uids {
        userUID = uid
        break
    }
    
    if userUID == "" {
        return "", fmt.Errorf("failed to get user UID from response")
    }
    
    console.Info(fmt.Sprintf("Created user with passwordless DID: %s", did))
    return userUID, nil
}

// UpdateUserWithPasswordlessDID updates an existing user to use passwordless DID
func (s *DIDService) UpdateUserWithPasswordlessDID(ctx context.Context, userUID, email, passphrase string) error {
    // Generate the DID
    did := s.GeneratePasswordlessDID(email, passphrase)
    
    // Get current time
    t, err := localtime.Now()
    if err != nil {
        return fmt.Errorf("failed to get current time: %v", err)
    }
    
    // Create mutation using N-Quad format with NewMutation().WithSetNquads()
    nquads := fmt.Sprintf(`
        <%s> <did> "%s" .
        <%s> <hasPassphrase> "true" .
        <%s> <status> "active" .
        <%s> <updatedAt> "%s" .
        <%s> <lastAuthTime> "%s" .
    `, 
        userUID, dgraph.EscapeRDF(did),
        userUID,
        userUID,
        userUID, t.Format(time.RFC3339),
        userUID, t.Format(time.RFC3339))
    
    mutation := dgraph.NewMutation().WithSetNquads(nquads)
    
    console.Debug(fmt.Sprintf("Executing mutation with nquads: %s", nquads))
    
    // Execute the mutation
    _, err = dgraph.ExecuteMutations(s.conn, mutation)
    if err != nil {
        console.Error(fmt.Sprintf("Failed to update user with passwordless DID: %v", err))
        return fmt.Errorf("failed to update user: %v", err)
    }
    
    console.Info(fmt.Sprintf("Updated user %s with passwordless DID: %s", userUID, did))
    return nil
}

// AuthenticateWithPasswordlessDID verifies a user's credentials without using stored passwords
func (s *DIDService) AuthenticateWithPasswordlessDID(ctx context.Context, email, passphrase string) (string, error) {
    // Query for the user by email
    query := fmt.Sprintf(`
        query {
            user(func: eq(email, "%s")) @filter(type(User)) {
                uid
                did
                status
                failedLoginAttempts
                lockedUntil
            }
        }
    `, dgraph.EscapeRDF(email))
    
    res, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: query})
    if err != nil {
        return "", fmt.Errorf("failed to query user: %v", err)
    }
    
    var result struct {
        User []struct {
            UID                string `json:"uid"`
            DID                string `json:"did"`
            Status             string `json:"status"`
            FailedLoginAttempts int    `json:"failedLoginAttempts"`
            LockedUntil        string `json:"lockedUntil"`
        } `json:"user"`
    }
    
    if err := json.Unmarshal([]byte(res.Json), &result); err != nil {
        return "", fmt.Errorf("failed to parse response: %v", err)
    }
    
    if len(result.User) == 0 {
        return "", fmt.Errorf("user not found")
    }
    
    user := result.User[0]
    
    // Check account status
    if user.Status != "active" {
        return "", fmt.Errorf("account is not active")
    }
    
    // Check account lock
    if user.LockedUntil != "" {
        lockedUntil, err := time.Parse(time.RFC3339, user.LockedUntil)
        if err == nil && lockedUntil.After(time.Now()) {
            return "", fmt.Errorf("account is locked")
        }
    }
    
    // Verify the DID
    if !s.VerifyPasswordlessDID(user.DID, email, passphrase) {
        // Increment failed login attempts
        t, _ := localtime.Now()
        failedAttempts := user.FailedLoginAttempts + 1
        
        // Update failed login attempts
        mutation := fmt.Sprintf(`
            <%s> <failedLoginAttempts> "%d" .
            <%s> <lastFailedLogin> "%s" .
        `, user.UID, failedAttempts, user.UID, t.Format(time.RFC3339))
        
        // Lock account if too many failed attempts
        if failedAttempts >= 5 {
            lockedUntil := t.Add(15 * time.Minute)
            mutation += fmt.Sprintf(`
                <%s> <lockedUntil> "%s" .
            `, user.UID, lockedUntil.Format(time.RFC3339))
        }
        
        _, _ = dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
        return "", fmt.Errorf("invalid credentials")
    }
    
    // Authentication successful, update user
    t, _ := localtime.Now()
    mutation := fmt.Sprintf(`
        <%s> <lastAuthTime> "%s" .
        <%s> <failedLoginAttempts> "0" .
    `, user.UID, t.Format(time.RFC3339), user.UID)
    
    _, err = dgraph.ExecuteQuery(s.conn, &dgraph.Query{Query: mutation})
    if err != nil {
        console.Warn(fmt.Sprintf("Failed to update last auth time: %v", err))
    }
    
    return user.UID, nil
}

// Close closes the underlying DGraph transaction
func (s *DIDService) Close() error {
    return nil
}
