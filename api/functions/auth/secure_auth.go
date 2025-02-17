package auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "github.com/hypermodeinc/modus/sdk/go/pkg/localtime"
    "nfe-modus/api/functions/auth/crypto"
    "nfe-modus/api/functions/auth/dgraph"
    "nfe-modus/api/functions/auth/logging"
    "nfe-modus/api/functions/auth/types"
)

// SecureAuthService provides secure authentication functionality
type SecureAuthService struct {
    store  *dgraph.Transaction
    logger *logging.AuditLogger
    hasher *crypto.EmailHasher
}

// AuthSession represents an authentication session
type AuthSession struct {
    DID       string `json:"did"`
    Challenge string `json:"challenge"`
}

// NewSecureAuthService creates a new secure authentication service
func NewSecureAuthService(conn string) (*SecureAuthService, error) {
    store, err := dgraph.NewTransaction(conn)
    if err != nil {
        return nil, fmt.Errorf("failed to create DGraph transaction: %v", err)
    }

    logger := logging.NewAuditLogger(conn)
    hasher := crypto.NewEmailHasher()

    return &SecureAuthService{
        store:  store,
        logger: logger,
        hasher: hasher,
    }, nil
}

// HashEmail hashes an email address for storage
func (s *SecureAuthService) HashEmail(email string) (string, error) {
    return s.hasher.HashEmail(email)
}

func (s *SecureAuthService) generateChallenge() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate challenge: %v", err)
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *SecureAuthService) generateDID() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate DID: %v", err)
    }
    return fmt.Sprintf("did:nfe:%s", base64.URLEncoding.EncodeToString(bytes)), nil
}

// StartRegistration begins the registration process for a new device
func (s *SecureAuthService) StartRegistration(ctx context.Context, email string) (*AuthSession, error) {
    hashedEmail, err := s.HashEmail(email)
    if err != nil {
        return nil, fmt.Errorf("failed to hash email: %v", err)
    }

    // Generate DID and challenge
    did, err := s.generateDID()
    if err != nil {
        return nil, fmt.Errorf("failed to generate DID: %v", err)
    }

    challenge, err := s.generateChallenge()
    if err != nil {
        return nil, fmt.Errorf("failed to generate challenge: %v", err)
    }

    // Create session
    session := &AuthSession{
        DID:       did,
        Challenge: challenge,
    }

    // Log registration attempt
    event := logging.AuditEvent{
        Type:     "registration_attempt",
        UserHash: hashedEmail,
        Details:  "Registration attempt started",
    }

    if err := s.logger.LogEvent(ctx, event); err != nil {
        console.Error("Failed to log registration attempt: " + err.Error())
    }

    return session, nil
}

// CompleteRegistration completes the registration process
func (s *SecureAuthService) CompleteRegistration(ctx context.Context, email string, did string, pubKey []byte) (*types.DeviceCredential, error) {
    t, err := localtime.Now()
    if err != nil {
        return nil, fmt.Errorf("failed to get current time: %v", err)
    }

    hashedEmail, err := s.HashEmail(email)
    if err != nil {
        return nil, fmt.Errorf("failed to hash email: %v", err)
    }

    // Create device credential
    return &types.DeviceCredential{
        DID:          did,
        UserHash:     hashedEmail,
        DeviceID:     did,
        PublicKey:    base64.URLEncoding.EncodeToString(pubKey),
        LastSyncTime: t,
        IsVerified:   false,
        IsRevoked:    false,
    }, nil
}

// StartAuthentication begins the authentication process for a user
func (s *SecureAuthService) StartAuthentication(ctx context.Context, email string) error {
    hashedEmail, err := s.HashEmail(email)
    if err != nil {
        return fmt.Errorf("failed to hash email: %v", err)
    }

    // Log authentication attempt
    event := logging.AuditEvent{
        Type:     "auth_attempt",
        UserHash: hashedEmail,
        Details:  "Authentication attempt started",
    }

    if err := s.logger.LogEvent(ctx, event); err != nil {
        console.Error("Failed to log auth attempt: " + err.Error())
    }

    return nil
}

// Close closes the underlying DGraph transaction
func (s *SecureAuthService) Close() error {
    return s.store.Close()
}
