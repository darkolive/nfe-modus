package auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "nfe-modus/api/functions/auth/store"
)

type Service struct {
    store *store.Store
}

func NewService(conn string) *Service {
    return &Service{
        store: store.New(conn),
    }
}

// StartRegistration initiates user registration
func (s *Service) StartRegistration(ctx context.Context, hashedEmail, deviceId string) (string, error) {
    // Generate challenge
    challenge, err := generateChallenge()
    if err != nil {
        console.Error(fmt.Sprintf("Failed to generate challenge: %v", err))
        return "", fmt.Errorf("failed to generate challenge: %v", err)
    }

    // Log registration attempt
    if err := s.store.LogAuthAttempt(ctx, hashedEmail, deviceId, "registration_start", ""); err != nil {
        console.Error(fmt.Sprintf("Failed to log registration attempt: %v", err))
        // Continue despite logging error
    }

    return challenge, nil
}

// CompleteRegistration finalizes user registration
func (s *Service) CompleteRegistration(ctx context.Context, hashedEmail, deviceId, publicKey string) error {
    // Create user with device
    if err := s.store.CreateUser(ctx, hashedEmail, deviceId, publicKey); err != nil {
        console.Error(fmt.Sprintf("Failed to create user: %v", err))
        return fmt.Errorf("failed to create user: %v", err)
    }

    // Log successful registration
    if err := s.store.LogAudit(ctx, hashedEmail, "registration_complete", "User registration completed", map[string]interface{}{
        "deviceId": deviceId,
    }); err != nil {
        console.Error(fmt.Sprintf("Failed to log registration completion: %v", err))
        // Continue despite logging error
    }

    return nil
}

// StartAuthentication initiates user authentication
func (s *Service) StartAuthentication(ctx context.Context, hashedEmail, deviceId string) (string, error) {
    // Get user's devices
    devices, err := s.store.GetUserDevices(ctx, hashedEmail)
    if err != nil {
        console.Error(fmt.Sprintf("Failed to get user devices: %v", err))
        return "", fmt.Errorf("failed to get user devices: %v", err)
    }

    if len(devices) == 0 {
        return "", fmt.Errorf("user not found or has no registered devices")
    }

    // Check if device is registered
    deviceFound := false
    for _, device := range devices {
        if device["deviceId"] == deviceId {
            deviceFound = true
            if device["isRevoked"].(bool) {
                return "", fmt.Errorf("device has been revoked")
            }
            break
        }
    }

    if !deviceFound {
        return "", fmt.Errorf("device not registered for user")
    }

    // Generate challenge
    challenge, err := generateChallenge()
    if err != nil {
        console.Error(fmt.Sprintf("Failed to generate challenge: %v", err))
        return "", fmt.Errorf("failed to generate challenge: %v", err)
    }

    // Log authentication attempt
    if err := s.store.LogAuthAttempt(ctx, hashedEmail, deviceId, "authentication_start", ""); err != nil {
        console.Error(fmt.Sprintf("Failed to log authentication attempt: %v", err))
        // Continue despite logging error
    }

    return challenge, nil
}

// CompleteAuthentication finalizes user authentication
func (s *Service) CompleteAuthentication(ctx context.Context, hashedEmail, deviceId string) error {
    // Log successful authentication
    if err := s.store.LogAudit(ctx, hashedEmail, "authentication_complete", "User authentication successful", map[string]interface{}{
        "deviceId": deviceId,
    }); err != nil {
        console.Error(fmt.Sprintf("Failed to log authentication completion: %v", err))
        // Continue despite logging error
    }

    return nil
}

// generateChallenge creates a secure random challenge
func generateChallenge() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %v", err)
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}
