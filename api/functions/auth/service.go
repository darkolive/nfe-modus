package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

type Service struct {
	conn string
}

func NewService(conn string) *Service {
	return &Service{
		conn: conn,
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
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:authAttempt <dgraph.type> "AuthAttempt" .
		_:authAttempt <authAttempt.email> "%s" .
		_:authAttempt <authAttempt.deviceId> "%s" .
		_:authAttempt <authAttempt.type> "registration_start" .
		_:authAttempt <authAttempt.createdAt> "%s" .
	`, dgraph.EscapeRDF(hashedEmail), 
	   dgraph.EscapeRDF(deviceId), 
	   dgraph.EscapeRDF(time.Now().UTC().Format(time.RFC3339))))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		// Continue despite logging error
	}

	return challenge, nil
}

// CompleteRegistration finalizes user registration
func (s *Service) CompleteRegistration(ctx context.Context, hashedEmail, deviceId, publicKey string) error {
	// Create user with device
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:user <dgraph.type> "User" .
		_:user <user.email> "%s" .
		_:user <user.deviceId> "%s" .
		_:user <user.publicKey> "%s" .
		_:user <user.createdAt> "%s" .
	`, dgraph.EscapeRDF(hashedEmail), 
	   dgraph.EscapeRDF(deviceId), 
	   dgraph.EscapeRDF(publicKey), 
	   dgraph.EscapeRDF(time.Now().UTC().Format(time.RFC3339))))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Log successful registration
	mutation = dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:audit <dgraph.type> "Audit" .
		_:audit <audit.email> "%s" .
		_:audit <audit.type> "registration_complete" .
		_:audit <audit.message> "User registration completed" .
		_:audit <audit.data> "{\"deviceId\":\"%s\"}" .
		_:audit <audit.createdAt> "%s" .
	`, dgraph.EscapeRDF(hashedEmail), 
	   dgraph.EscapeRDF(deviceId), 
	   dgraph.EscapeRDF(time.Now().UTC().Format(time.RFC3339))))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	mutResp, err = dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		// Continue despite logging error
	}

	return nil
}

// StartAuthentication initiates user authentication
func (s *Service) StartAuthentication(ctx context.Context, hashedEmail, deviceId string) (string, error) {
	// Get user's devices
	query := fmt.Sprintf(`
        {
            query {
                user(func: eq(email, "%s")) {
                    device {
                        deviceId
                        isRevoked
                    }
                }
            }
        }
    `, hashedEmail)

	console.Debug(fmt.Sprintf("Executing query: %s", query))

	resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error(fmt.Sprintf("Query error: %v", err))
		if resp != nil {
			console.Error(fmt.Sprintf("Query response: %s", resp.Json))
		}
		return "", fmt.Errorf("failed to get user devices: %v", err)
	}

	var devices []map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Json), &devices); err != nil {
		console.Error(fmt.Sprintf("Failed to unmarshal response: %v", err))
		return "", fmt.Errorf("failed to get user devices: %v", err)
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("user not found or has no registered devices")
	}

	// Check if device is registered
	deviceFound := false
	for _, device := range devices[0]["device"].([]interface{}) {
		deviceMap := device.(map[string]interface{})
		if deviceMap["deviceId"] == deviceId {
			deviceFound = true
			if deviceMap["isRevoked"].(bool) {
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
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:authAttempt <dgraph.type> "AuthAttempt" .
		_:authAttempt <authAttempt.email> "%s" .
		_:authAttempt <authAttempt.deviceId> "%s" .
		_:authAttempt <authAttempt.type> "authentication_start" .
		_:authAttempt <authAttempt.createdAt> "%s" .
	`, dgraph.EscapeRDF(hashedEmail), 
	   dgraph.EscapeRDF(deviceId), 
	   dgraph.EscapeRDF(time.Now().UTC().Format(time.RFC3339))))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		// Continue despite logging error
	}

	return challenge, nil
}

// CompleteAuthentication finalizes user authentication
func (s *Service) CompleteAuthentication(ctx context.Context, hashedEmail, deviceId string) error {
	// Log successful authentication
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:audit <dgraph.type> "Audit" .
		_:audit <audit.email> "%s" .
		_:audit <audit.type> "authentication_complete" .
		_:audit <audit.message> "User authentication successful" .
		_:audit <audit.data> "{\"deviceId\":\"%s\"}" .
		_:audit <audit.createdAt> "%s" .
	`, dgraph.EscapeRDF(hashedEmail), 
	   dgraph.EscapeRDF(deviceId), 
	   dgraph.EscapeRDF(time.Now().UTC().Format(time.RFC3339))))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		// Continue despite logging error
	}

	return nil
}

// PasskeyCredential represents WebAuthn credential data
type PasskeyCredential struct {
	ID            string   `json:"id"`              // base64 encoded credential ID
	PublicKey     string   `json:"publicKey"`       // base64 encoded public key
	SignCount     uint32   `json:"signCount"`
	UserHandle    string   `json:"userHandle"`      // base64 encoded user handle
	TransportsRaw []string `json:"transportsRaw,omitempty"`
}

// AuthenticatorData represents the authenticator data in a TinyGo-compatible format
type AuthenticatorData struct {
	RPIDHash []byte
	Flags    byte
	Counter  uint32
	AttData  []byte
}

// keyManager handles encryption key management
type keyManager struct {
	mu   sync.RWMutex
	keys map[string][]byte // keyID -> key
}

var km = &keyManager{
	keys: make(map[string][]byte),
}

func (km *keyManager) getCurrentKey() (string, []byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// For simplicity, we're using a single key
	// In production, implement proper key rotation
	const currentKeyID = "current"
	
	key, exists := km.keys[currentKeyID]
	if !exists {
		// Generate a new key if none exists
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return "", nil, fmt.Errorf("failed to generate key: %v", err)
		}
		km.keys[currentKeyID] = key
	}

	return currentKeyID, key, nil
}

// EncryptedData represents encrypted credential data
type EncryptedData struct {
	KeyID     string `json:"keyId"`
	Nonce     []byte `json:"nonce"`
	Data      []byte `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

func (s *Service) encryptCredential(credential *PasskeyCredential) ([]byte, error) {
	keyID, key, err := km.getCurrentKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Marshal credential to JSON
	credJSON, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %v", err)
	}

	// Encrypt the credential
	ciphertext := aesgcm.Seal(nil, nonce, credJSON, nil)

	// Create encrypted data structure
	encData := EncryptedData{
		KeyID: keyID,
		Nonce: nonce,
		Data:  ciphertext,
		Timestamp: time.Now().Unix(),
	}

	return json.Marshal(encData)
}

func (s *Service) decryptCredential(data []byte) (*PasskeyCredential, error) {
	var encData EncryptedData
	if err := json.Unmarshal(data, &encData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted data: %v", err)
	}

	km.mu.RLock()
	key, exists := km.keys[encData.KeyID]
	km.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("encryption key not found")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt the credential
	plaintext, err := aesgcm.Open(nil, encData.Nonce, encData.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	var cred PasskeyCredential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %v", err)
	}

	return &cred, nil
}

func (s *Service) verifySignature(publicKey, message, signature []byte) bool {
	// Parse the public key
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil {
		console.Error("Failed to unmarshal public key")
		return false
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Hash the message
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

	// Parse the signature (r || s)
	if len(signature) != 64 {
		console.Error("Invalid signature length")
		return false
	}

	var rInt, sInt big.Int
	rInt.SetBytes(signature[:32])
	sInt.SetBytes(signature[32:])

	// Verify the signature
	return ecdsa.Verify(pubKey, hash, &rInt, &sInt)
}

// RegisterPasskey registers a new passkey for a user
func (s *Service) RegisterPasskey(ctx context.Context, hashedEmail string, credentialData []byte) error {
	console.Debug(fmt.Sprintf("Registering passkey for email hash: %s", hashedEmail))
	
	// Parse the credential data
	var cred PasskeyCredential
	if err := json.Unmarshal(credentialData, &cred); err != nil {
		return fmt.Errorf("failed to parse credential data: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	userDID := fmt.Sprintf("did:nfe:%s", hashedEmail)

	// Create mutation to save the credential
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		_:device <dgraph.type> "Device" .
		_:device <id> "%s" .
		_:device <userDID> "%s" .
		_:device <credentialID> "%s" .
		_:device <publicKey> "%s" .
		_:device <createdAt> "%s" .
	`, dgraph.EscapeRDF(cred.ID), 
	   dgraph.EscapeRDF(userDID), 
	   dgraph.EscapeRDF(cred.ID), 
	   dgraph.EscapeRDF(cred.PublicKey), 
	   dgraph.EscapeRDF(now)))

	console.Debug(fmt.Sprintf("Executing mutation: %s", mutation.SetNquads))

	// Execute mutation
	mutResp, err := dgraph.ExecuteMutations(s.conn, mutation)
	if err != nil {
		console.Error(fmt.Sprintf("Mutation error: %v", err))
		if mutResp != nil {
			console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
		}
		return fmt.Errorf("failed to save passkey: %v", err)
	}

	if mutResp != nil {
		console.Debug(fmt.Sprintf("Mutation response: %s", mutResp.Json))
	}

	console.Debug("Successfully registered passkey")
	return nil
}

// VerifyPasskey verifies a passkey assertion
func (s *Service) VerifyPasskey(ctx context.Context, hashedEmail string, assertionData []byte) error {
	// Get stored credential
	query := fmt.Sprintf(`
        {
            query {
                device(func: eq(userDID, "did:nfe:%s")) {
                    credentialID
                    publicKey
                }
            }
        }
    `, hashedEmail)

	console.Debug(fmt.Sprintf("Executing query: %s", query))

	resp, err := dgraph.ExecuteQuery(s.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error(fmt.Sprintf("Query error: %v", err))
		if resp != nil {
			console.Error(fmt.Sprintf("Query response: %s", resp.Json))
		}
		return fmt.Errorf("passkey not found: %v", err)
	}

	var devices []map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Json), &devices); err != nil {
		console.Error(fmt.Sprintf("Failed to unmarshal response: %v", err))
		return fmt.Errorf("passkey not found: %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("passkey not found")
	}

	var cred PasskeyCredential
	cred.ID = devices[0]["credentialID"].(string)
	cred.PublicKey = devices[0]["publicKey"].(string)

	var assertion struct {
		CredentialID []byte `json:"credentialId"`
		Signature    []byte `json:"signature"`
		AuthData     []byte `json:"authenticatorData"`
		ClientData   []byte `json:"clientDataJSON"`
	}
	if err := json.Unmarshal(assertionData, &assertion); err != nil {
		return fmt.Errorf("invalid assertion data: %v", err)
	}

	// Verify the credential ID matches
	if !bytesEqual(assertion.CredentialID, []byte(cred.ID)) {
		return fmt.Errorf("credential ID mismatch")
	}

	// Verify the signature
	if !s.verifySignature([]byte(cred.PublicKey), assertion.AuthData, assertion.Signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// bytesEqual compares two byte slices in constant time
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func generateChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// WebAuthnService handles WebAuthn operations
type WebAuthnService struct {
	svc *Service
}

// NewWebAuthnService creates a new WebAuthn service instance
func NewWebAuthnService(conn string) *WebAuthnService {
	return &WebAuthnService{
		svc: NewService(conn),
	}
}

// WebAuthnRegistrationRequest represents a request to register a new passkey
type WebAuthnRegistrationRequest struct {
	Email          string `json:"email"`
	CredentialData []byte `json:"credentialData"`
	DeviceID       string `json:"deviceId"`
}

// WebAuthnRegistrationResponse represents the response to a passkey registration
type WebAuthnRegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	UserDID string `json:"userDid,omitempty"`
}

// WebAuthnVerificationRequest represents a request to verify a passkey
type WebAuthnVerificationRequest struct {
	Email         string `json:"email"`
	AssertionData []byte `json:"assertionData"`
	DeviceID      string `json:"deviceId"`
}

// WebAuthnVerificationResponse represents the response to a passkey verification
type WebAuthnVerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	User    *User  `json:"user,omitempty"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// RegisterWebAuthn handles passkey registration
func (s *WebAuthnService) RegisterWebAuthn(req *WebAuthnRegistrationRequest) (*WebAuthnRegistrationResponse, error) {
	ctx := context.Background()

	// Hash email for privacy
	hashedEmail := hashEmail(req.Email)

	// Register the passkey
	if err := s.svc.RegisterPasskey(ctx, hashedEmail, req.CredentialData); err != nil {
		return &WebAuthnRegistrationResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to register passkey: %v", err),
		}, err
	}

	// Generate DID for the user
	did := fmt.Sprintf("did:nfe:%s", hashedEmail)

	return &WebAuthnRegistrationResponse{
		Success: true,
		Message: "Passkey registered successfully",
		UserDID: did,
	}, nil
}

// VerifyWebAuthn handles passkey verification
func (s *WebAuthnService) VerifyWebAuthn(req *WebAuthnVerificationRequest) (*WebAuthnVerificationResponse, error) {
	ctx := context.Background()

	// Hash email for privacy
	hashedEmail := hashEmail(req.Email)

	// Verify the passkey
	if err := s.svc.VerifyPasskey(ctx, hashedEmail, req.AssertionData); err != nil {
		return &WebAuthnVerificationResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to verify passkey: %v", err),
		}, err
	}

	// Generate authentication token
	token, err := generateAuthToken(hashedEmail, req.DeviceID)
	if err != nil {
		return &WebAuthnVerificationResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to generate token: %v", err),
		}, err
	}

	// Return success response with token
	return &WebAuthnVerificationResponse{
		Success: true,
		Message: "Passkey verified successfully",
		Token:   token,
		User: &User{
			ID:    hashedEmail,
			Email: req.Email,
		},
	}, nil
}

// Helper function to hash email
func hashEmail(email string) string {
	h := sha256.New()
	h.Write([]byte(email))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// Helper function to generate authentication token
func generateAuthToken(hashedEmail, deviceID string) (string, error) {
	// TODO: Implement proper JWT token generation
	// For now, return a placeholder
	return base64.URLEncoding.EncodeToString([]byte(hashedEmail + ":" + deviceID)), nil
}
