package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// JWTService handles JWT token operations
type JWTService struct {
	secretKey   string
	issuer      string
	expiryHours int
}

// NewJWTService creates a new JWT service
func NewJWTService(secretKey, issuer string, expiryHours int) *JWTService {
	return &JWTService{
		secretKey:   secretKey,
		issuer:      issuer,
		expiryHours: expiryHours,
	}
}

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
	Nbf    int64  `json:"nbf"`
}

// GenerateToken generates a JWT token for a user
func (s *JWTService) GenerateToken(userID, email string) (string, error) {
	console.Debug(fmt.Sprintf("Generating JWT token for user: %s", userID))
	
	// Set expiration time
	now := time.Now()
	expirationTime := now.Add(time.Duration(s.expiryHours) * time.Hour)
	
	// Create header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	
	// Create claims
	claims := Claims{
		UserID: userID,
		Email:  email,
		Iss:    s.issuer,
		Sub:    userID,
		Exp:    expirationTime.Unix(),
		Iat:    now.Unix(),
		Nbf:    now.Unix(),
	}
	
	// Encode header and claims
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %v", err)
	}
	
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}
	
	// Base64 encode header and claims
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsBase64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	
	// Create signature
	signingInput := headerBase64 + "." + claimsBase64
	signature := s.createSignature(signingInput)
	
	// Combine all parts
	token := signingInput + "." + signature
	
	return token, nil
}

// ValidateToken validates a JWT token
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	
	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	expectedSignature := s.createSignature(signingInput)
	
	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("invalid token signature")
	}
	
	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %v", err)
	}
	
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %v", err)
	}
	
	// Check if token is expired
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}
	
	return &claims, nil
}

// createSignature creates an HMAC-SHA256 signature for the JWT
func (s *JWTService) createSignature(input string) string {
	h := hmac.New(sha256.New, []byte(s.secretKey))
	h.Write([]byte(input))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signature
}
