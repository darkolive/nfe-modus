package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// EmailEncryption is responsible for encrypting and decrypting email addresses
// This is important for storing user emails securely in the database
type EmailEncryption struct {
	key []byte
}

// NewEmailEncryption returns a new EmailEncryption instance using the key from environment variable
func NewEmailEncryption() (*EmailEncryption, error) {
	// Try to get the key from environment variable
	encryptionKey := os.Getenv("MODUS_ENCRYPTION_KEY")
	if encryptionKey == "" {
		return nil, fmt.Errorf("MODUS_ENCRYPTION_KEY environment variable not set")
	}
	
	// Decode key from base64
	key, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %v", err)
	}
	
	// AES requires key sizes of 16, 24, or 32 bytes
	// If the key is not one of these sizes, we'll derive a 32-byte key using SHA-256
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		console.Warn(fmt.Sprintf("Encryption key has invalid length %d, deriving 32-byte key", len(key)))
		hash := sha256.Sum256(key)
		key = hash[:]
	}
	
	return &EmailEncryption{key: key}, nil
}

// NewEmailEncryptionWithFallback returns an EmailEncryption instance with a fallback
// This should be used only in contexts where failing encryption would break critical flows
func NewEmailEncryptionWithFallback() *EmailEncryption {
	// Try to get the proper encryption key
	encryption, err := NewEmailEncryption()
	if err == nil {
		return encryption
	}
	
	// Log that we're using a fallback
	console.Warn("Using fallback encryption key - emails will not be securely encrypted!")
	
	// Generate a fallback key using a static string for development only
	// Hash it to ensure it's the correct size for AES (32 bytes)
	fallbackString := "fallback-key-for-development-only-do-not-use-in-production"
	hash := sha256.Sum256([]byte(fallbackString))
	
	return &EmailEncryption{key: hash[:]}
}

// EncryptEmail encrypts an email address using AES-GCM
func (e *EmailEncryption) EncryptEmail(email string) (string, error) {
	if email == "" {
		return "", nil
	}
	
	// Convert email to lowercase for consistency
	email = strings.ToLower(email)
	
	// Create a new AES cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		console.Error("Failed to create cipher: " + err.Error())
		return "", fmt.Errorf("encryption failed: %v", err)
	}
	
	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		console.Error("Failed to create GCM: " + err.Error())
		return "", fmt.Errorf("encryption failed: %v", err)
	}
	
	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	
	// For deterministic encryption (needed for search), we'll use a nonce derived from the email
	// This is less secure than a random nonce but allows us to search for encrypted emails
	emailHash := sha256.Sum256([]byte(email))
	copy(nonce, emailHash[:gcm.NonceSize()])
	
	// Encrypt the email
	ciphertext := gcm.Seal(nonce, nonce, []byte(email), nil)
	
	// Return base64 encoded ciphertext
	return "enc:" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEmail decrypts an encrypted email address
func (e *EmailEncryption) DecryptEmail(encryptedEmail string) (string, error) {
	// Check if the email is encrypted
	if !strings.HasPrefix(encryptedEmail, "enc:") {
		// Not encrypted, return as is
		return encryptedEmail, nil
	}
	
	// Remove the prefix
	encryptedData := strings.TrimPrefix(encryptedEmail, "enc:")
	
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		console.Error("Failed to decode base64: " + err.Error())
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	
	// Create a new AES cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		console.Error("Failed to create cipher: " + err.Error())
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	
	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		console.Error("Failed to create GCM: " + err.Error())
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	
	// Check if ciphertext is long enough
	if len(ciphertext) < gcm.NonceSize() {
		console.Error("Ciphertext too short")
		return "", fmt.Errorf("decryption failed: ciphertext too short")
	}
	
	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	
	// Decrypt the email
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		console.Error("Failed to decrypt: " + err.Error())
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	
	return string(plaintext), nil
}

// ErrEncryptionFailed is returned when encryption fails
var ErrEncryptionFailed = fmt.Errorf("encryption failed")

// ErrDecryptionFailed is returned when decryption fails
var ErrDecryptionFailed = fmt.Errorf("decryption failed")
