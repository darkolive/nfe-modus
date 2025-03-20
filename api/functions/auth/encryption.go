package auth

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

var (
	// ErrEncryptionFailed is returned when encryption fails
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")
)

// EmailEncryption handles encryption and decryption of email addresses
type EmailEncryption struct {
	key []byte
}

// NewEmailEncryption creates a new email encryption service
func NewEmailEncryption() (*EmailEncryption, error) {
	// Get encryption key from environment
	encKey := os.Getenv("MODUS_ENCRYPTION_KEY")
	if encKey == "" {
		return nil, fmt.Errorf("MODUS_ENCRYPTION_KEY environment variable not set")
	}

	// Convert the key to a fixed-size key using SHA-256
	// This ensures we have a consistent key size regardless of the environment variable
	hasher := sha256.New()
	hasher.Write([]byte(encKey))
	key := hasher.Sum(nil)

	return &EmailEncryption{
		key: key,
	}, nil
}

// EncryptEmail encrypts an email address
// Uses AES in ECB mode with PKCS#7 padding for deterministic encryption
// This ensures we can search for encrypted emails
func (ee *EmailEncryption) EncryptEmail(email string) (string, error) {
	if email == "" {
		return "", nil
	}

	// Create cipher
	block, err := aes.NewCipher(ee.key)
	if err != nil {
		console.Error("Failed to create cipher: " + err.Error())
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Pad the email to a multiple of the block size
	blockSize := block.BlockSize()
	paddedData := pkcs7Pad([]byte(email), blockSize)

	// Encrypt the data
	ciphertext := make([]byte, len(paddedData))
	
	// Use ECB mode (no IV) for deterministic encryption
	// This is required so we can search for the same email later
	for i := 0; i < len(paddedData); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], paddedData[i:i+blockSize])
	}

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEmail decrypts an encrypted email address
func (ee *EmailEncryption) DecryptEmail(encryptedEmail string) (string, error) {
	if encryptedEmail == "" {
		return "", nil
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedEmail)
	if err != nil {
		console.Error("Failed to decode base64: " + err.Error())
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Create cipher
	block, err := aes.NewCipher(ee.key)
	if err != nil {
		console.Error("Failed to create cipher: " + err.Error())
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Decrypt the data
	blockSize := block.BlockSize()
	paddedData := make([]byte, len(ciphertext))

	// Use ECB mode (no IV) for deterministic decryption
	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(paddedData[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	// Unpad the data
	plaintext, err := pkcs7Unpad(paddedData, blockSize)
	if err != nil {
		console.Error("Failed to unpad: " + err.Error())
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// PKCS#7 padding implementation (add padding)
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// PKCS#7 unpadding implementation (remove padding)
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	
	unpadding := int(data[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	
	// Validate the padding
	for i := length - unpadding; i < length; i++ {
		if data[i] != byte(unpadding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	
	return data[:length-unpadding], nil
}
