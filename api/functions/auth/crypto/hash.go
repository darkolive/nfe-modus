package crypto

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "strings"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

const (
    // Salt for email hashing - in production this should be in secure config
    emailSalt = "nfe-modus-email-salt-v1"
)

// HashEmail creates a SHA-256 hash of the email with salt
func HashEmail(email string) string {
    hasher := sha256.New()
    hasher.Write([]byte(email + emailSalt))
    hash := hex.EncodeToString(hasher.Sum(nil))
    console.Debug(fmt.Sprintf("Hashed email %s", email))
    return hash
}

// VerifyHash verifies if a given input matches a hash
func VerifyHash(input, hash string) bool {
    inputHash := HashEmail(input)
    return inputHash == hash
}

// EmailHasher handles secure email hashing
type EmailHasher struct{}

// NewEmailHasher creates a new email hasher
func NewEmailHasher() *EmailHasher {
    return &EmailHasher{}
}

// HashEmail hashes an email address for secure storage
func (h *EmailHasher) HashEmail(email string) (string, error) {
    // Normalize email
    email = strings.TrimSpace(strings.ToLower(email))

    // Hash email
    hasher := sha256.New()
    hasher.Write([]byte(email))
    hash := hasher.Sum(nil)

    // Encode as base64
    return base64.URLEncoding.EncodeToString(hash), nil
}
