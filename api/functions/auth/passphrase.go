package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	"golang.org/x/crypto/pbkdf2"
)

// Constants for PBKDF2
const (
	iterations = 100000 // Number of iterations
	keyLength  = 64     // Length of the derived key in bytes
	saltLength = 32     // Length of the salt in bytes
)

// PassphraseService handles passphrase operations like setting and verifying
type PassphraseService struct {
	conn        string
	otpService  *OTPService     // For email verification checks
	roleService *RoleService    // For role management
	emailEncryption *EmailEncryption // For email encryption
}

// NewPassphraseService creates a new passphrase service
func NewPassphraseService(conn string, otpService *OTPService, roleService *RoleService, emailEncryption *EmailEncryption) (*PassphraseService, error) {
	return &PassphraseService{
		conn:        conn,
		otpService:  otpService,
		roleService: roleService,
		emailEncryption: emailEncryption,
	}, nil
}

// SetPassphraseRequest contains data needed to set a passphrase
type SetPassphraseRequest struct {
	Email              string `json:"email"`
	Passphrase         string `json:"passphrase"`
	VerificationCookie string `json:"verificationCookie"`
	Name               string `json:"name"`
	MarketingConsent   bool   `json:"marketingConsent"`
}

// SetPassphraseResponse contains the result of setting a passphrase
type SetPassphraseResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// VerifyPassphraseRequest contains data needed to verify a passphrase
type VerifyPassphraseRequest struct {
	Email      string `json:"email"`
	Passphrase string `json:"passphrase"`
}

// VerifyPassphraseResponse contains the result of a verify passphrase operation
type VerifyPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	UserDID string `json:"did,omitempty"`
}

// passphraseHashInfo contains the hash and salt for a passphrase
type passphraseHashInfo struct {
	Hash string
	Salt string
}

// generateSalt creates a random salt for passphrase hashing
func generateSalt() (string, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// hashPassphrase hashes a passphrase using PBKDF2
func hashPassphrase(passphrase string, salt string) (string, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %v", err)
	}

	hash := pbkdf2.Key([]byte(passphrase), saltBytes, iterations, keyLength, sha512.New)
	return base64.StdEncoding.EncodeToString(hash), nil
}

// verifyPassphrase verifies a passphrase against a stored hash
// This is a helper function used by the PassphraseService.VerifyPassphrase method
func verifyPassphrase(passphrase, storedHash, storedSalt string) (bool, error) {
	// Hash the provided passphrase with the stored salt
	hash, err := hashPassphrase(passphrase, storedSalt)
	if err != nil {
		return false, err
	}

	// Constant-time comparison to prevent timing attacks
	hashBytes, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false, err
	}

	storedHashBytes, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil {
		return false, err
	}

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(hashBytes, storedHashBytes) == 1, nil
}

// generateUUID generates a UUID v4 compatible string
func generateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", err
	}
	// Set version to 4 (random UUID)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant to RFC4122
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	
	return fmt.Sprintf("%x-%x-%x-%x-%x", 
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// SetPassphrase sets a passphrase for a user
func (ps *PassphraseService) SetPassphrase(req *SetPassphraseRequest) (*SetPassphraseResponse, error) {
	console.Debug(fmt.Sprintf("Setting passphrase for email: %s", req.Email))

	// Validate input
	if req.Email == "" {
		return &SetPassphraseResponse{Success: false, Error: "Email is required"}, nil
	}
	if req.Passphrase == "" {
		return &SetPassphraseResponse{Success: false, Error: "Passphrase is required"}, nil
	}

	// Basic passphrase validation
	if len(req.Passphrase) < 12 {
		return &SetPassphraseResponse{
			Success: false, Error: "Passphrase must be at least 12 characters long",
		}, nil
	}

	// Check if email was verified recently via OTP
	verifiedEmail, verificationTime, exists := ps.otpService.GetVerifiedEmail(req.Email)
	if !exists {
		console.Error("Email verification not found")
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Email verification required before setting passphrase",
		}, nil
	}

	// Ensure the email matches what was verified
	if verifiedEmail != req.Email {
		console.Error("Email mismatch")
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Email mismatch",
		}, nil
	}

	// Ensure the verification is fresh (within 5 minutes)
	if time.Since(verificationTime) > 5*time.Minute {
		console.Error("Email verification has expired")
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Email verification has expired",
		}, nil
	}

	// Encrypt the email for storage and searching
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(req.Email)
	if err != nil {
		console.Error("Failed to encrypt email: " + err.Error())
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// Query the user by encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			email
		}
	}`, encryptedEmail)

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Failed to query user",
		}, nil
	}

	type QueryResult struct {
		User []struct {
			Uid   string `json:"uid"`
			Email string `json:"email"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to parse user response: " + err.Error())
		return &SetPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// If user doesn't exist, create a new user
	if len(result.User) == 0 {
		console.Debug("User not found, creating new user")
		// Ensure that the email verification is available
		if !exists {
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Email verification information not found",
			}, nil
		}

		// Ensure roles exist
		err = ps.roleService.EnsureRolesExist()
		if err != nil {
			console.Error("Failed to ensure roles exist: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Error setting up user roles",
			}, nil
		}

		// Create a new user with passphrase
		// Generate a uuid for the user DID
		did, err := generateUUID()
		if err != nil {
			console.Error("Failed to generate UUID: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Failed to generate user identifier",
			}, nil
		}

		// Hash the passphrase
		salt, err := generateSalt()
		if err != nil {
			console.Error("Failed to generate salt: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Internal server error",
			}, nil
		}
		hash, err := hashPassphrase(req.Passphrase, salt)
		if err != nil {
			console.Error("Failed to hash passphrase: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Internal server error",
			}, nil
		}

		// Store new user in Dgraph
		now := time.Now().UTC().Format(time.RFC3339)
		didStr := did

		// Create the user with encrypted email
		mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			_:user <dgraph.type> "User" .
			_:user <email> %q .
			_:user <did> %q .
			_:user <hasPassphrase> "true" .
			_:user <passwordHash> %q .
			_:user <passwordSalt> %q .
			_:user <verified> "true" .
			_:user <status> "active" .
			_:user <dateJoined> %q .
			_:user <createdAt> %q .
			_:user <updatedAt> %q .
		`,
			dgraph.EscapeRDF(encryptedEmail),
			dgraph.EscapeRDF(didStr),
			dgraph.EscapeRDF(hash),
			dgraph.EscapeRDF(salt),
			dgraph.EscapeRDF(now),
			dgraph.EscapeRDF(now),
			dgraph.EscapeRDF(now)))

		console.Debug(fmt.Sprintf("Creating user: %s", mutation.SetNquads))
		mutResp, err := dgraph.ExecuteMutations(ps.conn, mutation)
		if err != nil {
			console.Error("Failed to create user: " + err.Error())
			if mutResp != nil {
				console.Error(fmt.Sprintf("Mutation response: %s", mutResp.Json))
			}
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Failed to create user",
			}, nil
		}

		// Get the created user UID
		var uidResult map[string][]map[string]string
		if err := json.Unmarshal([]byte(mutResp.Json), &uidResult); err != nil {
			console.Error("Failed to parse user creation response: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Failed to process user creation",
			}, nil
		}

		// Assign the registered role to the new user
		uid := uidResult["uids"][0]["user"]
		roleErr := ps.roleService.AssignRoleToUser(uid, "registered")
		if roleErr != nil {
			console.Error("Failed to assign role: " + roleErr.Error())
			// This is non-fatal, continue with the passphrase setup
		}
	} else {
		// Update existing user's passphrase
		console.Debug("User found, updating passphrase")
		user := result.User[0]

		// Hash the passphrase
		salt, err := generateSalt()
		if err != nil {
			console.Error("Failed to generate salt: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Internal server error",
			}, nil
		}
		hash, err := hashPassphrase(req.Passphrase, salt)
		if err != nil {
			console.Error("Failed to hash passphrase: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Internal server error",
			}, nil
		}

		// Update the user with new passphrase
		now := time.Now().UTC().Format(time.RFC3339)
		mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
			<%s> <hasPassphrase> "true" .
			<%s> <passwordHash> "%s" .
			<%s> <passwordSalt> "%s" .
			<%s> <verified> "true" .
			<%s> <status> "active" .
			<%s> <updatedAt> "%s" .
			<%s> <lastAuthTime> "%s" .
		`,
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(hash),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(salt),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(now),
			dgraph.EscapeRDF(user.Uid),
			dgraph.EscapeRDF(now)))

		console.Debug(fmt.Sprintf("Updating user: %s", mutation.SetNquads))
		_, err = dgraph.ExecuteMutations(ps.conn, mutation)
		if err != nil {
			console.Error("Failed to update user: " + err.Error())
			return &SetPassphraseResponse{
				Success: false,
				Error:   "Failed to update user",
			}, nil
		}
	}

	// Clear the verified email from memory
	ps.otpService.ClearVerifiedEmail(req.Email)

	return &SetPassphraseResponse{
		Success: true,
		Message: "Passphrase set successfully",
	}, nil
}

// VerifyPassphrase verifies a user's passphrase
func (ps *PassphraseService) VerifyPassphrase(req *VerifyPassphraseRequest) (*VerifyPassphraseResponse, error) {
	console.Debug(fmt.Sprintf("Verifying passphrase for email: %s", req.Email))

	if req.Email == "" || req.Passphrase == "" {
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Email and passphrase are required",
		}, nil
	}

	// Encrypt the email for searching
	encryptedEmail, err := ps.emailEncryption.EncryptEmail(req.Email)
	if err != nil {
		console.Error("Failed to encrypt email for search: " + err.Error())
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, nil
	}

	// Check if user exists using encrypted email
	query := fmt.Sprintf(`
	{
		user(func: eq(email, "%s")) @filter(type(User)) {
			uid
			did
			verified
			hasPassphrase
			passwordHash
			passwordSalt
		}
	}`, encryptedEmail)

	console.Debug(fmt.Sprintf("Querying user: %s", query))
	resp, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
		Query: query,
	})
	if err != nil {
		console.Error("Failed to query user: " + err.Error())
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Failed to query user",
		}, err
	}

	type QueryResult struct {
		User []struct {
			Uid          string `json:"uid"`
			Did          string `json:"did"`
			Verified     bool   `json:"verified"`
			HasPassphrase bool  `json:"hasPassphrase"`
			PasswordHash string `json:"passwordHash"`
			PasswordSalt string `json:"passwordSalt"`
		} `json:"user"`
	}

	var result QueryResult
	if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
		console.Error("Failed to unmarshal user query result: " + err.Error())
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Failed to process user data",
		}, err
	}

	if len(result.User) == 0 {
		console.Debug("User not found")
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Invalid email or passphrase",
		}, nil
	}

	user := result.User[0]

	// Verify that user has a passphrase set
	if !user.HasPassphrase {
		console.Debug("User does not have a passphrase")
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Passphrase not set for user",
		}, nil
	}

	// Verify the passphrase
	isValid, err := verifyPassphrase(req.Passphrase, user.PasswordHash, user.PasswordSalt)
	if err != nil {
		console.Error("Failed to verify passphrase: " + err.Error())
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Failed to verify passphrase",
		}, err
	}

	if !isValid {
		console.Debug("Invalid passphrase")
		return &VerifyPassphraseResponse{
			Success: false,
			Error:   "Invalid email or passphrase",
		}, nil
	}

	// Update last auth time
	now := time.Now().UTC().Format(time.RFC3339)
	mutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
		<%s> <lastAuthTime> "%s" .
	`, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(now)))

	console.Debug(fmt.Sprintf("Updating last auth time: %s", mutation.SetNquads))
	_, err = dgraph.ExecuteMutations(ps.conn, mutation)
	if err != nil {
		console.Error("Failed to update last auth time: " + err.Error())
		// Non-fatal error, continue with login
		console.Info("User authenticated but failed to update last auth time")
	}

	// Return success with DID for session creation
	return &VerifyPassphraseResponse{
		Success: true,
		UserDID: user.Did,
	}, nil
}
