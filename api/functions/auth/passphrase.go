package auth

import (
	"encoding/json"
	"fmt"
	"time"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"

	"nfe-modus/api/functions/audit"
	"nfe-modus/api/functions/email"
)

// PassphraseService handles passphrase operations like setting and verifying
type PassphraseService struct {
	conn            string
	otpService      *OTPService      // For email verification checks
	roleService     *RoleService     // For role management
	emailEncryption *EmailEncryption // For email encryption
	emailService    *email.Service   // For sending emails
	didService      *DIDService      // For passwordless authentication
}

// SigninPassphraseRequest contains data for signing in with a passphrase
type SigninPassphraseRequest struct {
	Passphrase string `json:"passphrase"`
	Cookie     string `json:"cookie"`
	// Fields needed for audit logging
	ClientIP   string `json:"clientIp,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
}

// SigninPassphraseResponse contains the result of a signin passphrase operation
type SigninPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	UserDID string `json:"did,omitempty"`
}

// RegisterPassphraseRequest contains data for registering a new passphrase
type RegisterPassphraseRequest struct {
	Passphrase         string `json:"passphrase"`
	VerificationCookie string `json:"verificationCookie"`
	// Fields needed for audit logging
	ClientIP   string `json:"clientIp,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
}

// RegisterPassphraseResponse contains the result of a register passphrase operation
type RegisterPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	UserID  string `json:"userId,omitempty"`
	DID     string `json:"did,omitempty"`
}

// RecoveryPassphraseRequest contains data for recovering a user's passphrase
type RecoveryPassphraseRequest struct {
	Email string `json:"email"`
	// Fields needed for audit logging
	ClientIP   string `json:"clientIp,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
}

// RecoveryPassphraseResponse contains the result of a recovery passphrase operation
type RecoveryPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// ResetPassphraseRequest contains data for resetting a user's passphrase
type ResetPassphraseRequest struct {
	Passphrase         string `json:"passphrase"`
	VerificationCookie string `json:"verificationCookie"`
	// Fields needed for audit logging
	ClientIP   string `json:"clientIp,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
}

// ResetPassphraseResponse contains the result of a reset passphrase operation
type ResetPassphraseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// UserDetailsRequest contains data for updating user details
type UserDetailsRequest struct {
	Cookie    string            `json:"cookie"`
	Details   map[string]string `json:"details"`
	// Fields needed for audit logging
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// RegisterUserDetailsRequest contains data for registering initial user details
type RegisterUserDetailsRequest struct {
	Cookie    string            `json:"cookie"`
	Details   map[string]string `json:"details"`
	// Fields needed for audit logging
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// UserDetailsResponse contains the result of a user details update operation
type UserDetailsResponse struct {
	Success           bool              `json:"success"`
	Error             string            `json:"error,omitempty"`
	Message           string            `json:"message,omitempty"`
	Details           map[string]string `json:"details,omitempty"`
	VerificationCookie string            `json:"verificationCookie,omitempty"`
}

// NewPassphraseService creates a new instance of PassphraseService
func NewPassphraseService(conn string, otpService *OTPService, roleService *RoleService, emailEncryption *EmailEncryption, emailService *email.Service) (*PassphraseService, error) {
	didService, err := NewDIDService(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID service: %v", err)
	}
	
	return &PassphraseService{
		conn:            conn,
		otpService:      otpService,
		roleService:     roleService,
		emailEncryption: emailEncryption,
		emailService:    emailService,
		didService:      didService,
	}, nil
}

// generateUniqueID creates a unique ID for use in DIDs or other identifiers
func generateUniqueID() string {
	// Generate 16 random bytes
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp if random generation fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	
	// Convert to hex string
	return hex.EncodeToString(b)
}

// SigninPassphrase verifies a user's passphrase
func (ps *PassphraseService) SigninPassphrase(req *SigninPassphraseRequest) (*SigninPassphraseResponse, error) {
    // Get client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    // Initialize audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Get email from cookie
    otpData, err := ps.otpService.decryptOTPData(req.Cookie)
    if err != nil {
        console.Error("Failed to decrypt cookie: " + err.Error())
        
        // Log failed authentication attempt (invalid cookie)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // User is unknown at this point
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Failed to decrypt cookie for signin",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Invalid cookie",
        }, nil
    }
    
    email := otpData.Email
    console.Debug(fmt.Sprintf("Verifying passphrase for email: %s", email))

    if email == "" || req.Passphrase == "" {
        // Log failed authentication attempt (missing credentials)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // User is still unknown
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Email or passphrase missing",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Email and passphrase are required",
        }, nil
    }

    // Encrypt the email for searching
    encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
    if err != nil {
        console.Error("Failed to encrypt email for search: " + err.Error())
        
        // Log failed authentication attempt (encryption error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // Cannot identify user
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Failed to process user data: encryption error",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &SigninPassphraseResponse{
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
            status
            failedLoginAttempts
            lockedUntil
        }
    }`, encryptedEmail)

    console.Debug(fmt.Sprintf("Querying user: %s", query))
    queryRes, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{
        Query: query,
    })
    if err != nil {
        console.Error("Failed to query user: " + err.Error())
        
        // Log failed authentication attempt (database error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // User lookup failed
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Failed to query user: database error",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Failed to query user",
        }, err
    }

    type QueryResult struct {
        User []struct {
            Uid               string `json:"uid"`
            Did               string `json:"did"`
            Status            string `json:"status"`
            FailedLoginAttempts int  `json:"failedLoginAttempts"`
            LockedUntil       string `json:"lockedUntil"`
        } `json:"user"`
    }

    var result QueryResult
    if err := json.Unmarshal([]byte(queryRes.Json), &result); err != nil {
        console.Error("Failed to unmarshal user query result: " + err.Error())
        
        // Log failed authentication attempt (data processing error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // Cannot identify user
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Failed to process user data: unmarshal error",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Failed to process user data",
        }, err
    }

    if len(result.User) == 0 {
        console.Debug("User not found")
        
        // Log failed authentication attempt (user not found)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        "unknown", // User does not exist
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "User not found with provided credentials",
            AuditTimestamp: time.Now().UTC(),
            ComplianceFlags: []string{"ISO27001", "SECURITY_EVENT"},
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Invalid email or passphrase",
        }, nil
    }

    user := result.User[0]
    
    // Now we have a user ID for audit logs
    userID := user.Uid

    // Verify the account status
    if user.Status != "active" {
        console.Debug("User account is not active")
        
        // Log failed authentication attempt (inactive account)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_AUTHENTICATION",
            ActorID:        userID,
            ActorType:      "user",
            OperationType:  "signin",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/signin",
            Details:        "Account is not active",
            AuditTimestamp: time.Now().UTC(),
            ComplianceFlags: []string{"ISO27001", "SECURITY_EVENT"},
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Account is not active",
        }, nil
    }

    // Check if account is locked
    if user.LockedUntil != "" {
        lockedUntil, err := time.Parse(time.RFC3339, user.LockedUntil)
        if err == nil && lockedUntil.After(time.Now()) {
            console.Debug("User account is locked")
            
            // Log failed authentication attempt (locked account)
            _ = auditService.CreateAuditLog(audit.AuditLogData{
                Action:              "USER_AUTHENTICATION",
                ActorID:             userID,
                ActorType:           "user",
                OperationType:       "signin",
                ClientIP:            clientIP,
                UserAgent:           userAgent,
                SessionID:           sessionID,
                Success:             false,
                RequestMethod:       "POST",
                RequestPath:         "/auth/signin",
                Details:             "Account is locked due to too many failed attempts",
                AuditTimestamp:      time.Now().UTC(),
                SensitiveOperation:  true,
                ComplianceFlags:     []string{"ISO27001", "SECURITY_EVENT", "ACCOUNT_LOCKOUT"},
            })
            
            return &SigninPassphraseResponse{
                Success: false,
                Error:   "Account is locked due to too many failed login attempts. Please try again later.",
            }, nil
        }
    }

    // Use passwordless authentication
    isValid := ps.didService.VerifyPasswordlessDID(user.Did, email, req.Passphrase)
    if !isValid {
        console.Debug("Invalid passphrase")
        
        // Update failed login attempts
        failedAttempts := user.FailedLoginAttempts + 1
        var lockUntil string
        
        // Lock account after 5 failed attempts
        if failedAttempts >= 5 {
            // Lock for 30 minutes
            lockTime := time.Now().Add(30 * time.Minute)
            lockUntil = lockTime.Format(time.RFC3339)
        }
        
        // Update the failed login attempts in the database
        updateMutation := dgraph.NewMutation().WithSetNquads(fmt.Sprintf(`
            <%s> <failedLoginAttempts> "%d" .
        `, dgraph.EscapeRDF(user.Uid), failedAttempts))
        
        if lockUntil != "" {
            updateMutation = updateMutation.WithSetNquads(fmt.Sprintf(`
                <%s> <lockedUntil> "%s" .
            `, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(lockUntil)))
        }
        
        // Execute the mutation
        _, _ = dgraph.ExecuteMutations(ps.conn, updateMutation) // Ignore errors here
        
        // Log failed authentication attempt (invalid credentials)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:              "USER_AUTHENTICATION",
            ActorID:             userID,
            ActorType:           "user",
            OperationType:       "signin",
            ClientIP:            clientIP,
            UserAgent:           userAgent,
            SessionID:           sessionID,
            Success:             false,
            RequestMethod:       "POST",
            RequestPath:         "/auth/signin",
            Details:             fmt.Sprintf("Failed login attempt %d/5", failedAttempts),
            AuditTimestamp:      time.Now().UTC(),
            SensitiveOperation:  failedAttempts >= 3, // Mark as sensitive if approaching lockout
            ComplianceFlags:     []string{"ISO27001", "SECURITY_EVENT", "FAILED_LOGIN"},
        })
        
        return &SigninPassphraseResponse{
            Success: false,
            Error:   "Invalid email or passphrase",
        }, nil
    }

    // Reset failed login attempts on successful login
    if user.FailedLoginAttempts > 0 {
        resetMutation := dgraph.NewMutation()
        resetMutation = resetMutation.WithSetNquads(fmt.Sprintf(`
            <%s> <failedLoginAttempts> "0" .
            <%s> <lockedUntil> "" .
        `, dgraph.EscapeRDF(user.Uid), dgraph.EscapeRDF(user.Uid)))
        
        _, _ = dgraph.ExecuteMutations(ps.conn, resetMutation) // Ignore errors here
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
    
    // Log successful authentication
    _ = auditService.CreateAuditLog(audit.AuditLogData{
        Action:              "USER_AUTHENTICATION",
        ActorID:             userID,
        ActorType:           "user",
        OperationType:       "signin",
        ClientIP:            clientIP,
        UserAgent:           userAgent,
        SessionID:           sessionID,
        Success:             true,
        RequestMethod:       "POST",
        RequestPath:         "/auth/signin",
        Details:             "Successful authentication",
        AuditTimestamp:      time.Now().UTC(),
        SensitiveOperation:  false,
        ComplianceFlags:     []string{"ISO27001", "SECURITY_EVENT", "SUCCESSFUL_LOGIN"},
    })

    // Return success with DID for session creation
    return &SigninPassphraseResponse{
        Success: true,
        UserDID: user.Did,
    }, nil
}

// RegisterPassphrase registers a new passphrase for a user after email verification
func (ps *PassphraseService) RegisterPassphrase(req *RegisterPassphraseRequest) (*RegisterPassphraseResponse, error) {
    // Create audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Extract client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    if clientIP == "" {
        clientIP = "unknown"
    }
    if userAgent == "" {
        userAgent = "unknown"
    }
    if sessionID == "" {
        sessionID = "unknown"
    }
    
    // Get verified email from verification cookie - first try the new V2 format
    verificationInfo, verifyInfoErr := ps.otpService.CheckVerificationCookie("", req.VerificationCookie)

    var email string
    var verifiedAt time.Time

    if verifyInfoErr == nil {
        // Successfully parsed V2 verification cookie
        email = verificationInfo.Email
        verifiedAt = verificationInfo.VerifiedAt
        console.Debug("Successfully parsed V2 verification cookie")
    } else {
        // Fall back to legacy format
        otpData, otpErr := ps.otpService.decryptOTPData(req.VerificationCookie)
        if otpErr != nil {
            console.Error("Failed to decrypt verification cookie: " + otpErr.Error())
            
            // Log failed registration attempt (invalid verification cookie)
            _ = auditService.CreateAuditLog(audit.AuditLogData{
                Action:         "USER_REGISTRATION",
                ActorID:        "unknown", // User is unknown at this point
                ActorType:      "user",
                OperationType:  "register",
                ClientIP:       clientIP,
                UserAgent:      userAgent,
                SessionID:      sessionID,
                Success:        false,
                RequestMethod:  "POST",
                RequestPath:    "/auth/register",
                Details:        "Failed to decrypt verification cookie",
                AuditTimestamp: time.Now().UTC(),
            })
            
            return &RegisterPassphraseResponse{
                Success: false,
                Error:   "Invalid verification cookie",
            }, nil
        }
        
        // Use email from OTP data
        email = otpData.Email
        verifiedAt = otpData.CreatedAt
        console.Debug("Using legacy OTP cookie format")
    }
    
    if email == "" {
        console.Error("Email missing from verification data")
        
        // Log failed registration (missing email)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Email missing from verification data",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Invalid verification data",
        }, nil
    }
    
    // Check if the verification is still valid (within 5 minutes)
    if time.Since(verifiedAt) > 5*time.Minute {
        console.Error("Verification expired")
        
        // Log failed registration (verification expired)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Verification expired, must be valid",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Verification expired, please verify your email again",
        }, nil
    }
    
    // Check if a user with this email already exists
    var encryptedEmail string
    encryptedEmail, err := ps.emailEncryption.EncryptEmail(email)
    if err != nil {
        console.Error("Failed to encrypt email for query: " + err.Error())
        // Fall back to plaintext email if encryption fails
        encryptedEmail = email
    }

    console.Debug("Looking for existing user with encrypted email: " + encryptedEmail)
    query := fmt.Sprintf(`
        query {
            users(func: eq(email, %q)) {
                uid
                did
                active
            }
        }
    `, encryptedEmail)
    
    response, queryErr := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{Query: query})
    if queryErr != nil {
        console.Error("Failed to query Dgraph: " + queryErr.Error())
        
        // Log failed registration (DB error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Database error during user check",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    var userQueryResponse struct {
        Users []struct {
            Uid    string `json:"uid"`
            Did    string `json:"did"`
            Active bool   `json:"active"`
        } `json:"users"`
    }
    
    if err := json.Unmarshal([]byte(response.Json), &userQueryResponse); err != nil {
        console.Error("Failed to parse query response: " + err.Error())
        
        // Log failed registration (parsing error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Error parsing database response",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    // If user exists, update their passphrase
    if len(userQueryResponse.Users) > 0 {
        user := userQueryResponse.Users[0]
        
        // Generate passwordless DID with the email and passphrase
        did := ps.didService.GeneratePasswordlessDID(email, req.Passphrase)
        
        // Update user's DID
        nquads := fmt.Sprintf(`
            <%s> <did> %q .
            <%s> <active> "true" .
            <%s> <hasPassphrase> "true" .
        `, user.Uid, did, user.Uid, user.Uid)
        
        mutation := dgraph.NewMutation().WithSetNquads(nquads)
        
        // Execute the mutation
        _, err = dgraph.ExecuteMutations(ps.conn, mutation)
        if err != nil {
            console.Error("Failed to update user DID: " + err.Error())
            
            // Log failed registration (DB update error)
            _ = auditService.CreateAuditLog(audit.AuditLogData{
                Action:         "USER_REGISTRATION",
                ActorID:        user.Did,
                ActorType:      "user",
                OperationType:  "register",
                ClientIP:       clientIP,
                UserAgent:      userAgent,
                SessionID:      sessionID,
                Success:        false,
                RequestMethod:  "POST",
                RequestPath:    "/auth/register",
                Details:        "Failed to update user DID in database",
                AuditTimestamp: time.Now().UTC(),
            })
            
            return &RegisterPassphraseResponse{
                Success: false,
                Error:   "Failed to update user account",
            }, nil
        }
        
        // Log successful passphrase update
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        did,
            ActorType:      "user",
            OperationType:  "passphrase_update",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        true,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Successfully updated user passphrase",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: true,
            Message: "Passphrase updated successfully",
        }, nil
    }
    
    // Create new user with passwordless authentication
    did := ps.didService.GeneratePasswordlessDID(email, req.Passphrase)
    
    // Encrypt email
    encryptedEmail, err = ps.emailEncryption.EncryptEmail(email)
    if err != nil {
        console.Error("Failed to encrypt email: " + err.Error())
        
        // Log failed registration (email encryption error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        did,
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Failed to encrypt email",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Failed to encrypt user data",
        }, nil
    }
    
    // Create user in Dgraph
    nquads := fmt.Sprintf(`
        _:user <did> %q .
        _:user <email> %q .
        _:user <active> "true" .
        _:user <isAdmin> "false" .
        _:user <hasPassphrase> "true" .
        _:user <joinedAt> %q .
        _:user <dgraph.type> "User" .
    `, did, encryptedEmail, time.Now().Format(time.RFC3339))
    
    mutation := dgraph.NewMutation().WithSetNquads(nquads)
    
    // Execute the mutation
    createRes, err := dgraph.ExecuteMutations(ps.conn, mutation)
    if err != nil {
        console.Error("Failed to create user: " + err.Error())
        
        // Log failed registration (DB insertion error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        did,
            ActorType:      "user",
            OperationType:  "register",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register",
            Details:        "Failed to create user in database",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RegisterPassphraseResponse{
            Success: false,
            Error:   "Failed to create user account",
        }, nil
    }
    
    // Extract the user UID
    var userId string
    for _, uid := range createRes.Uids {
        userId = uid
        break
    }
    
    // Assign default role if we got a valid user ID
    if userId != "" && ps.roleService != nil {
        err = ps.roleService.AssignRoleToUser(userId, "User") // Assign default "User" role
        if err != nil {
            console.Error("Failed to assign default role: " + err.Error())
            // Non-fatal error, continue
        }
    }
    
    // Log successful registration
    _ = auditService.CreateAuditLog(audit.AuditLogData{
        Action:         "USER_REGISTRATION",
        ActorID:        did,
        ActorType:      "user",
        OperationType:  "register",
        ClientIP:       clientIP,
        UserAgent:      userAgent,
        SessionID:      sessionID,
        Success:        true,
        RequestMethod:  "POST",
        RequestPath:    "/auth/register",
        Details:        "User successfully registered",
        AuditTimestamp: time.Now().UTC(),
    })
    
    return &RegisterPassphraseResponse{
        Success: true,
        Message: "User registered successfully",
        UserID:  userId,
        DID:     did,
    }, nil
}

// RecoveryPassphrase initiates passphrase recovery for a user
func (ps *PassphraseService) RecoveryPassphrase(req *RecoveryPassphraseRequest) (*RecoveryPassphraseResponse, error) {
    // Create audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Extract client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    if clientIP == "" {
        clientIP = "unknown"
    }
    if userAgent == "" {
        userAgent = "unknown"
    }
    if sessionID == "" {
        sessionID = "unknown"
    }
    
    // Find user by email
    query := fmt.Sprintf(`
        query {
            users(func: eq(email, %q)) {
                uid
                did
                active
                locked
            }
        }
    `, req.Email)
    
    res, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{Query: query})
    if err != nil {
        console.Error("Failed to query Dgraph: " + err.Error())
        
        // Log failed recovery attempt (DB error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RECOVERY",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "recovery_initiate",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/recover",
            Details:        "Database error during user lookup",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RecoveryPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    var userQueryResponse struct {
        Users []struct {
            Uid    string `json:"uid"`
            Did    string `json:"did"`
            Active bool   `json:"active"`
            Locked bool   `json:"locked"`
        } `json:"users"`
    }
    
    if err := json.Unmarshal([]byte(res.Json), &userQueryResponse); err != nil {
        console.Error("Failed to parse query response: " + err.Error())
        
        // Log failed recovery (parsing error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RECOVERY",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "recovery_initiate",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/recover",
            Details:        "Error parsing database response",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RecoveryPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    // User not found
    if len(userQueryResponse.Users) == 0 {
        // For security reasons, don't reveal whether email exists
        console.Warn("User not found for recovery: " + req.Email)
        
        // Log recovery attempt for non-existent user
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RECOVERY",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "recovery_initiate",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/recover",
            Details:        "User not found",
            AuditTimestamp: time.Now().UTC(),
        })
        
        // For security, still return success
        return &RecoveryPassphraseResponse{
            Success: true,
            Message: "If your email is registered, you will receive a recovery link",
        }, nil
    }
    
    user := userQueryResponse.Users[0]
    
    // Generate OTP for password recovery
    otpReq := &GenerateOTPRequest{
        Email: req.Email,
    }
    
    _, err = ps.otpService.GenerateOTP(otpReq)
    if err != nil {
        console.Error("Failed to generate OTP: " + err.Error())
        
        // Log failed recovery (OTP generation error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RECOVERY",
            ActorID:        user.Did,
            ActorType:      "user",
            OperationType:  "recovery_initiate",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/recover",
            Details:        "Failed to generate OTP",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &RecoveryPassphraseResponse{
            Success: false,
            Error:   "Failed to generate recovery code",
        }, nil
    }
    
    // Log successful recovery initiation
    _ = auditService.CreateAuditLog(audit.AuditLogData{
        Action:         "PASSWORD_RECOVERY",
        ActorID:        user.Did,
        ActorType:      "user",
        OperationType:  "recovery_initiate",
        ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        true,
            RequestMethod:  "POST",
            RequestPath:    "/auth/recover",
            Details:        "Recovery email sent",
            AuditTimestamp: time.Now().UTC(),
    })
    
    return &RecoveryPassphraseResponse{
        Success: true,
        Message: "Recovery email sent",
    }, nil
}

// ResetPassphrase resets a user's passphrase after verification
func (ps *PassphraseService) ResetPassphrase(req *ResetPassphraseRequest) (*ResetPassphraseResponse, error) {
    // Create audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Extract client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    if clientIP == "" {
        clientIP = "unknown"
    }
    if userAgent == "" {
        userAgent = "unknown"
    }
    if sessionID == "" {
        sessionID = "unknown"
    }
    
    // Get verified email from verification cookie
    otpData, err := ps.otpService.decryptOTPData(req.VerificationCookie)
    if err != nil {
        console.Error("Failed to decrypt verification cookie: " + err.Error())
        
        // Log failed reset (invalid verification cookie)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Failed to decrypt verification cookie",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Invalid verification cookie",
        }, nil
    }
    
    email := otpData.Email
    if email == "" {
        console.Error("Email missing from verification data")
        
        // Log failed reset (missing email)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Email missing from verification data",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Invalid verification data",
        }, nil
    }
    
    // Check if the OTP is still valid (not expired)
    if otpData.ExpiresAt.Before(time.Now()) {
        console.Error("Verification expired")
        
        // Log failed reset (verification expired)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Verification expired",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Verification expired, please request a new reset link",
        }, nil
    }
    
    // Find user by email
    query := fmt.Sprintf(`
        query {
            users(func: eq(email, %q)) {
                uid
                did
                active
            }
        }
    `, email)
    
    res, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{Query: query})
    if err != nil {
        console.Error("Failed to query Dgraph: " + err.Error())
        
        // Log failed reset (DB error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Database error during user lookup",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    var userQueryResponse struct {
        Users []struct {
            Uid    string `json:"uid"`
            Did    string `json:"did"`
            Active bool   `json:"active"`
        } `json:"users"`
    }
    
    if err := json.Unmarshal([]byte(res.Json), &userQueryResponse); err != nil {
        console.Error("Failed to parse query response: " + err.Error())
        
        // Log failed reset (parsing error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Error parsing database response",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Internal server error",
        }, nil
    }
    
    // User not found
    if len(userQueryResponse.Users) == 0 {
        console.Warn("User not found for reset: " + email)
        
        // Log reset attempt for non-existent user
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "User not found",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Invalid user",
        }, nil
    }
    
    user := userQueryResponse.Users[0]
    
    // Generate passwordless DID with the email and passphrase
    did := ps.didService.GeneratePasswordlessDID(email, req.Passphrase)
    
    // Update user's DID
    nquads := fmt.Sprintf(`
        <%s> <did> %q .
        <%s> <active> "true" .
        <%s> <hasPassphrase> "true" .
        <%s> <failedLoginAttempts> "0" .
        <%s> <lockedUntil> "" .
    `, user.Uid, did, user.Uid, user.Uid, user.Uid, user.Uid)
    
    mutation := dgraph.NewMutation().WithSetNquads(nquads)
    
    // Execute the mutation
    _, err = dgraph.ExecuteMutations(ps.conn, mutation)
    if err != nil {
        console.Error("Failed to update user DID: " + err.Error())
        
        // Log failed reset (DB update error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "PASSWORD_RESET",
            ActorID:        user.Did,
            ActorType:      "user",
            OperationType:  "reset",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Failed to update user passphrase in database",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &ResetPassphraseResponse{
            Success: false,
            Error:   "Failed to reset passphrase",
        }, nil
    }
    
    // Log successful passphrase reset
    _ = auditService.CreateAuditLog(audit.AuditLogData{
        Action:         "PASSWORD_RESET",
        ActorID:        did,
        ActorType:      "user",
        OperationType:  "reset",
        ClientIP:       clientIP,
        UserAgent:      userAgent,
        SessionID:      sessionID,
        Success:        true,
        RequestMethod:  "POST",
            RequestPath:    "/auth/reset",
            Details:        "Successfully reset user passphrase",
            AuditTimestamp: time.Now().UTC(),
    })
    
    return &ResetPassphraseResponse{
        Success: true,
        Message: "Passphrase reset successfully",
    }, nil
}

// UpdateUserDetails updates a user's profile details
func (ps *PassphraseService) UpdateUserDetails(req *UserDetailsRequest) (*UserDetailsResponse, error) {
    // Create audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Extract client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    if clientIP == "" {
        clientIP = "unknown"
    }
    if userAgent == "" {
        userAgent = "unknown"
    }
    if sessionID == "" {
        sessionID = "unknown"
    }
    
    // Get email from cookie
    otpData, err := ps.otpService.decryptOTPData(req.Cookie)
    if err != nil {
        console.Error("Failed to decrypt cookie: " + err.Error())
        
        // Log failed update (invalid cookie)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "Failed to decrypt cookie",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Invalid cookie",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    email := otpData.Email
    
    // Now check if the user's email exists by searching for it
    var encryptedEmail string
    encryptedEmail, err = ps.emailEncryption.EncryptEmail(email)
    if err != nil {
        console.Error("Failed to encrypt email for query: " + err.Error())
        // Fall back to plaintext email if encryption fails
        encryptedEmail = email
    }

    query := fmt.Sprintf(`
        query {
            user(func: eq(email, %q)) {
                uid
                did
                active
            }
        }
    `, encryptedEmail)
    
    userQueryRes, err := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{Query: query})
    if err != nil {
        console.Error("Failed to query Dgraph: " + err.Error())
        
        // Log failed update (DB error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "Database error during user lookup",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Internal server error",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    var userQueryResponse struct {
        User []struct {
            Uid    string `json:"uid"`
            Did    string `json:"did"`
            Active bool   `json:"active"`
        } `json:"user"`
    }
    
    if err := json.Unmarshal([]byte(userQueryRes.Json), &userQueryResponse); err != nil {
        console.Error("Failed to parse query response: " + err.Error())
        
        // Log failed update (parsing error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "Error parsing database response",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Internal server error",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    // User not found
    if len(userQueryResponse.User) == 0 {
        console.Warn("User not found for update details: " + email)
        
        // Log update attempt for non-existent user
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "User not found",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "User not found",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    user := userQueryResponse.User[0]
    
    // Build the update nquads for the user details
    nquads := ""
    for key, value := range req.Details {
        // Sanitize and validate the key and value
        if key == "" || value == "" {
            continue
        }
        
        // Skip sensitive fields that shouldn't be updated this way
        if key == "did" || key == "email" || key == "isAdmin" || key == "active" {
            continue
        }
        
        nquads += fmt.Sprintf(`<%s> <%s> %q .
`, user.Uid, key, dgraph.EscapeRDF(value))
    }
    
    // Update timestamp
    nquads += fmt.Sprintf(`<%s> <updatedAt> %q .
`, user.Uid, time.Now().UTC().Format(time.RFC3339))
    
    // If no valid fields to update
    if nquads == "" {
        // Log skipped update (no valid fields)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        user.Did,
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "No valid fields to update",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "No valid fields to update",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    mutation := dgraph.NewMutation().WithSetNquads(nquads)
    
    // Execute the mutation
    _, err = dgraph.ExecuteMutations(ps.conn, mutation)
    if err != nil {
        console.Error("Failed to update user details: " + err.Error())
        
        // Log failed update (DB update error)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        user.Did,
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/update-details",
            Details:        "Failed to update user details in database",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Failed to update user details",
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    }
    
    // Log successful details update
    _ = auditService.CreateAuditLog(audit.AuditLogData{
        Action:         "USER_UPDATE",
        ActorID:        user.Did,
        ActorType:      "user",
        OperationType:  "update_details",
        ClientIP:       clientIP,
        UserAgent:      userAgent,
        SessionID:      sessionID,
        Success:        true,
        RequestMethod:  "POST",
        RequestPath:    "/auth/update-details",
        Details:        "Successfully updated user details",
        AuditTimestamp: time.Now().UTC(),
    })
    
    return &UserDetailsResponse{
        Success: true,
        Message: "User details updated successfully",
        Details: req.Details,
        VerificationCookie: req.Cookie, // Pass the verification cookie back
    }, nil
}

// RegisterUserDetails adds initial profile details for a newly registered user
func (ps *PassphraseService) RegisterUserDetails(req *RegisterUserDetailsRequest) (*UserDetailsResponse, error) {
    // Create audit service
    auditService := audit.NewAuditService(ps.conn)
    
    // Extract client info for audit logging
    clientIP := req.ClientIP
    userAgent := req.UserAgent
    sessionID := req.SessionID
    
    if clientIP == "" {
        clientIP = "unknown"
    }
    if userAgent == "" {
        userAgent = "unknown"
    }
    if sessionID == "" {
        sessionID = "unknown"
    }
    
    // Attempt to decrypt verification cookie to check if it's a new user
    verificationInfo, verifyErr := ps.otpService.CheckVerificationCookie("", req.Cookie)

    var email string
    var verifiedAt time.Time
    var isNewUser bool

    if verifyErr == nil {
        // Successfully parsed V2 verification cookie
        email = verificationInfo.Email
        verifiedAt = verificationInfo.VerifiedAt
        isNewUser = verificationInfo.IsNewUser
        console.Debug("Successfully parsed V2 verification cookie")
    } else {
        // Fall back to legacy format
        otpData, otpErr := ps.otpService.decryptOTPData(req.Cookie)
        if otpErr != nil {
            console.Error("Failed to decrypt verification cookie: " + otpErr.Error())
            
            // Log failed registration attempt (invalid verification cookie)
            _ = auditService.CreateAuditLog(audit.AuditLogData{
                Action:         "USER_REGISTRATION",
                ActorID:        "unknown", // User is unknown at this point
                ActorType:      "user",
                OperationType:  "register_details",
                ClientIP:       clientIP,
                UserAgent:      userAgent,
                SessionID:      sessionID,
                Success:        false,
                RequestMethod:  "POST",
                RequestPath:    "/auth/register-details",
                Details:        "Failed to decrypt verification cookie",
                AuditTimestamp: time.Now().UTC(),
            })
            
            return &UserDetailsResponse{
                Success: false,
                Error:   "Invalid verification cookie",
            }, nil
        }
        
        // Use email from OTP data
        email = otpData.Email
        verifiedAt = otpData.CreatedAt
        isNewUser = false // Old cookies don't have isNewUser
        console.Debug("Using legacy OTP cookie format")
    }
    
    if email == "" {
        console.Error("Email missing from verification data")
        
        // Log failed registration (missing email)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register-details",
            Details:        "Email missing from verification data",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Invalid verification data",
        }, nil
    }
    
    // Check if the verification is still valid (within 5 minutes)
    if time.Since(verifiedAt) > 5*time.Minute {
        console.Error("Verification expired")
        
        // Log failed registration (verification expired)
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_REGISTRATION",
            ActorID:        "unknown",
            ActorType:      "user",
            OperationType:  "register_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        false,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register-details",
            Details:        "Verification expired, must be valid",
            AuditTimestamp: time.Now().UTC(),
        })
        
        return &UserDetailsResponse{
            Success: false,
            Error:   "Verification expired, please verify your email again",
        }, nil
    }
    
    // Check if verification is for a new user
    if isNewUser {
        // This should update an existing user created during OTP verification
        console.Debug("User was created during OTP verification, updating user details")
        
        // Find the existing user by email - need to encrypt the email just like we do during creation
        encryptedEmail, encryptErr := ps.emailEncryption.EncryptEmail(verificationInfo.Email)
        if encryptErr != nil {
            console.Error("Error encrypting email: " + encryptErr.Error())
            return &UserDetailsResponse{
                Success: false,
                Error:   "Error processing user data",
            }, encryptErr
        }
        
        console.Debug("Searching for user with encrypted email: " + encryptedEmail)
        userQuery := fmt.Sprintf(`
            query {
                user(func: eq(email, %q)) {
                    uid
                }
            }
        `, encryptedEmail)
        
        userRes, userErr := dgraph.ExecuteQuery(ps.conn, &dgraph.Query{Query: userQuery})
        if userErr != nil {
            console.Error("Error finding user: " + userErr.Error())
            return &UserDetailsResponse{
                Success: false,
                Error:   "Error finding user account",
            }, userErr
        }
        
        var userResponse struct {
            User []struct {
                Uid string `json:"uid"`
            } `json:"user"`
        }
        
        if err := json.Unmarshal([]byte(userRes.Json), &userResponse); err != nil {
            console.Error("Error unmarshaling user query: " + err.Error())
            return &UserDetailsResponse{
                Success: false,
                Error:   "Error processing user data",
            }, err
        }
        
        if len(userResponse.User) == 0 {
            console.Error("User not found despite isNewUser flag being true")
            return &UserDetailsResponse{
                Success: false,
                Error:   "User account not found",
            }, fmt.Errorf("user not found")
        }
        
        // Update the user with the details
        nquads := []string{}
        
        // Add marketing preference if provided
        if marketingVal, ok := req.Details["marketing"]; ok {
            nquads = append(nquads, fmt.Sprintf("<%s> <marketing> %q .", userResponse.User[0].Uid, marketingVal))
        }
        
        // Add name if provided
        if nameVal, ok := req.Details["name"]; ok {
            nquads = append(nquads, fmt.Sprintf("<%s> <name> %q .", userResponse.User[0].Uid, nameVal))
        }
        
        // Set updatedAt
        nquads = append(nquads, fmt.Sprintf("<%s> <updatedAt> %q .", userResponse.User[0].Uid, time.Now().UTC().Format(time.RFC3339)))
        
        var updateErr error
        if len(nquads) > 0 {
            mutation := dgraph.NewMutation().WithSetNquads(strings.Join(nquads, "\n"))
            
            // Execute the mutation
            _, updateErr = dgraph.ExecuteMutations(ps.conn, mutation)
            if updateErr != nil {
                console.Error("Failed to update user details: " + updateErr.Error())
                // Non-fatal error, continue
            }
        }
        
        // Log audit success
        _ = auditService.CreateAuditLog(audit.AuditLogData{
            Action:         "USER_UPDATE",
            ActorID:        userResponse.User[0].Uid,
            ActorType:      "user",
            OperationType:  "update_details",
            ClientIP:       clientIP,
            UserAgent:      userAgent,
            SessionID:      sessionID,
            Success:        true,
            RequestMethod:  "POST",
            RequestPath:    "/auth/register-details",
            Details:        "Successfully updated user details",
            AuditTimestamp: time.Now().UTC(),
        })
        
        // Return success with verification cookie for next step
        return &UserDetailsResponse{
            Success: true,
            Message: "User details updated successfully",
            Details: req.Details,
            VerificationCookie: req.Cookie, // Pass the verification cookie back
        }, nil
    } else {
        // User is not new, use the existing update function
        return ps.UpdateUserDetails(&UserDetailsRequest{
            Cookie:    req.Cookie,
            Details:   req.Details,
            ClientIP:  req.ClientIP,
            UserAgent: req.UserAgent,
            SessionID: req.SessionID,
        })
    }
}
