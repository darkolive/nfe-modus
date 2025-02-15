package user

import (
	"time"
)

// VerificationStatus represents the status of a verification attempt
type VerificationStatus string

const (
	VerificationStatusPending  VerificationStatus = "PENDING"
	VerificationStatusVerified VerificationStatus = "VERIFIED"
	VerificationStatusExpired  VerificationStatus = "EXPIRED"
)

// EventType represents different types of security and user lifecycle events
type EventType string

const (
	EventTypeAuthOTPGenerated      EventType = "AUTH_OTP_GENERATED"
	EventTypeAuthOTPVerified       EventType = "AUTH_OTP_VERIFIED"
	EventTypeAuthOTPFailed         EventType = "AUTH_OTP_FAILED"
	EventTypeAuthLoginSuccess      EventType = "AUTH_LOGIN_SUCCESS"
	EventTypeAuthLoginFailed       EventType = "AUTH_LOGIN_FAILED"
	EventTypeAuthLogout           EventType = "AUTH_LOGOUT"
	EventTypeUserCreated          EventType = "USER_CREATED"
	EventTypeUserUpdated          EventType = "USER_UPDATED"
	EventTypeEmailChanged         EventType = "EMAIL_CHANGED"
	EventTypeAccountLocked        EventType = "ACCOUNT_LOCKED"
	EventTypeAccountUnlocked      EventType = "ACCOUNT_UNLOCKED"
	EventTypeAccountVerified      EventType = "ACCOUNT_VERIFIED"
	EventTypeAccountSuspended     EventType = "ACCOUNT_SUSPENDED"
	EventTypeAccountReactivated   EventType = "ACCOUNT_REACTIVATED"
	EventTypeAccountDeactivated   EventType = "ACCOUNT_DEACTIVATED"
	EventTypeAccountDeleted       EventType = "ACCOUNT_DELETED"
	EventTypeDataDeletionRequest  EventType = "DATA_DELETION_REQUESTED"
	EventTypeDataDeletionComplete EventType = "DATA_DELETION_COMPLETED"
)

// User represents a user in the system with minimal identifiable information
type User struct {
	UID          string    `json:"uid,omitempty"`
	HashedEmail  string    `json:"hashedEmail"`
	Status       string    `json:"status"`
	DateJoined   time.Time `json:"dateJoined"`
	LastAuthTime time.Time `json:"lastAuthTime"`
}

// AuthenticationAttempt represents an authentication attempt for a user
type AuthenticationAttempt struct {
	UID                string    `json:"uid,omitempty"`
	UserHash          string    `json:"userHash"`
	OTP               string    `json:"otp"`
	OTPCreatedAt      time.Time `json:"otpCreatedAt"`
	FailedAttempts    int       `json:"failedAttempts"`
	VerificationStatus string    `json:"verificationStatus"`
}

// AuditLog represents a security-relevant event in the system
type AuditLog struct {
	UID       string    `json:"uid,omitempty"`
	UserHash  string    `json:"userHash"`
	EventType string    `json:"eventType"`
	Timestamp time.Time `json:"timestamp"`
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	Details   string    `json:"details"`
}

// UserTimestamps represents timing information for a user
type UserTimestamps struct {
	DateJoined      time.Time `json:"dateJoined"`
	LastAuthTime    time.Time `json:"lastAuthTime"`
	DaysSinceJoined int       `json:"daysSinceJoined"`
	LastSeenStatus  string    `json:"lastSeenStatus"`
	IsActive        bool      `json:"isActive"`
	FailedAttempts  int       `json:"failedAttempts"`
	LastOTPTime     time.Time `json:"lastOTPTime"`
}

// GetUserTimestampsInput represents the input for getting user timestamps
type GetUserTimestampsInput struct {
	Email string `json:"email"`
}
