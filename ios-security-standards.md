# NFE-Modus Security Architecture

## Overview of Security Framework

The NFE-Modus platform implements a comprehensive security architecture that protects user data while providing a seamless authentication experience. This document outlines the key security standards that our system adheres to, how these standards are implemented, and what they mean for privacy and security.

## Security Standards Implemented

### ISO/IEC 27001 - Information Security Management

Our security architecture follows the principles outlined in ISO/IEC 27001, which provides a framework for information security management systems (ISMS).

**Implementation in Our System:**
- Systematic approach to managing sensitive user information
- Risk assessment and treatment processes
- Comprehensive security policies covering all aspects of the application
- Secure development lifecycle

**Impact on Privacy and Security:**
- Ensures a holistic approach to security rather than point solutions
- Provides a framework for identifying and addressing new threats
- Establishes accountability and clear security governance

### ISO/IEC 27018 - Protection of Personally Identifiable Information (PII)

This standard focuses specifically on cloud privacy and the protection of personal data.

**Implementation in Our System:**
- Data minimization principles in our database design
- Transparent policies on data collection and usage
- Strong controls for user consent
- Encryption of sensitive user data

**Impact on Privacy and Security:**
- Enhanced protection of user data stored in our database
- Greater transparency about how personal information is handled
- Stronger user control over their own data

## Key Security Technologies

### Email Encryption

Our system uses AES-256-GCM encryption to protect sensitive user information, particularly email addresses.

**Implementation:**
- AES-256-GCM encryption algorithm
- Secure key management using environment variables
- IV (Initialization Vector) and auth tag stored with encrypted data
- Robust error handling for decryption failures

**Privacy and Security Benefits:**
- Protection of user email addresses even if the database is compromised
- Compliance with data protection regulations
- Defense against data breaches

### WebAuthn Authentication

Our system implements the WebAuthn standard for passwordless authentication, leveraging the security capabilities of users' devices.

**Implementation:**
- Challenge-response authentication protocol
- Secure credential storage
- Device information tracking
- Biometric detection and verification
- Role-based access control

**Privacy and Security Benefits:**
- Elimination of password-related vulnerabilities
- Phishing-resistant authentication
- Enhanced user experience with stronger security
- Detailed device tracking for security auditing

## Data Storage Architecture

### Dgraph Database

Our system uses Dgraph, a graph database, to store user information and relationships.

**Implementation:**
- Structured schema with defined types (User, Device, Role)
- Relationship-based data model
- Encrypted sensitive fields
- Type-safe queries

**Privacy and Security Benefits:**
- Granular access control
- Efficient relationship traversal
- Structured data validation
- Protection of sensitive information

### User Data Structure

The system maintains the following user data structure:

```
User {
  uid: string
  did: string (unique identifier)
  email: string (encrypted)
  name: string
  verified: boolean
  emailVerified: timestamp
  dateJoined: timestamp
  lastAuthTime: timestamp
  status: 'active' | 'inactive' | 'locked'
  hasWebAuthn: boolean
  hasPassphrase: boolean
  failedLoginAttempts: number
  lastFailedLogin: timestamp
  lockedUntil: timestamp
  createdAt: timestamp
  updatedAt: timestamp
  roles: [Role]
  devices: [Device]
}
```

**Privacy Considerations:**
- Email addresses are always encrypted
- Authentication status is tracked but not authentication methods
- Failed login attempts are monitored for security
- Timestamps provide audit trail

### Device Information

For each user device, we store:

```
Device {
  uid: string
  credentialID: string
  credentialPublicKey: string
  counter: number
  transports: string[]
  lastUsed: timestamp
  deviceName: string
  deviceType: string
  isBiometric: boolean
  deviceInfo: string
  createdAt: timestamp
  updatedAt: timestamp
}
```

**Security Considerations:**
- Device fingerprinting for fraud detection
- Biometric capability tracking
- Usage timestamps for suspicious activity detection
- No storage of private keys or biometric data

## Authentication Flow

### Registration Process

1. Email verification
   - User provides email
   - System sends verification link
   - Email is validated before registration proceeds

2. WebAuthn credential creation
   - Challenge generated and stored
   - User creates credential on device
   - Credential verified against challenge
   - User and device information stored

3. Role assignment
   - Default "registered" role assigned
   - Permissions attached to role

**Security Measures:**
- Challenge expiration (5 minutes)
- Verification of origin and RP ID
- Secure credential storage
- Explicit role assignment

### Login Process

1. Email verification
   - User provides email
   - System looks up user by encrypted email

2. WebAuthn authentication
   - Challenge generated
   - User authenticates with device
   - Credential verified against stored public key
   - Session token created

**Security Measures:**
- Counter verification to prevent replay attacks
- Device verification
- Secure session management
- Failed attempt tracking

## Audit and Logging

Our system implements comprehensive audit logging for security events that complies with ISO/IEC 27001 standards:

### ISO/IEC 27001 Compliant Audit Trail

**Implementation:**
- Standardized action codes for all authentication operations
- Comprehensive event capture across the entire authentication lifecycle
- Detailed metadata collection including IP addresses and device information
- Consistent format for all audit events with ISO 27001 compliance flags
- Full traceability from request initiation to completion

**Authentication Events Logged:**

1. **Passphrase Registration:**
   - Success events (PASSPHRASE_REGISTER_SUCCESS)
   - Validation failures (PASSPHRASE_REGISTER_VALIDATION_FAILED)
   - Email verification status (PASSPHRASE_REGISTER_EMAIL_NOT_VERIFIED)
   - Verification expiration (PASSPHRASE_REGISTER_VERIFICATION_EXPIRED)
   - Duplicate registration attempts (PASSPHRASE_REGISTER_USER_EXISTS)
   - Rate limiting events (PASSPHRASE_REGISTER_RATE_LIMIT)
   - Unhandled errors (PASSPHRASE_REGISTER_UNHANDLED_ERROR)

2. **Passphrase Reset:**
   - Reset requests (PASSPHRASE_RESET_REQUEST_SUCCESS)
   - Unknown user attempts (PASSPHRASE_RESET_REQUEST_UNKNOWN_USER)
   - Email delivery failures (PASSPHRASE_RESET_EMAIL_FAILED)
   - Successful resets (PASSPHRASE_RESET_SUCCESS)
   - Invalid requests (PASSPHRASE_RESET_INVALID_REQUEST)
   - Token validation failures (PASSPHRASE_RESET_INVALID_TOKEN)
   - Token expiration (PASSPHRASE_RESET_EXPIRED_TOKEN)

3. **WebAuthn Registration:**
   - Registration initiation (WEBAUTHN_REGISTER_START)
   - User creation events (WEBAUTHN_REGISTER_USER_CREATED)
   - Role assignment (WEBAUTHN_REGISTER_ROLE_ASSIGNED)
   - Verification success (WEBAUTHN_REGISTRATION_SUCCESS)
   - Verification failures (WEBAUTHN_REGISTRATION_VERIFICATION_FAILURE)
   - Credential storage (WEBAUTHN_REGISTER_CREATE_CREDENTIAL)

**Data Captured in Each Log:**
- Actor identifier and type (user ID or anonymous)
- Operation type (registration, reset, authentication)
- Standardized action code
- Request metadata (path, method, status code)
- Client IP address with forwarding detection
- Full user agent with parsed device information
- Timestamp with millisecond precision
- Success/failure indicator
- Detailed error information when applicable
- Compliance flags (ISO27001, GDPR)

**Security Benefits:**
- Complete audit trail for security investigations
- Evidence for compliance with regulatory requirements
- Detection of suspicious behavior patterns
- Forensic information for incident response
- Performance and security monitoring
- User activity reconstruction for dispute resolution

**Cookie Management for Security:**
- Automatic removal of verification cookies after successful operations
- Proper cleanup of authentication artifacts
- Reduced attack surface through minimized persistent state

## Encryption Implementation

Our encryption system uses the following approach:

```javascript
// Encryption
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
let encrypted = cipher.update(data, 'utf8', 'base64');
encrypted += cipher.final('base64');
const authTag = cipher.getAuthTag().toString('base64');
return `${encrypted}:${iv.toString('base64')}:${authTag}`;

// Decryption
const [encryptedData, ivBase64, authTagBase64] = encryptedString.split(':');
const iv = Buffer.from(ivBase64, 'base64');
const authTag = Buffer.from(authTagBase64, 'base64');
const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
decipher.setAuthTag(authTag);
let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
decrypted += decipher.final('utf8');
return decrypted;
```

**Security Features:**
- GCM mode provides authentication
- Unique IV for each encryption
- Auth tag verification prevents tampering
- Base64 encoding for safe storage

## Security Best Practices

The codebase follows these security best practices:

1. **Environment Variable Management**
   - Sensitive keys stored in environment variables
   - No hardcoded secrets
   - Separate development and production environments

2. **Error Handling**
   - Graceful failure modes
   - Limited error information in production
   - Detailed internal logging
   - Safe decryption fallbacks

3. **Input Validation**
   - Request body validation
   - Type checking
   - Length and format restrictions
   - Sanitization of user inputs

4. **Session Management**
   - Secure cookie settings
   - Token-based authentication
   - Limited session duration
   - Secure token generation

## Conclusion

The NFE-Modus security architecture is built on a foundation of internationally recognized standards and best practices. By implementing these standards throughout our codebase, we provide a comprehensive security architecture that protects user privacy while enabling powerful functionality.

Our WebAuthn implementation, combined with email encryption and secure data storage, ensures that users can trust our platform with their sensitive information. As threats evolve, we continue to enhance our security measures while maintaining compatibility with international standards.