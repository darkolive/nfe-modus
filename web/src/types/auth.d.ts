// Base user interface
export interface User {
  id: string;
  email: string;
  did?: string;
  name?: string;
  verified?: boolean;
  hasWebAuthn?: boolean;
  hasPassphrase?: boolean;
  passwordHash?: string;
  passwordSalt?: string;
  recoveryEmail?: string;
  mfaEnabled?: boolean;
  mfaMethod?: string;
  mfaSecret?: string;
  failedLoginAttempts?: number;
  lastFailedLogin?: string;
  lockedUntil?: string;
}

// Session interface
export interface Session {
  user: {
    id: string;
    email: string;
    did?: string;
    name?: string;
    hasWebAuthn?: boolean;
    hasPassphrase?: boolean;
    roles?: string[];
  };
}

// DGraph client params
export interface DgraphClientParams {
  endpoint: string;
  authToken?: string;
  graphqlEndpoint?: string;
}

// Challenge data
export interface ChallengeData {
  id: string;
  challenge: string;
  email: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
}

import type { CredentialDeviceType, AuthenticatorTransportFuture, Base64URLString } from "@simplewebauthn/server";

// Credential data
export interface CredentialData {
  uid?: string;
  credentialID: Base64URLString;
  credentialPublicKey: Base64URLString;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  createdAt: Date;
  lastUsed?: Date;
  userId: string;
  isBiometric?: boolean;
  name?: string;
  deviceType: CredentialDeviceType;
  deviceInfo: string;
}

// User data
export interface UserData {
  id?: string;
  email: string;
  name?: string;
  did?: string;
  verified?: boolean;
  emailVerified?: Date;
  dateJoined?: Date;
  lastAuthTime?: Date;
  status?: string;
  hasWebAuthn?: boolean;
  hasPassphrase?: boolean;
  passwordHash?: string;
  passwordSalt?: string;
  recoveryEmail?: string;
  mfaEnabled?: boolean;
  mfaMethod?: string;
  mfaSecret?: string;
  failedLoginAttempts?: number;
  lastFailedLogin?: string;
  lockedUntil?: string;
  preferences?: {
    marketingEmails?: boolean;
    notificationEmails?: boolean;
  };
}

// WebAuthn verification result
export interface WebAuthnVerificationResult {
  verified: boolean;
  error?: string;
  credentialID?: string;
  userId?: string;
  publicKey?: string;
}

// OTP verification result
export interface OtpVerificationResult {
  success: boolean;
  error?: string;
}

// Audit log data
export interface AuditLogData {
  id: string;
  userId: string;
  action: string;
  details: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
}

// Session token data
export interface SessionTokenData {
  id: string;
  userId: string;
  token: string;
  expiresAt: string;
  createdAt: string;
  lastUsed?: string;
  ipAddress?: string;
  userAgent?: string;
  isRevoked?: boolean;
}

// Password reset token data
export interface PasswordResetTokenData {
  id: string;
  userId: string;
  token: string;
  expiresAt: string;
  createdAt: string;
  isUsed: boolean;
}

// MFA verification data
export interface MFAVerificationData {
  success: boolean;
  error?: string;
  userId?: string;
}
