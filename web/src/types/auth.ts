import type { AuthenticatorTransportFuture, Base64URLString } from "@simplewebauthn/server";

// Raw types as stored in Dgraph
export interface Challenge {
  email: string;
  challenge: string;  // @index(exact) - stored as base64url string in Dgraph
  timestamp: datetime;
  expiresAt: datetime;
  userId: string;
}

// Raw types as stored in Dgraph
export interface Device {
  credentialID: string;  // @index(exact) - stored as base64url string in Dgraph
  credentialPublicKey: string;  // stored as base64url string in Dgraph
  counter: number;
  transports: string[];  // [string] in Dgraph schema
  lastUsed: datetime;
  deviceName: string;
  isBiometric: boolean;
  deviceType: string;
  deviceInfo: string;
  userId: string;
}

// WebAuthn runtime types (not storage)
export interface WebAuthnDevice {
  credentialID: Base64URLString;
  credentialPublicKey: Base64URLString;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  lastUsed: datetime;
  deviceName: string;
  isBiometric: boolean;
  deviceType: string;
  deviceInfo: string;
  userId: string;
}

// WebAuthn authentication types from Dgraph schema
export interface StartAuthenticationRequest {
  email: string;
}

export interface StartAuthenticationResponse {
  success: boolean;
  message: string;
  challenge: string;  // Matches startAuth.challenge in Dgraph
}

export interface VerifyPasskeyRequest {
  email: string;
  deviceID: string;
  assertionData: string;  // Matches verifyPasskey.assertionData in Dgraph
}

export interface VerifyPasskeyResponse {
  success: boolean;
  message: string;
  token: string;
  user: { uid: string };
}

export interface VerifyOTPResponse {
  success: boolean;
  message: string;
  token: string;
  user: { uid: string };
}

export interface User {
  email: string;  // @index(exact)
  did: string;  // @index(exact)
  name: string | null;
  verified: boolean;
  emailVerified: datetime | null;
  dateJoined: datetime;
  lastAuthTime: datetime | null;
  status: string;  // @index(exact)
  hasWebAuthn: boolean;
  hasPassphrase: boolean;
  passwordHash: string | null;
  passwordSalt: string | null;
  recoveryEmail: string | null;
  mfaEnabled: boolean;
  mfaMethod: string | null;
  mfaSecret: string | null;
  failedLoginAttempts: number;
  lastFailedLogin: datetime | null;
  lockedUntil: datetime | null;
  roles: Array<{ uid: string }>;  // [uid] @reverse
  createdAt: datetime;
  updatedAt: datetime | null;
  devices: Array<{ uid: string }>;  // [uid] @reverse
}

// Matches Dgraph AuthenticationSession type
export interface AuthenticationSession {
  id: string;  // @index(hash) @upsert
  userDID: string;
  token: string;  // @index(hash)
  deviceID: string;
  createdAt: datetime;
  expiresAt: datetime;
  user: { uid: string };  // @reverse
}

// Runtime session data (not storage)
export interface SessionData {
  id: string;
  userId: string;
  email: string;
  name?: string; // User's name for personalization
  deviceId: string;
  roles: string[];
}

export interface AuditLogInput {
  userId: string;
  details: string;
  ipAddress: string;
  userAgent: string;
  timestamp?: datetime;
  metadata?: Record<string, unknown>;
}

export interface AuditLog extends AuditLogInput {
  action: string;
  timestamp: datetime;
}

export interface DgraphClientParams {
  apiEndpoint: string;
  apiKey: string;
  debug?: boolean;
}

export interface DgraphClient {
  // User management
  getUserByEmail(email: string): Promise<User | null>;
  createUser(user: Partial<User>): Promise<string>;
  updateUser(userId: string, updates: Partial<User>): Promise<void>;
  updateUserHasWebAuthn(userId: string, hasWebAuthn: boolean): Promise<void>;
  
  // Challenge handling
  storeChallenge(challenge: Challenge): Promise<void>;
  getChallenge(email: string): Promise<Challenge | null>;
  deleteChallenge(email: string): Promise<void>;
  getLatestChallenge(email: string): Promise<Challenge | null>;
  getAllChallenges(email: string): Promise<Challenge[]>;
  
  // Security
  isAccountLocked(email: string): Promise<boolean>;
  incrementFailedLoginAttempts(email: string): Promise<void>;
  resetFailedLoginAttempts(userId: string): Promise<void>;
  
  // Email verification
  getVerifiedEmail(email: string): Promise<string | null>;
  storeVerifiedEmail(email: string, timestamp: datetime): Promise<void>;
  deleteVerifiedEmail(email: string): Promise<void>;
  
  // Passphrase management
  storePassphraseHash(userId: string, hash: string, salt: string): Promise<void>;
  
  // Role management
  getUserRoles(userId: string): Promise<Array<{ uid: string }>>;
  getRolePermissions(roleId: string): Promise<string[]>;
  assignRoleToUser(userId: string, roleId: string): Promise<void>;
  
  // WebAuthn methods
  getUserDevices(userId: string): Promise<Device[]>;  // Returns raw Dgraph devices
  getUserCredentials(userId: string): Promise<WebAuthnDevice[]>;  // Returns converted WebAuthn devices
  storeCredential(credential: Device): Promise<void>;  // Takes raw Dgraph device
  updateCredentialCounter(credentialId: string, counter: number): Promise<void>;
  
  // Session management
  createAuthenticationSession(session: Omit<AuthenticationSession, 'id'>): Promise<string>;
  getAuthenticationSession(id: string): Promise<AuthenticationSession | null>;
  deleteAuthenticationSession(id: string): Promise<void>;
  
  // Generic query
  executeDQLQuery<T>(query: string, vars?: Record<string, unknown>): Promise<T>;
}

// Type alias for Dgraph datetime type
type datetime = Date;
