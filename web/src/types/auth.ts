import type { AuthenticatorTransportFuture, Base64URLString } from "@simplewebauthn/types";

export interface Challenge {
  email: string;
  challenge: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface CredentialData {
  uid: string;
  userId: string;
  credentialID: string;
  credentialPublicKey: string;
  counter: number;
  transports: string[];
  lastUsed: Date;
  createdAt: Date;
  name: string;
  isBiometric: boolean;
  deviceType: string;
  deviceInfo: string;
}

export interface User {
  id: string;
  email: string;
  name?: string;
  did: string;
  verified: boolean;
  dateJoined: Date;
  status: "active" | "inactive" | "suspended";
  hasWebAuthn: boolean;
  hasPassphrase: boolean;
  mfaEnabled: boolean;
  failedLoginAttempts: number;
  roles: string[];
}

export interface UserData extends Omit<User, "id"> {}

export interface SessionData {
  id: string;
  email: string;
  roles: string[];
  [key: string]: unknown;
}

export interface AuditLogInput {
  userId: string;
  action: string;
  details: string;
  ipAddress: string;
  userAgent: string;
  timestamp?: Date;
  metadata?: Record<string, unknown>;
}

export interface AuditLog extends AuditLogInput {
  id: string;
  createdAt: Date;
}

export interface AuditLogData {
  id: string;
  userId: string;
  action: string;
  status: "success" | "error";
  email: string;
  metadata?: Record<string, unknown>;
  details?: Record<string, unknown>;
  method?: string;
  createdAt: Date;
}

export interface PassphraseData {
  hash: string;
  salt: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface RegistrationOptions {
  challenge: Base64URLString;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: {
    alg: number;
    type: "public-key";
  }[];
  timeout: number;
  attestation: "direct" | "indirect" | "none";
  excludeCredentials: {
    id: Base64URLString;
    type: "public-key";
    transports?: AuthenticatorTransportFuture[];
  }[];
  authenticatorSelection: {
    authenticatorAttachment?: "platform" | "cross-platform";
    requireResidentKey?: boolean;
    residentKey?: "required" | "preferred" | "discouraged";
    userVerification?: "required" | "preferred" | "discouraged";
  };
}

export interface DgraphClientParams {
  endpoint: string;
  authToken: string;
}

export interface DQLResponse<T> {
  data: T;
}

export interface DgraphClient {
  getUserByEmail(email: string): Promise<User | null>;
  getUserCredentials(userId: string): Promise<CredentialData[]>;
  createUser(userData: UserData): Promise<string>;
  deleteChallenge(email: string): Promise<void>;
  storeChallenge(challenge: Challenge): Promise<void>;
  getChallenge(email: string): Promise<Challenge | null>;
  isAccountLocked(email: string): Promise<boolean>;
  incrementFailedLoginAttempts(email: string): Promise<void>;
  getUserRoles(userId: string): Promise<string[]>;
  getLatestChallenge(email: string): Promise<Challenge | null>;
  getAllChallenges(email: string): Promise<Challenge[]>;
  executeDQLQuery<T>(query: string, vars?: Record<string, any>): Promise<T>;
}
