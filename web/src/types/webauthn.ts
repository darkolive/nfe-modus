import { AuthenticatorTransportFuture } from "@simplewebauthn/server";

export interface CredentialData {
  uid: string;
  credentialID: string;
  credentialPublicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  lastUsed: Date | null;
  createdAt: Date;
  updatedAt: Date | null;
  name: string;
  isBiometric: boolean;
  deviceType: string;
  deviceInfo: string;
  userId: string;
}

export interface Challenge {
  email: string;
  challenge: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface UserData {
  email: string;
  did: string;
  verified: boolean;
  emailVerified: Date | null;
  dateJoined: Date;
  lastAuthTime: Date | null;
  status: 'active' | 'inactive' | 'locked';
  hasWebAuthn: boolean;
  hasPassphrase: boolean;
  roles: string[];
  mfaEnabled: boolean;
  failedLoginAttempts: number;
  lastFailedLogin: Date | null;
  lockedUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
}
