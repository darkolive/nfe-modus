import { AuthenticatorTransportFuture } from "@simplewebauthn/server";

export interface CredentialData {
  uid: string;
  credentialID: string;
  credentialPublicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  lastUsed: string | null;
  createdAt: string;
  updatedAt: string | null;
  deviceName: string;  
  isBiometric: boolean;
  deviceType: string;
  deviceInfo: string;
  userId: string;
  "dgraph.type": string;  
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
  failedLoginAttempts: number;
  lastFailedLogin: Date | null;
  lockedUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
}
