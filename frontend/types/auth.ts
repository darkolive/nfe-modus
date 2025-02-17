export interface AuthSession {
  did: string;
  challenge: string;
}

export interface AuthResponse {
  token?: string;
  session: AuthSession;
  needsVerification?: boolean;
}

export interface DeviceCredential {
  did: string;
  userHash: string;
  deviceId: string;
  publicKey: string;
  lastSyncTime: string;
  isVerified: boolean;
  isRevoked: boolean;
}

export interface APIError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}
