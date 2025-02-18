export interface AuthSession {
  did: string;
  challenge?: string;
  otpId?: string;
}

export interface AuthResponse {
  token?: string;
  session: AuthSession;
  needsVerification?: boolean;
  message?: string;
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
  message: string;
  code?: string;
  status?: number;
}
