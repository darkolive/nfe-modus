export interface AuthSession {
  did: string
  challenge: string
  deviceId: string
  userEmail: string
}

export interface AuthResponse {
  token?: string
  session: AuthSession
  needsVerification?: boolean
}

export interface VerificationResponse {
  needsVerification: boolean
  session: AuthSession
}

export type AuthResult = AuthResponse | VerificationResponse;

export interface DeviceCredential {
  did: string
  userHash: string
  deviceId: string
  publicKey: string
  lastSyncTime: string
  isVerified: boolean
  isRevoked: boolean
}

export interface User {
  email: string
  deviceId: string
  did?: string
}

export interface WebAuthnOptions {
  challenge: string
  timeout: number
  rpId: string
  userVerification: UserVerificationRequirement;
}

export interface WebAuthnRegistrationResponse {
  creation: PublicKeyCredentialCreationOptions;
  session: AuthSession;
}

export interface APIError {
  code: string
  message: string
  details?: Record<string, unknown>
}
