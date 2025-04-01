/**
 * Helper functions for WebAuthn client-side operations
 */

export interface DeviceInfo {
  type: string;
  deviceName: string;
  isBiometric: boolean;
  userAgent: string;
}

/**
 * Detects information about the user's device for WebAuthn registration
 */
export function detectDeviceInfo(): DeviceInfo {
  // Only run in browser environment
  if (typeof window === 'undefined') {
    return {
      type: 'unknown',
      deviceName: 'unknown',
      isBiometric: false,
      userAgent: ''
    };
  }

  const userAgent = navigator.userAgent;
  const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
  const isTablet = /iPad|Android(?!.*Mobile)/i.test(userAgent);
  
  // Determine device type
  let type = 'desktop';
  if (isTablet) {
    type = 'tablet';
  } else if (isMobile) {
    type = 'mobile';
  }

  // Try to identify device name
  let deviceName = 'Unknown Device';
  
  // iOS
  if (/iPhone/.test(userAgent)) {
    deviceName = 'iPhone';
  } else if (/iPad/.test(userAgent)) {
    deviceName = 'iPad';
  } 
  // Android
  else if (/Android/.test(userAgent)) {
    const match = userAgent.match(/Android\s([0-9.]+)/);
    deviceName = match ? `Android ${match[1]}` : 'Android Device';
  }
  // Mac
  else if (/Mac/.test(navigator.platform)) {
    deviceName = 'Mac';
  }
  // Windows
  else if (/Win/.test(navigator.platform)) {
    deviceName = 'Windows';
  }
  // Linux
  else if (/Linux/.test(navigator.platform)) {
    deviceName = 'Linux';
  }

  // Check if the device likely has biometric capabilities
  const isBiometric = 
    // MacBooks with Touch ID
    (/Mac/.test(navigator.platform) && /Safari/.test(userAgent)) ||
    // Windows Hello compatible
    (/Windows/.test(userAgent) && /Chrome|Edge/.test(userAgent)) ||
    // iOS devices (all modern ones support biometric)
    /iPhone|iPad/.test(userAgent) ||
    // Android with fingerprint (likely)
    (/Android/.test(userAgent) && /Chrome/.test(userAgent));

  return {
    type,
    deviceName,
    isBiometric,
    userAgent
  };
}

/**
 * Converts a standard base64 string to base64url format
 * Replaces '+' with '-', '/' with '_', and removes '=' padding
 */
export function toBase64Url(base64: string): string {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Converts a base64url string to standard base64 format
 * Replaces '-' with '+', '_' with '/', and adds '=' padding
 */
export function fromBase64Url(base64url: string): string {
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  
  return base64;
}

/**
 * Converts a base64 string to an ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  // Convert base64url to base64 if needed
  if (base64.indexOf('-') !== -1 || base64.indexOf('_') !== -1) {
    base64 = fromBase64Url(base64);
  }
  
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Converts an ArrayBuffer to a base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Converts an ArrayBuffer to a base64url string
 */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  return toBase64Url(arrayBufferToBase64(buffer));
}

/**
 * Interface for WebAuthn options and responses
 */
export interface WebAuthnResponse {
  id: string;
  rawId: string;
  type: string;
  response: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Starts the WebAuthn registration process
 */
export async function startRegistration(options: Record<string, unknown>): Promise<WebAuthnResponse> {
  if (typeof window === 'undefined' || !options) {
    throw new Error('WebAuthn is not available or options are invalid');
  }

  // Clone the options for modification
  const publicKeyOptions: Record<string, unknown> = JSON.parse(JSON.stringify(options));

  // Process challenge if present (convert base64 to ArrayBuffer)
  if (typeof publicKeyOptions.challenge === 'string') {
    publicKeyOptions.challenge = base64ToArrayBuffer(publicKeyOptions.challenge);
  }
  
  // Process user data if present (convert id from base64 to ArrayBuffer)
  if (publicKeyOptions.user && typeof publicKeyOptions.user === 'object') {
    const user = publicKeyOptions.user as Record<string, unknown>;
    if (typeof user.id === 'string') {
      user.id = base64ToArrayBuffer(user.id);
    }
  }
  
  // Process exclude credentials if present (convert ids from base64 to ArrayBuffer)
  if (Array.isArray(publicKeyOptions.excludeCredentials)) {
    publicKeyOptions.excludeCredentials = publicKeyOptions.excludeCredentials.map(
      (cred: Record<string, unknown>) => ({
        ...cred,
        id: typeof cred.id === 'string' ? base64ToArrayBuffer(cred.id) : cred.id
      })
    );
  }

  try {
    // Request the browser to create a credential
    const credential = await navigator.credentials.create({
      publicKey: publicKeyOptions as unknown as PublicKeyCredentialCreationOptions
    });

    if (!credential) {
      throw new Error('Failed to create credential');
    }

    // Cast to PublicKeyCredential to access credential properties
    const pkCredential = credential as unknown as {
      id: string;
      rawId: ArrayBuffer;
      type: string;
      response: {
        attestationObject: ArrayBuffer;
        clientDataJSON: ArrayBuffer;
      };
    };

    // Convert the credential data to a format that can be sent to the server
    // Using base64url format as required by the Modus backend
    return {
      id: pkCredential.id,
      rawId: arrayBufferToBase64Url(pkCredential.rawId),
      type: pkCredential.type,
      response: {
        attestationObject: arrayBufferToBase64Url(pkCredential.response.attestationObject),
        clientDataJSON: arrayBufferToBase64Url(pkCredential.response.clientDataJSON),
      },
    };
  } catch (error) {
    console.error('WebAuthn registration error:', error);
    throw error;
  }
}

/**
 * Starts the WebAuthn authentication process
 */
export async function startAuthentication(options: Record<string, unknown>): Promise<WebAuthnResponse> {
  if (typeof window === 'undefined' || !options) {
    throw new Error('WebAuthn is not available or options are invalid');
  }

  // Clone the options for modification
  const publicKeyOptions: Record<string, unknown> = JSON.parse(JSON.stringify(options));
  
  // Process challenge if present (convert base64 to ArrayBuffer)
  if (typeof publicKeyOptions.challenge === 'string') {
    publicKeyOptions.challenge = base64ToArrayBuffer(publicKeyOptions.challenge);
  }
  
  // Process allow credentials if present (convert ids from base64 to ArrayBuffer)
  if (Array.isArray(publicKeyOptions.allowCredentials)) {
    publicKeyOptions.allowCredentials = publicKeyOptions.allowCredentials.map(
      (cred: Record<string, unknown>) => ({
        ...cred,
        id: typeof cred.id === 'string' ? base64ToArrayBuffer(cred.id) : cred.id
      })
    );
  }

  try {
    // Request the browser to get a credential
    const credential = await navigator.credentials.get({
      publicKey: publicKeyOptions as unknown as PublicKeyCredentialRequestOptions
    });

    if (!credential) {
      throw new Error('Failed to get credential');
    }

    // Cast to PublicKeyCredential to access credential properties
    const pkCredential = credential as unknown as {
      id: string;
      rawId: ArrayBuffer;
      type: string;
      response: {
        authenticatorData: ArrayBuffer;
        clientDataJSON: ArrayBuffer;
        signature: ArrayBuffer;
        userHandle: ArrayBuffer | null;
      };
    };

    // Convert the credential data to a format that can be sent to the server
    // Using base64url format as required by the Modus backend
    return {
      id: pkCredential.id,
      rawId: arrayBufferToBase64Url(pkCredential.rawId),
      type: pkCredential.type,
      response: {
        authenticatorData: arrayBufferToBase64Url(pkCredential.response.authenticatorData),
        clientDataJSON: arrayBufferToBase64Url(pkCredential.response.clientDataJSON),
        signature: arrayBufferToBase64Url(pkCredential.response.signature),
        userHandle: pkCredential.response.userHandle 
          ? arrayBufferToBase64Url(pkCredential.response.userHandle)
          : null,
      },
    };
  } catch (error) {
    console.error('WebAuthn authentication error:', error);
    throw error;
  }
}
