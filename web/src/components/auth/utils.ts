import { webcrypto } from 'node:crypto';

export const COOKIE_MAX_AGE = 5 * 60; // 5 minutes in seconds

interface OtpData {
  email: string;
  otp: string;
  expiresAt: number;
}

export function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// AES-GCM requires a 32-byte key
function getEncryptionKey(): Uint8Array {
  const key = process.env.ENCRYPTION_KEY || 'default-key-must-be-32-bytes-long!!';
  // Ensure key is exactly 32 bytes by hashing it
  const keyBuffer = new TextEncoder().encode(key);
  const hash = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    hash[i] = keyBuffer[i % keyBuffer.length];
  }
  return hash;
}

export async function encrypt(data: string): Promise<string> {
  const key = await webcrypto.subtle.importKey(
    'raw',
    getEncryptionKey(),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(data);

  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  const encryptedData = new Uint8Array(iv.length + ciphertext.byteLength);
  encryptedData.set(iv);
  encryptedData.set(new Uint8Array(ciphertext), iv.length);

  return Buffer.from(encryptedData).toString('base64');
}

export async function decrypt(encryptedData: string): Promise<string> {
  const key = await webcrypto.subtle.importKey(
    'raw',
    getEncryptionKey(),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const data = Buffer.from(encryptedData, 'base64');
  const iv = data.subarray(0, 12);
  const ciphertext = data.subarray(12);

  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

export async function createOtpData(email: string, otp: string): Promise<string> {
  const data: OtpData = {
    email,
    otp,
    expiresAt: Date.now() + COOKIE_MAX_AGE * 1000
  };

  return encrypt(JSON.stringify(data));
}

export async function verifyOtpData(email: string, submittedOtp: string, encryptedData: string): Promise<boolean> {
  try {
    const decrypted = await decrypt(encryptedData);
    const data: OtpData = JSON.parse(decrypted);

    return (
      data.email === email &&
      data.otp === submittedOtp &&
      data.expiresAt > Date.now()
    );
  } catch {
    return false;
  }
}
