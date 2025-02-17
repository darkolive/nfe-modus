import { randomBytes } from 'crypto';

export async function generateChallenge(): Promise<string> {
  return Buffer.from(randomBytes(32)).toString('base64');
}

export async function hashPassword(password: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Buffer.from(hash).toString('hex');
}

export async function generateZKProof(password: string, challenge: string): Promise<string> {
  // This is a placeholder for actual ZK-SNARK implementation
  // We would use a library like snarkjs or circom here
  const proof = await hashPassword(password + challenge, 'zk-salt');
  return proof;
}
