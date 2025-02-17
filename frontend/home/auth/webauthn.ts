import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { generateChallenge } from './crypto';

export interface WebAuthnOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  userVerification: UserVerificationRequirement;
}

export async function registerWebAuthnDevice(email: string, did: string) {
  const challenge = await generateChallenge();
  
  const options = await fetch('/api/auth/webauthn/register/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email,
      did,
      challenge 
    }),
  }).then(r => r.json());

  const attestation = await startRegistration(options);
  
  return fetch('/api/auth/webauthn/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email,
      did,
      attestation 
    }),
  }).then(r => r.json());
}

export async function authenticateWithWebAuthn(email: string) {
  const challenge = await generateChallenge();
  
  const options = await fetch('/api/auth/webauthn/authenticate/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email,
      challenge 
    }),
  }).then(r => r.json());

  const assertion = await startAuthentication(options);
  
  return fetch('/api/auth/webauthn/authenticate/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email,
      assertion 
    }),
  }).then(r => r.json());
}
