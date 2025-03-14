"use client";

import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/types";

/**
 * Client-side WebAuthn functions for use in React components
 */

/**
 * Starts the WebAuthn registration process
 *
 * @param options - The registration options from the server
 * @returns The registration response
 */
export async function registerWebAuthn(
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  try {
    // Start the registration process
    const response = await startRegistration({ optionsJSON: options });
    return response;
  } catch (error) {
    console.error("Error during WebAuthn registration:", error);
    throw error;
  }
}

/**
 * Starts the WebAuthn authentication process
 *
 * @param options - The authentication options from the server
 * @returns The authentication response
 */
export async function authenticateWebAuthn(
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<AuthenticationResponseJSON> {
  try {
    // Start the authentication process
    const response = await startAuthentication({ optionsJSON: options });
    return response;
  } catch (error) {
    console.error("Error during WebAuthn authentication:", error);
    throw error;
  }
}

/**
 * Checks if WebAuthn is available in the current browser
 *
 * @returns Whether WebAuthn is available
 */
export function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === "function"
  );
}

/**
 * Checks if the browser supports conditional UI for WebAuthn
 *
 * @returns Whether conditional UI is supported
 */
export async function isConditionalMediationSupported(): Promise<boolean> {
  if (!isWebAuthnAvailable()) {
    return false;
  }

  return (
    (await PublicKeyCredential.isConditionalMediationAvailable?.()) || false
  );
}
