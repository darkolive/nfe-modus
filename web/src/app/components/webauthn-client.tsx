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
} from "@simplewebauthn/server";

/**
 * Detects device information from the user agent
 * @returns Object containing device name, type, and detailed info
 */
export function detectDeviceInfo() {
  const userAgent = navigator.userAgent || "";
  let deviceName = "Unknown device";
  let deviceType = "unknown";
  let isBiometric = false;
  
  // Detect platform
  if (/iPhone/i.test(userAgent)) {
    deviceName = "iPhone";
    deviceType = "mobile";
    isBiometric = true; // iPhones typically use FaceID/TouchID
  } else if (/iPad/i.test(userAgent)) {
    deviceName = "iPad";
    deviceType = "tablet";
    isBiometric = true;
  } else if (/Android/i.test(userAgent)) {
    deviceName = "Android";
    deviceType = "mobile";
    if (/tablet|SM-T/i.test(userAgent)) {
      deviceName = "Android Tablet";
      deviceType = "tablet";
    }
  } else if (/Macintosh/i.test(userAgent)) {
    deviceName = "Mac";
    deviceType = "desktop";
    // Modern Macs often have TouchID
    if (/Mac OS X 10|Mac OS X 11|Mac OS X 12|macOS 11|macOS 12|macOS 13|macOS 14/i.test(userAgent)) {
      isBiometric = true;
    }
  } else if (/Windows/i.test(userAgent)) {
    deviceName = "Windows PC";
    deviceType = "desktop";
    // Windows Hello potentially available on modern Windows
    if (/Windows 10|Windows 11/i.test(userAgent)) {
      isBiometric = true;
    }
  } else if (/Linux/i.test(userAgent) && !/Android/i.test(userAgent)) {
    deviceName = "Linux Device";
    deviceType = "desktop";
  }
  
  // Make device name more specific if possible
  if (/Chrome/i.test(userAgent)) {
    deviceName += " (Chrome)";
  } else if (/Firefox/i.test(userAgent)) {
    deviceName += " (Firefox)";
  } else if (/Safari/i.test(userAgent) && !/Chrome/i.test(userAgent)) {
    deviceName += " (Safari)";
  } else if (/Edge|Edg/i.test(userAgent)) {
    deviceName += " (Edge)";
  }
  
  return {
    deviceName,
    deviceType,
    isBiometric,
    deviceInfo: userAgent
  };
}

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
): Promise<{ response: RegistrationResponseJSON, deviceInfo: ReturnType<typeof detectDeviceInfo> }> {
  try {
    // Start the registration process
    const response = await startRegistration({ optionsJSON: options });
    
    // Detect device information
    const deviceInfo = detectDeviceInfo();
    
    // Return both the response and device info
    return { response, deviceInfo };
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
