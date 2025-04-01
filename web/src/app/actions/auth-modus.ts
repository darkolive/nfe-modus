"use server"

import { fetchQuery } from "../actions";
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';

// Custom type to accommodate both WebAuthn response formats
export type WebAuthnRegistrationResponse = {
  id: string;
  rawId: string;
  response: {
    attestationObject?: string;
    clientDataJSON: string;
    transports?: string[];
  } | Record<string, unknown>;
  type: string;
  clientExtensionResults?: Record<string, unknown>;
  authenticatorAttachment?: string;
};

// Type for WebAuthn authentication response
export type WebAuthnAuthenticationResponse = {
  id: string;
  rawId: string;
  response: {
    authenticatorData?: string;
    clientDataJSON: string;
    signature?: string;
    userHandle?: string;
  } | Record<string, unknown>;
  type: string;
  clientExtensionResults?: Record<string, unknown>;
};

/**
 * Send OTP email for authentication
 */
export async function sendOtpEmail(
  email: string
): Promise<{ success: boolean; error?: string; message?: string; cookie?: string }> {
  try {
    const graphqlQuery = `
      query GenerateOTP($req: GenerateOTPRequestInput!) {
        generateOTP(req: $req) {
          success
          message
          cookie
        }
      }
    `;

    // We need to get the cookie value from the response
    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { email } },
    });

    if (error) {
      console.error("Error sending OTP:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to send OTP" };
    }

    // Return the cookie value for the client to use in verification
    if (data?.generateOTP) {
      return {
        success: data.generateOTP.success,
        message: data.generateOTP.message,
        cookie: data.generateOTP.cookie,
        error: data.generateOTP.success ? undefined : data.generateOTP.message
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error sending OTP:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to send OTP";
    return { success: false, error: errorMessage };
  }
}

/**
 * Verifies an OTP code
 */
export async function verifyOtp(
  email: string, 
  otp: string,
  cookie: string
): Promise<{
  success: boolean;
  error?: string;
  token?: string;
  userId?: string;
  cookie?: string;
  isNewUser?: boolean;
}> {
  try {
    const graphqlQuery = `
      query VerifyOTP($req: VerifyOTPRequestInput!) {
        verifyOTP(req: $req) {
          success
          message
          token
          user {
            uID
          }
          verificationCookie
        }
      }
    `;

    // The Modus API requires the cookie to be passed in the request
    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { oTP: otp, cookie } },
    });

    if (error) {
      console.error("Error verifying OTP:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to verify OTP" };
    }

    if (data?.verifyOTP) {
      // The verification cookie contains isNewUser flag when decoded
      // We'll check for indicators of a new user in the response
      const verificationCookie = data.verifyOTP.verificationCookie || '';
      
      // Attempt to determine if this is a new user from the cookie
      // Typically new users will have a different message pattern or no verification history
      const isNewUser = checkIfNewUserFromCookie(verificationCookie);
      
      return {
        success: data.verifyOTP.success,
        token: data.verifyOTP.token,
        userId: data.verifyOTP.user?.uID,
        cookie: verificationCookie,
        isNewUser,
        error: data.verifyOTP.success ? undefined : data.verifyOTP.message
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error verifying OTP:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to verify OTP";
    return { success: false, error: errorMessage };
  }
}

/**
 * Attempts to determine if a user is new from the verification cookie
 * The cookie contains a VerificationInfo object with isNewUser flag
 */
function checkIfNewUserFromCookie(cookie: string): boolean {
  if (!cookie) return false;
  
  try {
    // The cookie is base64 encoded - we can check for the isNewUser flag
    // Format is typically: base64({"email":"user@example.com","verifiedAt":"timestamp","method":"OTP","isNewUser":true})
    const decodedCookie = atob(cookie);
    return decodedCookie.includes('"isNewUser":true');
  } catch (e) {
    console.error("Error parsing verification cookie:", e);
    return false;
  }
}

/**
 * Checks if a user exists by email
 */
export async function checkUserExists(
  email: string
): Promise<{ exists: boolean; error?: string }> {
  try {
    // Use the signInWebAuthn endpoint to check user existence
    // This doesn't send emails or generate OTPs, just validates user existence
    const graphqlQuery = `
      query CheckUserExists($email: String!) {
        signInWebAuthn(req: { 
          email: $email, 
          clientIP: "0.0.0.0", 
          userAgent: "check-only", 
          sessionID: "check-only" 
        }) {
          success
          error
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { email },
    });

    if (error) {
      // If there's an error specifically saying the user doesn't exist, handle that
      if (error instanceof Error && error.message.includes("user not found")) {
        return { exists: false };
      }
      
      console.error("Error checking user:", error);
      return { 
        exists: false, 
        error: error instanceof Error ? error.message : "Failed to check user" 
      };
    }

    // If the query succeeded, the user exists
    return { 
      exists: data?.signInWebAuthn?.success === true,
      error: data?.signInWebAuthn?.error
    };
  } catch (error: unknown) {
    console.error("Error checking user:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error checking user";
    return { exists: false, error: errorMessage };
  }
}

/**
 * Get WebAuthn register options
 */
export async function getWebAuthnRegisterOptions(
  email: string,
  displayName?: string
): Promise<{
  success: boolean;
  options?: PublicKeyCredentialCreationOptionsJSON;
  error?: string;
  userExists?: boolean;
}> {
  try {
    const graphqlQuery = `
      query RegisterWebAuthn($req: RegisterWebAuthnRequestInput!) {
        registerWebAuthn(req: $req) {
          success
          error
          message
          credentialOptions {
            challenge
            rpName
            rpID
            userID
            userName
            userDisplay
            timeout
            excludeKeys
            authenticatorParams
          }
          userExists
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { 
        req: { 
          email, 
          displayName: displayName || email 
        } 
      },
    });

    if (error) {
      console.error("Error getting WebAuthn register options:", error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to get WebAuthn registration options" 
      };
    }

    if (data?.registerWebAuthn) {
      const result = data.registerWebAuthn;
      
      // Get credential options directly from the response
      // No need to parse as JSON since GraphQL already returns the structured data
      const credentialOptions = result.credentialOptions;

      return { 
        success: result.success, 
        options: credentialOptions as PublicKeyCredentialCreationOptionsJSON,
        userExists: result.userExists,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error getting WebAuthn registration options:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to get WebAuthn registration options";
    return { success: false, error: errorMessage };
  }
}

/**
 * Verify WebAuthn registration
 */
export async function verifyWebAuthnRegistration(
  email: string,
  response: WebAuthnRegistrationResponse,
  deviceName: string,
  deviceType: string,
  isBiometric: boolean,
  marketingConsent?: boolean
): Promise<{
  success: boolean;
  error?: string;
  message?: string;
  token?: string;
}> {
  try {
    const graphqlQuery = `
      query VerifyWebAuthnRegistration($req: VerifyWebAuthnRegistrationRequestInput!) {
        verifyWebAuthnRegistration(req: $req) {
          success
          error
          message
          token
        }
      }
    `;

    // The response needs to be serialized to be sent correctly
    const serializedResponse = JSON.stringify(response);

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { 
        req: { 
          email,
          response: serializedResponse,
          deviceName,
          deviceType,
          isBiometric,
          marketingConsent: marketingConsent || false
        } 
      },
    });

    if (error) {
      console.error("Error verifying WebAuthn registration:", error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to verify WebAuthn registration" 
      };
    }

    if (data?.verifyWebAuthnRegistration) {
      const result = data.verifyWebAuthnRegistration;
      return {
        success: result.success,
        message: result.message,
        token: result.token,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error verifying WebAuthn registration:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to verify WebAuthn registration";
    return { success: false, error: errorMessage };
  }
}

/**
 * Get WebAuthn authentication options
 */
export async function getWebAuthnAuthOptions(
  email: string
): Promise<{
  success: boolean;
  options?: PublicKeyCredentialRequestOptionsJSON;
  error?: string;
}> {
  try {
    const graphqlQuery = `
      query SignInWebAuthn($req: SignInWebAuthnRequestInput!) {
        signInWebAuthn(req: $req) {
          success
          error
          message
          credentialOptions {
            challenge
            rpName
            rpID
            userID
            userName
            userDisplay
            timeout
            excludeKeys
            authenticatorParams
          }
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { email } },
    });

    if (error) {
      console.error("Error getting WebAuthn auth options:", error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to get WebAuthn authentication options" 
      };
    }

    if (data?.signInWebAuthn) {
      const result = data.signInWebAuthn;
      
      // Get credential options directly from the response
      // No need to parse as JSON since GraphQL already returns the structured data
      const credentialOptions = result.credentialOptions;

      return { 
        success: result.success, 
        options: credentialOptions as PublicKeyCredentialRequestOptionsJSON,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error getting WebAuthn auth options:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to get WebAuthn authentication options";
    return { success: false, error: errorMessage };
  }
}

/**
 * Verify WebAuthn authentication
 */
export async function verifyWebAuthnAuthentication(
  email: string,
  response: WebAuthnAuthenticationResponse
): Promise<{
  success: boolean;
  error?: string;
  token?: string;
  cookie?: string;
  userId?: string;
}> {
  try {
    const graphqlQuery = `
      query VerifyWebAuthnAuthentication($req: VerifyWebAuthnAuthenticationRequestInput!) {
        verifyWebAuthnAuthentication(req: $req) {
          success
          error
          message
          token
          cookie
          user {
            uID
          }
        }
      }
    `;

    // The response needs to be serialized to be sent correctly
    const serializedResponse = JSON.stringify(response);

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { 
        req: { 
          email,
          response: serializedResponse
        } 
      },
    });

    if (error) {
      console.error("Error verifying WebAuthn authentication:", error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to verify WebAuthn authentication" 
      };
    }

    if (data?.verifyWebAuthnAuthentication) {
      const result = data.verifyWebAuthnAuthentication;
      return {
        success: result.success,
        token: result.token,
        cookie: result.cookie,
        userId: result.user?.uID,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error verifying WebAuthn authentication:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to verify WebAuthn authentication";
    return { success: false, error: errorMessage };
  }
}

/**
 * Authenticate with passphrase
 */
export async function authenticateWithPassphrase(
  email: string,
  passphrase: string
): Promise<{
  success: boolean;
  error?: string;
  token?: string;
  cookie?: string;
  userId?: string;
}> {
  try {
    const graphqlQuery = `
      query SigninPassphrase($req: SigninPassphraseRequestInput!) {
        signinPassphrase(req: $req) {
          success
          error
          message
          token
          cookie
          user {
            uID
          }
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { email, passphrase } },
    });

    if (error) {
      console.error("Error authenticating with passphrase:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to authenticate" };
    }

    if (data?.signinPassphrase) {
      const result = data.signinPassphrase;
      return {
        success: result.success,
        token: result.token,
        cookie: result.cookie,
        userId: result.user?.uID,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error authenticating with passphrase:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to authenticate";
    return { success: false, error: errorMessage };
  }
}

/**
 * Setup passphrase
 */
export async function setupPassphrase(
  email: string,
  passphrase: string,
  marketingConsent: boolean
): Promise<{
  success: boolean;
  error?: string;
  token?: string;
  cookie?: string;
  userId?: string;
}> {
  try {
    const graphqlQuery = `
      query SetupPassphrase($req: SetupPassphraseRequestInput!) {
        setupPassphrase(req: $req) {
          success
          error
          message
          token
          cookie
          user {
            uID
          }
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { email, passphrase, marketingConsent } },
    });

    if (error) {
      console.error("Error setting up passphrase:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to set up passphrase" };
    }

    if (data?.setupPassphrase) {
      const result = data.setupPassphrase;
      return {
        success: result.success,
        token: result.token,
        cookie: result.cookie,
        userId: result.user?.uID,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error setting up passphrase:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to set up passphrase";
    return { success: false, error: errorMessage };
  }
}

/**
 * Request passphrase reset
 */
export async function requestPassphraseReset(
  email: string
): Promise<{ success: boolean; error?: string; message?: string }> {
  try {
    const graphqlQuery = `
      query RequestPassphraseReset($req: RequestPassphraseResetRequestInput!) {
        requestPassphraseReset(req: $req) {
          success
          error
          message
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { email } },
    });

    if (error) {
      console.error("Error requesting passphrase reset:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to request passphrase reset" };
    }

    if (data?.requestPassphraseReset) {
      const result = data.requestPassphraseReset;
      return {
        success: result.success,
        message: result.message,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error requesting passphrase reset:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to request passphrase reset";
    return { success: false, error: errorMessage };
  }
}

/**
 * Reset passphrase with token
 */
export async function resetPassphrase(
  token: string,
  passphrase: string
): Promise<{ success: boolean; error?: string; message?: string }> {
  try {
    const graphqlQuery = `
      query ResetPassphrase($req: ResetPassphraseRequestInput!) {
        resetPassphrase(req: $req) {
          success
          error
          message
        }
      }
    `;

    const { data, error } = await fetchQuery({
      query: graphqlQuery,
      variables: { req: { token, passphrase } },
    });

    if (error) {
      console.error("Error resetting passphrase:", error);
      return { success: false, error: error instanceof Error ? error.message : "Failed to reset passphrase" };
    }

    if (data?.resetPassphrase) {
      const result = data.resetPassphrase;
      return {
        success: result.success,
        message: result.message,
        error: result.success ? undefined : (result.error || result.message)
      };
    }

    return { success: false, error: "Invalid response from server" };
  } catch (error: unknown) {
    console.error("Error resetting passphrase:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to reset passphrase";
    return { success: false, error: errorMessage };
  }
}
