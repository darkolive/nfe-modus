import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { verifyAuthentication } from "@/lib/webauthn";
import { createSessionToken } from "@/lib/jwt";
import { type AuthenticationResponseJSON, type Base64URLString } from "@simplewebauthn/types";
import { z } from "zod";
import logger from "@/lib/logger";

// Input validation schema following Skeleton v3 patterns
const AuthenticateVerifySchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  response: z.object({
    id: z.string().refine((val): val is Base64URLString => {
      // Base64URL format: Only contains A-Z, a-z, 0-9, -, _, and no padding
      return /^[A-Za-z0-9\-_]+$/.test(val);
    }, "ID must be in base64url format"),
    rawId: z.string().refine((val): val is Base64URLString => {
      // Base64URL format: Only contains A-Z, a-z, 0-9, -, _, and no padding
      return /^[A-Za-z0-9\-_]+$/.test(val);
    }, "Raw ID must be in base64url format"),
    response: z.object({
      clientDataJSON: z.string(),
      authenticatorData: z.string(),
      signature: z.string(),
      userHandle: z.string().optional(),
    }).passthrough(),
    clientExtensionResults: z.object({}),
    type: z.literal("public-key"),
  }),
});

export async function POST(request: Request) {
  try {
    // Get client IP for logging
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // Parse and validate input
    const body = await request.json();
    const result = AuthenticateVerifySchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid WebAuthn authentication input", {
        action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
        ip,
        error: result.error.format(),
      });
      return NextResponse.json(
        {
          success: false,
          error: "Please check your input",
          details: result.error.format(),
          fields: Object.keys(result.error.format()).filter(k => k !== "_errors"),
        },
        { status: 400 }
      );
    }

    const { email, response } = result.data;
    const client = new DgraphClient();

    // Get user, challenge, and credentials
    const user = await client.getUserByEmail(email);
    const challenge = await client.getChallenge(email);
    
    if (!user) {
      logger.error("User not found", {
        action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "User not found",
          details: "No user found with this email address",
        },
        { status: 404 }
      );
    }

    if (!challenge) {
      logger.error("Challenge not found or expired", {
        action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Authentication session expired",
          details: "Please try authenticating again",
        },
        { status: 400 }
      );
    }

    // Find the credential being used
    const credentials = await client.getUserCredentials(user.id);
    const credential = credentials.find(cred => cred.credentialID === response.id);

    if (!credential) {
      logger.error("Credential not found", {
        action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Credential not found",
          details: "The security key used is not registered with this account",
        },
        { status: 404 }
      );
    }

    // The challenge from the database is already in base64url format
    const verification = await verifyAuthentication(
      response as AuthenticationResponseJSON,
      challenge.challenge,
      credential
    );

    if (!verification.verified) {
      logger.error("Authentication verification failed", {
        action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Authentication failed",
          details: "Unable to verify the security key",
        },
        { status: 400 }
      );
    }

    // Update the credential counter
    await client.updateCredentialCounter(
      credential.uid!,
      verification.authenticationInfo.newCounter
    );

    // Update user's last authentication time
    const now = new Date();
    const updates = {
      id: user.id,
      lastAuthTime: now,
      updatedAt: now,
      hasWebAuthn: true, // Ensure this is set since we've verified WebAuthn
    };
    await client.updateUser(updates);

    // Create session token
    const sessionData = {
      id: user.id,
      email: user.email,
      roles: user.roles,
      hasWebAuthn: true,
      hasPassphrase: user.hasPassphrase,
    };

    const token = await createSessionToken(sessionData);

    // Delete the challenge
    await client.deleteChallenge(email);

    logger.info("WebAuthn authentication verified", {
      action: "WEBAUTHN_AUTHENTICATION_VERIFY_SUCCESS",
      email,
      ip,
      userId: user.id,
    });

    return NextResponse.json(
      {
        success: true,
        token,
      },
      {
        headers: {
          "Set-Cookie": `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${60 * 60 * 24 * 7}`,
        },
      }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`WebAuthn authentication verification failed: ${message}`, {
      action: "WEBAUTHN_AUTHENTICATION_VERIFY_ERROR",
      error: message,
    });
    return NextResponse.json(
      {
        success: false,
        error: "Unable to verify authentication",
        details: message,
      },
      { status: 500 }
    );
  }
}
