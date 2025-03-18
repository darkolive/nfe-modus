import { NextRequest, NextResponse } from "next/server";
import { verifySessionToken } from "@/lib/jwt";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { verifyRegistration } from "@/lib/webauthn";
import { z } from "zod";

// Input validation schema
const requestSchema = z.object({
  email: z.string().email("Invalid email format"),
  response: z.any(),
  deviceName: z.string().optional(),
  deviceInfo: z.string().optional(),
});

/**
 * Endpoint to verify and add a new WebAuthn credential to an existing account
 * This is used when a user with a passphrase wants to add WebAuthn as an authentication method
 */
export async function POST(request: NextRequest) {
  try {
    // Get client IP for logging
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // Verify user is authenticated
    const sessionToken = request.cookies.get("session-token")?.value;
    if (!sessionToken) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    // Verify JWT
    let sessionPayload;
    try {
      sessionPayload = await verifySessionToken(sessionToken);
    } catch (error) {
      logger.error("Session token verification failed", {
        action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
        error: error instanceof Error ? error.message : String(error),
      });
      return NextResponse.json(
        { error: "Invalid session token" },
        { status: 401 }
      );
    }

    // Parse and validate input
    const body = await request.json();
    const validationResult = requestSchema.safeParse(body);

    if (!validationResult.success) {
      logger.warn(
        `Invalid WebAuthn add credential verify input: ${JSON.stringify(
          validationResult.error.errors
        )}`,
        {
          action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
          ip,
          error: "Invalid input",
        }
      );
      return NextResponse.json(
        {
          error: "Invalid input",
          details: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    const { email, response, deviceName = "Security Key", deviceInfo = "Web Browser" } = validationResult.data;

    // Verify the authenticated user is the same as the requested email
    if (sessionPayload.email !== email) {
      logger.warn(`Email mismatch in WebAuthn add credential verify request`, {
        action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
        ip,
        error: "Email mismatch",
      });
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 403 }
      );
    }

    const client = new DgraphClient();

    // Get user by email
    const user = await client.getUserByEmail(email);
    if (!user) {
      logger.warn(`User not found for WebAuthn add credential: ${email}`, {
        action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
        ip,
        error: "User not found",
      });
      return NextResponse.json(
        {
          error: "User not found",
          details: "No user found with this email address",
        },
        { status: 404 }
      );
    }

    // Verify the registration
    try {
      // Call verifyRegistration with all required parameters
      await verifyRegistration(
        user.id,
        email,
        deviceName,
        response,
        deviceInfo
      );
      
      // The verification process will store the credential in Dgraph
      // Now we need to update the user's WebAuthn status
      await client.updateUserHasWebAuthn(user.id, true);

      logger.info(`WebAuthn credential added for user: ${email}`, {
        action: "WEBAUTHN_ADD_CREDENTIAL_SUCCESS",
        ip,
        userId: user.id,
      });

      return NextResponse.json({
        success: true,
        message: "WebAuthn credential added successfully",
      });
    } catch (error) {
      logger.error(`Error verifying WebAuthn credential: ${error}`, {
        action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
        ip,
        userId: user.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return NextResponse.json(
        { error: "Failed to verify and add WebAuthn credential", details: error instanceof Error ? error.message : "Verification failed" },
        { status: 500 }
      );
    }
  } catch (error) {
    logger.error(`Error in WebAuthn add credential verify: ${error}`, {
      action: "WEBAUTHN_ADD_CREDENTIAL_VERIFY_ERROR",
      error: error instanceof Error ? error.message : String(error),
    });
    return NextResponse.json(
      { error: "Failed to verify and add WebAuthn credential" },
      { status: 500 }
    );
  }
}
