import { NextResponse } from "next/server";
import { verifyRegistration, storeCredential } from "@/lib/webauthn";
import { DgraphClient } from "@/lib/dgraph";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";

// DGraph client for storing and retrieving user data
const dgraphClient = new DgraphClient();

// Input validation schema - using a more specific approach to avoid type issues
const requestSchema = z.object({
  email: z.string().email("Invalid email format"),
  response: z.object({
    id: z.string(),
    rawId: z.string(),
    type: z.string(),
    response: z.object({
      clientDataJSON: z.string(),
      attestationObject: z.string(),
      transports: z.array(z.string()).optional(),
    }),
    authenticatorAttachment: z.string().optional(),
    clientExtensionResults: z.record(z.unknown()).optional(),
  }),
  name: z.string().optional(),
  marketingConsent: z.boolean().optional(),
});

// Type assertion function to safely cast to RegistrationResponseJSON
function assertRegistrationResponse(
  data: unknown
): asserts data is RegistrationResponseJSON {
  // Basic validation already done by zod schema
  if (!data || typeof data !== "object") {
    throw new Error("Invalid registration response format");
  }
}

export async function POST(request: Request) {
  try {
    // Get client IP for logging and security checks
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";

    // Parse and validate input
    const body = await request.json();
    const validationResult = requestSchema.safeParse(body);

    if (!validationResult.success) {
      logger.warn(
        `Invalid WebAuthn registration verification input: ${JSON.stringify(validationResult.error.errors)}`,
        {
          action: "WEBAUTHN_REGISTRATION_VERIFY_ERROR",
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

    const { email, response, name, marketingConsent } = validationResult.data;

    logger.info(`Verifying WebAuthn registration for email: ${email}`, {
      action: "WEBAUTHN_REGISTRATION_VERIFY_REQUEST",
      ip,
    });

    // Type assertion for the response
    assertRegistrationResponse(response);

    // Verify the registration
    const verification = await verifyRegistration(email, response, ip);

    if (!verification.verified) {
      return NextResponse.json(
        { error: verification.error || "Verification failed" },
        { status: 400 }
      );
    }

    // Check if user already exists
    let user = await dgraphClient.getUserByEmail(email);
    logger.debug(`User lookup result for ${email}:`, user);

    if (!user) {
      // Create a new user
      logger.info(`Creating new user for email: ${email}`, {
        action: "USER_CREATION",
        ip,
      });
      user = await dgraphClient.createUser({
        email,
        name: name || email.split("@")[0],
        verified: true,
        emailVerified: new Date(),
        preferences: {
          marketingEmails: marketingConsent || false,
          notificationEmails: true,
        },
        hasWebAuthn: true,
        hasPassphrase: false,
      });
      logger.debug(`Created new user:`, user);

      // Assign default role
      await dgraphClient.assignRoleToUser(user.id!, "user");
    } else {
      logger.info(`User already exists with ID: ${user.id}`, {
        action: "USER_EXISTS",
        ip,
      });
      // Update user to indicate they have WebAuthn
      await dgraphClient.updateUserHasWebAuthn(user.id!, true);
    }

    // Store the credential in DGraph
    logger.info(
      `Storing credential for user ${user.id} with credentialID: ${verification.credentialID}`,
      {
        action: "CREDENTIAL_STORAGE",
        ip,
      }
    );

    const credentialData = {
      credentialID: verification.credentialID!,
      publicKey: verification.publicKey!,
      counter: 0, // Initial counter value
      transports: response.response.transports || ["internal"],
      createdAt: new Date(),
      userId: user.id!,
      isBiometric: true,
      name: name ? `${name}'s device` : "My device",
      deviceType: userAgent.includes("Mobile") ? "mobile" : "desktop",
      deviceInfo: {
        userAgent,
        registrationTime: new Date().toISOString(),
        ipAddress: ip,
      },
    };

    const credentialId = await storeCredential(user.id!, credentialData);
    logger.debug(`Stored credential with ID: ${credentialId}`, {
      action: "CREDENTIAL_STORED",
      ip,
    });

    // Get user roles for RBAC
    const userRoles = await dgraphClient.getUserRoles(user.id!);

    // Create a session token
    const secret = new TextEncoder().encode(
      process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
    );

    const token = await new SignJWT({
      id: user.id,
      email: user.email,
      did: user.did,
      name: user.name,
      roles: userRoles,
      hasWebAuthn: true,
      hasPassphrase: user.hasPassphrase || false,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .sign(secret);

    // Set the session cookie
    const cookieStore = await cookies();
    await cookieStore.set("session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 60 * 60, // 30 days
      path: "/",
      sameSite: "lax",
    });

    // Log the successful registration
    await dgraphClient.createAuditLog({
      userId: user.id!,
      action: "WEBAUTHN_REGISTRATION_SUCCESS",
      details: {
        credentialID: verification.credentialID,
        deviceType: credentialData.deviceType,
      },
      ipAddress: ip,
      userAgent,
    });

    return NextResponse.json({
      verified: true,
      userId: user.id,
      did: user.did,
      shouldSetupPassphrase: true,
    });
  } catch (error) {
    logger.error(`Error verifying WebAuthn registration: ${error}`, {
      action: "WEBAUTHN_REGISTRATION_VERIFY_ERROR",
      error: error instanceof Error ? error.message : String(error),
    });
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Failed to verify registration",
      },
      { status: 500 }
    );
  }
}
