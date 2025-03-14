import { NextResponse } from "next/server";
import { verifyAuthentication } from "@/lib/webauthn";
import { DgraphClient } from "@/lib/dgraph";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { z } from "zod";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";

// DGraph client for user operations
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
      authenticatorData: z.string(),
      signature: z.string(),
      userHandle: z.string().optional(),
    }),
    clientExtensionResults: z.record(z.unknown()).optional(),
  }),
});

// Type assertion function to safely cast to AuthenticationResponseJSON
function assertAuthenticationResponse(
  data: unknown
): asserts data is AuthenticationResponseJSON {
  // Basic validation already done by zod schema
  if (!data || typeof data !== "object") {
    throw new Error("Invalid authentication response format");
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
        `Invalid WebAuthn login verification input: ${JSON.stringify(validationResult.error.errors)}`,
        {
          action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
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

    const { email, response } = validationResult.data;

    logger.info(`Verifying WebAuthn login for email: ${email}`, {
      action: "WEBAUTHN_LOGIN_VERIFY_REQUEST",
      ip,
    });

    // Type assertion for the response
    assertAuthenticationResponse(response);

    // Verify the authentication
    const verification = await verifyAuthentication(email, response, ip);

    if (!verification.verified) {
      return NextResponse.json(
        { error: verification.error || "Authentication failed" },
        { status: 401 }
      );
    }

    // Get the user
    const user = await dgraphClient.getUserByEmail(email);

    if (!user) {
      logger.warn(`User not found for email: ${email}`, {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        ip,
        error: "User not found",
      });
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Check if MFA is enabled
    if (user.mfaEnabled) {
      logger.info(
        `MFA is enabled for user: ${user.id}, method: ${user.mfaMethod}`,
        {
          action: "MFA_REQUIRED",
          ip,
        }
      );

      // Create a temporary session token for MFA verification
      const secret = new TextEncoder().encode(
        process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
      );

      const mfaToken = await new SignJWT({
        id: user.id,
        email: user.email,
        requiresMfa: true,
        mfaMethod: user.mfaMethod,
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("5m") // Short expiration for MFA verification
        .sign(secret);

      // Set a temporary MFA cookie
      const cookieStore = await cookies();
      await cookieStore.set("mfa_pending", mfaToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 5 * 60, // 5 minutes
        path: "/",
        sameSite: "lax",
      });

      return NextResponse.json({
        requiresMfa: true,
        mfaMethod: user.mfaMethod,
      });
    }

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
      roles: userRoles, // Include roles in the JWT
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

    // Log the successful login
    await dgraphClient.createAuditLog({
      userId: user.id!,
      action: "WEBAUTHN_LOGIN_SUCCESS",
      details: {
        method: "webauthn",
      },
      ipAddress: ip,
      userAgent,
    });

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        did: user.did,
        name: user.name,
        hasWebAuthn: true,
        hasPassphrase: user.hasPassphrase || false,
      },
    });
  } catch (error) {
    logger.error(`Error verifying WebAuthn login: ${error}`, {
      action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
      error: error instanceof Error ? error.message : String(error),
    });
    return NextResponse.json(
      {
        error:
          error instanceof Error ? error.message : "Failed to verify login",
      },
      { status: 500 }
    );
  }
}
