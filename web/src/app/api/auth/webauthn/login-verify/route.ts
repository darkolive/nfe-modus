import { NextResponse } from "next/server";
import { verifyAuthentication } from "@/lib/webauthn";
import { DgraphClient } from "@/lib/dgraph";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { z } from "zod";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";

const dgraphClient = new DgraphClient();

const verifySchema = z.object({
  email: z.string().email("Invalid email format"),
  response: z.custom<AuthenticationResponseJSON>((val) => {
    return val && typeof val === "object" && "id" in val;
  }, "Invalid authentication response")
});

export async function POST(request: Request) {
  try {
    const ip = request.headers.get("x-forwarded-for") || 
               request.headers.get("x-real-ip") || 
               "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";

    const body = await request.json();
    const result = verifySchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid WebAuthn login verification input", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        ip,
        error: result.error.errors
      });
      return NextResponse.json(
        { error: "Invalid request data" },
        { status: 400 }
      );
    }

    const { email, response } = result.data;

    // Get the stored challenge
    const challenge = await dgraphClient.getChallenge(response.response.clientDataJSON);
    if (!challenge) {
      return NextResponse.json(
        { error: "Challenge not found or expired" },
        { status: 400 }
      );
    }

    // Check if challenge is expired (5 minutes)
    const now = new Date();
    if (now > challenge.expiresAt) {
      await dgraphClient.deleteChallenge(challenge.email);
      return NextResponse.json(
        { error: "Challenge expired" },
        { status: 400 }
      );
    }

    // Get user and their credentials
    const user = await dgraphClient.getUserByEmail(email);
    if (!user) {
      logger.warn(`User not found for email: ${email}`, {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        ip,
        error: "User not found"
      });
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      );
    }

    // Get the credential used for this authentication
    const credential = await dgraphClient.getCredentialById(response.id);
    if (!credential) {
      logger.warn(`Credential not found: ${response.id}`, {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        ip,
        error: "Credential not found"
      });
      return NextResponse.json(
        { error: "Credential not found" },
        { status: 404 }
      );
    }

    try {
      // Verify the authentication
      const verification = await verifyAuthentication(
        response,
        challenge.challenge,
        credential
      );

      if (!verification.verified) {
        logger.warn("Authentication verification failed", {
          action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
          ip,
          userId: user.id,
          error: "Verification failed"
        });
        return NextResponse.json(
          { error: "Authentication failed" },
          { status: 401 }
        );
      }

      // Update credential counter
      await dgraphClient.updateCredentialCounter(
        credential.uid,
        verification.authenticationInfo.newCounter
      );

      // Check if MFA is enabled
      if (user.mfaEnabled) {
        logger.info(`MFA required for user: ${user.id}`, {
          action: "MFA_REQUIRED",
          ip,
          userId: user.id,
          method: user.mfaMethod
        });

        // Create temporary MFA token
        const secret = new TextEncoder().encode(
          process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
        );

        const mfaToken = await new SignJWT({
          id: user.id,
          email: user.email,
          requiresMfa: true,
          mfaMethod: user.mfaMethod
        })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(secret);

        // Set MFA cookie
        const cookieStore = await cookies();
        await cookieStore.set("mfa_pending", mfaToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: 5 * 60,
          path: "/",
          sameSite: "lax"
        });

        return NextResponse.json({
          requiresMfa: true,
          mfaMethod: user.mfaMethod
        });
      }

      // Get user roles
      const userRoles = await dgraphClient.getUserRoles(user.id);

      // Create session token
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
        hasPassphrase: user.hasPassphrase
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("30d")
        .sign(secret);

      // Set session cookie
      const cookieStore = await cookies();
      await cookieStore.set("session", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 30 * 24 * 60 * 60,
        path: "/",
        sameSite: "lax"
      });

      // Log successful login
      await dgraphClient.createAuditLog({
        userId: user.id,
        action: "WEBAUTHN_LOGIN_SUCCESS",
        details: JSON.stringify({
          method: "webauthn",
          credentialId: credential.uid
        }),
        ipAddress: ip,
        userAgent,
        metadata: {
          deviceInfo: credential.deviceInfo
        }
      });

      return NextResponse.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          did: user.did,
          name: user.name,
          hasWebAuthn: true,
          hasPassphrase: user.hasPassphrase
        }
      });
    } catch (error) {
      logger.error("Error during authentication verification:", error);

      // Log failed login attempt
      await dgraphClient.createAuditLog({
        userId: user.id,
        action: "WEBAUTHN_LOGIN_FAILED",
        details: JSON.stringify({
          method: "webauthn",
          error: error instanceof Error ? error.message : "Unknown error"
        }),
        ipAddress: ip,
        userAgent,
        metadata: {
          error: error instanceof Error ? error.message : "Unknown error"
        }
      });

      return NextResponse.json(
        { error: "Authentication verification failed" },
        { status: 401 }
      );
    }
  } catch (error) {
    logger.error("Error in WebAuthn login verification:", error);
    return NextResponse.json(
      { error: "An error occurred during login verification" },
      { status: 500 }
    );
  }
}
