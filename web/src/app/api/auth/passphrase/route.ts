import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { createSessionToken } from "@/lib/jwt";
import { z } from "zod";
import logger from "@/lib/logger";
import { verifyPassphrase } from "@/lib/crypto";

// Input validation schema
const PassphraseSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  passphrase: z
    .string()
    .min(12, "Passphrase must be at least 12 characters long"),
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
    const result = PassphraseSchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid passphrase input", {
        action: "PASSPHRASE_AUTH_ERROR",
        ip,
        error: result.error.format(),
      });
      return NextResponse.json(
        {
          success: false,
          error: "Please check your input",
          details: result.error.format(),
          fields: Object.keys(result.error.format()).filter(
            (k) => k !== "_errors"
          ),
        },
        { status: 400 }
      );
    }

    const { email, passphrase } = result.data;
    const client = new DgraphClient();

    // Get user
    const user = await client.getUserByEmail(email);
    if (!user) {
      logger.error("User not found", {
        action: "PASSPHRASE_AUTH_ERROR",
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

    // Check if user has passphrase set up
    if (!user.hasPassphrase || !user.passwordHash || !user.passwordSalt) {
      logger.error("Passphrase not set up", {
        action: "PASSPHRASE_AUTH_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Passphrase not set up",
          details: "Please set up a passphrase first",
          code: "NO_PASSPHRASE",
        },
        { status: 400 }
      );
    }

    // Check if account is locked
    const isLocked = await client.isAccountLocked(user.id);
    if (isLocked) {
      logger.error("Account locked", {
        action: "PASSPHRASE_AUTH_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Account locked",
          details: "Too many failed attempts. Please try again later.",
          code: "ACCOUNT_LOCKED",
        },
        { status: 403 }
      );
    }

    // Verify passphrase
    const isValid = await verifyPassphrase(
      passphrase,
      user.passwordHash,
      user.passwordSalt
    );
    if (!isValid) {
      // Increment failed login attempts
      await client.incrementFailedLoginAttempts(user.id);

      logger.error("Invalid passphrase", {
        action: "PASSPHRASE_AUTH_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Invalid passphrase",
          details: "The passphrase you entered is incorrect",
        },
        { status: 401 }
      );
    }

    // Reset failed login attempts
    await client.updateUser({
      id: user.id,
      failedLoginAttempts: 0,
      lastAuthTime: new Date(),
      updatedAt: new Date(),
    });

    // Create session token
    const sessionData = {
      id: user.id,
      email: user.email,
      roles: user.roles,
      hasWebAuthn: user.hasWebAuthn,
      hasPassphrase: user.hasPassphrase,
    };

    const token = await createSessionToken(sessionData);

    logger.info("Passphrase authentication successful", {
      action: "PASSPHRASE_AUTH_SUCCESS",
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
    logger.error(`Passphrase authentication failed: ${message}`, {
      action: "PASSPHRASE_AUTH_ERROR",
      error: message,
    });
    return NextResponse.json(
      {
        success: false,
        error: "Unable to verify passphrase",
        details: message,
      },
      { status: 500 }
    );
  }
}
