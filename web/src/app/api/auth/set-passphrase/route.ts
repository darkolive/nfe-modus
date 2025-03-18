import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { z } from "zod";
import logger from "@/lib/logger";
import { hashPassphrase } from "@/lib/crypto";
import * as crypto from 'crypto';
import { inMemoryStore } from "@/lib/in-memory-store";

// Input validation schema
const SetPassphraseSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  passphrase: z.string()
    .min(12, "Passphrase must be at least 12 characters long")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).+$/,
      "Passphrase must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    ),
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
    const result = SetPassphraseSchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid set-passphrase input", {
        action: "SET_PASSPHRASE_ERROR",
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

    const { email, passphrase } = result.data;
    
    // Check email verification from memory
    const verification = inMemoryStore.getEmailVerification(email);
    if (!verification) {
      logger.error("Email not verified", {
        action: "SET_PASSPHRASE_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Email verification required",
          details: "Please verify your email first",
        },
        { status: 401 }
      );
    }

    const client = new DgraphClient();

    // Get user or create if not exists
    let user = await client.getUserByEmail(email);

    // Hash the passphrase
    const { hash, salt } = await hashPassphrase(passphrase);

    if (!user) {
      // Create new user with required fields
      await client.createUser({
        email,
        name: email.split("@")[0], // Use part before @ as temporary name
        did: crypto.randomUUID(),
        verified: true,
        emailVerified: new Date(verification.timestamp).toISOString(),
        dateJoined: new Date().toISOString(),
        lastAuthTime: new Date().toISOString(),
        status: "active",
        hasWebAuthn: false,
        hasPassphrase: true,
        passwordHash: hash,
        passwordSalt: salt,
        recoveryEmail: null,
        mfaEnabled: false,
        mfaMethod: null,
        mfaSecret: null,
        failedLoginAttempts: 0,
        lastFailedLogin: null,
        lockedUntil: null,
        roles: [], // Empty array of role objects
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        devices: []
      });

      // Get the newly created user
      user = await client.getUserByEmail(email);
      if (!user) {
        throw new Error("Failed to create user");
      }
    } else {
      // Update user with passphrase
      await client.updateUser(user.id, {
        hasPassphrase: true,
        passwordHash: hash,
        passwordSalt: salt,
        lastAuthTime: new Date().toISOString()
      });
    }

    // Clear the verification from memory since we've used it
    inMemoryStore.deleteEmailVerification(email);

    logger.info("Passphrase set successfully", {
      action: "SET_PASSPHRASE_SUCCESS",
      email,
      ip,
      userId: user.id,
    });

    return NextResponse.json({
      success: true,
      message: "Passphrase set successfully",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Failed to set passphrase: ${message}`, {
      action: "SET_PASSPHRASE_ERROR",
      error: message,
    });
    return NextResponse.json(
      {
        success: false,
        error: "Unable to set passphrase",
        details: message,
      },
      { status: 500 }
    );
  }
}
