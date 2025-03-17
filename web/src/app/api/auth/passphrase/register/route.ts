import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { hashPassphrase } from "@/lib/crypto";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { z } from "zod";
import { registrationRateLimiter } from "@/lib/rate-limiter";
import { generateDid } from "@/lib/did";
import type { UserData } from "@/types/auth";

const dgraphClient = new DgraphClient();

const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  passphrase: z.string().min(12, "Passphrase must be at least 12 characters"),
  name: z.string().min(1, "Name is required"),
  recoveryEmail: z.string().email("Invalid recovery email").optional(),
});

export async function POST(request: Request) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";

    // Check rate limit
    try {
      await registrationRateLimiter.consume(ip);
    } catch (error) {
      logger.warn("Rate limit exceeded for passphrase registration", {
        action: "PASSPHRASE_REGISTER_RATE_LIMIT",
        ip,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return NextResponse.json(
        { error: "Too many registration attempts. Please try again later." },
        { status: 429 }
      );
    }

    const body = await request.json();
    const result = registerSchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid passphrase registration input", {
        action: "PASSPHRASE_REGISTER_ERROR",
        ip,
        error: result.error.errors,
      });
      return NextResponse.json(
        { error: "Invalid request data" },
        { status: 400 }
      );
    }

    const { email, passphrase, name, recoveryEmail } = result.data;

    // Check if email was recently verified
    const verifiedEmail = await dgraphClient.getVerifiedEmail(email);
    if (!verifiedEmail) {
      return NextResponse.json(
        { error: "Email not verified" },
        { status: 400 }
      );
    }

    // Check if verification is expired (5 minutes)
    const now = new Date();
    if (now > verifiedEmail.expiresAt) {
      await dgraphClient.deleteVerifiedEmail(email);
      return NextResponse.json(
        { error: "Email verification expired" },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = await dgraphClient.getUserByEmail(email);
    if (existingUser) {
      return NextResponse.json(
        { error: "User already exists" },
        { status: 400 }
      );
    }

    // Hash the passphrase
    const { hash, salt } = await hashPassphrase(passphrase);

    // Generate DID
    const did = generateDid();

    // Create user data object
    const userData: Omit<UserData, "id"> = {
      email,
      name,
      did,
      verified: true,
      emailVerified: verifiedEmail.verifiedAt,
      dateJoined: now,
      lastAuthTime: null,
      status: "active",
      hasWebAuthn: false,
      hasPassphrase: true,
      passwordHash: hash,
      passwordSalt: salt,
      recoveryEmail,
      mfaEnabled: false,
      mfaMethod: undefined,
      mfaSecret: undefined,
      failedLoginAttempts: 0,
      lastFailedLogin: null,
      lockedUntil: null,
      roles: ["user"],
      createdAt: now,
      updatedAt: now,
    };

    // Create user
    const userId = await dgraphClient.createUser(userData);

    // Get user roles
    const userRoles = await dgraphClient.getUserRoles(userId);

    // Create session token
    const secret = new TextEncoder().encode(
      process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
    );

    const token = await new SignJWT({
      id: userId,
      email,
      did,
      name,
      roles: userRoles,
      hasWebAuthn: false,
      hasPassphrase: true,
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
      sameSite: "lax",
    });

    // Log successful registration
    await dgraphClient.createAuditLog({
      userId,
      action: "PASSPHRASE_REGISTER_SUCCESS",
      details: JSON.stringify({
        method: "passphrase",
        hasRecoveryEmail: !!recoveryEmail,
      }),
      ipAddress: ip,
      userAgent,
      metadata: {
        verificationMethod: verifiedEmail.method,
      },
    });

    // Assign default role
    await dgraphClient.assignRoleToUser(userId, "user");

    return NextResponse.json({
      success: true,
      user: {
        id: userId,
        did,
        email,
        name,
        hasWebAuthn: false,
        hasPassphrase: true,
      },
    });
  } catch (error) {
    logger.error("Error in passphrase registration:", error);
    return NextResponse.json(
      { error: "An error occurred during registration" },
      { status: 500 }
    );
  }
}
