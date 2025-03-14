import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { verifyPassphrase } from "@/lib/passphrase";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import { loginRateLimiter } from "@/lib/rate-limiter";
import logger from "@/lib/logger";
import { z } from "zod";

// DGraph client for user operations
const dgraphClient = new DgraphClient();

// Input validation schema
const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  passphrase: z.string().min(1, "Passphrase is required"),
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
});

export async function POST(request: Request) {
  try {
    // Get client IP for rate limiting
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // Check rate limiting
    try {
      await loginRateLimiter.consume(ip);
    } catch {
      // No need to use the error variable
      logger.warn(`Rate limit exceeded for login attempt from IP: ${ip}`);
      return NextResponse.json(
        {
          error: "Too many login attempts. Please try again later.",
        },
        { status: 429 }
      );
    }

    // Parse and validate input
    const body = await request.json();
    const validationResult = loginSchema.safeParse(body);

    if (!validationResult.success) {
      logger.warn(
        `Invalid login input: ${JSON.stringify(validationResult.error.errors)}`
      );
      return NextResponse.json(
        {
          error: "Invalid input",
          details: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    const { email, passphrase } = validationResult.data;
    const ipAddress = body.ipAddress || ip;
    const userAgent =
      body.userAgent || request.headers.get("user-agent") || "unknown";

    logger.info(`Attempting passphrase login for email: ${email}`);

    // Get the user
    const user = await dgraphClient.getUserByEmail(email);

    if (!user) {
      logger.info(`User not found for email: ${email}`);
      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    logger.debug(`Found user with ID: ${user.id}`);

    // Check if account is locked
    if (user.id && (await dgraphClient.isAccountLocked(user.id))) {
      logger.warn(`Login attempt for locked account: ${user.id}`);
      return NextResponse.json(
        {
          error:
            "Account is temporarily locked due to too many failed login attempts. Please try again later.",
        },
        { status: 403 }
      );
    }

    // First check if the user has a passphrase set up
    if (!user.hasPassphrase) {
      logger.info(`User does not have a passphrase set up: ${user.id}`);
      return NextResponse.json(
        { error: "User does not have a passphrase set up" },
        { status: 400 }
      );
    }

    // Check if the user has password data
    if (!user.passwordHash || !user.passwordSalt) {
      logger.warn(
        `User has hasPassphrase=true but no password data found: ${user.id}`
      );

      // This is a data inconsistency - update the flag and reject the login
      await dgraphClient.updateUserHasPassphrase(user.id!, false);
      logger.info(
        `Updated hasPassphrase flag to false for user: ${user.id} due to missing password data`
      );

      return NextResponse.json(
        {
          error:
            "Password data is missing. Please use another authentication method or reset your password.",
          needsReset: true,
        },
        { status: 400 }
      );
    }

    logger.debug(
      `Password data retrieved: Hash length=${user.passwordHash.length}, Salt length=${user.passwordSalt.length}`
    );

    // Verify the passphrase
    const isValid = verifyPassphrase(
      passphrase,
      user.passwordHash,
      user.passwordSalt
    );

    if (!isValid) {
      logger.warn(`Invalid passphrase for user: ${user.id}`);

      // Increment failed login attempts
      if (user.id) {
        await dgraphClient.incrementFailedLoginAttempts(user.id);
      }

      // Log the failed login attempt
      await dgraphClient.createAuditLog({
        userId: user.id!,
        action: "LOGIN_FAILED",
        details: {
          method: "passphrase",
          reason: "Invalid passphrase",
        },
        ipAddress,
        userAgent,
      });

      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    logger.info(`Passphrase verified for user: ${user.id}`);

    // Reset failed login attempts
    if (user.id) {
      await dgraphClient.resetFailedLoginAttempts(user.id);
    }

    // Check if MFA is enabled
    if (user.mfaEnabled) {
      logger.info(
        `MFA is enabled for user: ${user.id}, method: ${user.mfaMethod}`
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
      hasWebAuthn: user.hasWebAuthn || false,
      hasPassphrase: true,
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

    logger.info(`Session created for user: ${user.id}`);

    // Log the successful login
    await dgraphClient.createAuditLog({
      userId: user.id!,
      action: "LOGIN_SUCCESS",
      details: {
        method: "passphrase",
      },
      ipAddress,
      userAgent,
    });

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        did: user.did,
        name: user.name,
        hasWebAuthn: user.hasWebAuthn || false,
        hasPassphrase: true,
      },
    });
  } catch (error) {
    logger.error(`Error in passphrase login: ${error}`);
    return NextResponse.json(
      { error: "Failed to authenticate" },
      { status: 500 }
    );
  }
}
