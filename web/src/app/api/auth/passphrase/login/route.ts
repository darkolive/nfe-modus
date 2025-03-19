import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { verifyPassphrase, hashPassphrase } from "@/lib/passphrase";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { UAParser } from "ua-parser-js";
import { z } from "zod";

const dgraphClient = new DgraphClient();

const loginSchema = z.object({
  email: z.string().email(),
  passphrase: z.string().min(1)
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = loginSchema.safeParse(body);
    
    if (!result.success) {
      return NextResponse.json(
        { error: "Invalid request data" },
        { status: 400 }
      );
    }

    const { email, passphrase } = result.data;

    // Get user agent for device info
    const userAgent = request.headers.get("user-agent") || "";
    const uaParser = new UAParser(userAgent);
    const deviceInfo = uaParser.getResult();

    // Get IP address from request headers
    const ipAddress = request.headers.get("x-forwarded-for") || 
                     request.headers.get("x-real-ip") || 
                     "unknown";

    // Get user by email
    const user = await dgraphClient.getUserByEmail(email);
    if (!user || !user.passwordHash || !user.passwordSalt) {
      logger.warn(`Invalid login attempt - user, hash, or salt missing for email: ${email}`);
      
      // Create audit log entry for failed login
      await dgraphClient.createAuditLog({
        actorId: "anonymous",
        actorType: "anonymous",
        operationType: "login",
        action: "LOGIN_FAILED",
        details: JSON.stringify({
          reason: "INVALID_CREDENTIALS",
          method: "passphrase",
          deviceInfo,
        }),
        clientIp: ipAddress,
        userAgent,
        success: false
      });

      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    logger.debug(`User found for login: ${user.uid}, attempting to verify passphrase`);
    logger.debug(`User has passwordHash of length: ${user.passwordHash.length}, passwordSalt of length: ${user.passwordSalt.length}`);

    // Check if user has passphrase set
    if (!user.hasPassphrase) {
      return NextResponse.json(
        { error: "Passphrase not set for this account" },
        { status: 401 }
      );
    }

    // Check if account is locked
    if (user.lockedUntil) {
      const lockedUntilDate = new Date(user.lockedUntil);
      if (lockedUntilDate > new Date()) {
        return NextResponse.json(
          { error: "Account is temporarily locked" },
          { status: 401 }
        );
      }
    }

    // For diagnostics, log the hash that would be generated with current passphrase and salt
    const { hash: diagnosticHash } = await hashPassphrase(passphrase, user.passwordSalt);
    logger.debug(`Diagnostic hash with current input: hash length=${diagnosticHash.length}, prefix=${diagnosticHash.substring(0, 5)}...`);
    
    if (user.passwordHash.substring(0, 5) !== diagnosticHash.substring(0, 5)) {
      logger.warn(`Hash prefix mismatch: stored=${user.passwordHash.substring(0, 5)}, computed=${diagnosticHash.substring(0, 5)}`);
    }

    const isValid = await verifyPassphrase(
      passphrase,
      user.passwordHash!,
      user.passwordSalt!
    );

    if (!isValid) {
      logger.warn(`Invalid passphrase for user: ${user.uid}`);
      // Increment failed login attempts
      const failedAttempts = (user.failedLoginAttempts || 0) + 1;
      let lockedUntil: Date | undefined;

      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }

      await dgraphClient.incrementFailedLoginAttempts(user.uid!);

      // Log the failed login attempt
      await dgraphClient.createAuditLog({
        actorId: user.uid!,
        actorType: "user",
        operationType: "login",
        action: "LOGIN_FAILED",
        details: JSON.stringify({
          method: "passphrase",
          reason: "Invalid passphrase",
          failedAttempts,
          lockedUntil: lockedUntil?.toISOString(),
          deviceInfo,
        }),
        clientIp: ipAddress,
        userAgent,
        success: false
      });

      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    logger.info(`Passphrase verified for user: ${user.uid}`);

    // Generate and return JWT token
    const token = await new SignJWT({
      sub: user.uid,
      email: user.email,
      name: user.name,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hour expiry
    })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode(process.env.JWT_SECRET!));

    // Reset failed login attempts
    if (user.failedLoginAttempts) {
      await dgraphClient.resetFailedLoginAttempts(user.uid!);
    }

    // Create audit log entry for successful login
    await dgraphClient.createAuditLog({
      actorId: user.uid!,
      actorType: "user",
      operationType: "login",
      action: "LOGIN_SUCCESS",
      details: JSON.stringify({
        method: "passphrase",
        deviceInfo,
      }),
      clientIp: ipAddress,
      userAgent,
      success: true
    });

    // Set JWT as a cookie
    const response = NextResponse.json({
      success: true,
      userId: user.uid,
      name: user.name,
      email: user.email,
      canAddWebAuthn: !user.hasWebAuthn // Include whether user can add WebAuthn
    });

    // Set cookie with HttpOnly for security
    response.cookies.set({
      name: "session-token",
      value: token,
      httpOnly: true,
      maxAge: 60 * 60 * 24, // 1 day
      path: "/",
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production"
    });

    return response;
  } catch (error) {
    logger.error("Error in passphrase login:", error);
    return NextResponse.json(
      { error: "An error occurred during login" },
      { status: 500 }
    );
  }
}
