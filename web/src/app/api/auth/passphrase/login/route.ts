import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { verifyPassphrase } from "@/lib/passphrase";
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
    if (!user) {
      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

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

    // Verify passphrase
    const isValid = await verifyPassphrase(
      passphrase,
      user.passwordHash!,
      user.passwordSalt!
    );

    if (!isValid) {
      // Increment failed login attempts
      const failedAttempts = (user.failedLoginAttempts || 0) + 1;
      let lockedUntil: Date | undefined;

      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }

      await dgraphClient.incrementFailedLoginAttempts(user.id!);

      // Log the failed login attempt
      await dgraphClient.createAuditLog({
        userId: user.id!,
        action: "LOGIN_FAILED",
        details: JSON.stringify({
          method: "passphrase",
          reason: "Invalid passphrase",
          failedAttempts,
          lockedUntil: lockedUntil?.toISOString()
        }),
        ipAddress,
        userAgent,
        metadata: {
          deviceInfo,
          failedAttempts,
          lockedUntil: lockedUntil?.toISOString()
        }
      });

      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    logger.info(`Passphrase verified for user: ${user.id}`);

    // Reset failed login attempts
    await dgraphClient.resetFailedLoginAttempts(user.id!);

    // Create session token
    const token = await new SignJWT({
      sub: user.id,
      email: user.email
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("24h")
      .sign(new TextEncoder().encode(process.env.JWT_SECRET));

    // Create response with session cookie
    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        verified: user.verified,
        emailVerified: user.emailVerified,
        hasWebAuthn: user.hasWebAuthn,
        hasPassphrase: user.hasPassphrase,
        mfaEnabled: user.mfaEnabled,
        roles: user.roles
      }
    });

    // Set session cookie
    response.cookies.set("session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24 // 24 hours
    });

    // Log successful login
    await dgraphClient.createAuditLog({
      userId: user.id!,
      action: "LOGIN_SUCCESS",
      details: JSON.stringify({
        method: "passphrase"
      }),
      ipAddress,
      userAgent,
      metadata: {
        deviceInfo
      }
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
