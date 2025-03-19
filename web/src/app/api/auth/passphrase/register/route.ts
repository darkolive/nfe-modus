import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { hashPassphrase } from "@/lib/passphrase";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import logger from "@/lib/logger";
import { z } from "zod";
import { registrationRateLimiter } from "@/lib/rate-limiter";
import { generateDid } from "@/lib/did";
import { inMemoryStore } from "@/lib/in-memory-store";
import { getClientIp } from "@/lib/utils";
import { UAParser } from "ua-parser-js";
import { createAuditLog } from "@/lib/audit";

const dgraphClient = new DgraphClient();

const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  passphrase: z.string().min(12, "Passphrase must be at least 12 characters"),
  name: z.string().min(1, "Name is required"),
  recoveryEmail: z.string().email("Invalid recovery email").optional(),
});

export async function POST(request: Request): Promise<NextResponse> {
  try {
    // Get client IP and user agent using our utility function
    const ip = getClientIp(request);
    const userAgent = request.headers.get("user-agent") || "unknown";
    const parser = new UAParser(userAgent);
    const deviceInfo = parser.getResult();

    // Check rate limit
    try {
      await registrationRateLimiter.consume(ip);
    } catch (error) {
      logger.warn("Rate limit exceeded for passphrase registration", {
        action: "PASSPHRASE_REGISTER_RATE_LIMIT",
        ip,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      
      // Log rate limit exceeded
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown user
        actorType: "anonymous",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_RATE_LIMIT",
        details: JSON.stringify({
          ip,
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 429
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
      
      // Get the specific error messages from Zod
      const errorMessages = result.error.errors.map(err => `${err.path.join('.')}: ${err.message}`).join(', ');
      
      // Log validation failure
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown user
        actorType: "anonymous",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_VALIDATION_FAILED",
        details: JSON.stringify({
          errors: result.error.errors.map(e => ({ path: e.path.join('.'), message: e.message })),
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 400
      });
      
      return NextResponse.json(
        { error: `Validation failed: ${errorMessages}` },
        { status: 400 }
      );
    }

    const { email, passphrase, name, recoveryEmail } = result.data;

    // Check if email was recently verified
    let verifiedEmail = inMemoryStore.getEmailVerification(email);
    logger.debug(`Checking email verification for registration: ${email}, found in memory: ${verifiedEmail ? 'yes' : 'no'}`);
    
    // If not found in memory, check for verification cookie
    if (!verifiedEmail) {
      logger.debug(`Email verification not found in memory, checking cookies`);
      
      // Check if verification cookie exists
      const cookies = request.headers.get("cookie");
      const verificationCookie = cookies
        ?.split(";")
        .map((cookie) => cookie.trim())
        .find((cookie) => cookie.startsWith(`emailVerification=`));
      
      if (verificationCookie) {
        logger.debug(`Found verification cookie for registration`);
        // We have a verification cookie, so the email was verified
        // Create a synthetic verification
        verifiedEmail = {
          email,
          timestamp: new Date().toISOString(),
          method: 'otp'
        };
        
        // Store it in memory for future use
        inMemoryStore.storeEmailVerification(verifiedEmail);
      }
    }
    
    if (!verifiedEmail) {
      logger.warn(`Email verification not found for registration: ${email}`);
      
      // Debug the current state of verified emails
      const allVerified = inMemoryStore.getAllVerifiedEmails();
      logger.debug(`Current verified emails in memory: ${[...allVerified.keys()].join(', ') || 'none'}`);
      
      // Log email verification missing
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown user
        actorType: "anonymous",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_EMAIL_NOT_VERIFIED",
        details: JSON.stringify({
          email,
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 400
      });
      
      return NextResponse.json(
        { error: "Email not verified" },
        { status: 400 }
      );
    }

    // Check if verification is expired (5 minutes)
    const now = new Date();
    const verificationTime = new Date(verifiedEmail.timestamp);
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
    
    if (verificationTime < fiveMinutesAgo) {
      inMemoryStore.deleteEmailVerification(email);
      
      // Log verification expired
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown user
        actorType: "anonymous",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_VERIFICATION_EXPIRED",
        details: JSON.stringify({
          email,
          verificationTime: verificationTime.toISOString(),
          expirationTime: fiveMinutesAgo.toISOString(),
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 400
      });
      
      return NextResponse.json(
        { error: "Email verification expired" },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = await dgraphClient.getUserByEmail(email);
    if (existingUser) {
      // Log duplicate user registration attempt
      await createAuditLog(dgraphClient, {
        actorId: existingUser.uid || "0",
        actorType: "user",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_USER_EXISTS",
        details: JSON.stringify({
          email,
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 400
      });
      
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
    const userData = {
      email,
      name,
      did,
      verified: true,
      emailVerified: verifiedEmail.timestamp,
      dateJoined: now.toISOString(),
      lastAuthTime: null,
      status: "active" as const,
      hasWebAuthn: false,
      hasPassphrase: true,
      passwordHash: hash,
      passwordSalt: salt,
      recoveryEmail: recoveryEmail || null,
      failedLoginAttempts: 0,
      lastFailedLogin: null,
      lockedUntil: null,
      roles: [],
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      devices: []
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
    await createAuditLog(dgraphClient, {
      actorId: userId,
      actorType: "user",
      operationType: "passphrase_registration",
      action: "PASSPHRASE_REGISTER_SUCCESS",
      details: JSON.stringify({
        method: "passphrase",
        hasRecoveryEmail: !!recoveryEmail,
        verificationMethod: verifiedEmail.method,
        deviceInfo
      }),
      clientIp: ip,
      userAgent,
      success: true,
      requestPath: request.url,
      requestMethod: request.method,
      responseStatus: 200
    });

    // Assign default role
    try {
      const registeredRoleId = await dgraphClient.getRoleId("registered");
      if (registeredRoleId) {
        logger.debug("Starting role assignment process", {
          action: "PASSPHRASE_REGISTER_ROLE_ASSIGNMENT",
          userId,
          roleId: registeredRoleId,
          roleName: "registered"
        });
        await dgraphClient.assignRoleToUser(userId, registeredRoleId);
        logger.info("Successfully assigned role to user", {
          action: "PASSPHRASE_REGISTER_ROLE_ASSIGNMENT_SUCCESS",
          userId,
          roleId: registeredRoleId,
          roleName: "registered"
        });
      } else {
        logger.error("Could not find the 'registered' role ID", {
          action: "PASSPHRASE_REGISTER_ROLE_ID_NOT_FOUND",
          userId
        });
      }
    } catch (roleError) {
      logger.error("Error assigning role to user during passphrase registration", {
        action: "PASSPHRASE_REGISTER_ROLE_ASSIGNMENT_ERROR",
        userId,
        roleName: "registered",
        error: roleError instanceof Error ? roleError.message : String(roleError)
      });
      // Continue without throwing, as the user is created but just missing the role
    }

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
    
    // Attempt to log the error even if registration failed
    try {
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown since registration failed
        actorType: "system",
        operationType: "passphrase_registration",
        action: "PASSPHRASE_REGISTER_UNHANDLED_ERROR",
        details: JSON.stringify({
          error: error instanceof Error ? error.message : String(error)
        }),
        clientIp: getClientIp(request),
        userAgent: request.headers.get("user-agent") || "Unknown",
        success: false,
        requestPath: request.url,
        requestMethod: request.method,
        responseStatus: 500
      });
    } catch (auditError) {
      logger.error("Failed to log registration error", {
        error: auditError instanceof Error ? auditError.message : String(auditError)
      });
    }
    
    return NextResponse.json(
      { error: "An error occurred during registration" },
      { status: 500 }
    );
  }
}
