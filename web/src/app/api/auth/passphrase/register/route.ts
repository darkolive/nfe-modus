import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { hashPassphrase, generateDID } from "@/lib/passphrase";
import { cookies } from "next/headers";
import { SignJWT } from "jose";
import { registrationRateLimiter } from "@/lib/rate-limiter";
import logger from "@/lib/logger";
import { z } from "zod";

// DGraph client for storing and retrieving user data
const dgraphClient = new DgraphClient();

// Input validation schema
const registerSchema = z.object({
  email: z.string().email("Invalid email format"),
  passphrase: z.string().min(8, "Passphrase must be at least 8 characters"),
  name: z.string().optional(),
  marketingConsent: z.boolean().optional(),
  recoveryEmail: z.string().email("Invalid recovery email format").optional(),
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
      await registrationRateLimiter.consume(ip);
    } catch {
      // No need to use the error variable
      logger.warn(
        `Rate limit exceeded for registration attempt from IP: ${ip}`
      );
      return NextResponse.json(
        {
          error: "Too many registration attempts. Please try again later.",
        },
        { status: 429 }
      );
    }

    // Parse and validate input
    const body = await request.json();
    const validationResult = registerSchema.safeParse(body);

    if (!validationResult.success) {
      logger.warn(
        `Invalid registration input: ${JSON.stringify(validationResult.error.errors)}`
      );
      return NextResponse.json(
        {
          error: "Invalid input",
          details: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    const { email, passphrase, name, marketingConsent, recoveryEmail } =
      validationResult.data;
    const ipAddress = body.ipAddress || ip;
    const userAgent =
      body.userAgent || request.headers.get("user-agent") || "unknown";

    logger.info(`Registering user with passphrase: ${email}`);

    // Check if user already exists
    const existingUser = await dgraphClient.getUserByEmail(email);

    if (existingUser) {
      logger.info(`User already exists: ${existingUser.id}`);
      return NextResponse.json(
        { error: "User already exists" },
        { status: 400 }
      );
    }

    // Hash the passphrase
    const { hash, salt } = hashPassphrase(passphrase);
    logger.debug(
      `Generated hash (${hash.length} chars) and salt (${salt.length} chars)`
    );

    // Generate a DID
    const did = generateDID(email, passphrase);

    logger.info(`Creating user with email: ${email}, did: ${did}`);

    // Create user with password data directly
    const userData = {
      email,
      name: name || email.split("@")[0],
      did,
      verified: true,
      emailVerified: new Date(),
      preferences: {
        marketingEmails: marketingConsent || false,
        notificationEmails: true,
      },
      hasWebAuthn: false,
      hasPassphrase: true, // Set to true directly
      passwordHash: hash,
      passwordSalt: salt,
      recoveryEmail,
      failedLoginAttempts: 0,
    };

    // Create the user with all data in one mutation
    const user = await dgraphClient.createUser(userData);
    logger.info(`Created user with ID: ${user.id}`);

    // Verify the password data was stored correctly
    const verifiedUser = await dgraphClient.getUserById(user.id!);
    logger.debug(`Verification of user data:`, {
      hasPassphrase: verifiedUser?.hasPassphrase,
      passwordHashLength: verifiedUser?.passwordHash?.length || 0,
      passwordSaltLength: verifiedUser?.passwordSalt?.length || 0,
    });

    // If password data wasn't stored correctly, try a direct update
    if (!verifiedUser?.passwordHash || !verifiedUser?.passwordSalt) {
      logger.warn(
        `Password data not found after user creation, trying direct update...`
      );
      await dgraphClient.storePassphrase(user.id!, hash, salt);
    }

    // Create a session token
    const secret = new TextEncoder().encode(
      process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
    );

    const token = await new SignJWT({
      id: user.id,
      email: user.email,
      did: user.did,
      name: user.name,
      hasWebAuthn: false,
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

    // Log the registration
    await dgraphClient.createAuditLog({
      userId: user.id!,
      action: "USER_REGISTERED",
      details: {
        method: "passphrase",
        hasRecoveryEmail: !!recoveryEmail,
      },
      ipAddress,
      userAgent,
    });

    // Assign default role
    await dgraphClient.assignRoleToUser(user.id!, "user");

    return NextResponse.json({
      success: true,
      userId: user.id,
      did: user.did,
    });
  } catch (error) {
    logger.error(`Error registering with passphrase: ${error}`);
    return NextResponse.json(
      { error: "Failed to register with passphrase" },
      { status: 500 }
    );
  }
}
