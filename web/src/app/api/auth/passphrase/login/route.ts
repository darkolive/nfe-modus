import { type NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db-operations";
import logger from "@/lib/logger";
import crypto from "crypto";
import { headers } from "next/headers";

// Constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 30;

export async function POST(request: NextRequest) {
  try {
    const { email, passphrase } = await request.json();

    if (!email || !passphrase) {
      return NextResponse.json(
        { error: "Email and passphrase are required" },
        { status: 400 }
      );
    }

    // Get user by email
    const user = await db.getUserByEmail(email);

    if (!user) {
      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    // Check if account is locked
    const isLocked = await db.isAccountLocked(user.id);
    if (isLocked) {
      return NextResponse.json(
        {
          error: "Account is locked due to too many failed login attempts",
          lockedUntil: user.lockedUntil,
        },
        { status: 403 }
      );
    }

    // Verify passphrase
    const isValid = await verifyPassphrase(user, passphrase);

    // Get request metadata
    const headersList = await headers();
    const ip = headersList.get("x-forwarded-for") || "127.0.0.1";
    const userAgent = headersList.get("user-agent") || "Unknown";

    if (!isValid) {
      // Increment failed login attempts
      const failedAttempts = await db.incrementFailedLoginAttempts(user.id);

      // Create audit log for failed login
      await db.createAuditLog({
        userId: user.id,
        action: "LOGIN_FAILED",
        ipAddress: ip,
        userAgent: userAgent,
        details: {
          reason: "Invalid passphrase",
          failedAttempts,
        },
      });

      // Check if account should be locked
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date();
        lockUntil.setMinutes(lockUntil.getMinutes() + LOCK_DURATION_MINUTES);

        await db.updateUser({
          id: user.id,
          lockedUntil: lockUntil.toISOString(),
        });

        return NextResponse.json(
          {
            error:
              "Account is now locked due to too many failed login attempts",
            lockedUntil: lockUntil.toISOString(),
          },
          { status: 403 }
        );
      }

      return NextResponse.json(
        { error: "Invalid email or passphrase" },
        { status: 401 }
      );
    }

    // Reset failed login attempts on successful login
    await db.resetFailedLoginAttempts(user.id);

    // Check if MFA is enabled
    if (user.mfaEnabled) {
      // Create audit log for MFA required
      await db.createAuditLog({
        userId: user.id,
        action: "MFA_REQUIRED",
        ipAddress: ip,
        userAgent: userAgent,
        details: {
          mfaMethod: user.mfaMethod,
        },
      });

      // Return MFA required response
      if (user.mfaMethod === "webauthn") {
        return NextResponse.json({
          success: true,
          requiresMfa: true,
          mfaMethod: "webauthn",
        });
      } else if (user.mfaMethod === "totp") {
        return NextResponse.json({
          success: true,
          requiresMfa: true,
          mfaMethod: "totp",
        });
      } else {
        return NextResponse.json({
          success: true,
          requiresMfa: true,
          mfaMethod: user.mfaMethod,
        });
      }
    }

    // Get user roles
    const roles = await db.getUserRoles(user.id);

    // Create successful login response
    const response = {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        did: user.did,
        roles,
      },
      hasWebAuthn: user.hasWebAuthn || false,
    };

    // Create audit log for successful login
    await db.createAuditLog({
      userId: user.id,
      action: "LOGIN_SUCCESS",
      ipAddress: ip,
      userAgent: userAgent,
      details: {
        roles,
      },
    });

    return NextResponse.json(response);
  } catch (error) {
    logger.error("Login error", {
      action: "LOGIN",
      error,
    });
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}

/**
 * Verify user passphrase
 */
async function verifyPassphrase(
  user: {
    id: string;
    passwordHash?: string;
    passwordSalt?: string;
    hasPassphrase?: boolean;
  },
  passphrase: string
): Promise<boolean> {
  // Check if user has a passphrase set
  if (!user.hasPassphrase || !user.passwordHash || !user.passwordSalt) {
    // If no passphrase is set, update the user to have one
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto
      .pbkdf2Sync(passphrase, salt, 1000, 64, "sha512")
      .toString("hex");

    // Update user with new passphrase
    await db.updateUserHasPassphrase(user.id, true);
    await db.updateUser({
      id: user.id,
      passwordHash: hash,
      passwordSalt: salt,
    });

    return true;
  }

  // Verify existing passphrase
  const hash = crypto
    .pbkdf2Sync(passphrase, user.passwordSalt, 1000, 64, "sha512")
    .toString("hex");

  return hash === user.passwordHash;
}
