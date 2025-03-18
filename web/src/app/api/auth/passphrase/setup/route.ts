import { DgraphClient } from "@/lib/dgraph";
import { inMemoryStore } from "@/lib/in-memory-store";
import { hashPassphrase } from "@/lib/passphrase";
import logger from "@/lib/logger";
import { verifySessionToken } from "@/lib/jwt";
import { type NextRequest } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const { passphrase, email } = await request.json();
    
    // First try to get authentication from JWT token
    let userEmail = null;
    let userId = null;
    
    // Check for JWT token in request cookies
    const token = request.cookies.get("token")?.value;
    
    if (token) {
      try {
        const decoded = await verifySessionToken(token);
        userEmail = decoded.email;
        userId = decoded.userId;
        
        logger.info("User authenticated via JWT token", {
          action: "PASSPHRASE_SETUP_JWT_AUTH",
          email: userEmail
        });
      } catch (tokenError) {
        logger.warn("Invalid JWT token", {
          action: "PASSPHRASE_SETUP_INVALID_TOKEN",
          error: tokenError instanceof Error ? tokenError.message : "Unknown error"
        });
      }
    }
    
    // If JWT verification failed, try in-memory email verification
    if (!userEmail && email) {
      userEmail = email;
      
      // Get email verification from memory
      const verification = inMemoryStore.getEmailVerification(email);
      if (!verification) {
        logger.error("Authentication required - no valid session or email verification found", {
          action: "PASSPHRASE_SETUP_NO_AUTH",
          email
        });
        return Response.json(
          { error: "Authentication required" },
          { status: 401 }
        );
      }

      // Verify that the email was verified within the last 5 minutes
      const now = new Date();
      const verificationTime = new Date(verification.timestamp);
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);

      if (verificationTime < fiveMinutesAgo) {
        inMemoryStore.deleteEmailVerification(email);
        logger.error("Email verification expired", {
          action: "PASSPHRASE_SETUP_VERIFICATION_EXPIRED",
          email
        });
        return Response.json(
          { error: "Email verification expired" },
          { status: 401 }
        );
      }

      // Verify that the verification method is OTP
      if (verification.method !== "otp") {
        logger.error("Invalid verification method", {
          action: "PASSPHRASE_SETUP_INVALID_METHOD",
          email,
          method: verification.method
        });
        return Response.json(
          { error: "Invalid verification method" },
          { status: 401 }
        );
      }
    }
    
    if (!userEmail) {
      logger.error("No valid authentication method found", {
        action: "PASSPHRASE_SETUP_NO_AUTH"
      });
      return Response.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    // Hash the passphrase
    const { hash, salt } = await hashPassphrase(passphrase);

    // Store the passphrase hash in the database
    const client = new DgraphClient();
    
    // Get the user by email if we don't have userId yet
    if (!userId) {
      const user = await client.getUserByEmail(userEmail);
      if (!user) {
        logger.error("User not found", {
          action: "PASSPHRASE_SETUP_USER_NOT_FOUND",
          email: userEmail
        });
        return Response.json(
          { error: "User not found" },
          { status: 404 }
        );
      }
      userId = user.id;
    }
    
    // Update the user with the passphrase hash and salt
    await client.updateUser(userId, {
      passwordHash: hash,
      passwordSalt: salt,
      hasPassphrase: true,
      updatedAt: new Date().toISOString()
    });

    logger.info("Passphrase set up successfully", {
      action: "PASSPHRASE_SETUP_SUCCESS",
      email: userEmail
    });

    // Clear any email verification from memory
    if (userEmail) {
      inMemoryStore.deleteEmailVerification(userEmail);
    }

    return Response.json({ success: true });
  } catch (error) {
    logger.error("Error setting up passphrase:", error);
    return Response.json(
      { error: "Failed to set up passphrase" },
      { status: 500 }
    );
  }
}
