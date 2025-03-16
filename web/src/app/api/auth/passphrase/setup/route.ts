import { NextRequest } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { inMemoryStore } from "@/lib/in-memory-store";
import { hashPassphrase } from "@/lib/passphrase";
import logger from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    const { email, passphrase } = await request.json();

    // Get email verification from memory
    const verification = inMemoryStore.getEmailVerification(email);
    if (!verification) {
      logger.error("Email verification required");
      return Response.json(
        { error: "Email verification required" },
        { status: 401 }
      );
    }

    // Verify that the email was verified within the last 5 minutes
    const now = new Date();
    const verificationTime = new Date(verification.timestamp);
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);

    if (verificationTime < fiveMinutesAgo) {
      inMemoryStore.deleteEmailVerification(email);
      logger.error("Email verification expired");
      return Response.json(
        { error: "Email verification expired" },
        { status: 401 }
      );
    }

    // Verify that the verification method is OTP
    if (verification.method !== "otp") {
      logger.error("Invalid verification method");
      return Response.json(
        { error: "Invalid verification method" },
        { status: 401 }
      );
    }

    // Hash the passphrase
    const { hash, salt } = await hashPassphrase(passphrase);

    // Store the passphrase hash in the database
    const client = new DgraphClient();
    await client.storePassphraseHash(email, hash, salt);

    // Clear the email verification from memory
    inMemoryStore.deleteEmailVerification(email);

    return Response.json({ success: true });
  } catch (error) {
    logger.error("Error setting up passphrase:", error);
    return Response.json(
      { error: "Failed to set up passphrase" },
      { status: 500 }
    );
  }
}
