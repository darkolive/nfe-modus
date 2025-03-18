import { NextRequest, NextResponse } from "next/server";
import { inMemoryStore } from "@/lib/in-memory-store";
import logger from "@/lib/logger";

/**
 * Validate a passphrase reset token
 * This endpoint checks if a reset token is valid and not expired
 */
export async function GET(req: NextRequest) {
  try {
    // Get token from query params
    const url = new URL(req.url);
    const token = url.searchParams.get("token");

    if (!token) {
      return NextResponse.json(
        { valid: false, error: "Token is required" },
        { status: 400 }
      );
    }

    // Check if token exists in memory store
    const resetData = await inMemoryStore.get(`passphrase-reset:${token}`);
    
    if (!resetData) {
      logger.info("Invalid reset token attempted", { token });
      return NextResponse.json(
        { valid: false, error: "Invalid or expired token" },
        { status: 400 }
      );
    }

    // Check if token is expired
    const expiresAt = new Date(resetData.expiresAt);
    if (expiresAt < new Date()) {
      // Token has expired, remove it from memory
      await inMemoryStore.delete(`passphrase-reset:${token}`);
      
      logger.info("Expired reset token attempted", { token });
      return NextResponse.json(
        { valid: false, error: "Reset link has expired" },
        { status: 400 }
      );
    }

    // Token is valid
    return NextResponse.json({ valid: true });
  } catch (error) {
    logger.error("Error validating reset token", {
      error: error instanceof Error ? error.message : String(error)
    });
    return NextResponse.json(
      { valid: false, error: "Failed to validate token" },
      { status: 500 }
    );
  }
}
