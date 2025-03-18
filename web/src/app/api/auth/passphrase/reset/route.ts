import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { inMemoryStore } from "@/lib/in-memory-store";
import { hashPassphrase } from "@/lib/passphrase";
import { createSessionToken } from "@/lib/jwt";

const dgraphClient = new DgraphClient();

/**
 * Handle passphrase reset
 * This endpoint accepts a token and new passphrase to update the user's credentials
 */
export async function POST(req: NextRequest) {
  try {
    // Get token and passphrase from request body
    const { token, passphrase } = await req.json();

    if (!token || !passphrase) {
      return NextResponse.json(
        { error: "Token and passphrase are required" },
        { status: 400 }
      );
    }

    // Validate passphrase
    if (passphrase.length < 8) {
      return NextResponse.json(
        { error: "Passphrase must be at least 8 characters" },
        { status: 400 }
      );
    }

    // Check if token exists in memory store
    const resetData = inMemoryStore.get(`passphrase-reset:${token}`);
    
    if (!resetData) {
      logger.info("Invalid reset token used", { token });
      return NextResponse.json(
        { error: "Invalid or expired token" },
        { status: 400 }
      );
    }

    // Check if token is expired
    const expiresAt = new Date(resetData.expiresAt);
    if (expiresAt < new Date()) {
      // Token has expired, remove it from memory
      inMemoryStore.delete(`passphrase-reset:${token}`);
      
      logger.info("Expired reset token used", { token });
      return NextResponse.json(
        { error: "Reset link has expired" },
        { status: 400 }
      );
    }

    const { email } = resetData;

    // Get user from database
    const user = await dgraphClient.getUserByEmail(email);
    
    if (!user) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      );
    }

    // Hash the new passphrase
    const { hash, salt } = await hashPassphrase(passphrase);

    // Update user's passphrase
    try {
      await dgraphClient.updateUserPassphrase(user.uid, hash, salt);
      logger.info("Passphrase reset successful", { userId: user.uid });
    } catch (updateError) {
      logger.error("Failed to update user passphrase", {
        userId: user.uid,
        error: updateError instanceof Error ? updateError.message : String(updateError)
      });
      return NextResponse.json(
        { error: "Failed to update passphrase" },
        { status: 500 }
      );
    }

    // Clean up the reset token
    inMemoryStore.delete(`passphrase-reset:${token}`);

    // Create a session token for the user
    const sessionToken = await createSessionToken({
      id: user.id || user.uid,
      userId: user.uid,
      email: user.email,
      deviceId: "web", // Default device ID
      roles: user.roles?.map(r => r.uid) || [] // Default to empty array if no roles
    });

    // Set the session token cookie
    const response = NextResponse.json({ success: true });
    response.cookies.set({
      name: "session-token",
      value: sessionToken,
      httpOnly: true,
      path: "/",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 24 * 30, // 30 days
    });

    return response;
  } catch (error) {
    logger.error("Error processing passphrase reset", {
      error: error instanceof Error ? error.message : String(error)
    });
    return NextResponse.json(
      { error: "Failed to reset passphrase" },
      { status: 500 }
    );
  }
}
