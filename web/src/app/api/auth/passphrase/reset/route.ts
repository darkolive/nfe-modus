import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { inMemoryStore } from "@/lib/in-memory-store";
import { hashPassphrase } from "@/lib/passphrase";
import { createSessionToken } from "@/lib/jwt";
import { getClientIp } from "@/lib/utils";
import { UAParser } from "ua-parser-js";
import { createAuditLog } from "@/lib/audit";

const dgraphClient = new DgraphClient();

/**
 * Handle passphrase reset
 * This endpoint accepts a token and new passphrase to update the user's credentials
 */
export async function POST(req: NextRequest) {
  try {
    // Get token and passphrase from request body
    const { token, passphrase } = await req.json();

    // Get client IP and user agent for audit logging
    const ip = getClientIp(req);
    const userAgent = req.headers.get("user-agent") || "Unknown";
    const parser = new UAParser(userAgent);
    const deviceInfo = parser.getResult();

    if (!token || !passphrase) {
      // Log invalid request
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown user
        actorType: "anonymous",
        operationType: "reset",
        action: "PASSPHRASE_RESET_INVALID_REQUEST",
        details: JSON.stringify({
          missingFields: !token ? "token" : "passphrase",
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 400
      });

      return NextResponse.json(
        { error: "Token and passphrase are required" },
        { status: 400 }
      );
    }

    // Validate passphrase
    if (passphrase.length < 8) {
      // Log invalid passphrase
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown at this point
        actorType: "anonymous",
        operationType: "reset",
        action: "PASSPHRASE_RESET_INVALID_PASSPHRASE",
        details: JSON.stringify({
          reason: "Passphrase too short",
          deviceInfo
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 400
      });

      return NextResponse.json(
        { error: "Passphrase must be at least 8 characters" },
        { status: 400 }
      );
    }

    // Check if token exists in memory store
    const resetData = inMemoryStore.get(`passphrase-reset:${token}`);
    
    if (!resetData) {
      logger.info("Invalid reset token used", { token });
      
      // Log invalid token
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown at this point
        actorType: "anonymous",
        operationType: "reset",
        action: "PASSPHRASE_RESET_INVALID_TOKEN",
        details: JSON.stringify({
          token: token.substring(0, 8) + "..." // Only log first few chars for security
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 400
      });

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
      
      // Log expired token
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown at this point
        actorType: "anonymous",
        operationType: "reset",
        action: "PASSPHRASE_RESET_EXPIRED_TOKEN",
        details: JSON.stringify({
          token: token.substring(0, 8) + "...", // Only log first few chars
          expired: expiresAt.toISOString()
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 400
      });

      return NextResponse.json(
        { error: "Reset link has expired" },
        { status: 400 }
      );
    }

    const { email } = resetData;

    // Get user from database
    const user = await dgraphClient.getUserByEmail(email);
    
    if (!user) {
      // Log user not found
      await createAuditLog(dgraphClient, {
        actorId: "0",
        actorType: "anonymous",
        operationType: "reset",
        action: "PASSPHRASE_RESET_USER_NOT_FOUND",
        details: JSON.stringify({
          email
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 404
      });

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
      
      // Log successful reset
      await createAuditLog(dgraphClient, {
        actorId: user.uid,
        actorType: "user",
        operationType: "reset",
        action: "PASSPHRASE_RESET_SUCCESS",
        details: JSON.stringify({
          email,
          deviceInfo,
          hasPassphrase: true
        }),
        clientIp: ip,
        userAgent,
        success: true,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 200
      });
    } catch (updateError) {
      logger.error("Failed to update user passphrase", {
        userId: user.uid,
        error: updateError instanceof Error ? updateError.message : String(updateError)
      });
      
      // Log failed update
      await createAuditLog(dgraphClient, {
        actorId: user.uid,
        actorType: "user",
        operationType: "reset",
        action: "PASSPHRASE_RESET_UPDATE_FAILED",
        details: JSON.stringify({
          email,
          error: updateError instanceof Error ? updateError.message : String(updateError)
        }),
        clientIp: ip,
        userAgent,
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 500
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
      id: user.uid,
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
    
    // Log unhandled error
    try {
      await createAuditLog(dgraphClient, {
        actorId: "0", // Unknown since we couldn't process the request
        actorType: "system",
        operationType: "reset",
        action: "PASSPHRASE_RESET_UNHANDLED_ERROR",
        details: JSON.stringify({
          error: error instanceof Error ? error.message : String(error)
        }),
        clientIp: getClientIp(req),
        userAgent: req.headers.get("user-agent") || "Unknown",
        success: false,
        requestPath: req.nextUrl.pathname,
        requestMethod: req.method,
        responseStatus: 500
      });
    } catch (auditError) {
      logger.error("Failed to log reset error", {
        error: auditError instanceof Error ? auditError.message : String(auditError)
      });
    }

    return NextResponse.json(
      { error: "Failed to reset passphrase" },
      { status: 500 }
    );
  }
}
