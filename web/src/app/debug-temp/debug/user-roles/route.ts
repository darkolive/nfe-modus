import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";

// Define credential and role interfaces
interface Credential {
  uid: string;
  credentialID: string;
  deviceName?: string;
  createdAt?: string;
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const email = searchParams.get('email');
  
  if (!email) {
    return NextResponse.json({ error: "Email parameter is required" }, { status: 400 });
  }

  logger.info(`Debug: Checking user roles for email: ${email}`, {
    action: "DEBUG_CHECK_USER_ROLES",
    email
  });

  try {
    const dgraphClient = new DgraphClient();
    
    // Get the user
    const user = await dgraphClient.getUserByEmail(email);
    
    if (!user) {
      logger.warn(`Debug: User not found for email: ${email}`, {
        action: "DEBUG_USER_NOT_FOUND",
        email
      });
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }
    
    // Log user details
    logger.info(`Debug: Found user for email: ${email}`, {
      action: "DEBUG_USER_FOUND",
      email,
      userId: user.uid,
      hasUid: Boolean(user.uid)
    });
    
    // Check if user.uid exists before proceeding
    if (!user.uid) {
      return NextResponse.json({ 
        error: "User found but has no UID",
        user: {
          email: user.email,
          verified: user.verified,
          hasWebAuthn: user.hasWebAuthn
        }
      }, { status: 400 });
    }
    
    // Get the user's roles using getUserRoles (only if uid exists)
    let roles: string[] = [];
    try {
      roles = await dgraphClient.getUserRoles(user.uid);
      logger.info(`Debug: Retrieved roles for user with email: ${email}`, {
        action: "DEBUG_USER_ROLES_FOUND",
        email,
        userId: user.uid,
        roleCount: roles.length,
        roles
      });
    } catch (roleError) {
      logger.error(`Debug: Error retrieving roles for user with email: ${email}`, {
        action: "DEBUG_USER_ROLES_ERROR",
        email,
        userId: user.uid,
        error: roleError instanceof Error ? roleError.message : String(roleError)
      });
    }
    
    // Get WebAuthn credentials if any
    let credentials: Credential[] = [];
    try {
      credentials = await dgraphClient.getUserCredentials(user.uid);
      logger.info(`Debug: Retrieved credentials for user with email: ${email}`, {
        action: "DEBUG_USER_CREDENTIALS_FOUND",
        email,
        userId: user.uid,
        credentialCount: credentials.length
      });
    } catch (credError) {
      logger.error(`Debug: Error retrieving credentials for user with email: ${email}`, {
        action: "DEBUG_USER_CREDENTIALS_ERROR",
        email,
        userId: user.uid,
        error: credError instanceof Error ? credError.message : String(credError)
      });
    }
    
    return NextResponse.json({
      user: {
        uid: user.uid,
        email: user.email,
        name: user.name,
        did: user.did,
        verified: user.verified,
        status: user.status,
        hasWebAuthn: user.hasWebAuthn,
        hasPassphrase: user.hasPassphrase,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      },
      roles,
      credentials: credentials.map(cred => ({
        uid: cred.uid,
        credentialID: cred.credentialID,
        deviceName: cred.deviceName || "Unknown Device",
        createdAt: cred.createdAt
      }))
    });
  } catch (error) {
    logger.error("Error retrieving user roles", {
      action: "DEBUG_GET_USER_ROLES_ERROR",
      email,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    
    return NextResponse.json({ 
      error: "Failed to retrieve user roles",
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}
