import { NextResponse } from "next/server";
import logger from "@/lib/logger";

export async function POST() {
  try {
    logger.info("Updating Dgraph schema");

    // Update the schema to ensure all required fields are properly defined
    const schemaUpdate = `
      # User authentication fields
      email: string @index(exact) .
      did: string @index(exact) .
      passwordHash: string .
      passwordSalt: string .
      hasWebAuthn: bool .
      hasPassphrase: bool .
      verified: bool .
      status: string .
      
      # MFA fields
      mfaEnabled: bool .
      mfaMethod: string .
      mfaSecret: string .
      
      # Account security fields
      failedLoginAttempts: int .
      lastFailedLogin: datetime .
      lockedUntil: datetime .
      recoveryEmail: string @index(exact) .
      
      # Audit fields
      action: string @index(exact) .
      details: string .
      ipAddress: string .
      userAgent: string .
      timestamp: datetime @index(hour) .
      
      # Credential fields
      credentialID: string @index(exact) .
      publicKey: string .
      counter: int .
      transports: [string] .
      lastUsed: datetime .
      deviceType: string .
      deviceInfo: string .
      
      # Challenge fields
      challenge: string @index(exact) .
      expiresAt: datetime .
      
      # Token fields
      token: string @index(exact) .
      isRevoked: bool .
      isUsed: bool .
      
      # Type definitions
      type User {
        email
        did
        name
        verified
        emailVerified
        dateJoined
        lastAuthTime
        status
        hasWebAuthn
        hasPassphrase
        passwordHash
        passwordSalt
        recoveryEmail
        mfaEnabled
        mfaMethod
        mfaSecret
        failedLoginAttempts
        lastFailedLogin
        lockedUntil
        preferences
        roles
      }
      
      type UserPreferences {
        marketingEmails
        notificationEmails
      }
      
      type Role {
        name
        permissions
      }
      
      type Device {
        credentialID
        publicKey
        counter
        transports
        lastUsed
        createdAt
        name
        isBiometric
        deviceType
        deviceInfo
        userId
      }
      
      type Challenge {
        challenge
        email
        userId
        createdAt
        expiresAt
      }
      
      type AuditLog {
        userId
        action
        details
        ipAddress
        userAgent
        timestamp
      }
      
      type SessionToken {
        userId
        token
        expiresAt
        createdAt
        lastUsed
        ipAddress
        userAgent
        isRevoked
      }
      
      type PasswordResetToken {
        userId
        token
        expiresAt
        createdAt
        isUsed
      }
    `;

    // Execute the schema update
    const response = await fetch(
      `${process.env.DGRAPH_ENDPOINT || "http://localhost:8080"}/alter`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/rdf",
        },
        body: schemaUpdate,
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(
        `Schema update failed: ${response.statusText}, Details: ${errorText}`
      );
      throw new Error(
        `Schema update failed: ${response.statusText}, Details: ${errorText}`
      );
    }

    const result = await response.json();
    logger.info("Schema updated successfully", result);

    return NextResponse.json({
      success: true,
      message: "Schema updated successfully",
      result,
    });
  } catch (error) {
    logger.error(`Error updating schema: ${error}`);
    return NextResponse.json(
      { error: "Failed to update schema" },
      { status: 500 }
    );
  }
}
