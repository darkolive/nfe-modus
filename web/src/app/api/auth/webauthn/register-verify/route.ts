import { NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import { cookies } from "next/headers";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import type { CredentialData } from "@/types/webauthn";
import { verifyEmailVerificationData } from "@/lib/utils";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";

// Initialize Dgraph client
const dgraphClient = new DgraphClient();

// Helper functions
function getOrigin(): string {
  return process.env.NEXT_PUBLIC_ORIGIN || "http://localhost:3000";
}

function getRpID(): string {
  return process.env.NEXT_PUBLIC_RP_ID || "localhost";
}

export async function POST(request: Request): Promise<NextResponse> {
  try {
    logger.debug("WebAuthn registration verification request received");
    
    // Parse the request body
    const body = await request.json();
    const response = body.response as RegistrationResponseJSON;
    
    // Extract the email from the cookie
    const cookieStore = await cookies();
    const emailVerificationCookie = cookieStore.get("emailVerification");
    
    if (!emailVerificationCookie || !emailVerificationCookie.value) {
      logger.warn("No email verification cookie found for WebAuthn registration");
      return NextResponse.json(
        { error: "Email verification required" },
        { status: 401 }
      );
    }
    
    // Decrypt and verify the email verification cookie
    let email: string;
    try {
      const verificationData = await verifyEmailVerificationData(emailVerificationCookie.value);
      if (!verificationData || !verificationData.email) {
        logger.warn("Invalid email verification cookie for WebAuthn registration");
        return NextResponse.json(
          { error: "Invalid email verification" },
          { status: 401 }
        );
      }
      
      email = verificationData.email;
      logger.debug(`Email verified via cookie for ${email}`);
    } catch (error) {
      logger.error("Error verifying email verification cookie", {
        action: "WEBAUTHN_REGISTER_VERIFY_COOKIE_ERROR",
        error: error instanceof Error ? error.message : "Unknown error"
      });
      return NextResponse.json(
        { error: "Invalid email verification" },
        { status: 401 }
      );
    }
    
    // Get the challenge for this email
    const challenge = await dgraphClient.getChallenge(email);
    
    if (!challenge) {
      logger.warn(`No challenge found for WebAuthn registration: ${email}`);
      return NextResponse.json(
        { error: "Challenge not found" },
        { status: 400 }
      );
    }
    
    logger.debug("Challenge found for WebAuthn registration");
    
    // Check if the challenge has expired
    const expiresAt = new Date(challenge.expiresAt);
    if (expiresAt < new Date()) {
      logger.warn(`Challenge expired for WebAuthn registration: ${email}`);
      return NextResponse.json(
        { error: "Challenge expired" },
        { status: 400 }
      );
    }
    
    // Verify the WebAuthn registration response
    const origin = getOrigin();
    const rpID = getRpID();
    
    // Log the email verification for debugging
    logger.debug("Email verification confirmed for WebAuthn registration", {
      email,
      action: "WEBAUTHN_REGISTER_EMAIL_VERIFICATION",
    });

    // First, ensure system roles exist
    await dgraphClient.initializeSystemRoles();
    
    // Get the registered role UID
    const registeredRole = await dgraphClient.getRoleByName("registered");
    
    if (!registeredRole) {
      logger.error("Registered role not found", {
        action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
        error: "Registered role not found"
      });
      // Continue anyway, we'll create the user without a role
    }

    // Check if user already exists
    const existingUser = await dgraphClient.getUserByEmail(email);
    let userId: string;
    
    // If user exists but doesn't have WebAuthn credentials yet, we'll update them
    if (existingUser) {
      logger.info("User already exists, updating WebAuthn status", {
        action: "WEBAUTHN_REGISTER_USER_EXISTS",
        email,
        userId: existingUser.did
      });
      
      userId = existingUser.did;
      
      // Ensure the user has the registered role
      if (registeredRole) {
        const userRoles = await dgraphClient.getUserRoles(userId);
        if (!userRoles.includes("registered")) {
          try {
            await dgraphClient.assignRoleToUser(userId, registeredRole.uid);
            logger.info("Registered role assigned to existing user", {
              action: "WEBAUTHN_REGISTER_ROLE_ASSIGNED",
              email,
              userId,
              roleId: registeredRole.uid
            });
          } catch (roleError) {
            logger.warn("Failed to assign registered role to existing user", {
              action: "WEBAUTHN_REGISTER_ROLE_ASSIGN_ERROR",
              email,
              userId,
              error: roleError instanceof Error ? roleError.message : String(roleError)
            });
          }
        }
      }
    } else {
      // Create a new user if one doesn't exist
      logger.info(`Creating new user for WebAuthn registration: ${email}`, {
        action: "WEBAUTHN_REGISTER_CREATE_USER",
        email
      });

      try {
        // First, ensure system roles exist
        await dgraphClient.initializeSystemRoles();
        
        // Get the registered role UID
        const registeredRole = await dgraphClient.getRoleByName("registered");
        
        if (!registeredRole) {
          logger.error("Registered role not found", {
            action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
            error: "Registered role not found"
          });
          // Continue anyway, we'll create the user without a role
        }
        
        // Log the user data we're about to create
        logger.debug("Creating user with data:");
        
        // Create a new user
        const now = new Date();
        const newUser: {
          email: string;
          did: string;
          name: string | null;
          verified: boolean;
          emailVerified: string | null;
          dateJoined: Date;
          lastAuthTime: string | null;
          status: "active" | "inactive" | "suspended";
          hasWebAuthn: boolean;
          hasPassphrase: boolean;
          passwordHash?: string | null;
          passwordSalt?: string | null;
          recoveryEmail?: string | null;
          mfaEnabled: boolean;
          mfaMethod: string | undefined;
          mfaSecret: string | undefined;
          failedLoginAttempts: number;
          lastFailedLogin: string | null;
          lockedUntil: string | null;
          roles: Array<{ uid: string }>;
          createdAt: Date;
          updatedAt: Date | null;
        } = {
          email,
          did: uuidv4(), // Generate a DID for the user
          name: null,
          verified: true,
          emailVerified: now.toISOString(),
          dateJoined: now,
          lastAuthTime: null,
          status: "active",
          hasWebAuthn: true,
          hasPassphrase: false,
          mfaEnabled: false,
          mfaMethod: undefined,
          mfaSecret: undefined,
          failedLoginAttempts: 0,
          lastFailedLogin: null,
          lockedUntil: null,
          roles: registeredRole ? [{ uid: registeredRole.uid }] : [],
          createdAt: now,
          updatedAt: null
        };

        // Create the user in Dgraph
        userId = await dgraphClient.createUser(newUser);
        
        logger.info("User created successfully", {
          action: "WEBAUTHN_REGISTER_USER_CREATED",
          email,
          userId
        });

        // Check if user was created successfully
        if (!userId) {
          logger.error(`Failed to create user for WebAuthn registration: ${email}`, {
            action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
            error: "User ID is empty"
          });
          return NextResponse.json(
            { error: "Failed to create user" },
            { status: 500 }
          );
        }

        // If we found the registered role but couldn't add it during user creation,
        // assign it now using the assignRoleToUser method
        if (registeredRole && newUser.roles.length === 0) {
          try {
            await dgraphClient.assignRoleToUser(userId, registeredRole.uid);
            logger.info("Registered role assigned to user", {
              action: "WEBAUTHN_REGISTER_ROLE_ASSIGNED",
              email,
              userId,
              roleId: registeredRole.uid
            });
          } catch (roleError) {
            // Log the error but continue with the registration process
            logger.warn("Failed to assign registered role to user", {
              action: "WEBAUTHN_REGISTER_ROLE_ASSIGN_ERROR",
              email,
              userId,
              error: roleError instanceof Error ? roleError.message : String(roleError)
            });
          }
        }

        // Update the challenge with the new user ID
        // Since we can't update the challenge directly, we'll create a new one
        await dgraphClient.deleteChallenge(email);
        await dgraphClient.storeChallenge({
          userId,
          email,
          challenge: challenge.challenge
        });
        
        // Get the updated challenge
        const updatedChallenge = await dgraphClient.getChallenge(email);
        if (!updatedChallenge) {
          logger.error("Failed to update challenge with new user ID", {
            action: "WEBAUTHN_REGISTER_CHALLENGE_UPDATE_ERROR",
            email,
            userId
          });
          return NextResponse.json(
            { error: "Failed to update challenge" },
            { status: 500 }
          );
        }
      } catch (error) {
        logger.error("Error creating user for WebAuthn registration", {
          action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
          email,
          error: error instanceof Error ? error.message : "Unknown error"
        });
        return NextResponse.json(
          { error: "Failed to create user" },
          { status: 500 }
        );
      }
    }

    try {
      // Get the latest challenge for verification
      const currentChallenge = await dgraphClient.getChallenge(email);
      if (!currentChallenge) {
        logger.error("Challenge not found after user creation", {
          action: "WEBAUTHN_REGISTER_CHALLENGE_ERROR",
          email,
          userId
        });
        return NextResponse.json(
          { error: "Challenge not found" },
          { status: 400 }
        );
      }

      // Verify the registration response
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: currentChallenge.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true
      });

      if (!verification.verified) {
        logger.error("WebAuthn registration verification failed", {
          action: "WEBAUTHN_REGISTER_VERIFICATION_ERROR",
          email,
          userId
        });
        return NextResponse.json(
          { error: "Verification failed" },
          { status: 400 }
        );
      }

      // Store the credential
      const { registrationInfo } = verification;
      
      if (!registrationInfo) {
        logger.error("Registration info missing from verification", {
          action: "WEBAUTHN_REGISTER_INFO_ERROR",
          email,
          userId
        });
        return NextResponse.json(
          { error: "Registration info missing" },
          { status: 400 }
        );
      }

      // Get the credential data
      const now = new Date();
      const credentialData: CredentialData = {
        uid: "", // This will be assigned by Dgraph
        credentialID: Buffer.from(registrationInfo.credential.id).toString('base64url'),
        credentialPublicKey: Buffer.from(registrationInfo.credential.publicKey).toString('base64url'),
        counter: registrationInfo.credential.counter,
        transports: response.response.transports || [],
        lastUsed: now,
        name: body.deviceName || "Unknown device",
        isBiometric: body.isBiometric || false,
        deviceType: body.deviceType || "unknown",
        deviceInfo: body.deviceInfo || "",
        userId,
        createdAt: now,
        updatedAt: null
      };

      // Store the credential in Dgraph
      await dgraphClient.storeCredential(credentialData);

      // Update the user's hasWebAuthn flag
      await dgraphClient.updateUserHasWebAuthn(userId, true);

      // Delete the challenge
      await dgraphClient.deleteChallenge(email);

      // Return success
      return NextResponse.json({ success: true });
    } catch (error) {
      logger.error("Error during WebAuthn registration verification", {
        action: "WEBAUTHN_REGISTER_ERROR",
        email,
        error: error instanceof Error ? error.message : "Unknown error"
      });
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "Unknown error" },
        { status: 500 }
      );
    }
  } catch (error) {
    logger.error("Unexpected error in WebAuthn registration verification", {
      action: "WEBAUTHN_REGISTER_UNEXPECTED_ERROR",
      error: error instanceof Error ? error.message : "Unknown error"
    });
    return NextResponse.json(
      { error: "An unexpected error occurred" },
      { status: 500 }
    );
  }
}
