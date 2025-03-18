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

    try {
      // First, ensure system roles exist
      logger.info(`Starting system role initialization for WebAuthn registration: ${email}`, {
        action: "WEBAUTHN_REGISTER_INIT_ROLES_START",
        email,
        requestId: uuidv4() // Add a unique identifier to track this specific request
      });
      
      await dgraphClient.initializeSystemRoles();
      
      // Get the registered role UID
      logger.info(`Getting registered role for WebAuthn registration: ${email}`, {
        action: "WEBAUTHN_REGISTER_GET_ROLE",
        email
      });
      
      const registeredRole = await dgraphClient.getRoleByName("registered");
      
      if (!registeredRole) {
        logger.error("Registered role not found", {
          action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
          error: "Registered role not found"
        });
        // Continue anyway, we'll create the user without a role
      } else {
        logger.info(`Found registered role for WebAuthn registration: ${email}`, {
          action: "WEBAUTHN_REGISTER_ROLE_FOUND",
          email,
          roleId: registeredRole.uid
        });
      }
      
      // Check if user already exists
      const existingUser = await dgraphClient.getUserByEmail(email);
      let userId: string;
      let newUser: {
        email: string;
        did: string;
        name: string | null;
        verified: boolean;
        emailVerified: string;
        dateJoined: string;
        lastAuthTime: string | null;
        status: 'active' | 'inactive' | 'suspended';
        hasWebAuthn: boolean;
        hasPassphrase: boolean;
        passwordHash: string | null;
        passwordSalt: string | null;
        recoveryEmail: string | null;
        mfaEnabled: boolean;
        mfaMethod: string | null;
        mfaSecret: string | null;
        failedLoginAttempts: number;
        lastFailedLogin: string | null;
        lockedUntil: string | null;
        roles: { uid: string }[];
        createdAt: string;
        updatedAt: string | null;
        devices: { uid: string }[];
      };
      
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
          } else {
            logger.info("User already has registered role", {
              action: "WEBAUTHN_REGISTER_HAS_ROLE",
              email,
              userId
            });
          }
        }
      } else {
        // Log the user data we're about to create
        logger.debug(`Preparing user data for WebAuthn registration: ${email}`, {
          action: "WEBAUTHN_REGISTER_PREPARE_USER_DATA",
          email
        });
        
        // Create a new user
        const now = new Date();
        newUser = {
          email,
          did: uuidv4(), // Generate a DID for the user
          name: null,
          verified: true,
          emailVerified: now.toISOString(),
          dateJoined: now.toISOString(),
          lastAuthTime: null,
          status: "active" as const,
          hasWebAuthn: true,
          hasPassphrase: false,
          passwordHash: null,
          passwordSalt: null,
          recoveryEmail: null,
          mfaEnabled: false,
          mfaMethod: null,
          mfaSecret: null,
          failedLoginAttempts: 0,
          lastFailedLogin: null,
          lockedUntil: null,
          roles: registeredRole ? [{ uid: registeredRole.uid }] : [],
          createdAt: now.toISOString(),
          updatedAt: null,
          devices: []
        };
        
        logger.info(`Creating user in Dgraph for WebAuthn registration: ${email}`, {
          action: "WEBAUTHN_REGISTER_CREATE_USER_START",
          email,
          hasRole: registeredRole ? true : false,
          roleId: registeredRole ? registeredRole.uid : null,
          roles: newUser.roles
        });
        
        try {
          userId = await dgraphClient.createUser(newUser);
          
          logger.info("User created successfully", {
            action: "WEBAUTHN_REGISTER_USER_CREATED",
            email,
            userId,
            roles: newUser.roles.length
          });

          // Explicitly assign the registered role to the user
          if (registeredRole && userId) {
            try {
              await dgraphClient.assignRoleToUser(userId, registeredRole.uid);
              logger.info("Explicitly assigned registered role to new user", {
                action: "WEBAUTHN_REGISTER_ROLE_ASSIGNED_EXPLICITLY",
                email,
                userId,
                roleId: registeredRole.uid
              });
            } catch (roleError) {
              logger.warn("Failed to explicitly assign registered role to new user", {
                action: "WEBAUTHN_REGISTER_EXPLICIT_ROLE_ASSIGN_ERROR",
                email,
                userId,
                error: roleError instanceof Error ? roleError.message : String(roleError)
              });
            }
          }
  
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
        } catch (createError) {
          logger.error("Error creating user for WebAuthn registration", {
            action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
            email,
            error: createError instanceof Error ? createError.message : "Unknown error"
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
        
        logger.debug("Retrieved challenge for verification", {
          action: "WEBAUTHN_REGISTER_GET_CHALLENGE",
          email,
          userId,
          hasChallenge: currentChallenge ? true : false,
          challengeFormat: currentChallenge ? currentChallenge.challenge : "no challenge"
        });
        
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
        // The SimpleWebAuthn library expects the challenge in base64url format
        try {
          // Log the challenge for debugging purposes
          logger.debug("Challenge for verification", {
            action: "WEBAUTHN_REGISTER_CHALLENGE_DEBUG",
            email,
            userId,
            storedChallenge: currentChallenge.challenge
          });

          const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: currentChallenge.challenge, // Already in base64url format
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
          
          // Delete the previous challenge
          await dgraphClient.deleteChallenge(email);
          logger.debug("Challenge deleted after successful verification", {
            action: "WEBAUTHN_REGISTER_DELETE_CHALLENGE",
            email,
            userId
          });

          // Store the credential
          const currentTime = new Date();
          
          // Check if verification.registrationInfo is defined
          if (!verification.registrationInfo) {
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
          
          const credentialData: CredentialData = {
            uid: "_:credential", // Use a named blank node for better tracking
            credentialID: Buffer.from(verification.registrationInfo.credential.id).toString('base64url'),
            credentialPublicKey: Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64url'),
            counter: verification.registrationInfo.credential.counter,
            transports: response.response.transports || [],
            lastUsed: currentTime.toISOString(),
            deviceName: body.deviceName || "Unknown device",
            isBiometric: body.isBiometric || false,
            deviceType: body.deviceType || "unknown",
            deviceInfo: body.deviceInfo || "",
            userId: userId,
            createdAt: currentTime.toISOString(),
            updatedAt: null,
            "dgraph.type": "Device"
          };

          logger.debug("Creating WebAuthn credential", {
            action: "WEBAUTHN_REGISTER_CREATE_CREDENTIAL",
            email,
            userId,
            credentialData: JSON.stringify({
              ...credentialData,
              credentialPublicKey: "[REDACTED]" // Don't log the actual key
            })
          });

          try {
            const credentialId = await dgraphClient.storeCredential(credentialData);
            
            // Check if credential was stored correctly
            if (!credentialId) {
              logger.error("Failed to store credential", {
                action: "WEBAUTHN_REGISTER_STORE_CREDENTIAL_ERROR",
                email,
                userId
              });
              return NextResponse.json(
                { error: "Failed to store credential" },
                { status: 500 }
              );
            }
            
            logger.info("WebAuthn credential stored successfully", {
              action: "WEBAUTHN_REGISTER_CREDENTIAL_STORED",
              email,
              userId,
              credentialId
            });
            
            // Return success
            return NextResponse.json({
              verified: true,
              registrationInfo: {
                fmt: verification.registrationInfo.fmt,
                counter: verification.registrationInfo.credential.counter,
                credentialID: credentialData.credentialID,
                credentialDeviceType: verification.registrationInfo.credentialDeviceType,
                credentialBackedUp: verification.registrationInfo.credentialBackedUp,
                aaguid: verification.registrationInfo.aaguid || ""
              }
            });
          } catch (credentialError) {
            logger.error("Error storing WebAuthn credential", {
              action: "WEBAUTHN_REGISTER_CREDENTIAL_ERROR",
              email,
              userId,
              error: credentialError instanceof Error ? credentialError.message : String(credentialError)
            });
            
            return NextResponse.json(
              { error: "Failed to store WebAuthn credential" },
              { status: 500 }
            );
          }
        } catch (error) {
          // Handle errors during registration verification
          logger.error("Error during WebAuthn registration verification", {
            action: "WEBAUTHN_REGISTER_VERIFICATION_ERROR",
            email,
            error: error instanceof Error ? error.message : "Unknown error",
            stack: error instanceof Error ? error.stack : undefined
          });
          
          return NextResponse.json(
            { error: error instanceof Error ? error.message : "Verification failed" },
            { status: 500 }
          );
        }
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
