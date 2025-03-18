import { NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import { cookies } from "next/headers";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type {
  RegistrationResponseJSON,
  Base64URLString,
} from "@simplewebauthn/server";
import { verifyEmailVerificationData } from "@/lib/utils";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { createSessionToken } from "@/lib/jwt";
import type { CredentialData } from "@/types/webauthn";

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

    // Log the entire request body for debugging
    logger.debug("WebAuthn registration verification request body", {
      action: "WEBAUTHN_REGISTER_DEBUG_REQUEST",
      deviceName: body.deviceName,
      deviceType: body.deviceType,
      isBiometric: body.isBiometric,
      hasDeviceInfo: !!body.deviceInfo,
      responseTransports: response.response.transports,
    });

    // Extract the email from the cookie
    const cookieStore = await cookies();
    const emailVerificationCookie = cookieStore.get("emailVerification");

    if (!emailVerificationCookie || !emailVerificationCookie.value) {
      logger.warn(
        "No email verification cookie found for WebAuthn registration"
      );
      return NextResponse.json(
        { error: "Email verification required" },
        { status: 401 }
      );
    }

    // Decrypt and verify the email verification cookie
    let email: string;
    try {
      const verificationData = await verifyEmailVerificationData(
        emailVerificationCookie.value
      );
      if (!verificationData || !verificationData.email) {
        logger.warn(
          "Invalid email verification cookie for WebAuthn registration"
        );
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
        error: error instanceof Error ? error.message : "Unknown error",
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
      return NextResponse.json({ error: "Challenge expired" }, { status: 400 });
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
      logger.info(
        `Starting system role initialization for WebAuthn registration: ${email}`,
        {
          action: "WEBAUTHN_REGISTER_INIT_ROLES_START",
          email,
          requestId: uuidv4(), // Add a unique identifier to track this specific request
        }
      );

      await dgraphClient.initializeSystemRoles();

      // Get the registered role UID
      logger.info(
        `Getting registered role for WebAuthn registration: ${email}`,
        {
          action: "WEBAUTHN_REGISTER_GET_ROLE",
          email,
        }
      );

      const registeredRole = await dgraphClient.getRoleByName("registered");

      if (!registeredRole) {
        logger.error("Registered role not found", {
          action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
          error: "Registered role not found",
        });
        // Continue anyway, we'll create the user without a role
      } else {
        logger.info(
          `Found registered role for WebAuthn registration: ${email}`,
          {
            action: "WEBAUTHN_REGISTER_ROLE_FOUND",
            email,
            roleId: registeredRole.uid,
          }
        );
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
        status: "active" | "inactive" | "suspended";
        hasWebAuthn: boolean;
        hasPassphrase: boolean;
        passwordHash: string | null;
        passwordSalt: string | null;
        recoveryEmail: string | null;
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
          userId: existingUser.id,
        });

        userId = existingUser.id;

        // Ensure the user has the registered role
        if (registeredRole) {
          try {
            logger.debug("Getting user roles", {
              action: "WEBAUTHN_REGISTER_GET_ROLES",
              email,
              userId,
            });

            const userRoles = await dgraphClient.getUserRoles(userId);

            logger.debug("User roles retrieved", {
              action: "WEBAUTHN_REGISTER_ROLES_RETRIEVED",
              email,
              userId,
              roles: userRoles,
            });

            if (!userRoles.includes("registered")) {
              try {
                logger.debug("Assigning registered role to user", {
                  action: "WEBAUTHN_REGISTER_ASSIGNING_ROLE",
                  email,
                  userId,
                  roleId: registeredRole.uid,
                });

                await dgraphClient.assignRoleToUser(userId, registeredRole.uid);

                logger.info("Registered role assigned to existing user", {
                  action: "WEBAUTHN_REGISTER_ROLE_ASSIGNED",
                  email,
                  userId,
                  roleId: registeredRole.uid,
                });
              } catch (roleError) {
                logger.warn(
                  "Failed to assign registered role to existing user",
                  {
                    action: "WEBAUTHN_REGISTER_ROLE_ASSIGN_ERROR",
                    email,
                    userId,
                    error:
                      roleError instanceof Error
                        ? roleError.message
                        : String(roleError),
                    stack:
                      roleError instanceof Error ? roleError.stack : undefined,
                  }
                );
                // Continue despite role assignment error - don't block registration
              }
            } else {
              logger.info("User already has registered role", {
                action: "WEBAUTHN_REGISTER_HAS_ROLE",
                email,
                userId,
              });
            }
          } catch (error) {
            logger.error("Error getting user roles", {
              action: "WEBAUTHN_REGISTER_GET_ROLES_ERROR",
              email,
              userId,
              error: error instanceof Error ? error.message : "Unknown error",
              stack: error instanceof Error ? error.stack : undefined,
            });
          }
        }
      } else {
        // Log the user data we're about to create
        logger.debug(
          `Preparing user data for WebAuthn registration: ${email}`,
          {
            action: "WEBAUTHN_REGISTER_PREPARE_USER_DATA",
            email,
          }
        );

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
          failedLoginAttempts: 0,
          lastFailedLogin: null,
          lockedUntil: null,
          roles: registeredRole ? [{ uid: registeredRole.uid }] : [],
          createdAt: now.toISOString(),
          updatedAt: null,
          devices: [],
        };

        logger.info(
          `Creating user in Dgraph for WebAuthn registration: ${email}`,
          {
            action: "WEBAUTHN_REGISTER_CREATE_USER_START",
            email,
            hasRole: registeredRole ? true : false,
            roleId: registeredRole ? registeredRole.uid : null,
            roles: newUser.roles,
          }
        );

        try {
          userId = await dgraphClient.createUser(newUser);

          logger.info("User created successfully", {
            action: "WEBAUTHN_REGISTER_USER_CREATED",
            email,
            userId,
            roles: newUser.roles.length,
          });

          // Explicitly assign the registered role to the user
          if (registeredRole && userId) {
            try {
              logger.debug("Assigning registered role to user", {
                action: "WEBAUTHN_REGISTER_ASSIGNING_ROLE",
                email,
                userId,
                roleId: registeredRole.uid,
              });

              await dgraphClient.assignRoleToUser(userId, registeredRole.uid);

              logger.info("Explicitly assigned registered role to new user", {
                action: "WEBAUTHN_REGISTER_ROLE_ASSIGNED_EXPLICITLY",
                email,
                userId,
                roleId: registeredRole.uid,
              });
            } catch (roleError) {
              logger.warn(
                "Failed to explicitly assign registered role to new user",
                {
                  action: "WEBAUTHN_REGISTER_EXPLICIT_ROLE_ASSIGN_ERROR",
                  email,
                  userId,
                  error:
                    roleError instanceof Error
                      ? roleError.message
                      : String(roleError),
                  stack:
                    roleError instanceof Error ? roleError.stack : undefined,
                }
              );
            }
          }

          // Check if user was created successfully
          if (!userId) {
            logger.error(
              `Failed to create user for WebAuthn registration: ${email}`,
              {
                action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
                error: "User ID is empty",
              }
            );
            return NextResponse.json(
              { error: "Failed to create user" },
              { status: 500 }
            );
          }
        } catch (createError) {
          logger.error("Error creating user for WebAuthn registration", {
            action: "WEBAUTHN_REGISTER_CREATE_USER_ERROR",
            email,
            error:
              createError instanceof Error
                ? createError.message
                : "Unknown error",
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
          challengeFormat: currentChallenge
            ? currentChallenge.challenge
            : "no challenge",
        });

        if (!currentChallenge) {
          logger.error("Challenge not found after user creation", {
            action: "WEBAUTHN_REGISTER_CHALLENGE_ERROR",
            email,
            userId,
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
            storedChallenge: currentChallenge.challenge,
          });

          // Log client data for debugging
          logger.debug("Client data for verification", {
            action: "WEBAUTHN_REGISTER_CLIENT_DATA",
            email,
            userId,
            responseId: response.id,
            hasClientData: !!response.response.clientDataJSON,
            hasAttestationObject: !!response.response.attestationObject,
            transports: response.response.transports,
          });

          // Important: verification expects challenge exactly as stored from generateRegistrationOptions
          // Do NOT convert the challenge - let the SimpleWebAuthn library handle it
          const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: currentChallenge.challenge, // Must be EXACTLY as it was stored
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: true,
          });

          logger.debug("Verification result", {
            action: "WEBAUTHN_REGISTER_VERIFICATION_RESULT",
            email,
            userId,
            verified: verification.verified,
            hasRegistrationInfo: !!verification.registrationInfo,
            fmt: verification.registrationInfo?.fmt,
          });

          if (!verification.verified) {
            logger.error("WebAuthn registration verification failed", {
              action: "WEBAUTHN_REGISTER_VERIFICATION_ERROR",
              email,
              userId,
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
            userId,
          });

          // Store the credential
          const currentTime = new Date();

          // Check if verification.registrationInfo is defined
          if (!verification.registrationInfo) {
            logger.error("Registration info missing from verification", {
              action: "WEBAUTHN_REGISTER_INFO_ERROR",
              email,
              userId,
            });
            return NextResponse.json(
              { error: "Registration info missing" },
              { status: 400 }
            );
          }

          // Get credential data from verification result
          // Use proper base64url encoding as required by WebAuthn v13
          const credentialIDBuffer =
            verification.registrationInfo.credential.id;
          const credentialPublicKeyBuffer =
            verification.registrationInfo.credential.publicKey;

          // Convert to base64 strings and then to base64url format
          const credentialIDBase64 =
            Buffer.from(credentialIDBuffer).toString("base64");
          const credentialPublicKeyBase64 = Buffer.from(
            credentialPublicKeyBuffer
          ).toString("base64");

          // Convert to base64url by replacing characters and removing padding
          const toBase64Url = (base64: string): string => {
            return base64
              .replace(/\+/g, "-")
              .replace(/\//g, "_")
              .replace(/=/g, "");
          };

          // Create credential data object with proper formatting
          const credentialData: CredentialData = {
            uid: "_:credential", // Use a named blank node for better tracking
            credentialID: toBase64Url(credentialIDBase64) as Base64URLString,
            credentialPublicKey: toBase64Url(
              credentialPublicKeyBase64
            ) as Base64URLString,
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
            "dgraph.type": "Device",
          };

          logger.debug("Creating WebAuthn credential", {
            action: "WEBAUTHN_REGISTER_CREATE_CREDENTIAL",
            email,
            userId,
            credentialData: JSON.stringify({
              ...credentialData,
              credentialPublicKey: "[REDACTED]", // Don't log the actual key
            }),
          });

          try {
            const credentialId =
              await dgraphClient.storeCredential(credentialData);

            // Check if credential was stored correctly
            if (!credentialId) {
              logger.error("Failed to store credential", {
                action: "WEBAUTHN_REGISTER_STORE_CREDENTIAL_ERROR",
                email,
                userId,
              });
              return NextResponse.json(
                { error: "Failed to store credential" },
                { status: 500 }
              );
            }

            // Update the user's hasWebAuthn flag to true
            await dgraphClient.updateWebAuthnStatus(userId, true);

            // Create a session token for the user
            const sessionId = uuidv4();
            const sessionToken = await createSessionToken({
              id: sessionId,
              userId: userId,
              email: email,
              deviceId: credentialId,
              roles: ["registered"],
            });

            // Set the token in a cookie
            const cookieStore = await cookies();
            cookieStore.set("token", sessionToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production",
              sameSite: "strict",
              maxAge: 60 * 60 * 24, // 24 hours
              path: "/",
            });

            logger.info(
              "WebAuthn credential stored successfully and user status updated",
              {
                action: "WEBAUTHN_REGISTER_COMPLETE",
                email,
                userId,
                credentialId,
                hasWebAuthnUpdated: true,
              }
            );

            // Return success
            return NextResponse.json({
              verified: true,
              registrationInfo: {
                fmt: verification.registrationInfo.fmt,
                counter: verification.registrationInfo.credential.counter,
                credentialID: credentialData.credentialID,
                credentialDeviceType:
                  verification.registrationInfo.credentialDeviceType,
                credentialBackedUp:
                  verification.registrationInfo.credentialBackedUp,
                aaguid: verification.registrationInfo.aaguid || "",
              },
            });
          } catch (credentialError) {
            logger.error("Error storing WebAuthn credential", {
              action: "WEBAUTHN_REGISTER_CREDENTIAL_ERROR",
              email,
              userId,
              error:
                credentialError instanceof Error
                  ? credentialError.message
                  : String(credentialError),
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
            stack: error instanceof Error ? error.stack : undefined,
          });

          return NextResponse.json(
            {
              error:
                error instanceof Error ? error.message : "Verification failed",
            },
            { status: 500 }
          );
        }
      } catch (error) {
        logger.error("Error during WebAuthn registration verification", {
          action: "WEBAUTHN_REGISTER_ERROR",
          email,
          error: error instanceof Error ? error.message : "Unknown error",
        });
        return NextResponse.json(
          { error: error instanceof Error ? error.message : "Unknown error" },
          { status: 500 }
        );
      }
    } catch (error) {
      logger.error("Unexpected error in WebAuthn registration verification", {
        action: "WEBAUTHN_REGISTER_UNEXPECTED_ERROR",
        errorMessage: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });

      return NextResponse.json(
        {
          error:
            "An unexpected error occurred during registration verification",
        },
        { status: 500 }
      );
    }
  } catch (error) {
    logger.error("Unexpected error in WebAuthn registration verification", {
      action: "WEBAUTHN_REGISTER_UNEXPECTED_ERROR",
      errorMessage: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    return NextResponse.json(
      {
        error: "An unexpected error occurred during registration verification",
      },
      { status: 500 }
    );
  }
}
