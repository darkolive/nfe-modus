import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { verifyRegistration } from "@/lib/webauthn";
import logger from "@/lib/logger";
import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";

const dgraphClient = new DgraphClient();

const verifySchema = z.object({
  response: z.custom<RegistrationResponseJSON>((val) => {
    return val && typeof val === "object" && "id" in val;
  }, "Invalid registration response"),
  deviceName: z.string().min(1).max(64),
  deviceType: z.string().min(1).max(32),
  isBiometric: z.boolean()
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = verifySchema.safeParse(body);

    if (!result.success) {
      return NextResponse.json(
        { error: "Invalid request data" },
        { status: 400 }
      );
    }

    const { response, deviceName, deviceType, isBiometric } = result.data;

    // Get the stored challenge
    const challenge = await dgraphClient.getChallenge(response.response.clientDataJSON);
    if (!challenge) {
      return NextResponse.json(
        { error: "Challenge not found or expired" },
        { status: 400 }
      );
    }

    // Check if challenge is expired (5 minutes)
    const now = new Date();
    if (now > challenge.expiresAt) {
      await dgraphClient.deleteChallenge(challenge.email);
      return NextResponse.json(
        { error: "Challenge expired" },
        { status: 400 }
      );
    }

    // Get user by email
    const user = await dgraphClient.getUserByEmail(challenge.email);
    if (!user) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      );
    }

    try {
      // Verify the registration response
      const verificationResult = await verifyRegistration(
        response,
        challenge.challenge,
        user.id
      );

      // Add device info to credential
      const deviceInfo = {
        name: deviceName,
        type: deviceType,
        isBiometric,
        userAgent: request.headers.get("user-agent") || "unknown"
      };

      // Store the credential
      await dgraphClient.storeCredential({
        ...verificationResult,
        uid: `0x${Math.floor(Math.random() * 16777215).toString(16)}`,
        deviceInfo: JSON.stringify(deviceInfo),
        userId: user.id,
        name: deviceName,
        deviceType,
        isBiometric,
        lastUsed: new Date(),
        createdAt: new Date()
      });

      // Update user hasWebAuthn flag
      await dgraphClient.updateUserHasWebAuthn(user.id, true);

      // Delete the challenge
      await dgraphClient.deleteChallenge(challenge.email);

      // Log successful registration
      await dgraphClient.createAuditLog({
        userId: user.id,
        action: "WEBAUTHN_REGISTER_SUCCESS",
        details: JSON.stringify({
          method: "webauthn",
          deviceName,
          deviceType,
          isBiometric
        }),
        ipAddress: request.headers.get("x-forwarded-for") || 
                  request.headers.get("x-real-ip") || 
                  "unknown",
        userAgent: request.headers.get("user-agent") || "unknown",
        metadata: {
          deviceInfo
        }
      });

      return NextResponse.json({
        success: true,
        message: "WebAuthn credential registered successfully"
      });
    } catch (error) {
      logger.error("Error verifying registration:", error);

      // Log failed registration
      await dgraphClient.createAuditLog({
        userId: user.id,
        action: "WEBAUTHN_REGISTER_FAILED",
        details: JSON.stringify({
          method: "webauthn",
          error: error instanceof Error ? error.message : "Unknown error"
        }),
        ipAddress: request.headers.get("x-forwarded-for") || 
                  request.headers.get("x-real-ip") || 
                  "unknown",
        userAgent: request.headers.get("user-agent") || "unknown",
        metadata: {
          error: error instanceof Error ? error.message : "Unknown error"
        }
      });

      return NextResponse.json(
        { error: "Failed to verify registration" },
        { status: 400 }
      );
    }
  } catch (error) {
    logger.error("Error in WebAuthn registration verification:", error);
    return NextResponse.json(
      { error: "An error occurred during registration verification" },
      { status: 500 }
    );
  }
}
