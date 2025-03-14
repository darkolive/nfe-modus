import { type NextRequest, NextResponse } from "next/server";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import logger from "@/lib/logger";
import { headers, cookies } from "next/headers";
import { bufferToBase64url } from "@/lib/encoding";
import { db } from "@/lib/db-operations";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json();
    const { registration, userId } = body;

    if (!userId) {
      return NextResponse.json(
        { error: "User ID is required" },
        { status: 400 }
      );
    }

    // Get the challenge from the cookie
    const cookieStore = await cookies();
    const challenge = cookieStore.get("webauthn-challenge")?.value;

    if (!challenge) {
      logger.error("No challenge found in cookie", {
        action: "WEBAUTHN_REGISTER_VERIFY",
        userId,
      });
      return NextResponse.json(
        { error: "No challenge found" },
        { status: 400 }
      );
    }

    const headersList = await headers();
    const ip = headersList.get("x-forwarded-for") || "127.0.0.1";
    const userAgent = headersList.get("user-agent") || "Unknown";

    const verification = await verifyRegistrationResponse({
      response: registration as RegistrationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: process.env.NEXT_PUBLIC_APP_URL!,
      expectedRPID: process.env.NEXT_PUBLIC_WEBAUTHN_RPID!,
      requireUserVerification:
        process.env.WEBAUTHN_USER_VERIFICATION === "required",
    });

    // Clear the challenge cookie
    await cookieStore.delete("webauthn-challenge");

    if (!verification.verified || !verification.registrationInfo) {
      logger.error("Failed to verify registration", {
        action: "WEBAUTHN_REGISTER_VERIFY",
        userId,
        ip,
      });
      return NextResponse.json(
        { error: "Failed to verify registration" },
        { status: 400 }
      );
    }

    // Store the credential in DGraph
    logger.info(`Storing credential for user ${userId}`, {
      action: "CREDENTIAL_STORAGE",
      ip,
    });

    // Extract credential information from verification
    const { registrationInfo } = verification;

    // Ensure proper base64url encoding for credentialID
    const base64CredentialID = bufferToBase64url(registrationInfo.credentialID);
    const base64PublicKey = bufferToBase64url(
      registrationInfo.credentialPublicKey
    );

    const credentialData = {
      credentialID: base64CredentialID,
      publicKey: base64PublicKey,
      counter: 0, // Initial counter value
      transports: registration.response.transports || ["internal"],
      createdAt: new Date(),
      userId,
      isBiometric: true,
      name: "My device", // You can customize this based on user input
      deviceType: userAgent.includes("Mobile") ? "mobile" : "desktop",
      deviceInfo: {
        userAgent,
        registrationTime: new Date().toISOString(),
        ipAddress: ip,
      },
    };

    // Use your existing db client to create the credential
    await db.credential.create({
      data: credentialData,
    });

    // Update user to indicate they have WebAuthn credentials
    await db.updateUser({
      id: userId,
      hasWebAuthn: true,
    });

    logger.info(`Successfully stored credential for user ${userId}`, {
      action: "CREDENTIAL_STORAGE",
      userId,
      ip,
    });

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error";
    logger.error(errorMessage, {
      action: "WEBAUTHN_REGISTER_VERIFY",
    });
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
