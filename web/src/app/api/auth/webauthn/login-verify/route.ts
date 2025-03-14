import { type NextRequest, NextResponse } from "next/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { normalizeCredentialId } from "@/lib/encoding";
import logger from "@/lib/logger";
import { db } from "@/lib/db-operations";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { cookies } from "next/headers";

export async function POST(req: NextRequest) {
  try {
    const { id, response } = await req.json();

    if (!id || !response) {
      return NextResponse.json(
        { error: "Missing id or response" },
        { status: 400 }
      );
    }

    // Get user from database using your existing db client
    const user = await db.user.findUnique({
      where: {
        id: id,
      },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Get credentials using your existing db client
    const credentials = await db.credential.findMany({
      where: {
        userId: user.id,
      },
    });

    if (!credentials || credentials.length === 0) {
      return NextResponse.json(
        { error: "No credentials found for user" },
        { status: 404 }
      );
    }

    // Find the credential that matches the response
    const credential = credentials.find((cred: { credentialID: string }) => {
      // Normalize the credential ID format for comparison
      const normalizedCredID = normalizeCredentialId(cred.credentialID);
      const normalizedResponseID = normalizeCredentialId(response.id);

      return normalizedCredID === normalizedResponseID;
    });

    if (!credential) {
      return NextResponse.json(
        { error: "Credential not found" },
        { status: 404 }
      );
    }

    // Get the challenge from the cookie
    const cookieStore = await cookies();
    const challenge = cookieStore.get("webauthn-challenge")?.value;

    if (!challenge) {
      logger.error("No challenge found in cookie", {
        action: "WEBAUTHN_LOGIN_VERIFY",
        userId: user.id,
      });
      return NextResponse.json(
        { error: "No challenge found" },
        { status: 400 }
      );
    }

    const verification = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: process.env.NEXT_PUBLIC_DOMAIN!,
      expectedRPID: process.env.WEBAUTHN_RP_ID!,
      authenticator: {
        credentialID: Buffer.from(credential.credentialID, "base64"),
        credentialPublicKey: Buffer.from(credential.publicKey, "base64"),
        counter: credential.counter,
      },
      requireUserVerification:
        process.env.WEBAUTHN_USER_VERIFICATION === "required",
    });

    // Clear the challenge cookie
    await cookieStore.delete("webauthn-challenge");

    if (!verification.verified) {
      logger.error("Invalid credentials", {
        action: "WEBAUTHN_LOGIN_VERIFY",
        userId: user.id,
      });
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 400 }
      );
    }

    await db.credential.update({
      where: {
        id: credential.id,
      },
      data: {
        counter: verification.authenticationInfo.newCounter,
      },
    });

    logger.info("User authenticated successfully", {
      action: "WEBAUTHN_LOGIN_VERIFY",
      userId: user.id,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error("Login verification error", {
      action: "WEBAUTHN_LOGIN_VERIFY",
      error,
    });
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
