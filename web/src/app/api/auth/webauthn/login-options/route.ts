import { type NextRequest, NextResponse } from "next/server";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import logger from "@/lib/logger";
import { db } from "@/lib/db-operations";
import type {
  AuthenticatorTransport,
  UserVerificationRequirement,
} from "@simplewebauthn/types";
import { cookies } from "next/headers";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json();
    const { userId } = body;

    if (!userId) {
      return NextResponse.json(
        { error: "User ID is required" },
        { status: 400 }
      );
    }

    // Get user from database using your existing db client
    const user = await db.user.findUnique({
      where: {
        id: userId,
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

    // Format credentials for authentication
    const allowCredentials = credentials.map(
      (cred: { credentialID: string; transports?: string[] }) => ({
        id: Buffer.from(cred.credentialID, "base64"),
        type: "public-key" as const,
        transports: (cred.transports || [
          "internal",
        ]) as AuthenticatorTransport[],
      })
    );

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID: process.env.WEBAUTHN_RP_ID!,
      allowCredentials,
      userVerification: (process.env.WEBAUTHN_USER_VERIFICATION ||
        "preferred") as UserVerificationRequirement,
    });

    // Store the challenge in a cookie
    const cookieStore = await cookies();
    cookieStore.set("webauthn-challenge", options.challenge, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 60 * 5, // 5 minutes
      path: "/",
    });

    logger.info("Generated authentication options", {
      action: "WEBAUTHN_LOGIN_OPTIONS",
      userId: user.id,
    });

    return NextResponse.json(options);
  } catch (error) {
    logger.error("Failed to generate authentication options", {
      action: "WEBAUTHN_LOGIN_OPTIONS",
      error,
    });

    return NextResponse.json(
      { error: "Failed to generate authentication options" },
      { status: 500 }
    );
  }
}
