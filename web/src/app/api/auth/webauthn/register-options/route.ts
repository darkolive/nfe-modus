import { type NextRequest, NextResponse } from "next/server";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import logger from "@/lib/logger";
import type {
  AttestationConveyancePreference,
  AuthenticatorAttachment,
  UserVerificationRequirement,
} from "@simplewebauthn/types";
import { cookies } from "next/headers";

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Get user data from the request
    const body = await request.json();
    const { userId, email, name } = body;

    if (!userId || !email) {
      return NextResponse.json(
        { error: "User ID and email are required" },
        { status: 400 }
      );
    }

    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName: process.env.WEBAUTHN_RP_NAME!,
      rpID: process.env.WEBAUTHN_RP_ID!,
      userID: userId,
      userName: email,
      userDisplayName: name || email,
      attestationType: (process.env.WEBAUTHN_ATTESTATION_PREFERENCE ||
        "none") as AttestationConveyancePreference,
      authenticatorSelection: {
        userVerification: (process.env.WEBAUTHN_USER_VERIFICATION ||
          "preferred") as UserVerificationRequirement,
        authenticatorAttachment: (process.env
          .WEBAUTHN_AUTHENTICATOR_ATTACHMENT || undefined) as
          | AuthenticatorAttachment
          | undefined,
        requireResidentKey:
          process.env.WEBAUTHN_REQUIRE_RESIDENT_KEY === "true",
      },
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

    logger.info("Generated registration options", {
      action: "WEBAUTHN_REGISTER_OPTIONS",
      userId,
    });

    return NextResponse.json(options);
  } catch (error) {
    logger.error("Failed to generate registration options", {
      action: "WEBAUTHN_REGISTER_OPTIONS",
      error,
    });

    return NextResponse.json(
      { error: "Failed to generate registration options" },
      { status: 500 }
    );
  }
}
