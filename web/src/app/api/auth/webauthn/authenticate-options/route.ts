import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { generateAuthenticationOptions } from "@/lib/webauthn";
import { z } from "zod";
import logger from "@/lib/logger";

// Input validation schema following Skeleton v3 patterns
const AuthenticateOptionsSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
});

export async function POST(request: NextRequest) {
  try {
    // Get client IP for logging
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // Parse and validate input
    const body = await request.json();
    const result = AuthenticateOptionsSchema.safeParse(body);

    if (!result.success) {
      logger.warn("Invalid WebAuthn authentication options input", {
        action: "WEBAUTHN_AUTHENTICATION_OPTIONS_ERROR",
        ip,
        error: result.error.issues,
      });
      return NextResponse.json(
        {
          success: false,
          error: "Invalid input data",
          details: result.error.issues,
          fields: Object.keys(result.error.issues).filter(k => k !== "_errors"),
        },
        { status: 400 }
      );
    }

    const { email } = result.data;
    const client = new DgraphClient();

    // Get user and their credentials
    const user = await client.getUserByEmail(email);
    if (!user) {
      logger.error("User not found", {
        action: "WEBAUTHN_AUTHENTICATION_OPTIONS_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "User not found",
          details: "No user found with this email address",
          code: "USER_NOT_FOUND",
        },
        { status: 404 }
      );
    }

    const credentials = await client.getUserCredentials(user.id);
    if (!credentials.length) {
      logger.info("No WebAuthn credentials found", {
        action: "WEBAUTHN_AUTHENTICATION_OPTIONS_ERROR",
        email,
        ip,
      });
      return NextResponse.json(
        {
          success: false,
          error: "No security keys found",
          details: "Please register a security key first",
          code: "NO_CREDENTIALS",
        },
        { status: 200 }
      );
    }

    // Generate authentication options
    logger.info("Generating WebAuthn authentication options", {
      action: "WEBAUTHN_AUTHENTICATION_OPTIONS",
      email,
      ip,
    });
    const options = await generateAuthenticationOptions(email, credentials);
    logger.info("WebAuthn authentication options generated", {
      action: "WEBAUTHN_AUTHENTICATION_OPTIONS_SUCCESS",
      email,
      ip,
      options: {
        challenge: options.challenge,
        allowCredentials: options.allowCredentials,
      },
    });

    return NextResponse.json({
      success: true,
      options,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`WebAuthn authentication options failed: ${message}`, {
      action: "WEBAUTHN_AUTHENTICATION_OPTIONS_ERROR",
      error: message,
    });
    return NextResponse.json(
      {
        success: false,
        error: "Unable to generate authentication options",
        details: message,
      },
      { status: 500 }
    );
  }
}
