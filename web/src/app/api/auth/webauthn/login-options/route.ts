import { NextResponse } from "next/server";
import { generateAuthenticationOptions } from "@/lib/webauthn";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { z } from "zod";

// Input validation schema
const requestSchema = z.object({
  email: z.string().email("Invalid email format"),
});

export async function POST(request: Request) {
  try {
    // Get client IP for logging
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // Parse and validate input
    const body = await request.json();
    const validationResult = requestSchema.safeParse(body);

    if (!validationResult.success) {
      logger.warn(
        `Invalid WebAuthn login options input: ${JSON.stringify(validationResult.error.errors)}`,
        {
          action: "WEBAUTHN_LOGIN_OPTIONS_ERROR",
          ip,
          error: "Invalid input",
        }
      );
      return NextResponse.json(
        {
          error: "Invalid input",
          details: validationResult.error.errors,
        },
        { status: 400 }
      );
    }

    const { email } = validationResult.data;
    const client = new DgraphClient();

    // Get user and their credentials
    const user = await client.getUserByEmail(email);
    if (!user) {
      logger.warn(`User not found for WebAuthn login: ${email}`, {
        action: "WEBAUTHN_LOGIN_OPTIONS_ERROR",
        ip,
        error: "User not found",
      });
      return NextResponse.json(
        {
          error: "User not found",
          details: "No user found with this email address",
        },
        { status: 404 }
      );
    }

    // Check if user has WebAuthn enabled
    if (!user.hasWebAuthn) {
      logger.warn(`WebAuthn not enabled for user: ${email}`, {
        action: "WEBAUTHN_LOGIN_OPTIONS_ERROR",
        ip,
        error: "WebAuthn not enabled",
      });
      return NextResponse.json(
        {
          error: "WebAuthn not enabled",
          details: "Please set up WebAuthn first",
        },
        { status: 400 }
      );
    }

    // Get user's credentials
    const credentials = await client.getUserCredentials(user.id);
    if (!credentials || credentials.length === 0) {
      logger.warn(`No WebAuthn credentials found for user: ${email}`, {
        action: "WEBAUTHN_LOGIN_OPTIONS_ERROR",
        ip,
        error: "No credentials found",
      });
      return NextResponse.json(
        {
          error: "No credentials found",
          details: "No WebAuthn credentials found for this user",
        },
        { status: 400 }
      );
    }

    logger.info(`Generating WebAuthn login options for email: ${email}`, {
      action: "WEBAUTHN_LOGIN_OPTIONS_REQUEST",
      ip,
    });

    // Generate authentication options
    const options = await generateAuthenticationOptions(user, credentials);

    // Check if options contains an error
    if ("error" in options) {
      return NextResponse.json({ error: options.error }, { status: 400 });
    }

    return NextResponse.json(options);
  } catch (error) {
    logger.error(`Error generating WebAuthn login options: ${error}`, {
      action: "WEBAUTHN_LOGIN_OPTIONS_ERROR",
      error: error instanceof Error ? error.message : String(error),
    });
    return NextResponse.json(
      { error: "Failed to generate login options" },
      { status: 500 }
    );
  }
}
