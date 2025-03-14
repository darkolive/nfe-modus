import { NextResponse } from "next/server";
import { generateAuthenticationOptions } from "@/lib/webauthn";
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

    logger.info(`Generating WebAuthn login options for email: ${email}`, {
      action: "WEBAUTHN_LOGIN_OPTIONS_REQUEST",
      ip,
    });

    // Generate authentication options
    const options = await generateAuthenticationOptions(email);

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
