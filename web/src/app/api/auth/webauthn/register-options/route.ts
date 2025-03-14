import { NextResponse } from "next/server";
import { generateRegistrationOptions } from "@/lib/webauthn";
import logger from "@/lib/logger";
import { z } from "zod";

// Input validation schema
const requestSchema = z.object({
  email: z.string().email("Invalid email format"),
  name: z.string().optional(),
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
        `Invalid WebAuthn registration options input: ${JSON.stringify(validationResult.error.errors)}`,
        {
          action: "WEBAUTHN_REGISTRATION_OPTIONS_ERROR",
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

    const { email, name } = validationResult.data;

    logger.info(
      `Generating WebAuthn registration options for email: ${email}`,
      {
        action: "WEBAUTHN_REGISTRATION_OPTIONS_REQUEST",
        ip,
      }
    );

    // Generate registration options
    const options = await generateRegistrationOptions(email, name);

    return NextResponse.json(options);
  } catch (error) {
    logger.error(`Error generating WebAuthn registration options: ${error}`, {
      action: "WEBAUTHN_REGISTRATION_OPTIONS_ERROR",
      error: error instanceof Error ? error.message : String(error),
    });
    return NextResponse.json(
      { error: "Failed to generate registration options" },
      { status: 500 }
    );
  }
}
