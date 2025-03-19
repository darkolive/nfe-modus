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

    // Get WebAuthn credentials
    const credentials = await client.getUserCredentials(user.uid);
    if (!credentials || credentials.length === 0) {
      logger.info(`No credentials found for user: ${email}, generating registration options`, {
        action: "WEBAUTHN_REGISTRATION_REDIRECT",
        ip,
        userId: user.uid,
      });
      
      // Since user has no credentials, generate registration options instead
      try {
        // Import the function directly to avoid any potential circular imports
        const { generateRegistrationOptions } = await import("@/lib/webauthn");
        
        // Log user details for debugging
        logger.debug(`User details for registration: ${JSON.stringify({
          id: user.uid,
          email: user.email,
          name: user.name,
          hasUser: !!user
        })}`);
        
        // Get the user's existing WebAuthn credentials (if any)
        const existingCredentials = await client.getUserCredentials(user.uid) || [];
        
        // Log credentials for debugging
        logger.debug(`Existing credentials: ${JSON.stringify({
          count: existingCredentials.length,
          credentialIds: existingCredentials.map(c => c.credentialID?.substring(0, 10) + '...')
        })}`);
        
        // Generate registration options with proper parameters
        const regOptions = await generateRegistrationOptions(
          email,
          existingCredentials,
          user.name || email.split("@")[0]
        );
        
        // Return the registration options with a flag indicating this is registration
        return NextResponse.json({
          ...regOptions,
          isRegistrationFlow: true, // Flag to indicate this is a registration flow
          userId: user.uid // Include the user ID for reference
        });
      } catch (error) {
        logger.error(`Error generating registration options: ${error}`, {
          action: "WEBAUTHN_REGISTRATION_OPTIONS_ERROR",
          ip,
          userId: user.uid,
          error: error instanceof Error ? error.message : String(error)
        });
        
        // Fall back to the original behavior if registration options generation fails
        return NextResponse.json(
          {
            error: "No security keys found",
            details: "No WebAuthn credentials found for this account",
            canRegisterWebAuthn: true,
            userId: user.uid,
            hasPassphrase: user.hasPassphrase,
          },
          { status: 200 }
        );
      }
    }

    logger.info(`Generating WebAuthn login options for email: ${email}`, {
      action: "WEBAUTHN_LOGIN_OPTIONS_REQUEST",
      ip,
    });

    // Generate authentication options
    const options = await generateAuthenticationOptions(email, credentials);

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
