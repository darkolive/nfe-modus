import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { inMemoryStore } from "@/lib/in-memory-store";
import { nanoid } from "nanoid";
import { sendEmail } from "@/lib/email";

const dgraphClient = new DgraphClient();

/**
 * Handle passphrase reset request
 * This endpoint accepts an email and sends a reset link to that email
 */
export async function POST(req: NextRequest) {
  try {
    // Get email from request body
    const { email } = await req.json();

    if (!email) {
      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }

    // Check if user exists
    const user = await dgraphClient.getUserByEmail(email);
    
    if (!user) {
      // For security reasons, don't reveal if the email exists or not
      return NextResponse.json({ success: true });
    }

    // Generate a reset token
    const resetToken = nanoid(32);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 15); // Token expires in 15 minutes

    // Store the reset token in memory
    inMemoryStore.set(`passphrase-reset:${resetToken}`, {
      email,
      timestamp: new Date().toISOString(),
      expiresAt: expiresAt.toISOString(),
    });

    // Build the reset URL
    const resetUrl = `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/auth/reset-passphrase?token=${resetToken}`;

    // Send reset email
    try {
      await sendEmail({
        to: email,
        subject: "Reset your passphrase",
        text: `Click the following link to reset your passphrase: ${resetUrl}`,
        html: `
          <p>Hello,</p>
          <p>We received a request to reset your passphrase.</p>
          <p><a href="${resetUrl}">Click here to reset your passphrase</a></p>
          <p>If you didn't request this, you can safely ignore this email.</p>
          <p>This link will expire in 15 minutes.</p>
        `,
      });

      logger.info("Passphrase reset email sent", { email });
    } catch (emailError) {
      logger.error("Failed to send passphrase reset email", {
        email,
        error: emailError instanceof Error ? emailError.message : String(emailError)
      });
      return NextResponse.json(
        { error: "Failed to send reset email" },
        { status: 500 }
      );
    }

    // Return success
    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error("Error processing passphrase reset request", {
      error: error instanceof Error ? error.message : String(error)
    });
    return NextResponse.json(
      { error: "Failed to process reset request" },
      { status: 500 }
    );
  }
}
