import { DgraphClient } from "@/lib/dgraph";
import { NextResponse } from "next/server";
import { sendOTPEmail } from "@/lib/email";
import logger from "@/lib/logger";
import { cookies } from "next/headers";

export async function POST(request: Request) {
  try {
    const { email } = await request.json();

    if (!email) {
      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }
    
    const dgraph = new DgraphClient();
    
    // Check if user exists
    const user = await dgraph.getUserByEmail(email);
    
    if (!user) {
      try {
        // Create new user if they don't exist
        await dgraph.createUser({
          email,
          did: `did:web:${email.split("@")[1]}:${email.split("@")[0]}`,
          name: "",
          verified: false,
          emailVerified: null,
          dateJoined: new Date().toISOString(),
          lastAuthTime: null,
          status: "active",
          hasWebAuthn: false,
          hasPassphrase: false,
          failedLoginAttempts: 0,
          lastFailedLogin: null,
          lockedUntil: null,
          roles: [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          devices: [],
          passwordHash: null,
          passwordSalt: null,
          recoveryEmail: null
        });
      } catch (createError) {
        logger.error("Error creating user:", createError);
        return NextResponse.json(
          { error: "Failed to create user account" },
          { status: 500 }
        );
      }
    }

    try {
      // Send OTP via email and get encrypted data for cookie
      const { encryptedData } = await sendOTPEmail(email, "signup");
      
      // Set encrypted OTP data in cookie
      const response = NextResponse.json({ success: true });
      (await cookies()).set("otpData", encryptedData, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 5 * 60, // 5 minutes
        path: "/"
      });

      return response;
    } catch (otpError) {
      logger.error("Error sending OTP:", otpError);
      return NextResponse.json(
        { error: "Failed to send verification code" },
        { status: 500 }
      );
    }
  } catch (error) {
    logger.error("Unexpected error in email route:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred" },
      { status: 500 }
    );
  }
}
