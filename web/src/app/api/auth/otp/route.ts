import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { decrypt } from "@/lib/crypto";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";
import { toBase64Url } from "@/lib/webauthn";
import { inMemoryStore } from "@/lib/in-memory-store";

interface OTPData {
  email: string;
  otp: string;
  timestamp: string;
  purpose: "signup" | "recovery";
}

export async function POST(request: Request) {
  try {
    const { email, otp } = await request.json();

    if (!email || !otp) {
      return NextResponse.json(
        { error: "Email and OTP are required" },
        { status: 400 }
      );
    }

    // Get encrypted OTP data from cookie
    const cookieStore = await cookies();
    const otpCookie = cookieStore.get("otpData");

    if (!otpCookie?.value) {
      return NextResponse.json(
        { error: "OTP session expired" },
        { status: 400 }
      );
    }

    try {
      // Decrypt and verify OTP data
      const decryptedData = await decrypt(otpCookie.value);
      const { email: storedEmail, otp: storedOtp, timestamp } = JSON.parse(decryptedData) as OTPData;

      // Verify email matches
      if (email !== storedEmail) {
        return NextResponse.json(
          { error: "Invalid verification attempt" },
          { status: 400 }
        );
      }

      // Convert input OTP to base64url for comparison
      const base64OTP = toBase64Url(Buffer.from(otp).toString("base64"));

      // Verify OTP matches
      if (base64OTP !== storedOtp) {
        const dgraph = new DgraphClient();
        const user = await dgraph.getUserByEmail(storedEmail);
        if (user?.uid) {
          await dgraph.incrementFailedLoginAttempts(user.uid);
        }
        return NextResponse.json(
          { error: "Invalid verification code" },
          { status: 400 }
        );
      }

      // Verify OTP is not expired (5 minutes)
      const otpTimestamp = new Date(timestamp);
      const now = new Date();
      if (now.getTime() - otpTimestamp.getTime() > 5 * 60 * 1000) {
        return NextResponse.json(
          { error: "Verification code expired" },
          { status: 400 }
        );
      }

      // Get user and verify account not locked
      const dgraph = new DgraphClient();
      const user = await dgraph.getUserByEmail(storedEmail);
      
      if (!user) {
        return NextResponse.json(
          { error: "User not found" },
          { status: 404 }
        );
      }

      if (user.uid && await dgraph.isAccountLocked(user.uid)) {
        return NextResponse.json(
          { error: "Account is locked. Please try again later." },
          { status: 403 }
        );
      }

      // Reset failed login attempts if user exists
      if (user.uid) {
        await dgraph.resetFailedLoginAttempts(user.uid);
      }

      // Store verified email in memory for passphrase setup
      inMemoryStore.storeEmailVerification({
        email: storedEmail,
        timestamp: new Date().toISOString(),
        method: 'otp'
      });

      // Clear OTP cookie
      const response = NextResponse.json({ success: true });
      (await cookies()).set("otpData", "", { 
        maxAge: 0,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/"
      });
      return response;

    } catch (error) {
      logger.error("Error verifying OTP:", error);
      return NextResponse.json(
        { error: "Failed to verify code" },
        { status: 500 }
      );
    }
  } catch (error) {
    logger.error("Unexpected error in OTP route:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred" },
      { status: 500 }
    );
  }
}
