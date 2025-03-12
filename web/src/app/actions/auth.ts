"use server";

import { Resend } from "resend";
import { generateOTP, createOtpData } from "@/lib/utils";
import { cookies } from "next/headers";
import { COOKIE_MAX_AGE } from "@/lib/utils";

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendOtpEmail(email: string) {
  try {
    // Generate a 6-digit OTP
    const otp = generateOTP();

    // Create encrypted OTP data
    const encryptedData = await createOtpData(email, otp);

    // Store the encrypted data in a cookie
    const cookieStore = await cookies();
    cookieStore.set("otpData", encryptedData, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: COOKIE_MAX_AGE,
      path: "/",
    });

    // Send email with Resend
    const { error } = await resend.emails.send({
      from: "info@darkolive.co.uk", // Update with your verified domain
      to: email,
      subject: "Your verification code",
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333; font-size: 24px;">Your verification code</h1>
          <p style="color: #666; font-size: 16px;">Use the following code to complete your sign in:</p>
          <div style="background-color: #f4f4f4; padding: 24px; border-radius: 4px; text-align: center; margin: 24px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px;">${otp}</span>
          </div>
          <p style="color: #666; font-size: 14px;">This code will expire in 5 minutes.</p>
        </div>
      `,
    });

    if (error) {
      console.error("Error sending email:", error);
      return { success: false, error: "Failed to send verification code" };
    }

    return { success: true };
  } catch (error) {
    console.error("Error in sendOtpEmail:", error);
    return { success: false, error: "An unexpected error occurred" };
  }
}

export async function verifyOtp(email: string, otp: string) {
  try {
    const { verifyOtpData } = await import("@/lib/utils");

    // Get the encrypted OTP data from the cookie
    const cookieStore = await cookies();
    const otpDataCookie = cookieStore.get("otpData");

    if (!otpDataCookie) {
      return { success: false, error: "Verification code expired or invalid" };
    }

    // Verify the OTP
    const isValid = await verifyOtpData(email, otp, otpDataCookie.value);

    if (isValid) {
      // Clear the OTP cookie after successful verification
      cookieStore.delete("otpData");

      // Here you would typically set an authentication cookie or session
      // For now, we'll just return success
      return { success: true };
    }

    return { success: false, error: "Invalid verification code" };
  } catch (error) {
    console.error("Error in verifyOtp:", error);
    return { success: false, error: "An unexpected error occurred" };
  }
}
