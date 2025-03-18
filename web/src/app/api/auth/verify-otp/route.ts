import { verifyOtpData, createEmailVerificationData } from "@/lib/utils";
import { inMemoryStore } from "@/lib/in-memory-store";
import logger from "@/lib/logger";

const COOKIE_NAME = "auth_otp";
const VERIFIED_EMAIL_COOKIE_NAME = "emailVerification";

export async function POST(request: Request) {
  try {
    const { email, otp } = await request.json();

    if (!email || !otp) {
      return Response.json(
        { error: "Email and OTP are required" },
        { status: 400 }
      );
    }

    // Get the OTP cookie from the request
    const cookies = request.headers.get("cookie");
    const otpCookie = cookies
      ?.split(";")
      .map((cookie) => cookie.trim())
      .find((cookie) => cookie.startsWith(`${COOKIE_NAME}=`));

    if (!otpCookie) {
      return Response.json({ error: "No OTP request found" }, { status: 400 });
    }

    const encryptedData = otpCookie.split("=")[1];
    const isValid = await verifyOtpData(email, otp, encryptedData);

    if (!isValid) {
      return Response.json(
        { error: "Invalid or expired OTP" },
        { status: 400 }
      );
    }

    // Verification successful
    logger.info(`OTP verification successful for: ${email}`);
    
    logger.debug(`Storing email verification in memory for: ${email}`);
    inMemoryStore.storeEmailVerification({
      email,
      timestamp: new Date().toISOString(),
      method: 'otp'
    });
    
    logger.debug(`Email verification stored in memory for: ${email}`);

    // Create an encrypted verified-email cookie that will be used for the next stage validation
    // Set to expire in 5 minutes
    const FIVE_MINUTES = 5 * 60;
    const encryptedEmailVerification = await createEmailVerificationData(email);
    const verifiedEmailCookie = `${VERIFIED_EMAIL_COOKIE_NAME}=${encryptedEmailVerification}; HttpOnly; Path=/; Max-Age=${FIVE_MINUTES}; SameSite=Strict${process.env.NODE_ENV === "production" ? "; Secure" : ""}`;
    const clearOtpCookie = `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict${process.env.NODE_ENV === "production" ? "; Secure" : ""}`;

    // Clear the OTP cookie and return success with the verified email cookie
    const headers = new Headers();
    headers.set("Content-Type", "application/json");
    headers.append("Set-Cookie", clearOtpCookie);
    headers.append("Set-Cookie", verifiedEmailCookie);

    const response = new Response(JSON.stringify({ success: true }), { headers });

    return response;
  } catch (error) {
    console.error("Failed to verify OTP:", error);
    return Response.json({ error: "Failed to verify OTP" }, { status: 500 });
  }
}
