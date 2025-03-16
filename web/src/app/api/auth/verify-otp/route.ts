import { verifyOtpData } from "@/lib/utils";
import { inMemoryStore } from "@/lib/in-memory-store";
import logger from "@/lib/logger";

const COOKIE_NAME = "auth_otp";

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

    // Store verified email in memory with 5-minute expiration
    inMemoryStore.storeEmailVerification({
      email,
      timestamp: new Date().toISOString(),
      method: 'otp'
    });

    logger.debug(`Email verification stored in memory for: ${email}`);

    // Clear the OTP cookie and return success
    const response = new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        // Set cookie with past expiry to delete it
        "Set-Cookie": `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict${process.env.NODE_ENV === "production" ? "; Secure" : ""}`,
      },
    });

    return response;
  } catch (error) {
    console.error("Failed to verify OTP:", error);
    return Response.json({ error: "Failed to verify OTP" }, { status: 500 });
  }
}
