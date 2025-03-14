import { Resend } from "resend";
import { generateOTP, createOtpData, COOKIE_MAX_AGE } from "@/lib/utils";

const COOKIE_NAME = "auth_otp";
const resend = new Resend(process.env.RESEND_API_KEY);

export async function POST(request: Request) {
  try {
    const { email } = await request.json();
    const otp = generateOTP();

    const encryptedData = await createOtpData(email, otp);

    await resend.emails.send({
      from: "info@darkolive.co.uk",
      to: email,
      subject: "Your NFE Access Code",
      text: `Your one-time password is: ${otp}`,
    });

    // Create response with cookie
    const response = new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": `${COOKIE_NAME}=${encryptedData}; HttpOnly; Path=/; Max-Age=${COOKIE_MAX_AGE}; SameSite=Strict${process.env.NODE_ENV === "production" ? "; Secure" : ""}`,
      },
    });

    return response;
  } catch (error) {
    console.error("Failed to send OTP:", error);
    return Response.json({ error: "Failed to send OTP" }, { status: 500 });
  }
}
