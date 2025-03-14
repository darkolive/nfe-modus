export async function sendOtpEmail(
  email: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch("/api/auth/send-otp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email }),
    });

    const data = await response.json();

    if (data.success) {
      return { success: true };
    } else {
      return { success: false, error: data.error || "Failed to send OTP" };
    }
  } catch (error: unknown) {
    console.error("Error sending OTP:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to send OTP";
    return { success: false, error: errorMessage };
  }
}

export async function verifyOtp(
  email: string,
  otp: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch("/api/auth/verify-otp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, otp }),
    });

    const data = await response.json();

    if (data.success) {
      return { success: true };
    } else {
      return { success: false, error: data.error || "Invalid OTP" };
    }
  } catch (error: unknown) {
    console.error("Error verifying OTP:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Failed to verify OTP";
    return { success: false, error: errorMessage };
  }
}
