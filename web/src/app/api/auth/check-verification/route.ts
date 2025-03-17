import { NextRequest, NextResponse } from "next/server";
import { inMemoryStore } from "@/lib/in-memory-store";
import logger from "@/lib/logger";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const email = searchParams.get("email");

  if (!email) {
    return NextResponse.json(
      { verified: false, error: "Email is required" },
      { status: 400 }
    );
  }

  try {
    // Check if email was recently verified
    const verifiedEmail = inMemoryStore.getEmailVerification(email);
    
    if (!verifiedEmail) {
      return NextResponse.json({ verified: false });
    }

    // Check if verification has expired (5 minutes)
    const verificationTime = new Date(verifiedEmail.timestamp);
    const now = new Date();
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
    
    if (verificationTime < fiveMinutesAgo) {
      return NextResponse.json({ verified: false });
    }

    return NextResponse.json({ verified: true });
  } catch (error) {
    logger.error("Error checking email verification:", error);
    return NextResponse.json(
      { verified: false, error: "Failed to check verification status" },
      { status: 500 }
    );
  }
}
