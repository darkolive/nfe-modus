import { NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";

export async function GET(request: NextRequest) {
  const client = new DgraphClient();
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
    const verifiedEmail = await client.getVerifiedEmail(email);
    
    if (!verifiedEmail) {
      return NextResponse.json({ verified: false });
    }

    // Check if verification has expired (5 minutes)
    const now = new Date();
    if (verifiedEmail.expiresAt < now) {
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
