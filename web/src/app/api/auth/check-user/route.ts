import { type NextRequest, NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    // Create a new DgraphClient instance with the required options
    const client = new DgraphClient({
      endpoint: process.env.DGRAPH_ENDPOINT || "http://localhost:8080",
      authToken: process.env.DGRAPH_AUTH_TOKEN,
    });

    const { email } = await request.json();

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    logger.info("Checking if user exists", {
      action: "CHECK_USER",
      email,
    });

    const user = await client.getUserByEmail(email);

    if (!user) {
      return NextResponse.json({ exists: false });
    }

    return NextResponse.json({
      exists: true,
      hasPassphrase: user.hasPassphrase || false,
      hasWebAuthn: user.hasWebAuthn || false,
    });
  } catch (error) {
    logger.error("Error checking user", {
      action: "CHECK_USER",
      error,
    });
    return NextResponse.json(
      { error: "Failed to check user" },
      { status: 500 }
    );
  }
}
