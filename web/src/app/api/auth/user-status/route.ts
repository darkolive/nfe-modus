import { NextRequest, NextResponse } from "next/server";
import { verifySessionToken } from "@/lib/jwt";
import { DgraphClient } from "@/lib/dgraph";
import logger from "@/lib/logger";

/**
 * Get the authentication status of the current user
 * This endpoint requires authentication
 */
export async function GET(req: NextRequest) {
  try {
    // Get the session token from cookies (check both token names we use)
    const sessionToken = req.cookies.get("session-token")?.value || req.cookies.get("token")?.value;

    // If no token, user is not authenticated
    if (!sessionToken) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    // Verify the JWT
    const payload = await verifySessionToken(sessionToken);
    if (!payload || !payload.userId) {
      return NextResponse.json(
        { error: "Invalid authentication token" },
        { status: 401 }
      );
    }

    // Get user info from Dgraph
    const dgraph = new DgraphClient();
    const userInfo = await dgraph.getUserByEmail(payload.email);

    if (!userInfo) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      );
    }

    // Determine if the user has WebAuthn credentials
    const hasWebAuthn = Boolean(userInfo.hasWebAuthn);
    const hasPassphrase = Boolean(userInfo.hasPassphrase);

    return NextResponse.json({
      email: userInfo.email,
      hasWebAuthn,
      hasPassphrase,
      name: userInfo.name || userInfo.email?.split("@")[0] || "",
    });
  } catch (error) {
    logger.error("Error in user-status endpoint", { error });
    return NextResponse.json(
      { error: "Failed to get user status" },
      { status: 500 }
    );
  }
}
