import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";

// DGraph client for user operations
const dgraphClient = new DgraphClient();

export async function GET(request: Request) {
  try {
    // Get the email from the query parameters
    const url = new URL(request.url);
    const email = url.searchParams.get("email");

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    // Check if the user exists
    const user = await dgraphClient.getUserByEmail(email);

    return NextResponse.json({
      exists: !!user,
      hasWebAuthn: user?.hasWebAuthn || false,
      hasPassphrase: user?.hasPassphrase || false,
    });
  } catch (error) {
    console.error("Error checking user:", error);
    return NextResponse.json(
      { error: "Failed to check user" },
      { status: 500 }
    );
  }
}
