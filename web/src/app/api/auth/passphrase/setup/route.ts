import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { hashPassphrase } from "@/lib/passphrase";
import { cookies } from "next/headers";
import { jwtVerify } from "jose";

// DGraph client for user operations
const dgraphClient = new DgraphClient();

export async function POST(request: Request) {
  try {
    // Get the current user from the session
    const cookieStore = await cookies();
    const sessionCookie = cookieStore.get("session")?.value;

    if (!sessionCookie) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    // Verify the JWT
    const secret = new TextEncoder().encode(
      process.env.JWT_SECRET || "your-secret-key-at-least-32-characters-long"
    );

    let payload;
    try {
      const result = await jwtVerify(sessionCookie, secret);
      payload = result.payload;
    } catch (error) {
      console.error("JWT verification failed:", error);
      return NextResponse.json({ error: "Invalid session" }, { status: 401 });
    }

    const userId = payload.id as string;

    if (!userId) {
      return NextResponse.json({ error: "Invalid session" }, { status: 401 });
    }

    // Get the passphrase from the request
    const { passphrase } = await request.json();

    if (!passphrase) {
      return NextResponse.json(
        { error: "Passphrase is required" },
        { status: 400 }
      );
    }

    // Hash the passphrase
    const { hash, salt } = hashPassphrase(passphrase);

    // Store the passphrase hash
    const success = await dgraphClient.storePassphrase(userId, hash, salt);

    if (!success) {
      return NextResponse.json(
        { error: "Failed to store passphrase" },
        { status: 500 }
      );
    }

    // Update user record to indicate they have a passphrase set up
    await dgraphClient.updateUserHasPassphrase(userId, true);

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error setting up passphrase:", error);
    return NextResponse.json(
      { error: "Failed to set up passphrase" },
      { status: 500 }
    );
  }
}
