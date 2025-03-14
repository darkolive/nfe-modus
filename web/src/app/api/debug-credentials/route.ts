import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import type { CredentialData } from "@/types/auth";

// This is a debug endpoint to help diagnose credential storage issues
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const email = searchParams.get("email");

    if (!email) {
      return NextResponse.json(
        { error: "Email parameter is required" },
        { status: 400 }
      );
    }

    const dgraphClient = new DgraphClient();

    // Get the user
    const user = await dgraphClient.getUserByEmail(email);

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Get the user's credentials
    const credentials = await dgraphClient.getUserCredentials(user.id!);

    return NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      credentials,
      credentialCount: credentials.length,
    });
  } catch (error) {
    console.error("Error in debug-credentials:", error);
    return NextResponse.json(
      { error: (error as Error).message },
      { status: 500 }
    );
  }
}

// Add a credential to a user for testing
export async function POST(request: Request) {
  try {
    const { email } = await request.json();

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    const dgraphClient = new DgraphClient();

    // Get the user
    const user = await dgraphClient.getUserByEmail(email);

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Create a test credential
    const credentialData: Omit<CredentialData, "id"> = {
      credentialID: `test_credential_${Date.now()}`,
      publicKey: "test_public_key",
      counter: 0,
      transports: ["internal"],
      createdAt: new Date(),
      userId: user.id!,
      isBiometric: true,
      name: "Test Credential",
    };

    // Store the credential
    console.log(`Storing test credential for user ${user.id}:`, credentialData);
    const credentialId = await dgraphClient.storeCredential(credentialData);
    console.log(`Stored test credential with ID: ${credentialId}`);

    // Verify the credential was stored
    const credentials = await dgraphClient.getUserCredentials(user.id!);

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      credential: {
        id: credentialId,
        ...credentialData,
      },
      allCredentials: credentials,
    });
  } catch (error) {
    console.error("Error adding test credential:", error);
    return NextResponse.json(
      { error: (error as Error).message },
      { status: 500 }
    );
  }
}
