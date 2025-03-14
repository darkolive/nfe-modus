import { NextResponse } from "next/server";

// This endpoint will help us understand the DGraph schema and data structure
export async function GET() {
  try {
    const endpoint = process.env.DGRAPH_ENDPOINT || "http://localhost:8080";
    const authToken = process.env.DGRAPH_AUTH_TOKEN || "";

    // Headers for the request
    const headers: Record<string, string> = {
      "Content-Type": "application/dql",
    };

    if (authToken) {
      headers["X-Auth-Token"] = authToken;
    }

    // Query to get the schema
    const schemaQuery = `schema {}`;

    // Execute the schema query
    const schemaResponse = await fetch(`${endpoint}/query`, {
      method: "POST",
      headers,
      body: schemaQuery,
    });

    if (!schemaResponse.ok) {
      throw new Error(
        `DGraph schema query failed: ${schemaResponse.statusText}`
      );
    }

    const schemaData = await schemaResponse.json();

    // Query to get all Device nodes
    const deviceQuery = `{
      devices(func: type(Device)) {
        uid
        dgraph.type
        credentialID
        publicKey
        counter
        transports
        createdAt
        lastUsed
        userId
        isBiometric
        name
      }
    }`;

    // Execute the device query
    const deviceResponse = await fetch(`${endpoint}/query`, {
      method: "POST",
      headers,
      body: deviceQuery,
    });

    if (!deviceResponse.ok) {
      throw new Error(
        `DGraph device query failed: ${deviceResponse.statusText}`
      );
    }

    const deviceData = await deviceResponse.json();

    // Query to get all User nodes
    const userQuery = `{
      users(func: type(User)) {
        uid
        dgraph.type
        email
        did
        name
        verified
        emailVerified
        dateJoined
        status
      }
    }`;

    // Execute the user query
    const userResponse = await fetch(`${endpoint}/query`, {
      method: "POST",
      headers,
      body: userQuery,
    });

    if (!userResponse.ok) {
      throw new Error(`DGraph user query failed: ${userResponse.statusText}`);
    }

    const userData = await userResponse.json();

    // Return all data
    return NextResponse.json({
      schema: schemaData,
      devices: deviceData,
      users: userData,
      endpoint,
      hasAuthToken: !!authToken,
    });
  } catch (error) {
    console.error("Error debugging DGraph schema:", error);
    return NextResponse.json(
      {
        success: false,
        error: (error as Error).message,
      },
      { status: 500 }
    );
  }
}
