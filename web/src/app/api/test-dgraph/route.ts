import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";

export async function GET() {
  try {
    const dgraphClient = new DgraphClient();

    // Test the health endpoint first
    let healthStatus;
    try {
      const healthResponse = await fetch(
        `${process.env.DGRAPH_ENDPOINT || "http://localhost:8080"}/health`
      );
      if (healthResponse.ok) {
        healthStatus = await healthResponse.json();
      } else {
        healthStatus = { error: healthResponse.statusText };
      }
    } catch (error) {
      console.error("Health check error:", error);
      healthStatus = { error: (error as Error).message };
    }

    // Test a simple query to check if DGraph is accessible
    let queryResult;
    try {
      const testQuery = `{
        test(func: has(dgraph.type), first: 1) {
          uid
          dgraph.type
        }
      }`;
      queryResult = await dgraphClient["executeDQLQuery"](testQuery);
    } catch (error) {
      console.error("DGraph query error:", error);
      queryResult = { error: (error as Error).message };
    }

    // Test a simple JSON mutation
    let mutationResult;
    try {
      const testMutation = {
        set: [
          {
            "dgraph.type": "TestNode",
            name: `Test Node ${new Date().toISOString()}`,
            created: new Date().toISOString().replace("Z", "+00:00"),
          },
        ],
      };
      mutationResult = await dgraphClient["executeDQLMutation"](testMutation);
    } catch (error) {
      console.error("DGraph mutation error:", error);
      mutationResult = { error: (error as Error).message };
    }

    // Try to get a user (will return null if no users exist)
    let testUser = null;
    try {
      testUser = await dgraphClient.getUserByEmail("test@example.com");
    } catch (error) {
      console.error("Get user error:", error);
    }

    // Try to create a test challenge
    let testChallenge = null;
    try {
      const challengeId = await dgraphClient.storeChallenge({
        challenge: `test_challenge_${Date.now()}`,
        email: "test@example.com",
        userId: "test_user_id",
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      testChallenge = { id: challengeId };

      // Clean up the test challenge
      await dgraphClient.deleteChallenge("test@example.com");
    } catch (error) {
      console.error("Challenge test error:", error);
      testChallenge = { error: (error as Error).message };
    }

    return NextResponse.json({
      success: true,
      message: "DGraph connection test",
      healthStatus,
      queryResult,
      mutationResult,
      testUser,
      testChallenge,
      endpoint: process.env.DGRAPH_ENDPOINT || "http://localhost:8080",
      // Don't include the auth token in the response
      hasAuthToken: !!process.env.DGRAPH_AUTH_TOKEN,
    });
  } catch (error) {
    console.error("DGraph test error:", error);
    return NextResponse.json(
      {
        success: false,
        error: (error as Error).message,
      },
      { status: 500 }
    );
  }
}
