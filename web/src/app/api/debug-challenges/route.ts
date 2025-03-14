import { NextResponse } from "next/server";
import { DgraphClient } from "@/lib/dgraph";
import { inMemoryStore } from "@/lib/in-memory-store";

// This is a debug endpoint to help diagnose challenge storage issues
export async function GET() {
  try {
    const dgraphClient = new DgraphClient();

    // Get all challenges
    const challenges = await dgraphClient.getAllChallenges();

    // Get in-memory challenges
    const inMemoryChallenges = inMemoryStore.getAllChallenges();

    return NextResponse.json({
      dgraphChallenges: challenges,
      inMemoryChallenges,
      count: {
        dgraph: challenges.length,
        inMemory: inMemoryStore.getChallengeCount(),
      },
    });
  } catch (error) {
    console.error("Error getting challenges:", error);
    return NextResponse.json(
      { error: (error as Error).message },
      { status: 500 }
    );
  }
}
