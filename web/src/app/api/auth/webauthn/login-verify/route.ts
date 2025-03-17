import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { verifyAuthentication } from "@/lib/webauthn";
import { DgraphClient } from "@/lib/dgraph";
import { createSession } from "@/lib/session";
import type { SessionData } from "@/types/auth";
import logger from "@/lib/logger";
import { toBase64Url } from "@/lib/webauthn";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";

const dgraphClient = new DgraphClient();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, response } = body as {
      email: string;
      response: AuthenticationResponseJSON;
    };

    if (!email) {
      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }

    const verification = await verifyAuthentication(email, response);

    if (!verification.verified) {
      logger.warn("Authentication verification failed", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        error: "Verification failed",
      });
      return NextResponse.json(
        { error: "Authentication failed" },
        { status: 400 }
      );
    }

    const credential = await dgraphClient.getCredentialById(toBase64Url(response.id));

    if (!credential) {
      logger.warn("Credential not found", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        error: "Credential not found",
      });
      return NextResponse.json(
        { error: "Credential not found" },
        { status: 404 }
      );
    }

    // Create session data
    const sessionData: SessionData = {
      id: credential.uid,
      userId: credential.userId,
      email,
      deviceId: credential.credentialID,
      roles: [] // Default to empty roles, can be updated later if needed
    };

    // Get request metadata
    const userAgent = request.headers.get("user-agent") || "unknown";
    const forwardedFor = request.headers.get("x-forwarded-for");
    const ipAddress = forwardedFor ? forwardedFor.split(",")[0].trim() : request.headers.get("x-real-ip") || "unknown";

    // Create audit log and session in parallel
    const [cookie] = await Promise.all([
      createSession(sessionData),
      dgraphClient.createAuditLog({
        userId: credential.userId,
        action: "WEBAUTHN_LOGIN_SUCCESS",
        details: JSON.stringify({
          method: "webauthn",
          credentialId: credential.credentialID,
        }),
        ipAddress,
        userAgent,
        metadata: {
          deviceId: credential.credentialID,
          deviceType: credential.deviceType,
          deviceInfo: credential.deviceInfo,
        }
      })
    ]);

    return NextResponse.json(
      { success: true, user: { uid: credential.userId, email, hasWebAuthn: true } },
      { 
        status: 200,
        headers: cookie ? { "Set-Cookie": cookie } : undefined
      }
    );
  } catch (error) {
    logger.error("Error verifying login", {
      action: "LOGIN_VERIFY_ERROR",
      error: error instanceof Error ? error.message : "Unknown error"
    });
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}
