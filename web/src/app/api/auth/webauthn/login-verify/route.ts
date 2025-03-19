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

    // Get request metadata for audit logging
    const userAgent = request.headers.get("user-agent") || "unknown";
    const forwardedFor = request.headers.get("x-forwarded-for");
    const ipAddress = forwardedFor ? forwardedFor.split(",")[0].trim() : request.headers.get("x-real-ip") || "unknown";
    const requestMethod = request.method;
    const requestUrl = request.url;
    const parsedUrl = new URL(requestUrl);
    const requestPath = parsedUrl.pathname;

    if (!email) {
      // Log failed authentication attempt due to missing email
      await dgraphClient.createAuditLog({
        action: "WEBAUTHN_LOGIN_MISSING_EMAIL",
        actorId: "unknown",
        actorType: "unknown",
        operationType: "login",
        requestPath: requestPath,
        requestMethod: requestMethod,
        responseStatus: 400,
        clientIp: ipAddress,
        userAgent: userAgent,
        success: false,
        sensitiveOperation: true,
        complianceFlags: ["ISO27001", "GDPR"],
        details: JSON.stringify({
          error: "Email is required"
        })
      });

      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }

    // Get the stored challenge for this email
    const challenge = await dgraphClient.getChallenge(email);
    if (!challenge) {
      // Log failed authentication attempt due to missing challenge
      await dgraphClient.createAuditLog({
        action: "WEBAUTHN_LOGIN_NO_CHALLENGE",
        actorId: "unknown",
        actorType: "user",
        operationType: "login",
        requestPath: requestPath,
        requestMethod: requestMethod,
        responseStatus: 400,
        clientIp: ipAddress,
        userAgent: userAgent,
        success: false,
        sensitiveOperation: true,
        complianceFlags: ["ISO27001", "GDPR"],
        details: JSON.stringify({
          error: "No challenge found",
          email: email
        })
      });

      logger.warn("No challenge found for email", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        error: "No challenge found",
      });
      return NextResponse.json(
        { error: "Authentication failed - no challenge found" },
        { status: 400 }
      );
    }

    // Get the credential by ID
    const credentialId = toBase64Url(response.id);
    const credential = await dgraphClient.getCredentialById(credentialId);
    if (!credential) {
      // Log failed authentication attempt due to invalid credential
      await dgraphClient.createAuditLog({
        action: "WEBAUTHN_LOGIN_INVALID_CREDENTIAL",
        actorId: "unknown",
        actorType: "user",
        operationType: "login",
        requestPath: requestPath,
        requestMethod: requestMethod,
        responseStatus: 400,
        clientIp: ipAddress,
        userAgent: userAgent,
        success: false,
        sensitiveOperation: true,
        complianceFlags: ["ISO27001", "GDPR"],
        details: JSON.stringify({
          error: "Credential not found",
          email: email,
          credentialId: credentialId
        })
      });

      logger.warn("No credential found with ID", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        error: "No credential found",
      });
      return NextResponse.json(
        { error: "Authentication failed - credential not found" },
        { status: 400 }
      );
    }

    // Verify the authentication
    const verification = await verifyAuthentication(
      response,
      challenge.challenge,
      {
        credentialID: credential.credentialID,
        credentialPublicKey: credential.credentialPublicKey,
        counter: credential.counter,
        transports: credential.transports
      }
    );

    if (!verification.verified) {
      // Log failed authentication attempt due to verification failure
      await dgraphClient.createAuditLog({
        action: "WEBAUTHN_LOGIN_VERIFICATION_FAILED",
        actorId: credential.userId,
        actorType: "user",
        resourceId: credential.userId,
        resourceType: "user",
        operationType: "login",
        requestPath: requestPath,
        requestMethod: requestMethod,
        responseStatus: 400,
        clientIp: ipAddress,
        userAgent: userAgent,
        success: false,
        sensitiveOperation: true,
        complianceFlags: ["ISO27001", "GDPR"],
        details: JSON.stringify({
          error: "Verification failed",
          email: email,
          credentialId: credential.credentialID,
          deviceType: credential.deviceType
        })
      });

      logger.warn("Authentication verification failed", {
        action: "WEBAUTHN_LOGIN_VERIFY_ERROR",
        error: "Verification failed",
      });
      return NextResponse.json(
        { error: "Authentication failed" },
        { status: 400 }
      );
    }

    // Update the credential counter
    await dgraphClient.updateCredentialCounter(credential.credentialID, verification.authenticationInfo.newCounter);

    // Create session data
    const sessionData: SessionData = {
      id: credential.uid,
      userId: credential.userId,
      email,
      deviceId: credential.credentialID,
      roles: [] // Default to empty roles, can be updated later if needed
    };

    // Create audit log and session in parallel
    const [cookie] = await Promise.all([
      createSession(sessionData),
      dgraphClient.createAuditLog({
        actorId: credential.userId,
        actorType: "user",
        resourceId: credential.userId,
        resourceType: "user",
        operationType: "login",
        action: "WEBAUTHN_LOGIN_SUCCESS",
        requestPath: requestPath,
        requestMethod: requestMethod,
        responseStatus: 200,
        clientIp: ipAddress,
        userAgent: userAgent,
        success: true,
        sensitiveOperation: true,
        complianceFlags: ["ISO27001", "GDPR"],
        details: JSON.stringify({
          method: "webauthn",
          credentialId: credential.credentialID,
          deviceId: credential.credentialID,
          deviceType: credential.deviceType,
          counter: verification.authenticationInfo.newCounter
        })
      })
    ]);

    // Delete the used challenge
    await dgraphClient.deleteChallenge(email);

    return NextResponse.json(
      { success: true, user: { uid: credential.userId, email, hasWebAuthn: true } },
      { 
        status: 200,
        headers: cookie ? { "Set-Cookie": cookie } : undefined
      }
    );
  } catch (error) {
    // Get request metadata for audit logging
    const userAgent = request.headers.get("user-agent") || "unknown";
    const forwardedFor = request.headers.get("x-forwarded-for");
    const ipAddress = forwardedFor ? forwardedFor.split(",")[0].trim() : request.headers.get("x-real-ip") || "unknown";
    const requestMethod = request.method;
    const requestUrl = request.url;
    const parsedUrl = new URL(requestUrl);
    const requestPath = parsedUrl.pathname;

    // Log unexpected error during login
    await dgraphClient.createAuditLog({
      action: "WEBAUTHN_LOGIN_UNEXPECTED_ERROR",
      actorId: "unknown",
      actorType: "unknown",
      operationType: "login",
      requestPath: requestPath,
      requestMethod: requestMethod,
      responseStatus: 500,
      clientIp: ipAddress,
      userAgent: userAgent,
      success: false,
      sensitiveOperation: true,
      complianceFlags: ["ISO27001", "GDPR"],
      details: JSON.stringify({
        error: error instanceof Error ? error.message : "Unknown error"
      })
    });

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
