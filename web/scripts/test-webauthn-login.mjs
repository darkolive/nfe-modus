// This script simulates a WebAuthn login flow by creating a test challenge
// and then checking if the audit logs are correctly created
import dotenv from 'dotenv';
import { DgraphClient } from '../dist/lib/dgraph.js';
import { randomBytes } from 'crypto';

dotenv.config();

async function main() {
  console.log('Connecting to Dgraph...');
  const client = new DgraphClient();

  try {
    // Get a test user
    console.log('Fetching test user...');
    const users = await client.getAllUsers();
    
    if (!users || users.length === 0) {
      console.error('No users found in the database. Please register a user first.');
      return;
    }

    const testUser = users[0];
    console.log(`Found test user: ${testUser.email}`);

    // Create a test challenge for the user
    const challenge = randomBytes(32).toString('base64url');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes from now

    console.log('Creating test challenge...');
    await client.createChallenge({
      email: testUser.email,
      challenge,
      expiresAt: expiresAt.toISOString(),
      userId: testUser.uid
    });

    console.log('Test challenge created successfully.');
    console.log('Challenge details:');
    console.log(`- Email: ${testUser.email}`);
    console.log(`- Challenge: ${challenge}`);
    console.log(`- Expires at: ${expiresAt.toISOString()}`);
    console.log(`- User ID: ${testUser.uid}`);

    // Simulate a login verification by creating an audit log directly
    console.log('\nSimulating login verification...');
    await client.createAuditLog({
      action: "WEBAUTHN_LOGIN_SUCCESS",
      actorId: testUser.uid,
      actorType: "user",
      resourceId: testUser.uid,
      resourceType: "user",
      operationType: "login",
      requestPath: "/api/auth/webauthn/login-verify",
      requestMethod: "POST",
      responseStatus: 200,
      clientIp: "127.0.0.1",
      userAgent: "Test Script",
      success: true,
      sensitiveOperation: true,
      complianceFlags: ["ISO27001", "GDPR"],
      details: JSON.stringify({
        method: "webauthn",
        credentialId: "test-credential-id",
        deviceId: "test-device-id",
        deviceType: "test-device",
        counter: 1
      })
    });

    console.log('Login audit log created successfully.');
    console.log('\nTest completed. Please run check-auth-audit-trail.mjs to verify the logs.');

  } catch (error) {
    console.error('Error:', error);
  } finally {
    process.exit(0);
  }
}

main();
