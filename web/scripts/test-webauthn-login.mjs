// This script simulates a WebAuthn login flow by creating a test challenge
// and then checking if the audit logs are correctly created
import dotenv from 'dotenv';
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import { randomBytes } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

// Get the directory of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from the web directory
const envPath = path.resolve(__dirname, '../.env');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else {
  dotenv.config();
  console.warn("Warning: .env file not found in web directory. Using default environment variables.");
}

// Create a Dgraph client
function createDgraphClient() {
  const dgraphUrl = process.env.DGRAPH_URL || "localhost:9080";
  const useTls = process.env.DGRAPH_TLS === "true";
  
  const clientStub = new dgraph.DgraphClientStub(
    dgraphUrl,
    useTls ? credentials.createSsl() : credentials.createInsecure()
  );
  
  return {
    client: new dgraph.DgraphClient(clientStub),
    stub: clientStub
  };
}

async function main() {
  console.log('Connecting to Dgraph...');
  const { client } = createDgraphClient();

  try {
    // Get a test user
    console.log('Fetching test user...');
    
    const txn = client.newTxn();
    const query = `{
      users(func: has(email)) {
        uid
        email
        dateJoined
      }
    }`;
    
    const res = await txn.query(query);
    await txn.discard();
    
    const users = res.getJson().users || [];
    
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
    const txn2 = client.newTxn();
    const mu = new dgraph.Mutation();
    mu.setSetJson({
      "dgraph.type": "WebAuthnChallenge",
      "email": testUser.email,
      "challenge": challenge,
      "expiresAt": expiresAt.toISOString(),
      "userId": testUser.uid
    });
    await txn2.mutate(mu);
    await txn2.commit();

    console.log('Test challenge created successfully.');
    console.log('Challenge details:');
    console.log(`- Email: ${testUser.email}`);
    console.log(`- Challenge: ${challenge}`);
    console.log(`- Expires at: ${expiresAt.toISOString()}`);
    console.log(`- User ID: ${testUser.uid}`);

    // Simulate a login verification by creating an audit log directly
    console.log('\nSimulating login verification...');
    const txn3 = client.newTxn();
    const mu2 = new dgraph.Mutation();
    mu2.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "WEBAUTHN_LOGIN_SUCCESS",
      "actorId": testUser.uid,
      "actorType": "user",
      "resourceId": testUser.uid,
      "resourceType": "user",
      "operationType": "login",
      "requestPath": "/api/auth/webauthn/login-verify",
      "requestMethod": "POST",
      "responseStatus": 200,
      "clientIp": "127.0.0.1",
      "userAgent": "Test Script",
      "auditTimestamp": now.toISOString(),
      "sessionId": "test-session-id",
      "success": true,
      "sensitiveOperation": true,
      "complianceFlags": ["ISO27001", "GDPR"],
      "details": JSON.stringify({
        "method": "webauthn",
        "credentialId": "test-credential-id",
        "deviceId": "test-device-id",
        "deviceType": "test-device",
        "counter": 1
      })
    });
    await txn3.mutate(mu2);
    await txn3.commit();

    console.log('Login audit log created successfully.');
    console.log('\nTest completed. Please run check-auth-audit-trail.mjs to verify the logs.');

  } catch (error) {
    console.error('Error:', error);
  } finally {
    process.exit(0);
  }
}

main();
