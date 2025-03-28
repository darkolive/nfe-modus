// Test script for passphrase registration flow
import dotenv from 'dotenv';
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import { randomBytes, createHash } from 'crypto';
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

// Generate a random email for testing
function generateTestEmail() {
  const randomId = randomBytes(4).toString('hex');
  return `test-user-${randomId}@example.com`;
}

// Generate OTP for email verification
async function generateOTP(email) {
  console.log('=== Step 1: Generating OTP for email verification ===');
  
  // Generate a random 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  console.log(`Generated OTP: ${otp} for email: ${email}`);
  
  // Encrypt the email for storage in the cookie
  // In a real implementation, this would use proper encryption
  const encryptedEmail = Buffer.from(`enc:${email}`).toString('base64');
  
  // Create a cookie with the OTP information
  const otpData = {
    email: encryptedEmail,
    otp: otp,
    timestamp: new Date().toISOString()
  };
  
  // Convert to base64 for cookie storage
  const cookie = Buffer.from(JSON.stringify(otpData)).toString('base64');
  
  console.log('OTP generation successful');
  return { otp, cookie };
}

// Verify OTP and generate verification cookie
async function verifyOTP(otp, cookie) {
  console.log('=== Step 2: Verifying OTP ===');
  console.log(`Verifying OTP: ${otp} against cookie data`);
  
  // Decode the cookie
  const cookieData = JSON.parse(Buffer.from(cookie, 'base64').toString());
  
  // Verify OTP matches
  if (cookieData.otp !== otp) {
    throw new Error('Invalid OTP');
  }
  
  // Check timestamp is within 5 minutes
  const timestamp = new Date(cookieData.timestamp);
  const now = new Date();
  const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
  
  if (timestamp < fiveMinutesAgo) {
    throw new Error('OTP expired');
  }
  
  // Create verification cookie
  const verificationData = {
    email: cookieData.email,
    verified: true,
    verifiedAt: new Date().toISOString()
  };
  
  const verificationCookie = Buffer.from(JSON.stringify(verificationData)).toString('base64');
  console.log('OTP verification successful');
  
  return verificationCookie;
}

// Register user with passphrase
async function registerPassphrase(verificationCookie, passphrase) {
  console.log('=== Step 3: Registering with passphrase ===');
  
  // Decode verification cookie
  const verificationData = JSON.parse(Buffer.from(verificationCookie, 'base64').toString());
  
  if (!verificationData.verified) {
    throw new Error('Email not verified');
  }
  
  const email = verificationData.email.split(':')[1] || verificationData.email;
  console.log(`Using verified email from cookie: ${email}`);
  
  const { client, stub } = createDgraphClient();
  
  try {
    // Check if user already exists
    const txn = client.newTxn({ readOnly: true });
    const query = `query {
      users(func: eq(email, "${email}")) @filter(type(User)) {
        uid
      }
    }`;
    
    const res = await txn.query(query);
    await txn.discard();
    
    const users = res.getJson().users || [];
    
    if (users.length > 0) {
      throw new Error('User already exists');
    }
    
    // Create a new user
    const salt = randomBytes(16).toString('hex');
    const hashedPassphrase = createHash('sha256').update(passphrase + salt).digest('hex');
    
    // Generate DID in the NFE format
    const didSeed = randomBytes(16);
    const didIdentifier = didSeed.toString('hex');
    const did = `did:nfe:${didIdentifier}`;
    
    // First create the user with a specific blank node name
    const createTxn = client.newTxn();
    const mu = new dgraph.Mutation();
    const now = new Date();
    
    // Set the mutation with a named blank node
    const userData = {
      "dgraph.type": "User",
      "email": email,
      "did": did,
      "name": "Test User",
      "verified": true,
      "emailVerified": now.toISOString(),
      "dateJoined": now.toISOString(),
      "status": "active",
      "passphraseSalt": salt,
      "passphraseHash": hashedPassphrase,
      "failedLoginAttempts": 0,
      "hasPassphrase": true,
      "createdAt": now.toISOString(),
      "updatedAt": now.toISOString()
    };
    
    mu.setSetJson(userData);
    await createTxn.mutate(mu);
    await createTxn.commit();
    
    // Retrieve the user we just created by querying for it
    const findTxn = client.newTxn({ readOnly: true });
    const findQuery = `query {
      users(func: eq(did, "${did}")) @filter(type(User)) {
        uid
        email
        did
      }
    }`;
    
    const findRes = await findTxn.query(findQuery);
    await findTxn.discard();
    
    const createdUsers = findRes.getJson().users || [];
    if (createdUsers.length === 0) {
      throw new Error('Failed to retrieve created user');
    }
    
    const userId = createdUsers[0].uid;
    console.log('User created with UID:', userId);
    
    // Create a log for the successful passphrase registration
    const logTxn = client.newTxn();
    const logMu = new dgraph.Mutation();
    
    logMu.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "PASSPHRASE_REGISTER_SUCCESS",
      "actorId": userId,
      "actorType": "user",
      "resourceId": userId,
      "resourceType": "user",
      "operationType": "register",
      "requestPath": "/api/auth/passphrase/register",
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
        "method": "passphrase",
        "verificationMethod": "OTP"
      })
    });
    
    await logTxn.mutate(logMu);
    await logTxn.commit();
    
    console.log('User registered successfully with passphrase');
    console.log(`User ID: ${userId}`);
    console.log(`DID: ${did}`);
    console.log(`Email: ${email}`);
    
    return {
      userId,
      email,
      did,
      success: true
    };
  } catch (error) {
    console.error('Error registering with passphrase:', error);
    
    // Create a log for the failed registration
    const failTxn = client.newTxn();
    const failMu = new dgraph.Mutation();
    
    failMu.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "PASSPHRASE_REGISTER_VALIDATION_FAILED",
      "actorType": "anonymous",
      "resourceType": "user",
      "operationType": "register",
      "requestPath": "/api/auth/passphrase/register",
      "requestMethod": "POST",
      "responseStatus": 400,
      "clientIp": "127.0.0.1",
      "userAgent": "Test Script",
      "auditTimestamp": new Date().toISOString(),
      "sessionId": "test-session-id",
      "success": false,
      "sensitiveOperation": true,
      "complianceFlags": ["ISO27001", "GDPR"],
      "details": JSON.stringify({
        "method": "passphrase",
        "error": error.message,
        "verificationMethod": "OTP"
      })
    });
    
    await failTxn.mutate(failMu);
    await failTxn.commit();
    
    console.log('Registration failed. Error logged.');
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Run the complete passphrase registration flow
async function runPassphraseRegistrationFlow() {
  try {
    // Generate a random email
    const email = generateTestEmail();
    console.log(`Testing with email: ${email}`);
    
    // Generate a secure passphrase
    const passphrase = `SecurePass${Math.floor(1000 + Math.random() * 9000)}!`;
    console.log(`Using passphrase: ${passphrase}`);
    
    // Step 1: Generate OTP
    const { otp, cookie } = await generateOTP(email);
    
    // Step 2: Verify OTP
    const verificationCookie = await verifyOTP(otp, cookie);
    
    // Step 3: Register with passphrase
    const result = await registerPassphrase(verificationCookie, passphrase);
    
    console.log('\n=== Passphrase Registration Flow Completed Successfully ===');
    console.log('Registration details:');
    console.log(`Email: ${email}`);
    console.log(`User ID: ${result.userId}`);
    console.log(`DID: ${result.did}`);
    console.log('Run check-auth-audit-trail.mjs to see the audit logs');
    
    return {
      email,
      userId: result.userId,
      did: result.did,
      passphrase
    };
  } catch (error) {
    console.error('\nError in passphrase registration flow:', error);
  }
}

// Run the flow
runPassphraseRegistrationFlow();
