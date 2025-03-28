// This script tests the WebAuthn registration flow with the new OTP verification and recovery passphrase
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// Load environment variables from .env file manually
const loadEnv = () => {
  try {
    const envPath = path.resolve(process.cwd(), 'web/.env');
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf8');
      envContent.split('\n').forEach(line => {
        const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
        if (match) {
          const key = match[1];
          let value = match[2] || '';
          if (value.startsWith('"') && value.endsWith('"')) {
            value = value.substring(1, value.length - 1);
          }
          process.env[key] = value;
        }
      });
    }
  } catch (error) {
    console.error('Error loading .env file:', error);
  }
};

// Load environment variables
loadEnv();

// Create Dgraph client
function createDgraphClient() {
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
  );
  
  return {
    client: new dgraph.DgraphClient(clientStub),
    stub: clientStub
  };
}

// Generate a random IV for encryption
function generateIV() {
  return crypto.randomBytes(16);
}

// Get encryption key from env or use fallback
function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY || 'testing-key-for-development-only';
  return Buffer.from(key).slice(0, 32); // Ensure it's 32 bytes
}

// Encrypt email or other sensitive data
function encryptData(data) {
  try {
    const key = getEncryptionKey();
    const iv = generateIV();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return `enc:${Buffer.from(iv).toString('base64')}:${encrypted}`;
  } catch (error) {
    console.error('Encryption error:', error);
    return data; // Fallback to unencrypted on error
  }
}

// Simulate OTP generation
async function generateOTP(email) {
  console.log('=== Step 1: Generating OTP for email verification ===');
  const { stub } = createDgraphClient();
  
  try {
    // Generate OTP (simulated)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`Generated OTP: ${otp} for email: ${email}`);
    
    // Create a cookie with simulated data
    const cookieData = {
      email: encryptData(email),
      otp: otp,
      timestamp: new Date().toISOString()
    };
    
    const cookie = Buffer.from(JSON.stringify(cookieData)).toString('base64');
    console.log('OTP generation successful');
    
    return { otp, cookie };
  } catch (error) {
    console.error('Error generating OTP:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Simulate OTP verification
async function verifyOTP(otp, cookie) {
  console.log('=== Step 2: Verifying OTP ===');
  const { stub } = createDgraphClient();
  
  try {
    // Decode cookie
    const cookieData = JSON.parse(Buffer.from(cookie, 'base64').toString());
    console.log('Verifying OTP:', otp, 'against cookie data');
    
    // Verify OTP matches
    if (cookieData.otp !== otp) {
      throw new Error('Invalid OTP');
    }
    
    // Check if OTP is expired (5 minutes)
    const cookieTimestamp = new Date(cookieData.timestamp);
    const now = new Date();
    const fiveMinutes = 5 * 60 * 1000;
    
    if (now - cookieTimestamp > fiveMinutes) {
      throw new Error('OTP has expired');
    }
    
    console.log('OTP verification successful');
    
    // Create verification cookie
    const verificationData = {
      email: cookieData.email,
      verified: true,
      verifiedAt: now.toISOString()
    };
    
    const verificationCookie = Buffer.from(JSON.stringify(verificationData)).toString('base64');
    return verificationCookie;
  } catch (error) {
    console.error('Error verifying OTP:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Register WebAuthn credential
async function registerWebAuthn(verificationCookie, recoveryPassphrase) {
  console.log('=== Step 3: Registering WebAuthn credential ===');
  const { client, stub } = createDgraphClient();
  
  try {
    // Decode verification cookie to get email
    const verificationData = JSON.parse(Buffer.from(verificationCookie, 'base64').toString());
    console.log('Using verified email from cookie:', verificationData.email);
    
    // Generate test challenge
    const challenge = crypto.randomBytes(32).toString('base64url');
    console.log('Generated challenge for WebAuthn:', challenge);
    
    // Create simulated WebAuthn registration request
    const txn = client.newTxn();
    
    // First check if user exists
    const findUserQuery = `query {
      user(func: eq(email, "${verificationData.email}")) @filter(type(User)) {
        uid
      }
    }`;
    
    const findRes = await txn.query(findUserQuery);
    const users = findRes.getJson().user || [];
    
    let userId = null;
    if (users.length > 0) {
      userId = users[0].uid;
      console.log('Found existing user with ID:', userId);
    } else {
      console.log('User not found, will create a new one');
    }
    
    // Create challenge in Dgraph
    const mu = new dgraph.Mutation();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes from now
    
    // Set challenge
    mu.setSetJson({
      "dgraph.type": "Challenge",
      "email": verificationData.email,
      "challenge": challenge,
      "timestamp": now.toISOString(),
      "expiresAt": expiresAt.toISOString()
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    console.log('WebAuthn registration challenge created successfully');
    
    // Create a log for the WebAuthn registration attempt
    const txn2 = client.newTxn();
    const mu2 = new dgraph.Mutation();
    
    mu2.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "WEBAUTHN_REGISTER_ATTEMPT",
      "actorType": "user",
      "resourceType": "user",
      "operationType": "register",
      "requestPath": "/api/auth/webauthn/register",
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
        "recoveryPassphraseProvided": true,
        "verificationMethod": "OTP"
      })
    });
    
    await txn2.mutate(mu2);
    await txn2.commit();
    
    console.log('WebAuthn registration attempt logged successfully');
    
    return {
      email: verificationData.email,
      challenge: challenge,
      expiresAt: expiresAt.toISOString(),
      recoveryPassphrase: recoveryPassphrase,
      userId: userId
    };
  } catch (error) {
    console.error('Error registering WebAuthn:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Register a user in Dgraph
async function createUser(email) {
  console.log('=== Creating test user ===');
  const { client, stub } = createDgraphClient();
  
  try {
    const now = new Date();
    // Format DID in the NFE format
    const randomId = crypto.randomBytes(16).toString('hex');
    const did = `did:nfe:${randomId}`;
    
    // Create user
    const txn = client.newTxn();
    const mu = new dgraph.Mutation();
    
    mu.setSetJson({
      "dgraph.type": "User",
      "email": email,
      "did": did,
      "name": "Test User",
      "verified": true,
      "emailVerified": now.toISOString(),
      "dateJoined": now.toISOString(),
      "lastAuthTime": null,
      "status": "active",
      "hasWebAuthn": false,
      "hasPassphrase": false, // Will set to true when storing recovery passphrase
      "passwordHash": null,
      "passwordSalt": null,
      "recoveryEmail": null,
      "failedLoginAttempts": 0,
      "lastFailedLogin": null,
      "lockedUntil": null,
      "createdAt": now.toISOString(),
      "updatedAt": null
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    // Get the user ID
    const txn2 = client.newTxn();
    const query = `query {
      user(func: eq(email, "${email}")) @filter(type(User)) {
        uid
        email
        did
      }
    }`;
    
    const res = await txn2.query(query);
    await txn2.discard();
    
    const users = res.getJson().user || [];
    
    if (users.length === 0) {
      throw new Error('Failed to create user');
    }
    
    const userId = users[0].uid;
    console.log('Created user:', users[0]);
    
    return {
      userId,
      email,
      did
    };
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Store recovery passphrase for a user
async function storeRecoveryPassphrase(userId, recoveryPassphrase) {
  console.log('=== Storing recovery passphrase ===');
  const { client, stub } = createDgraphClient();
  
  try {
    // Create a salt and hash the passphrase
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(
      recoveryPassphrase,
      salt,
      10000,
      64,
      'sha512'
    ).toString('hex');
    
    // Update user with passphrase information
    const txn = client.newTxn();
    const mu = new dgraph.Mutation();
    
    mu.setSetJson({
      "uid": userId,
      "hasPassphrase": true,
      "passwordHash": hash,
      "passwordSalt": salt,
      "updatedAt": new Date().toISOString()
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    console.log('Recovery passphrase stored successfully');
    
    return true;
  } catch (error) {
    console.error('Error storing recovery passphrase:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Verify WebAuthn registration
async function verifyWebAuthnRegistration(email, challenge, fakePubKey) {
  console.log('=== Step 4: Verifying WebAuthn registration ===');
  const { client, stub } = createDgraphClient();
  
  try {
    // Simulate WebAuthn attestation verification
    console.log('Simulating WebAuthn attestation verification for email:', email);
    
    // Create a simulated credential for the user
    const txn = client.newTxn();
    const query = `query {
      user(func: eq(email, "${email}")) @filter(type(User)) {
        uid
      }
    }`;
    
    const res = await txn.query(query);
    const users = res.getJson().user || [];
    
    if (users.length === 0) {
      throw new Error('User not found');
    }
    
    const userId = users[0].uid;
    console.log('Found user with ID:', userId);
    
    // Create a simulated credential
    const credentialId = crypto.randomBytes(16).toString('base64url');
    const now = new Date();
    
    // First create the device node with a facet for dgraph.type
    const mu = new dgraph.Mutation();
    const deviceData = {
      "dgraph.type": "Device",
      "credentialID": credentialId,
      "credentialPublicKey": fakePubKey || crypto.randomBytes(32).toString('base64url'),
      "counter": 0,
      "transports": ["internal", "usb"],
      "deviceName": "Test Device",
      "isBiometric": true,
      "deviceType": "SecurityKey",
      "deviceInfo": JSON.stringify({
        "browser": "Test Browser",
        "os": "Test OS",
        "platform": "Test Platform"
      }),
      "createdAt": now.toISOString()
    };
    
    mu.setSetJson(deviceData);
    const resp = await txn.mutate(mu);
    
    // Get the blank node UID from the response
    const uids = resp.getUidsMap();
    const deviceUid = uids.get("blank-0");
    console.log('Created device with UID:', deviceUid);
    
    // Now link the device to the user
    const mu2 = new dgraph.Mutation();
    mu2.setSetJson({
      "uid": deviceUid,
      "user": {
        "uid": userId
      }
    });
    await txn.mutate(mu2);
    
    // Update user to indicate they have WebAuthn
    const mu3 = new dgraph.Mutation();
    mu3.setSetJson({
      "uid": userId,
      "hasWebAuthn": true,
      "devices": [
        {
          "uid": deviceUid
        }
      ]
    });
    
    await txn.mutate(mu3);
    await txn.commit();
    
    // Create a log for the successful WebAuthn registration
    const txn2 = client.newTxn();
    const mu4 = new dgraph.Mutation();
    
    mu4.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "WEBAUTHN_REGISTER_SUCCESS",
      "actorId": userId,
      "actorType": "user",
      "resourceId": userId,
      "resourceType": "user",
      "operationType": "register",
      "requestPath": "/api/auth/webauthn/register-verify",
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
        "credentialId": credentialId,
        "deviceId": deviceUid,
        "deviceType": "SecurityKey",
        "recoveryPassphraseStored": true
      })
    });
    
    await txn2.mutate(mu4);
    await txn2.commit();
    
    console.log('WebAuthn registration verified successfully');
    console.log('Created credential ID:', credentialId);
    console.log('Device UID:', deviceUid);
    
    return {
      userId,
      credentialId,
      deviceUid,
      success: true
    };
  } catch (error) {
    console.error('Error verifying WebAuthn registration:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Verify user WebAuthn devices
async function verifyUserDevices(userId) {
  console.log('=== Checking user WebAuthn devices ===');
  const { client, stub } = createDgraphClient();
  
  try {
    // Query for user devices
    const txn = client.newTxn({ readOnly: true });
    const query = `query {
      user(func: uid(${userId})) {
        uid
        email
        did
        hasWebAuthn
        hasPassphrase
        devices {
          uid
          credentialID
          deviceName
          deviceType
          isBiometric
          createdAt
        }
      }
    }`;
    
    const res = await txn.query(query);
    await txn.discard();
    
    const user = res.getJson().user?.[0] || null;
    
    if (!user) {
      console.error('User not found');
      return null;
    }
    
    console.log('User details:');
    console.log(JSON.stringify(user, null, 2));
    
    return user;
  } catch (error) {
    console.error('Error checking user devices:', error);
    return null;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Run the complete WebAuthn registration flow
async function runWebAuthnRegistrationFlow() {
  try {
    // Replace with your test email
    const email = 'test@example.com';
    const recoveryPassphrase = 'SecureRecovery123!';
    
    // Step 1: Generate OTP
    const { otp, cookie } = await generateOTP(email);
    console.log('OTP Cookie received:', cookie);
    
    // Step 2: Verify OTP
    const verificationCookie = await verifyOTP(otp, cookie);
    console.log('Verification Cookie:', verificationCookie);
    
    // Step 2.5: Create a user if not already exists
    const verificationData = JSON.parse(Buffer.from(verificationCookie, 'base64').toString());
    const user = await createUser(verificationData.email);
    console.log('User created or found:', user);
    
    // Step 3: Register WebAuthn
    const registration = await registerWebAuthn(verificationCookie, recoveryPassphrase);
    console.log('WebAuthn registration data:', registration);
    
    // Step 3.5: Store the recovery passphrase
    await storeRecoveryPassphrase(user.userId, recoveryPassphrase);
    
    // Step 4: Verify WebAuthn Registration
    const verificationResult = await verifyWebAuthnRegistration(registration.email, registration.challenge, null);
    console.log('WebAuthn verification result:', verificationResult);
    
    // Step 5: Verify user has the device properly linked
    await verifyUserDevices(user.userId);
    
    console.log('\n=== WebAuthn Registration Flow Completed Successfully ===');
  } catch (error) {
    console.error('Error in WebAuthn registration flow:', error);
  }
}

// Run the test
runWebAuthnRegistrationFlow();
