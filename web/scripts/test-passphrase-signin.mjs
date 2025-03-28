// Test script for passphrase sign-in flow
import dotenv from 'dotenv';
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import { createHash } from 'crypto';
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

// Find a user with passphrase authentication
async function findUser() {
  console.log('=== Finding a user with passphrase authentication ===');
  const { client, stub } = createDgraphClient();
  
  try {
    const txn = client.newTxn({ readOnly: true });
    const query = `{
      users(func: has(passphraseHash), first: 1) @filter(type(User) AND eq(hasPassphrase, true)) {
        uid
        email
        did
        passphraseHash
        passphraseSalt
        failedLoginAttempts
      }
    }`;
    
    const res = await txn.query(query);
    await txn.discard();
    
    const users = res.getJson().users || [];
    
    if (users.length === 0) {
      console.log('No users with passphrase found. Please run test-passphrase-registration.mjs first.');
      return null;
    }
    
    const user = users[0];
    console.log(`Found user with ID: ${user.uid}`);
    console.log(`Email: ${user.email}`);
    console.log(`DID: ${user.did}`);
    
    return user;
  } catch (error) {
    console.error('Error finding user:', error);
    return null;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Simulate passphrase sign-in
async function signInWithPassphrase(email, passphrase) {
  console.log('=== Signing in with passphrase ===');
  console.log(`Email: ${email}`);
  
  const { client, stub } = createDgraphClient();
  
  try {
    // Find user by email
    const txn = client.newTxn();
    const query = `query {
      user(func: eq(email, "${email}")) @filter(type(User)) {
        uid
        email
        did
        name
        passphraseHash
        passphraseSalt
        failedLoginAttempts
        lockedUntil
        status
      }
    }`;
    
    const res = await txn.query(query);
    const users = res.getJson().user || [];
    
    if (users.length === 0) {
      throw new Error('User not found');
    }
    
    const user = users[0];
    
    // Check if account is locked
    if (user.lockedUntil) {
      const lockedUntil = new Date(user.lockedUntil);
      if (lockedUntil > new Date()) {
        throw new Error('Account is locked');
      }
    }
    
    // Check if account is inactive
    if (user.status !== 'active') {
      throw new Error('Account is inactive');
    }
    
    // Verify passphrase
    const hashedPassphrase = createHash('sha256').update(passphrase + user.passphraseSalt).digest('hex');
    
    if (hashedPassphrase !== user.passphraseHash) {
      // Increment failed login attempts
      const mu = new dgraph.Mutation();
      mu.setSetJson({
        uid: user.uid,
        failedLoginAttempts: (user.failedLoginAttempts || 0) + 1
      });
      
      // If too many failures, lock the account
      if ((user.failedLoginAttempts || 0) + 1 >= 5) {
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + 30); // Lock for 30 minutes
        
        mu.setSetJson({
          uid: user.uid,
          lockedUntil: lockTime.toISOString()
        });
      }
      
      await txn.mutate(mu);
      await txn.commit();
      
      // Log failed login attempt
      const logTxn = client.newTxn();
      const logMu = new dgraph.Mutation();
      
      logMu.setSetJson({
        "dgraph.type": "AuditLog",
        "action": "PASSPHRASE_LOGIN_FAILED",
        "actorType": "anonymous",
        "resourceId": user.uid,
        "resourceType": "user",
        "operationType": "login",
        "requestPath": "/api/auth/passphrase/login",
        "requestMethod": "POST",
        "responseStatus": 401,
        "clientIp": "127.0.0.1",
        "userAgent": "Test Script",
        "auditTimestamp": new Date().toISOString(),
        "sessionId": "test-session-id",
        "success": false,
        "sensitiveOperation": true,
        "complianceFlags": ["ISO27001", "GDPR"],
        "details": JSON.stringify({
          "method": "passphrase",
          "reason": "Invalid passphrase",
          "failedAttempts": (user.failedLoginAttempts || 0) + 1
        })
      });
      
      await logTxn.mutate(logMu);
      await logTxn.commit();
      
      throw new Error('Invalid passphrase');
    }
    
    // Reset failed login attempts on successful login
    const mu = new dgraph.Mutation();
    mu.setSetJson({
      uid: user.uid,
      failedLoginAttempts: 0,
      lastAuthTime: new Date().toISOString()
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    // Log successful login
    const logTxn = client.newTxn();
    const logMu = new dgraph.Mutation();
    
    logMu.setSetJson({
      "dgraph.type": "AuditLog",
      "action": "PASSPHRASE_LOGIN_SUCCESS",
      "actorId": user.uid,
      "actorType": "user",
      "resourceId": user.uid,
      "resourceType": "user",
      "operationType": "login",
      "requestPath": "/api/auth/passphrase/login",
      "requestMethod": "POST",
      "responseStatus": 200,
      "clientIp": "127.0.0.1",
      "userAgent": "Test Script",
      "auditTimestamp": new Date().toISOString(),
      "sessionId": "test-session-id",
      "success": true,
      "sensitiveOperation": true,
      "complianceFlags": ["ISO27001", "GDPR"],
      "details": JSON.stringify({
        "method": "passphrase",
        "userId": user.uid,
        "did": user.did
      })
    });
    
    await logMu.setSetJson({
      "dgraph.type": "AuditLog"
    });
    
    await logTxn.mutate(logMu);
    await logTxn.commit();
    
    console.log('Sign-in successful');
    console.log(`User ID: ${user.uid}`);
    console.log(`DID: ${user.did}`);
    
    return {
      userId: user.uid,
      email: user.email,
      did: user.did,
      success: true
    };
  } catch (error) {
    console.error('Error signing in:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Run the passphrase sign-in flow
async function runPassphraseSignInFlow() {
  try {
    // Find a user with passphrase authentication
    const user = await findUser();
    
    if (!user) {
      console.error('No user found for testing. Please register a user with passphrase first.');
      return;
    }
    
    // For this test, we'll use a known valid passphrase
    // In a real scenario, this would be user-provided
    // Since we don't know the passphrase, we'll simulate a successful authentication
    // by modifying the user's passphrase hash and salt
    
    const testPassphrase = `TestPassword123!`;
    const { client, stub } = createDgraphClient();
    
    try {
      // Create a new hashed passphrase for testing
      const salt = user.passphraseSalt || "testsalt123";
      const hashedPassphrase = createHash('sha256').update(testPassphrase + salt).digest('hex');
      
      // Update the user with our test passphrase
      const txn = client.newTxn();
      const mu = new dgraph.Mutation();
      mu.setSetJson({
        uid: user.uid,
        passphraseHash: hashedPassphrase,
        passphraseSalt: salt
      });
      
      await txn.mutate(mu);
      await txn.commit();
      
      console.log(`Set test passphrase for user: ${testPassphrase}`);
      
      // Now sign in with the test passphrase
      const signInResult = await signInWithPassphrase(user.email, testPassphrase);
      
      console.log('\n=== Passphrase Sign-in Flow Completed Successfully ===');
      console.log('Sign-in details:');
      console.log(`Email: ${signInResult.email}`);
      console.log(`User ID: ${signInResult.userId}`);
      console.log(`DID: ${signInResult.did}`);
      console.log('Run check-auth-audit-trail.mjs to see the audit logs');
    } finally {
      if (stub) {
        stub.close();
      }
    }
  } catch (error) {
    console.error('\nError in passphrase sign-in flow:', error);
  }
}

// Run the flow
runPassphraseSignInFlow();
