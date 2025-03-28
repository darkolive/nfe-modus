// Test script for passphrase sign-in failure and audit logging
import dotenv from 'dotenv';
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
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
        lockedUntil
        status
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

// Reset user's failed login attempts and locked status
async function resetUserLockStatus(userId) {
  console.log(`Resetting lock status for user ${userId}`);
  const { client, stub } = createDgraphClient();
  
  try {
    const txn = client.newTxn();
    const mu = new dgraph.Mutation();
    mu.setSetJson({
      uid: userId,
      failedLoginAttempts: 0,
      lockedUntil: null
    });
    
    await txn.mutate(mu);
    await txn.commit();
    console.log('User lock status reset successfully');
  } catch (error) {
    console.error('Error resetting user lock status:', error);
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Simulate passphrase sign-in with wrong password
async function attemptWrongPassphrase(email, incorrectPassphrase) {
  console.log('=== Attempting sign-in with wrong passphrase ===');
  console.log(`Email: ${email}`);
  console.log(`Using incorrect passphrase: ${incorrectPassphrase}`);
  
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
        console.log(`Account is locked until ${lockedUntil.toISOString()}`);
        
        // Log locked account attempt
        const logTxn = client.newTxn();
        const logMu = new dgraph.Mutation();
        
        logMu.setSetJson({
          "dgraph.type": "AuditLog",
          "action": "PASSPHRASE_LOGIN_ACCOUNT_LOCKED",
          "actorType": "anonymous",
          "resourceId": user.uid,
          "resourceType": "user",
          "operationType": "login",
          "requestPath": "/api/auth/passphrase/login",
          "requestMethod": "POST",
          "responseStatus": 403,
          "clientIp": "127.0.0.1",
          "userAgent": "Test Script",
          "auditTimestamp": new Date().toISOString(),
          "sessionId": "test-session-id",
          "success": false,
          "sensitiveOperation": true,
          "complianceFlags": ["ISO27001", "GDPR"],
          "details": JSON.stringify({
            "method": "passphrase",
            "reason": "Account locked",
            "lockedUntil": user.lockedUntil
          })
        });
        
        await logTxn.mutate(logMu);
        await logTxn.commit();
        
        throw new Error('Account is locked');
      }
    }
    
    // Check if account is inactive
    if (user.status !== 'active') {
      throw new Error('Account is inactive');
    }
    
    // The passphrase is intentionally wrong, so this should fail
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
      
      console.log(`Account will be locked until ${lockTime.toISOString()}`);
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
        "failedAttempts": (user.failedLoginAttempts || 0) + 1,
        "accountLocked": (user.failedLoginAttempts || 0) + 1 >= 5
      })
    });
    
    await logTxn.mutate(logMu);
    await logTxn.commit();
    
    console.log(`Login failed with wrong passphrase`);
    console.log(`Failed attempts: ${(user.failedLoginAttempts || 0) + 1}`);
    
    return {
      userId: user.uid,
      email: user.email,
      did: user.did,
      failedAttempts: (user.failedLoginAttempts || 0) + 1,
      success: false
    };
  } catch (error) {
    console.error('Error in failed sign-in attempt:', error);
    throw error;
  } finally {
    if (stub) {
      stub.close();
    }
  }
}

// Test multiple failed login attempts to trigger account lockout
async function testFailedLoginAttempts() {
  try {
    // Find a user with passphrase authentication
    const user = await findUser();
    
    if (!user) {
      console.error('No user found for testing. Please register a user with passphrase first.');
      return;
    }
    
    // Reset user's failed login attempts to ensure we start clean
    await resetUserLockStatus(user.uid);
    
    // Incorrect passphrase
    const incorrectPassphrase = "WrongPassword123!";
    
    // Make multiple failed login attempts
    const maxAttempts = 5; // Number of attempts before lockout
    let currentAttempts = 0;
    let isLocked = false;
    
    console.log(`\n=== Testing ${maxAttempts} failed login attempts ===`);
    
    for (let i = 0; i < maxAttempts; i++) {
      console.log(`\nAttempt ${i+1}/${maxAttempts}`);
      
      try {
        const result = await attemptWrongPassphrase(user.email, incorrectPassphrase);
        currentAttempts = result.failedAttempts;
        
        if (currentAttempts >= maxAttempts) {
          isLocked = true;
          console.log(`Account is now locked after ${currentAttempts} failed attempts`);
        }
      } catch (error) {
        if (error.message === 'Account is locked') {
          isLocked = true;
          console.log('Account is now locked');
          break;
        }
        console.error(`Error on attempt ${i+1}:`, error.message);
      }
    }
    
    // Make one more attempt to confirm lockout
    if (isLocked) {
      console.log('\nMaking one more attempt to confirm lockout');
      try {
        await attemptWrongPassphrase(user.email, incorrectPassphrase);
      } catch (error) {
        console.log('Confirmed account is locked:', error.message);
      }
    }
    
    console.log('\n=== Test completed ===');
    console.log(`User: ${user.email}`);
    console.log(`Failed attempts: ${currentAttempts}`);
    console.log(`Account locked: ${isLocked}`);
    console.log('Run check-auth-audit-trail.mjs to see the audit logs');
    
    // Reset user status after test
    await resetUserLockStatus(user.uid);
    console.log('\nReset user status after test completion');
  } catch (error) {
    console.error('\nError in test flow:', error);
  }
}

// Run the test
testFailedLoginAttempts();
