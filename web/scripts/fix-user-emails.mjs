import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from 'dotenv';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// Create Dgraph client
const clientStub = new dgraph.DgraphClientStub(
  process.env.DGRAPH_URL || "localhost:9080",
  process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
);
const client = new dgraph.DgraphClient(clientStub);

// Check if a string appears to be encrypted
function isEncrypted(value) {
  return typeof value === 'string' && value.split(':').length === 3;
}

// Encrypt data using AES-256-GCM
function encryptData(value) {
  if (!value) return value;
  if (isEncrypted(value)) return value; // Already encrypted
  
  const key = process.env.EMAIL_ENCRYPTION_KEY;
  if (!key) {
    console.error('EMAIL_ENCRYPTION_KEY environment variable is not set');
    return value;
  }
  
  try {
    // Create a 16-byte initialization vector
    const iv = crypto.randomBytes(16);
    
    // Create cipher using AES-256-GCM
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      Buffer.from(key, 'base64'),
      iv
    );
    
    // Encrypt the data
    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    // Get the authentication tag
    const authTag = cipher.getAuthTag().toString('base64');
    
    // Return the encrypted data in the format: iv:encryptedData:authTag
    return `${iv.toString('base64')}:${encrypted}:${authTag}`;
  } catch (error) {
    console.error('Encryption error:', error);
    return value;
  }
}

// Attempt to decrypt data
function decryptData(value) {
  if (!value) return value;
  if (!isEncrypted(value)) return value;
  
  const key = process.env.EMAIL_ENCRYPTION_KEY;
  if (!key) {
    console.error('EMAIL_ENCRYPTION_KEY environment variable is not set');
    return null;
  }
  
  try {
    const parts = value.split(':');
    if (parts.length !== 3) {
      console.error('Invalid encrypted format');
      return null;
    }
    
    const [ivBase64, encryptedData, authTagBase64] = parts;
    
    const iv = Buffer.from(ivBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(key, 'base64'),
      iv
    );
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
}

// Execute DQL query
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    console.log("Executing query: \n", query, "\n");
    console.log("With variables:", JSON.stringify(vars));
    const res = await txn.queryWithVars(query, vars);
    const json = res.getJson();
    console.log("JSON data type:", typeof json);
    console.log("Parsed JSON data:", JSON.stringify(json, null, 2));
    return json;
  } catch (error) {
    console.error("Query error:", error);
    throw error;
  } finally {
    await txn.discard();
  }
}

// Get all users
async function getAllUsers() {
  const result = await executeDQLQuery(`
    {
      users(func: type(User)) {
        uid
        did
        email
        name
        verified
        emailVerified
        dateJoined
        lastAuthTime
        status
        hasWebAuthn
        hasPassphrase
        roles {
          uid
          name
        }
        createdAt
        updatedAt
      }
    }
  `);
  
  return result.users || [];
}

// Update user email
async function updateUserEmail(uid, email, originalEmail) {
  const txn = client.newTxn();
  try {
    console.log(`Updating user ${uid} email from "${originalEmail}" to "${email}"`);
    
    const mu = new dgraph.Mutation();
    mu.setSetJson({
      uid: uid,
      email: email,
      updatedAt: new Date().toISOString()
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    console.log(`User ${uid} email updated successfully`);
    return true;
  } catch (error) {
    console.error(`Error updating user ${uid} email:`, error);
    return false;
  } finally {
    try {
      await txn.discard();
    } catch (discardError) {
      console.error("Error discarding transaction:", discardError);
    }
  }
}

// Process a user's email
async function processUserEmail(user) {
  const originalEmail = user.email;
  
  // Try to decrypt the email if it's encrypted
  let decryptedEmail = null;
  let needsUpdate = false;
  
  if (isEncrypted(originalEmail)) {
    // Try to decrypt
    decryptedEmail = decryptData(originalEmail);
    
    if (decryptedEmail === null) {
      console.log(`Could not decrypt email for user ${user.uid}, will need to be fixed manually`);
      return false;
    }
    
    // Re-encrypt with current method to ensure consistency
    const newEncryptedEmail = encryptData(decryptedEmail);
    
    // Check if the encryption is different
    if (newEncryptedEmail !== originalEmail) {
      needsUpdate = true;
    }
  } else {
    // Email is not encrypted, encrypt it
    decryptedEmail = originalEmail;
    needsUpdate = true;
  }
  
  // Update if needed
  if (needsUpdate && decryptedEmail) {
    const newEncryptedEmail = encryptData(decryptedEmail);
    return await updateUserEmail(user.uid, newEncryptedEmail, originalEmail);
  }
  
  return false;
}

// Main function
async function main() {
  try {
    console.log("===== FIXING USER EMAILS =====");
    
    // Check if EMAIL_ENCRYPTION_KEY is set
    if (!process.env.EMAIL_ENCRYPTION_KEY) {
      console.error("EMAIL_ENCRYPTION_KEY environment variable is not set");
      return;
    }
    
    // Get all users
    const users = await getAllUsers();
    console.log(`Found ${users.length} users`);
    
    // Process each user
    let updatedCount = 0;
    let skippedCount = 0;
    let errorCount = 0;
    
    for (const user of users) {
      try {
        const updated = await processUserEmail(user);
        if (updated) {
          updatedCount++;
          console.log(`Updated user ${user.uid}`);
        } else {
          skippedCount++;
          console.log(`Skipped user ${user.uid} (no update needed)`);
        }
      } catch (error) {
        errorCount++;
        console.error(`Error processing user ${user.uid}:`, error);
      }
    }
    
    console.log("\n===== UPDATE SUMMARY =====");
    console.log(`Total users: ${users.length}`);
    console.log(`Updated: ${updatedCount}`);
    console.log(`Skipped: ${skippedCount}`);
    console.log(`Errors: ${errorCount}`);
    
  } catch (error) {
    console.error("Error:", error);
  } finally {
    clientStub.close();
  }
}

// Run the main function
main();
