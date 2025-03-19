import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from 'dotenv';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// Check for required environment variables
if (!process.env.EMAIL_ENCRYPTION_KEY) {
  console.error("ERROR: EMAIL_ENCRYPTION_KEY environment variable is required");
  process.exit(1);
}

// Get email from command line arguments
const email = process.argv[2];
if (!email) {
  console.error("Usage: node test-device-info.mjs <email>");
  process.exit(1);
}

// Create Dgraph client
const clientStub = new dgraph.DgraphClientStub(
  process.env.DGRAPH_URL || "localhost:9080",
  process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
);
const client = new dgraph.DgraphClient(clientStub);

// Encryption functions
function isEncrypted(value) {
  // Check if the string contains two colons which is our format for encrypted data
  return typeof value === 'string' && value.split(':').length === 3;
}

function encryptData(value) {
  if (!value) return value;
  if (isEncrypted(value)) return value; // Already encrypted
  
  const key = process.env.EMAIL_ENCRYPTION_KEY;
  if (!key) {
    console.error('EMAIL_ENCRYPTION_KEY environment variable is not set');
    return value; // Return original value if encryption key is not available
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
    return value; // Return original value on error
  }
}

function decryptData(value) {
  if (!value) return value;
  if (!isEncrypted(value)) return value; // Not encrypted
  
  const key = process.env.EMAIL_ENCRYPTION_KEY;
  if (!key) {
    console.error('EMAIL_ENCRYPTION_KEY environment variable is not set');
    return value; // Return original value if encryption key is not available
  }
  
  try {
    // Split the encrypted data into its components
    const [ivBase64, encryptedData, authTagBase64] = value.split(':');
    
    // Convert components from base64
    const iv = Buffer.from(ivBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    
    // Create decipher
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(key, 'base64'),
      iv
    );
    
    // Set the authentication tag
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null; // Return null on error to indicate failure
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

async function main() {
  console.log("===== DEVICE INFO TEST =====");
  console.log("Testing for email:", email);
  
  // Encrypt the email for lookup
  const encryptedEmail = encryptData(email);
  console.log("Encrypted email:", encryptedEmail);
  
  // Test decryption to verify it works
  const decryptedEmail = decryptData(encryptedEmail);
  console.log("Decrypted email:", decryptedEmail);
  console.log("Encryption/decryption working correctly:", decryptedEmail === email);
  console.log();
  
  // Look up user by email
  console.log("Looking up user with email...");
  
  // First try with unencrypted email
  console.log("Looking up user by email:", email);
  const result = await executeDQLQuery(
    `query getUser($email: string) {
      user(func: eq(email, $email)) @filter(type(User)) {
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
          permissions
        }
        createdAt
        updatedAt
        devices {
          uid
          credentialID
          deviceName
          deviceType
          deviceInfo
          isBiometric
          lastUsed
          createdAt
        }
      }
    }`,
    { $email: email }
  );
  
  // If no user found, try with encrypted email
  if (!result.user || result.user.length === 0) {
    console.log("Trying with encrypted email:", encryptedEmail);
    const encryptedResult = await executeDQLQuery(
      `query getUser($email: string) {
        user(func: eq(email, $email)) @filter(type(User)) {
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
            permissions
          }
          createdAt
          updatedAt
          devices {
            uid
            credentialID
            deviceName
            deviceType
            deviceInfo
            isBiometric
            lastUsed
            createdAt
          }
        }
      }`,
      { $email: encryptedEmail }
    );
    
    if (encryptedResult.user && encryptedResult.user.length > 0) {
      console.log("User found with encrypted email lookup");
      console.log("User found:", JSON.stringify(encryptedResult.user[0], null, 2));
      return;
    }
  } else {
    console.log("User found with direct email lookup");
    console.log("User found:", JSON.stringify(result.user[0], null, 2));
    return;
  }
  
  // If still no user found, try manual search and decrypt emails
  console.log("User not found with direct lookups, trying manual search");
  const allUsers = await executeDQLQuery(
    `
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
          permissions
        }
        createdAt
        updatedAt
        devices {
          uid
          credentialID
          deviceName
          deviceType
          deviceInfo
          isBiometric
          lastUsed
          createdAt
        }
      }
    }
   `
  );
  
  // Try to find user by decrypting emails
  let foundUser = null;
  if (allUsers.users) {
    for (const user of allUsers.users) {
      if (user.email) {
        try {
          const userEmail = decryptData(user.email);
          if (userEmail === email) {
            console.log(`Found user ${user.uid} with matching decrypted email`);
            foundUser = { ...user, decryptedEmail: userEmail };
            break;
          }
        } catch (error) {
          // Skip if decryption fails
          console.error(`Decryption failed for user ${user.uid}: ${error.message}`);
        }
      }
    }
  }
  
  if (foundUser) {
    console.log("User found:");
    console.log(JSON.stringify(foundUser, null, 2));
  } else {
    console.log("User not found with email:", email);
  }
}

// Run the main function
main()
  .then(() => {
    console.log("Test completed successfully");
    clientStub.close();
  })
  .catch((error) => {
    console.error("Test failed:", error);
    clientStub.close();
    process.exit(1);
  });
