import dotenv from 'dotenv';
import * as dgraph from 'dgraph-js';
import { credentials } from '@grpc/grpc-js';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// Get the encryption key from environment variables
const encryptionKey = process.env.EMAIL_ENCRYPTION_KEY;
if (!encryptionKey) {
  console.error('EMAIL_ENCRYPTION_KEY environment variable is not set');
  process.exit(1);
}

// Create a Dgraph client
function createDgraphClient() {
  // Create client stub with proper gRPC credentials
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
  );

  // Create client
  return new dgraph.DgraphClient(clientStub);
}

const client = createDgraphClient();

/**
 * Encrypt sensitive data
 * @param {string} data - Data to encrypt
 * @returns {string} - Encrypted data
 */
function encryptData(value) {
  if (!value) return value;
  
  const key = process.env.EMAIL_ENCRYPTION_KEY;
  if (!key) {
    console.error("EMAIL_ENCRYPTION_KEY is not set in environment variables");
    return value;
  }

  try {
    // For AES-256-GCM, we need a 32-byte key (256 bits)
    // If the key is in hex format, we need to convert it to a Buffer
    // If it's not exactly 32 bytes after conversion, we'll hash it to get a consistent length
    let keyBuffer;
    
    if (key.length === 64 && /^[0-9a-fA-F]+$/.test(key)) {
      // It's a 64-character hex string (32 bytes)
      keyBuffer = Buffer.from(key, 'hex');
    } else if (key.length === 32) {
      // It's already 32 bytes in UTF-8
      keyBuffer = Buffer.from(key, 'utf8');
    } else {
      // Hash the key to get a consistent length
      keyBuffer = crypto.createHash('sha256').update(key).digest();
    }

    // Generate a random initialization vector
    const iv = crypto.randomBytes(16);
    
    // Create cipher with key and iv
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    
    // Encrypt the value
    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    // Get the auth tag
    const authTag = cipher.getAuthTag().toString('base64');
    
    // Return the IV, encrypted data, and auth tag as a colon-separated string
    return `${iv.toString('base64')}:${encrypted}:${authTag}`;
  } catch (error) {
    console.error("Error encrypting data:", error.message);
    return value;
  }
}

/**
 * Execute a DQL query
 * @param {string} query - DQL query
 * @param {Object} vars - Query variables
 * @returns {Object} - Query result
 */
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    console.log("Executing query:", query);
    console.log("With variables:", JSON.stringify(vars));
    
    const res = await txn.queryWithVars(query, vars);
    
    // Extract the JSON data from the response
    let jsonData;
    
    try {
      // First try to get the JSON directly
      jsonData = res.getJson();
      console.log("JSON data type:", typeof jsonData);
      
      // If it's a string, parse it
      if (typeof jsonData === 'string') {
        jsonData = JSON.parse(jsonData);
      }
    } catch (jsonError) {
      console.log("Error getting JSON directly:", jsonError.message);
      
      // If that fails, try to extract from the Uint8Array
      if (res.u && Array.isArray(res.u) && res.u[0] instanceof Uint8Array) {
        try {
          const jsonStr = Buffer.from(res.u[0]).toString('utf8');
          console.log("Extracted JSON string from Uint8Array:", jsonStr);
          jsonData = JSON.parse(jsonStr);
        } catch (uint8Error) {
          console.error("Error parsing Uint8Array:", uint8Error.message);
          throw new Error("Failed to extract JSON data from response");
        }
      } else {
        throw new Error("Response does not contain valid JSON data");
      }
    }
    
    console.log("Parsed JSON data:", JSON.stringify(jsonData, null, 2));
    return jsonData;
  } catch (error) {
    console.error("Error executing query:", error.message);
    throw error;
  } finally {
    await txn.discard();
  }
}

/**
 * Get all users from the database
 * @returns {Promise<Array>} - Array of users
 */
async function getAllUsers() {
  const query = `
    {
      users(func: type(User)) {
        uid
        did
        email
        name
        hasWebAuthn
        hasPassphrase
        dgraph.type
        status
        verified
        emailVerified
        dateJoined
        lastAuthTime
        roles {
          uid
          name
          dgraph.type
        }
        devices {
          uid
          deviceName
          deviceType
          dgraph.type
        }
      }
    }
  `;
  
  try {
    console.log("Querying all users...");
    const result = await executeDQLQuery(query);
    
    // Extract users from the result
    if (result && result.users && Array.isArray(result.users)) {
      console.log(`Found ${result.users.length} users in the database`);
      return result.users;
    }
    
    console.error("No users found or unexpected response format:", JSON.stringify(result, null, 2));
    return [];
  } catch (error) {
    console.error("Error querying all users:", error.message);
    return [];
  }
}

/**
 * Update a user's email field
 * @param {string} userId - User ID
 * @param {string} email - Email to set
 * @returns {Promise<boolean>} - Success flag
 */
async function updateUserEmail(userId, email) {
  const txn = client.newTxn();
  try {
    console.log(`Updating email for user ${userId} to ${email}`);
    
    // Encrypt the email
    const encryptedEmail = encryptData(email);
    console.log(`Encrypted email: ${encryptedEmail}`);
    
    // Create mutation
    const mu = new dgraph.Mutation();
    const userUpdate = {
      uid: userId,
      email: encryptedEmail,
      "dgraph.type": "User"
    };
    
    mu.setSetJson(userUpdate);
    
    // Execute mutation
    await txn.mutate(mu);
    await txn.commit();
    
    console.log(`Successfully updated email for user ${userId}`);
    return true;
  } catch (error) {
    console.error(`Failed to update email for user ${userId}:`, error.message);
    return false;
  } finally {
    await txn.discard();
  }
}

/**
 * Main function
 */
async function main() {
  const email = process.argv[2];
  
  if (!email) {
    console.error('Please provide an email address as an argument');
    process.exit(1);
  }
  
  console.log(`===== UPDATE USER EMAIL =====`);
  console.log(`Email to set: ${email}`);
  
  try {
    // Get all users
    const users = await getAllUsers();
    
    if (users.length === 0) {
      console.log('No users found in the database');
      process.exit(0);
    }
    
    // Update each user's email field
    let updatedCount = 0;
    for (const user of users) {
      console.log(`\nUser details for UID ${user.uid}:`);
      console.log(JSON.stringify(user, null, 2));
      
      // Force update all users' email fields
      console.log(`Updating email for user ${user.uid}...`);
      const success = await updateUserEmail(user.uid, email);
      if (success) {
        updatedCount++;
      }
    }
    
    console.log(`\nUpdated ${updatedCount} users with email: ${email}`);
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Run the main function
main().catch(console.error);
