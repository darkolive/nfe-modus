import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import dotenv from 'dotenv';
import crypto from 'crypto';
import * as dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';

// Get the directory of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from .env file
dotenv.config({ path: resolve(__dirname, '../.env') });

// Get the encryption key from environment variables
const encryptionKey = process.env.EMAIL_ENCRYPTION_KEY;
if (!encryptionKey) {
  console.error('EMAIL_ENCRYPTION_KEY is not set in environment variables');
  process.exit(1);
}

// Create a client stub
const clientStub = new dgraph.DgraphClientStub(
  process.env.DGRAPH_URL || 'localhost:9080',
  process.env.DGRAPH_TLS === 'true'
    ? grpc.credentials.createSsl()
    : grpc.credentials.createInsecure()
);

// Create a client
const client = new dgraph.DgraphClient(clientStub);

/**
 * Encrypt sensitive data
 * @param {string} value - Data to encrypt
 * @returns {string} - Encrypted data
 */
function encryptData(value) {
  if (!value) return value;
  
  try {
    // For AES-256-GCM, we need a 32-byte key (256 bits)
    // If the key is in hex format, we need to convert it to a Buffer
    // If it's not exactly 32 bytes after conversion, we'll hash it to get a consistent length
    let keyBuffer;
    
    if (encryptionKey.length === 64 && /^[0-9a-fA-F]+$/.test(encryptionKey)) {
      // It's a 64-character hex string (32 bytes)
      keyBuffer = Buffer.from(encryptionKey, 'hex');
    } else if (encryptionKey.length === 32) {
      // It's already 32 bytes in UTF-8
      keyBuffer = Buffer.from(encryptionKey, 'utf8');
    } else {
      // Hash the key to get a consistent length
      keyBuffer = crypto.createHash('sha256').update(encryptionKey).digest();
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
 * Decrypt sensitive data
 * @param {string} value - Data to decrypt
 * @returns {string} - Decrypted data
 */
function decryptData(value) {
  if (!value) return value;
  
  try {
    // Split the value into IV, encrypted data, and auth tag
    const parts = value.split(':');
    if (parts.length !== 3) {
      console.error('Invalid encrypted data format');
      return value;
    }
    
    const [ivBase64, encryptedBase64, authTagBase64] = parts;
    
    // Convert the parts from base64 to buffers
    const iv = Buffer.from(ivBase64, 'base64');
    const encrypted = Buffer.from(encryptedBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    
    // Prepare the key
    let keyBuffer;
    
    if (encryptionKey.length === 64 && /^[0-9a-fA-F]+$/.test(encryptionKey)) {
      // It's a 64-character hex string (32 bytes)
      keyBuffer = Buffer.from(encryptionKey, 'hex');
    } else if (encryptionKey.length === 32) {
      // It's already 32 bytes in UTF-8
      keyBuffer = Buffer.from(encryptionKey, 'utf8');
    } else {
      // Hash the key to get a consistent length
      keyBuffer = crypto.createHash('sha256').update(encryptionKey).digest();
    }
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message);
    return value;
  }
}

/**
 * Execute a DQL query
 * @param {string} query - DQL query
 * @param {Object} vars - Query variables
 * @returns {Promise<Object>} - Query result
 */
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    console.log('Executing query: \n', query, '\n');
    console.log('With variables:', JSON.stringify(vars));
    
    const res = await txn.queryWithVars(query, vars);
    const data = res.getJson();
    
    console.log('JSON data type:', typeof data);
    console.log('Parsed JSON data:', JSON.stringify(data, null, 2));
    
    return data;
  } finally {
    await txn.discard();
  }
}

/**
 * Process user data by decrypting sensitive fields
 * @param {Object} user - User data
 * @returns {Object} - Processed user data
 */
function processUserData(user) {
  if (!user) return null;
  
  // Make a copy of the user object
  const processedUser = { ...user };
  
  // Decrypt email if it exists
  if (processedUser.email) {
    try {
      processedUser.decryptedEmail = decryptData(processedUser.email);
    } catch (error) {
      console.error('Error decrypting email:', error.message);
      processedUser.decryptedEmail = processedUser.email;
    }
  }
  
  return processedUser;
}

/**
 * Custom DgraphClient class for testing
 */
class DgraphClient {
  /**
   * Get a user by email
   * @param {string} email - Email to look up
   * @returns {Promise<Object|null>} - User object or null if not found
   */
  async getUserByEmail(email) {
    console.log(`Looking up user by email: ${email}`);
    
    // First try with unencrypted email
    try {
      const unencryptedResult = await executeDQLQuery(
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
              lastUsed
              createdAt
            }
          }
        }`,
        { $email: email }
      );
      
      if (unencryptedResult.user && unencryptedResult.user.length > 0) {
        console.log('User found with unencrypted email');
        return processUserData(unencryptedResult.user[0]);
      }
      
      // Try with encrypted email
      const encryptedEmail = encryptData(email);
      console.log(`Trying with encrypted email: ${encryptedEmail}`);
      
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
              lastUsed
              createdAt
            }
          }
        }`,
        { $email: encryptedEmail }
      );
      
      if (encryptedResult.user && encryptedResult.user.length > 0) {
        console.log('User found with encrypted email');
        return processUserData(encryptedResult.user[0]);
      }
      
      // If still not found, try the manual approach
      console.log('User not found with direct lookups, trying manual search');
      
      // Get all users
      const allUsers = await executeDQLQuery(`
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
              lastUsed
              createdAt
            }
          }
        }
      `);
      
      if (allUsers.users && allUsers.users.length > 0) {
        // Try to decrypt each user's email and check if it matches
        for (const user of allUsers.users) {
          if (user.email) {
            try {
              const decryptedEmail = decryptData(user.email);
              if (decryptedEmail === email) {
                console.log(`Found user ${user.uid} with matching decrypted email`);
                return processUserData(user);
              }
            } catch (error) {
              console.error(`Error decrypting email for user ${user.uid}:`, error.message);
            }
          }
        }
      }
      
      return null;
    } catch (error) {
      console.error('Error in getUserByEmail:', error.message);
      return null;
    }
  }
}

/**
 * Main function
 */
async function testEmailLookup() {
  const email = process.argv[2];
  
  if (!email) {
    console.error('Please provide an email address as an argument');
    process.exit(1);
  }
  
  console.log(`===== EMAIL LOOKUP TEST =====`);
  console.log(`Testing email: ${email}`);
  
  // Test encryption and decryption
  const encrypted = encryptData(email);
  console.log(`Encrypted email: ${encrypted}`);
  
  const decrypted = decryptData(encrypted);
  console.log(`Decrypted email: ${decrypted}`);
  console.log(`Encryption/decryption working correctly: ${decrypted === email}`);
  
  console.log('\nLooking up user with email...');
  
  // Create an instance of our DgraphClient class
  const dgraphClient = new DgraphClient();
  
  try {
    // Use the enhanced getUserByEmail method from our class
    const user = await dgraphClient.getUserByEmail(email);
    
    if (user) {
      console.log('User found:');
      console.log(JSON.stringify(user, null, 2));
    } else {
      console.log('No user found with this email.');
      
      // Fallback to manual search for diagnostic purposes
      console.log('\nChecking all users in the database...');
      console.log('Querying all users with detailed fields...');
      
      const allUsers = await executeDQLQuery(`
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
      `);
      
      if (allUsers.users && allUsers.users.length > 0) {
        console.log(`Found ${allUsers.users.length} users in the database\n`);
        
        // Iterate through users and try to decrypt their emails
        const matchingUsers = [];
        
        for (const user of allUsers.users) {
          console.log(`User details for UID ${user.uid}:`);
          console.log(JSON.stringify(user, null, 2));
          
          if (user.email) {
            try {
              const decryptedEmail = decryptData(user.email);
              console.log(`User ${user.uid}: Encrypted email ${user.email} decrypted to ${decryptedEmail}`);
              
              if (decryptedEmail === email) {
                matchingUsers.push({
                  ...user,
                  decryptedEmail
                });
              }
            } catch (error) {
              console.error(`Failed to decrypt email for user ${user.uid}:`, error.message);
            }
          } else {
            console.log(`User ${user.uid} has no email field`);
          }
        }
        
        console.log(`Found ${allUsers.users.length} users in the database.`);
        console.log(`Sample user data:`, JSON.stringify(allUsers.users[0], null, 2));
        
        if (matchingUsers.length > 0) {
          console.log(`\nFound ${matchingUsers.length} users with matching email after manual decryption:`);
          for (const user of matchingUsers) {
            console.log(`- UID: ${user.uid}, Email: ${user.email}, Decrypted: ${user.decryptedEmail}`);
            console.log(`  Has WebAuthn: ${user.hasWebAuthn}, Has Passphrase: ${user.hasPassphrase}`);
            console.log(`  Roles: ${user.roles ? user.roles.map(r => r.name).join(', ') : 'None'}`);
          }
        } else {
          console.log('\nNo users found with matching email after manual decryption.');
        }
      } else {
        console.log('No users found in the database.');
      }
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Run the main function
testEmailLookup().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
