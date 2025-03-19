import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

// Load environment variables from .env file manually
const loadEnv = () => {
  try {
    const envPath = path.resolve(process.cwd(), '.env');
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
const createDgraphClient = () => {
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
  );
  
  return new dgraph.DgraphClient(clientStub);
};

// Email encryption functions
const isEncrypted = (value) => {
  // Check if a string appears to be encrypted (contains two colons)
  return typeof value === 'string' && value.split(':').length === 3;
};

const encryptData = (value) => {
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
};

const decryptData = (value) => {
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
    return value; // Return original value on error
  }
};

// Test email encryption and user lookup
const testEmailEncryption = async (email) => {
  console.log('===== EMAIL ENCRYPTION TEST =====');
  console.log('Testing email:', email);
  
  // Encrypt the email
  const encryptedEmail = encryptData(email);
  console.log('Encrypted email:', encryptedEmail);
  
  // Decrypt the email
  const decryptedEmail = decryptData(encryptedEmail);
  console.log('Decrypted email:', decryptedEmail);
  
  // Verify encryption/decryption
  console.log('Encryption/decryption working correctly:', decryptedEmail === email);
  
  // Test user lookup with both encrypted and unencrypted email
  const client = createDgraphClient();
  
  // Try looking up with unencrypted email first
  console.log('\nLooking up user with unencrypted email...');
  const unencryptedQuery = `{
    user(func: eq(email, "${email}")) @filter(eq(dgraph.type, "User")) {
      uid
      did
      email
      name
      hasWebAuthn
      hasPassphrase
      roles {
        uid
        name
      }
    }
  }`;
  
  try {
    const unencryptedResult = await client.newTxn().query(unencryptedQuery);
    // Get the response data as a string and then parse it
    const responseJson = unencryptedResult.getJson();
    const unencryptedData = responseJson ? JSON.parse(responseJson) : { user: [] };
    
    if (unencryptedData.user && unencryptedData.user.length > 0) {
      console.log('User found with unencrypted email!');
      console.log('User details:', JSON.stringify(unencryptedData.user[0], null, 2));
    } else {
      console.log('No user found with unencrypted email.');
    }
  } catch (error) {
    console.error('Error querying with unencrypted email:', error);
  }
  
  // Try looking up with encrypted email
  console.log('\nLooking up user with encrypted email...');
  const encryptedQuery = `{
    user(func: eq(email, "${encryptedEmail}")) @filter(eq(dgraph.type, "User")) {
      uid
      did
      email
      name
      hasWebAuthn
      hasPassphrase
      roles {
        uid
        name
      }
    }
  }`;
  
  try {
    const encryptedResult = await client.newTxn().query(encryptedQuery);
    // Get the response data as a string and then parse it
    const responseJson = encryptedResult.getJson();
    const encryptedData = responseJson ? JSON.parse(responseJson) : { user: [] };
    
    if (encryptedData.user && encryptedData.user.length > 0) {
      console.log('User found with encrypted email!');
      console.log('User details:', JSON.stringify(encryptedData.user[0], null, 2));
    } else {
      console.log('No user found with encrypted email.');
    }
  } catch (error) {
    console.error('Error querying with encrypted email:', error);
  }
  
  // Check all users to find any with matching email (encrypted or not)
  console.log('\nChecking all users for matching email...');
  const allUsersQuery = `{
    users(func: type(User)) {
      uid
      did
      email
      name
      hasWebAuthn
      hasPassphrase
    }
  }`;
  
  try {
    const allUsersResult = await client.newTxn().query(allUsersQuery);
    // Get the response data as a string and then parse it
    const responseJson = allUsersResult.getJson();
    const allUsersData = responseJson ? JSON.parse(responseJson) : { users: [] };
    
    if (allUsersData.users) {
      const matchingUsers = allUsersData.users.filter(user => {
        if (!user.email) return false;
        
        // Try to decrypt the email if it's encrypted
        try {
          const userEmail = isEncrypted(user.email) ? decryptData(user.email) : user.email;
          return userEmail === email;
        } catch (error) {
          console.error(`Error decrypting email for user ${user.uid}:`, error.message);
          return false;
        }
      });
      
      if (matchingUsers.length > 0) {
        console.log(`Found ${matchingUsers.length} users with matching email (after decryption):`);
        matchingUsers.forEach(user => {
          let decryptedEmail = '(not encrypted)';
          if (isEncrypted(user.email)) {
            try {
              decryptedEmail = decryptData(user.email);
            } catch (error) {
              decryptedEmail = '(decryption failed)';
            }
          }
          console.log(`- UID: ${user.uid}, Email: ${user.email}, Decrypted: ${decryptedEmail}`);
        });
      } else {
        console.log('No users found with matching email after decryption check.');
      }
    }
  } catch (error) {
    console.error('Error querying all users:', error);
  }
};

// Query all users
const queryAllUsers = async () => {
  const client = createDgraphClient();
  
  try {
    const query = `{
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
        failedLoginAttempts
        lastFailedLogin
        lockedUntil
        createdAt
        updatedAt
        
        # Get user roles with permissions
        roles {
          uid
          name
          permissions
          createdAt
          updatedAt
        }
        
        # Get user devices
        devices {
          uid
          credentialID
          deviceName
          deviceType
          isBiometric
          counter
          lastUsed
          createdAt
          updatedAt
        }
      }
    }`;
    
    const txn = client.newTxn({ readOnly: true });
    try {
      const res = await txn.query(query);
      return res.getJson().users || [];
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error('Error querying users:', error);
    return [];
  }
};

// Get role by name
const getRoleByName = async (roleName) => {
  const client = createDgraphClient();
  
  try {
    const query = `{
      role(func: eq(name, "${roleName}")) @filter(type(Role)) {
        uid
        name
        permissions
        createdAt
        updatedAt
      }
    }`;
    
    const txn = client.newTxn({ readOnly: true });
    try {
      const res = await txn.query(query);
      const roles = res.getJson().role || [];
      return roles.length > 0 ? roles[0] : null;
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error(`Error getting role by name "${roleName}":`, error);
    return null;
  }
};

// Assign role to user
const assignRoleToUser = async (userId, roleId) => {
  const client = createDgraphClient();
  
  try {
    const txn = client.newTxn();
    try {
      const mutation = new dgraph.Mutation();
      const data = {
        uid: userId,
        dgraph_type: ["User"],
        roles: [
          {
            uid: roleId,
            dgraph_type: ["Role"]
          }
        ]
      };
      
      mutation.setSetJson(data);
      await txn.mutate(mutation);
      await txn.commit();
      
      console.log(`Successfully assigned role ${roleId} to user ${userId}`);
      return true;
    } catch (error) {
      console.error(`Error assigning role ${roleId} to user ${userId}:`, error);
      return false;
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error(`Error creating transaction:`, error);
    return false;
  }
};

// Fix incomplete user
const fixIncompleteUser = async (user, registeredRole) => {
  if (!registeredRole) {
    console.error('Cannot fix user without registered role');
    return false;
  }
  
  const client = createDgraphClient();
  const now = new Date();
  const userDid = user.did || `did:nfe:${uuidv4().replace(/-/g, '')}`;
  
  try {
    const txn = client.newTxn();
    try {
      const mutation = new dgraph.Mutation();
      const data = {
        uid: user.uid,
        did: userDid,
        verified: true,
        status: "active",
        dateJoined: user.dateJoined || now.toISOString(),
        createdAt: user.createdAt || now.toISOString(),
        updatedAt: now.toISOString(),
        dgraph_type: ["User"]
      };
      
      mutation.setSetJson(data);
      await txn.mutate(mutation);
      await txn.commit();
      
      console.log(`Fixed incomplete user ${user.uid}`);
      
      // Now assign the role
      await assignRoleToUser(user.uid, registeredRole.uid);
      
      return true;
    } catch (error) {
      console.error(`Error fixing incomplete user ${user.uid}:`, error);
      return false;
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error(`Error creating transaction:`, error);
    return false;
  }
};

// Main function
const main = async () => {
  // Check command line arguments
  const args = process.argv.slice(2);
  
  // If email test command is provided
  if (args[0] === 'test-email') {
    const email = args[1];
    if (!email) {
      console.error('Please provide an email address to test.');
      console.log('Usage: node diagnose-users.mjs test-email <email>');
      return;
    }
    
    await testEmailEncryption(email);
    return;
  }
  
  // Otherwise run the normal user diagnosis
  console.log('Starting user diagnosis...');
  
  // Query all users
  const users = await queryAllUsers();
  
  // Check for incomplete users
  const incompleteUsers = users.filter(user => !user.did || !user.email);
  
  if (incompleteUsers.length > 0) {
    console.log(`Found ${incompleteUsers.length} incomplete users:`);
    incompleteUsers.forEach(user => {
      console.log(`- UID: ${user.uid}, DID: ${user.did || 'MISSING'}, Email: ${user.email || 'MISSING'}`);
    });
    
    // Ask to fix incomplete users
    if (args.includes('--fix')) {
      console.log('\nFixing incomplete users...');
      
      // Get the registered role
      const registeredRole = await getRoleByName('registered');
      if (!registeredRole) {
        console.error('Could not find the "registered" role. Please ensure it exists.');
        return;
      }
      
      // Fix each incomplete user
      for (const user of incompleteUsers) {
        await fixIncompleteUser(user, registeredRole);
      }
      
      console.log('All incomplete users have been fixed.');
    } else {
      console.log('\nTo fix these users, run the script with the --fix flag:');
      console.log('node diagnose-users.mjs --fix');
    }
  } else {
    console.log('No incomplete users found. All users have required fields.');
  }
  
  // Check for users without roles
  const usersWithoutRoles = users.filter(user => !user.roles || user.roles.length === 0);
  
  if (usersWithoutRoles.length > 0) {
    console.log(`\nFound ${usersWithoutRoles.length} users without roles:`);
    usersWithoutRoles.forEach(user => {
      console.log(`- UID: ${user.uid}, DID: ${user.did || 'N/A'}, Email: ${user.email || 'N/A'}`);
    });
    
    // Ask to fix users without roles
    if (args.includes('--fix-roles')) {
      console.log('\nAssigning "registered" role to users without roles...');
      
      // Get the registered role
      const registeredRole = await getRoleByName('registered');
      if (!registeredRole) {
        console.error('Could not find the "registered" role. Please ensure it exists.');
        return;
      }
      
      // Assign role to each user without roles
      for (const user of usersWithoutRoles) {
        await assignRoleToUser(user.uid, registeredRole.uid);
        console.log(`Assigned "registered" role to user ${user.uid}`);
      }
      
      console.log('All users now have the "registered" role.');
    } else {
      console.log('\nTo assign the "registered" role to these users, run the script with the --fix-roles flag:');
      console.log('node diagnose-users.mjs --fix-roles');
    }
  } else {
    console.log('All users have at least one role assigned.');
  }
  
  console.log('\nUser diagnosis complete.');
  
  // Display usage information
  console.log('\nUsage:');
  console.log('  node diagnose-users.mjs                  - Run diagnosis only');
  console.log('  node diagnose-users.mjs --fix            - Fix incomplete users');
  console.log('  node diagnose-users.mjs --fix-roles      - Fix users without roles');
  console.log('  node diagnose-users.mjs test-email <email> - Test email encryption and user lookup');
};

// Run the main function
main().catch(error => {
  console.error('Error in main function:', error);
});
