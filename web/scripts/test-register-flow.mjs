// Test script to demonstrate the complete registration flow using Dgraph
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import fs from 'fs';
import path from 'path';
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
  
  return {
    client: new dgraph.DgraphClient(clientStub),
    stub: clientStub
  };
};

// Encryption helper functions

// Generate a random IV
function generateIV() {
  return crypto.randomBytes(16);
}

// Get encryption key from env or use fallback
function getEncryptionKey() {
  const key = process.env.EMAIL_ENCRYPTION_KEY || 'fallback-encryption-key-for-development-only';
  return crypto.createHash('sha256').update(key).digest();
}

// Encrypt email or other sensitive data
function encryptData(data) {
  if (!data) return data;
  
  const key = getEncryptionKey();
  const iv = generateIV();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  
  // Store IV and auth tag along with encrypted data
  const result = Buffer.concat([
    iv,
    authTag,
    Buffer.from(encrypted, 'base64')
  ]).toString('base64');
  
  return 'enc:' + result;
}

// Simulate OTP generation
async function generateOTP(email) {
  console.log('Step 1: Generating OTP for', email);
  
  // In a test environment, we'll use a fixed OTP for simplicity
  const otp = "123456";
  
  // Create a verification cookie that contains the email
  // This simulates what the OTP service would do
  const verificationData = {
    email: email,
    timestamp: new Date().toISOString()
  };
  
  // Encrypt verification data as base64
  const cookie = Buffer.from(JSON.stringify(verificationData)).toString('base64');
  
  console.log('OTP generated:', otp);
  console.log('Verification cookie created');
  
  return {
    otp,
    cookie
  };
}

// Simulate OTP verification
async function verifyOTP(otp, cookie) {
  console.log('Step 2: Verifying OTP');
  
  // Validate OTP (in real system this would check against stored OTP)
  if (otp !== "123456") {
    console.error('Invalid OTP');
    throw new Error('Invalid OTP');
  }
  
  // Decode the cookie to get the verification data
  let verificationData;
  try {
    verificationData = JSON.parse(Buffer.from(cookie, 'base64').toString('utf8'));
  } catch (error) {
    console.error('Invalid verification cookie:', error);
    throw new Error('Invalid verification cookie');
  }
  
  // Check if the verification data contains email
  if (!verificationData.email) {
    console.error('Missing email in verification data');
    throw new Error('Missing email in verification data');
  }
  
  console.log('OTP verified for email:', verificationData.email);
  
  // Store the verification in memory with a timestamp
  // This aligns with the memory about ensuring a seamless flow between verification steps
  const updatedVerificationData = {
    ...verificationData,
    verified: true,
    verificationTimestamp: new Date().toISOString(),
    verificationMethod: 'OTP'
  };
  
  // Create a new cookie with the updated verification data
  const verificationCookie = Buffer.from(JSON.stringify(updatedVerificationData)).toString('base64');
  
  return verificationCookie;
}

// Register user in Dgraph
async function registerUser(verificationCookie) {
  console.log('Step 3: Registering user');
  
  // Decode the verification cookie
  let verificationData;
  try {
    verificationData = JSON.parse(Buffer.from(verificationCookie, 'base64').toString('utf8'));
  } catch (error) {
    console.error('Invalid verification cookie:', error);
    throw new Error('Invalid verification cookie');
  }
  
  // Check if the verification is recent (within 5 minutes)
  const verificationTime = new Date(verificationData.verificationTimestamp).getTime();
  const currentTime = new Date().getTime();
  const fiveMinutesInMs = 5 * 60 * 1000;
  
  if (currentTime - verificationTime > fiveMinutesInMs) {
    console.error('Verification expired');
    throw new Error('Verification expired');
  }
  
  // Create user in Dgraph
  const { client, stub } = createDgraphClient();
  const txn = client.newTxn();
  
  try {
    // Encrypt email for storage
    const encryptedEmail = encryptData(verificationData.email);
    
    // Generate DID
    const did = 'did:nfe:' + crypto.randomBytes(16).toString('hex');
    
    // Create user mutation
    const mu = new dgraph.Mutation();
    const now = new Date().toISOString();
    
    // User details
    const userDetails = {
      "uid": "_:user",
      "name": "Test User",
      "email": encryptedEmail,
      "did": did,
      "verified": true,
      "dateJoined": now,
      "status": "active",
      "updatedAt": now,
      "dgraph.type": "User"
    };
    
    mu.setSetJson(userDetails);
    const response = await txn.mutate(mu);
    await txn.commit();
    
    // Get the UID from the response
    const uid = response.getUidsMap().get('user');
    console.log('User created with UID:', uid);
    
    return {
      uid,
      email: verificationData.email,
      did,
      clientStub: stub
    };
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  } finally {
    await txn.discard();
  }
}

// Register passphrase for user
async function registerPassphrase(user, passphrase) {
  console.log('Step 4: Setting passphrase for user:', user.uid);
  
  // In a real system, this would:
  // 1. Hash the passphrase
  // 2. Store it with the user
  // 3. Update the user's status
  
  const { client } = createDgraphClient();
  const txn = client.newTxn();
  
  try {
    // Generate passphrase hash
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(passphrase, salt, 10000, 64, 'sha512').toString('hex');
    
    // Create passphrase mutation
    const mu = new dgraph.Mutation();
    const now = new Date().toISOString();
    
    const passphraseNode = {
      uid: user.uid,
      hasPassphrase: true,
      passphraseHash: hash,
      passphraseSalt: salt,
      lastAuthTime: now,
      updatedAt: now
    };
    
    mu.setSetJson(passphraseNode);
    await txn.mutate(mu);
    await txn.commit();
    
    console.log('Passphrase set for user:', user.uid);
    
    return {
      success: true,
      message: 'Passphrase registered successfully'
    };
  } catch (error) {
    console.error('Error setting passphrase:', error);
    throw error;
  } finally {
    await txn.discard();
  }
}

// Run the complete flow
async function runRegistrationFlow() {
  let clientStub = null;
  
  try {
    // Replace with your test email
    const email = 'test@example.com';
    
    // Step 1: Generate OTP
    const { otp, cookie } = await generateOTP(email);
    console.log('OTP Cookie received:', cookie);
    
    // Step 2: Verify OTP
    const verificationCookie = await verifyOTP(otp, cookie);
    console.log('Verification Cookie:', verificationCookie);
    
    // Step 3: Register User
    const user = await registerUser(verificationCookie);
    console.log('User registered:', user);
    clientStub = user.clientStub;
    
    // Step 4: Register Passphrase
    const result = await registerPassphrase(user, 'SecurePassword123!');
    console.log('Registration complete!', result);
    
  } catch (error) {
    console.error('Error in registration flow:', error);
  } finally {
    // Close Dgraph client stub if available
    if (clientStub) {
      try {
        clientStub.close();
        console.log('Closed Dgraph connection');
      } catch (err) {
        console.error('Error closing Dgraph connection:', err);
      }
    }
  }
}

// Run the test
runRegistrationFlow();
