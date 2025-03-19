/**
 * Test script for verifying email encryption and user lookup
 * 
 * This script tests the following:
 * 1. Email encryption and decryption
 * 2. User lookup by email (both encrypted and unencrypted)
 * 3. Verifies that the getUserByEmail method works correctly
 */

import { DgraphClient } from '../src/lib/dgraph';
import { encryptData, decryptData, isEncrypted } from '../src/lib/encryption';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Check if EMAIL_ENCRYPTION_KEY is set
if (!process.env.EMAIL_ENCRYPTION_KEY) {
  console.error('EMAIL_ENCRYPTION_KEY environment variable is not set.');
  process.exit(1);
}

// Create Dgraph client
const dgraphClient = new DgraphClient();

// Email to test with (can be provided as command line argument)
const testEmail = process.argv[2] || 'test@example.com';

async function runTests() {
  console.log('===== EMAIL ENCRYPTION TEST =====');
  console.log('Original email:', testEmail);
  
  // Test encryption
  const encryptedEmail = encryptData(testEmail);
  console.log('Encrypted email:', encryptedEmail);
  
  // Test decryption
  const decryptedEmail = decryptData(encryptedEmail);
  console.log('Decrypted email:', decryptedEmail);
  
  // Verify
  console.log('Encryption/decryption working correctly:', decryptedEmail === testEmail);
  console.log('Is encrypted format:', isEncrypted(encryptedEmail));
  
  console.log('\n===== USER LOOKUP TEST =====');
  
  // Test user lookup with unencrypted email
  console.log('Looking up user with unencrypted email...');
  const userByUnencrypted = await dgraphClient.getUserByEmail(testEmail);
  console.log('User found with unencrypted email:', !!userByUnencrypted);
  
  if (userByUnencrypted) {
    console.log('User details:');
    console.log('- UID:', userByUnencrypted.uid);
    console.log('- DID:', userByUnencrypted.did);
    console.log('- Email:', userByUnencrypted.email);
    console.log('- Name:', userByUnencrypted.name);
    console.log('- WebAuthn:', userByUnencrypted.hasWebAuthn);
    console.log('- Passphrase:', userByUnencrypted.hasPassphrase);
    console.log('- Roles:', userByUnencrypted.roles?.map(r => r.name || r.uid).join(', ') || 'none');
  }
  
  // Test direct query with encrypted email
  console.log('\nDirect query with encrypted email...');
  try {
    const query = `
      query getUser($email: string) {
        user(func: eq(email, $email)) @filter(eq(dgraph.type, "User")) {
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
      }
    `;
    
    const result = await dgraphClient.executeDQLQuery(query, { $email: encryptedEmail });
    console.log('Query result:', JSON.stringify(result, null, 2));
    
    if (result.user && result.user.length > 0) {
      console.log('User found directly with encrypted email!');
    } else {
      console.log('No user found directly with encrypted email.');
    }
  } catch (error) {
    console.error('Error in direct query:', error);
  }
  
  console.log('\n===== CHECK USER API SIMULATION =====');
  console.log('Simulating the check-user API endpoint...');
  
  // This simulates what happens in the check-user API
  const user = await dgraphClient.getUserByEmail(testEmail);
  
  console.log('User exists:', !!user);
  console.log('Has WebAuthn:', user?.hasWebAuthn || false);
  console.log('Has Passphrase:', user?.hasPassphrase || false);
  
  console.log('\n===== TEST COMPLETE =====');
}

runTests().catch(error => {
  console.error('Test failed:', error);
  process.exit(1);
});
