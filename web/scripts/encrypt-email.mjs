import { encryptData, isEncrypted } from '../src/lib/encryption.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Get email from command line arguments
const email = process.argv[2];
if (!email) {
  console.error('Please provide an email address as an argument.');
  process.exit(1);
}

// Check if encryption key is available
if (!process.env.EMAIL_ENCRYPTION_KEY) {
  console.error('EMAIL_ENCRYPTION_KEY environment variable is not set.');
  process.exit(1);
}

// Check if already encrypted
if (isEncrypted(email)) {
  console.log('Email is already encrypted:', email);
  process.exit(0);
}

try {
  // Encrypt the email
  const encryptedEmail = encryptData(email);
  console.log('Original email:', email);
  console.log('Encrypted email:', encryptedEmail);
  
  console.log('\nUse this query in Ratel:');
  console.log(`{
  user(func: eq(email, "${encryptedEmail}")) @filter(eq(dgraph.type, "User")) {
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
}`);
} catch (error) {
  console.error('Error encrypting email:', error);
  process.exit(1);
}
