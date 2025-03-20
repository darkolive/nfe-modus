// Script to generate and set DIDs for existing users
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import dgraph from '@hypermode/modus/sdk/js/dgraph';
import console from '@hypermode/modus/sdk/js/console';

// Read environment variables
const dotenvPath = process.env.DOTENV_PATH || '.env.dev.local';
const envConfig = readFileSync(dotenvPath, 'utf8')
  .split('\n')
  .filter(line => line && !line.startsWith('#'))
  .reduce((acc, line) => {
    const [key, value] = line.split('=');
    if (key && value) {
      acc[key.trim()] = value.trim().replace(/^["']|["']$/g, '');
    }
    return acc;
  }, {});

// Configure Dgraph
const dgraphEndpoint = process.env.DGRAPH_ENDPOINT || envConfig.DGRAPH_ENDPOINT || 'http://localhost:8080';
const connection = dgraph.connect(dgraphEndpoint);

async function generateMissingDIDs() {
  console.info('Starting DID generation for users without DIDs...');
  
  // Query all users without a DID
  const query = `
    query {
      users(func: type(User)) @filter(NOT has(did)) {
        uid
        email
        hasPassphrase
      }
    }
  `;
  
  try {
    const response = await connection.query(query);
    const usersWithoutDID = response.data.users || [];
    
    console.info(`Found ${usersWithoutDID.length} users without a DID`);
    
    for (const user of usersWithoutDID) {
      if (!user.hasPassphrase) {
        console.warn(`User ${user.uid} has no passphrase, skipping DID generation`);
        continue;
      }
      
      // Generate a deterministic DID based on the user's email
      // Since we don't have access to the passphrase, we'll use just the email for now
      // This is less secure but will work for existing users
      const email = user.email;
      let rawEmail = email;
      
      // Check if this is an encrypted email
      if (email.startsWith('enc:')) {
        console.warn(`User ${user.uid} has an encrypted email, using encrypted form to generate DID`);
      }
      
      // Generate a deterministic DID
      const didMaterial = rawEmail;
      const didHash = createHash('sha512').update(didMaterial).digest('hex');
      const did = `did:nfe:${didHash.substring(0, 32)}`; // Use first 16 bytes (32 hex chars)
      
      console.info(`Generated DID for user ${user.uid}: ${did}`);
      
      // Update the user with the new DID
      const mutation = {
        set: [
          {
            uid: user.uid,
            did: did
          }
        ]
      };
      
      await connection.mutate(mutation);
      console.info(`Updated user ${user.uid} with new DID`);
    }
    
    console.info('DID generation complete');
  } catch (error) {
    console.error(`Error generating DIDs: ${error.message}`);
  }
}

// Run the function
generateMissingDIDs().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
