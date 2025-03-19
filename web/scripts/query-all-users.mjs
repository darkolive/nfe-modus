import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import fs from 'fs';
import path from 'path';

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
      const users = res.getJson().users || [];
      
      console.log(`Found ${users.length} users:`);
      users.forEach((user, index) => {
        console.log(`\n--- User ${index + 1} ---`);
        console.log(`UID: ${user.uid}`);
        console.log(`DID: ${user.did}`);
        console.log(`Email: ${user.email}`);
        console.log(`Name: ${user.name || 'N/A'}`);
        console.log(`Verified: ${user.verified}`);
        console.log(`Status: ${user.status}`);
        console.log(`Has WebAuthn: ${user.hasWebAuthn}`);
        console.log(`Has Passphrase: ${user.hasPassphrase}`);
        
        // Display roles
        if (user.roles && user.roles.length > 0) {
          console.log(`Roles: ${user.roles.map(r => r.name).join(', ')}`);
        } else {
          console.log('Roles: None');
        }
        
        // Display devices
        if (user.devices && user.devices.length > 0) {
          console.log(`Devices: ${user.devices.length}`);
          user.devices.forEach((device, i) => {
            console.log(`  Device ${i + 1}: ${device.deviceName} (${device.deviceType})`);
          });
        } else {
          console.log('Devices: None');
        }
      });
      
      // Also output the full JSON for detailed inspection
      console.log('\n--- Full JSON Output ---');
      console.log(JSON.stringify(res.getJson(), null, 2));
      
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error('Error querying users:', error);
  }
};

// Run the query
queryAllUsers();
