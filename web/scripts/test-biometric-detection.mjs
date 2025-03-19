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

loadEnv();

// Check for required environment variables
if (!process.env.EMAIL_ENCRYPTION_KEY) {
  console.error('ERROR: EMAIL_ENCRYPTION_KEY environment variable is required');
  process.exit(1);
}

// Create a client
const createClient = () => {
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === 'true' ? credentials.createSsl() : credentials.createInsecure()
  );
  return new dgraph.DgraphClient(clientStub);
};

const dgraphClient = createClient();

// Function to update device biometric status
const updateDeviceBiometricStatus = async (deviceUid, isBiometric) => {
  const txn = dgraphClient.newTxn();
  try {
    const mu = new dgraph.Mutation();
    const now = new Date().toISOString();
    
    // Set the biometric status
    mu.setSetJson({
      uid: deviceUid,
      isBiometric: isBiometric,
      updatedAt: now
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    console.log(`Updated device ${deviceUid} biometric status to ${isBiometric}`);
    return true;
  } catch (error) {
    console.error('Error updating device biometric status:', error);
    return false;
  } finally {
    await txn.discard();
  }
};

// Function to get all users with their devices
const getAllUsers = async () => {
  const txn = dgraphClient.newTxn({ readOnly: true });
  try {
    const query = `
      {
        users(func: type(User)) {
          uid
          did
          email
          name
          verified
          emailVerified
          dateJoined
          status
          hasWebAuthn
          hasPassphrase
          failedLoginAttempts
          createdAt
          updatedAt
          roles {
            uid
            name
            permissions
            createdAt
          }
          devices {
            uid
            credentialID
            deviceName
            deviceType
            isBiometric
            counter
            lastUsed
            createdAt
          }
        }
      }
    `;

    const res = await txn.query(query);
    return res.getJson();
  } catch (error) {
    console.error('Error fetching users:', error);
    return { users: [] };
  } finally {
    await txn.discard();
  }
};

// Main function
const main = async () => {
  try {
    console.log('Fetching all users with their devices...');
    const data = await getAllUsers();
    
    if (!data.users || data.users.length === 0) {
      console.log('No users found in the database.');
      return;
    }
    
    console.log(`Found ${data.users.length} users in the database.`);
    
    // Process each user
    for (let i = 0; i < data.users.length; i++) {
      const user = data.users[i];
      console.log(`\nUser ${i + 1}:`);
      console.log(`- UID: ${user.uid}`);
      console.log(`- DID: ${user.did}`);
      console.log(`- Email: ${user.email}`);
      console.log(`- Name: ${user.name || 'N/A'}`);
      
      if (user.devices && user.devices.length > 0) {
        console.log(`- Devices: ${user.devices.length}`);
        
        for (let j = 0; j < user.devices.length; j++) {
          const device = user.devices[j];
          console.log(`  Device ${j + 1}: ${device.deviceName} (${device.deviceType})`);
          console.log(`    - UID: ${device.uid}`);
          console.log(`    - isBiometric: ${device.isBiometric}`);
          
          // For Mac devices, we'll update the biometric status to true
          if (device.deviceType === 'mac' && !device.isBiometric) {
            console.log('    - This is a Mac device, likely using Touch ID. Updating biometric status...');
            const success = await updateDeviceBiometricStatus(device.uid, true);
            if (success) {
              console.log('    - Successfully updated biometric status to true');
            }
          }
        }
      } else {
        console.log('- No devices found for this user.');
      }
    }
    
    console.log('\nDone!');
  } catch (error) {
    console.error('Error in main function:', error);
  }
};

main();
