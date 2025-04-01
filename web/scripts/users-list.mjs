#!/usr/bin/env node
/**
 * List all users in the Dgraph database with proper formatting
 * Consolidates functionality from query-all-users.mjs and list-all-users.mjs
 */
import { createDgraphClient, getAllUsers, closeConnection, checkUserTypes } from './db-utils.mjs';

/**
 * Format a user object for display
 * @param {Object} user - User object from Dgraph
 * @returns {string} Formatted user info
 */
function formatUser(user) {
  const hasDevices = user.devices && user.devices.length > 0;
  
  return `
User ID: ${user.uid}
DID: ${user.did || 'Not set'}
Email: ${user.email || 'Not available'}
Name: ${user.name || 'Not set'}
Verified: ${user.verified ? 'Yes' : 'No'}
Email Verified: ${user.emailVerified ? 'Yes' : 'No'}
Date Joined: ${user.dateJoined || 'Unknown'}
Status: ${user.status || 'Unknown'}
WebAuthn Enabled: ${user.hasWebAuthn ? 'Yes' : 'No'}
Passphrase Set: ${user.hasPassphrase ? 'Yes' : 'No'}
Devices: ${hasDevices ? user.devices.length : 0}
${hasDevices ? formatDevices(user.devices) : ''}
${'='.repeat(50)}`;
}

/**
 * Format user devices for display
 * @param {Array} devices - Array of device objects
 * @returns {string} Formatted devices info
 */
function formatDevices(devices) {
  if (!devices || devices.length === 0) {
    return '  No devices';
  }
  
  return devices.map((device, index) => `
  Device ${index + 1}:
    ID: ${device.uid}
    Name: ${device.deviceName || 'Unnamed'}
    Type: ${device.deviceType || 'Unknown'}
    Biometric: ${device.isBiometric ? 'Yes' : 'No'}
    Last Used: ${device.lastUsed || 'Never'}
    Created: ${device.createdAt || 'Unknown'}`
  ).join('\n');
}

async function main() {
  console.log('Fetching all users from the database...');
  
  const client = createDgraphClient();
  
  try {
    // Check user types to identify potential issues
    const { untypedUsers } = await checkUserTypes(client);
    
    // Get comprehensive user data
    const users = await getAllUsers(client);
    
    if (users.length === 0) {
      console.log('No users found in the database.');
      return;
    }
    
    console.log(`Found ${users.length} users:`);
    
    // Display type warnings if there are untyped users
    if (untypedUsers.length > 0) {
      console.log(`\n⚠️  WARNING: Found ${untypedUsers.length} users without the User type.`);
      console.log('Run users-fix.mjs to fix this issue.\n');
    }
    
    // Print detailed information for each user
    users.forEach(user => {
      console.log(formatUser(user));
    });
    
    // Output full JSON at the end for reference
    console.log('\n--- Full JSON Output ---');
    console.log(JSON.stringify({ users }, null, 2));
    
  } catch (error) {
    console.error('Error listing users:', error);
  } finally {
    await closeConnection(client);
  }
}

// Run the main function
main().catch(error => {
  console.error("Error in main function:", error);
  process.exit(1);
});
