#!/usr/bin/env node
/**
 * Clear users from the Dgraph database
 * Improved version of clear-users.mjs with better error handling
 */
import { createDgraphClient, executeQuery, closeConnection } from './db-utils.mjs';
import readline from 'readline';
import dgraphPkg from 'dgraph-js';

const { Mutation } = dgraphPkg;

/**
 * Create a readline interface for user input
 */
function createInterface() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
}

/**
 * Ask for confirmation before proceeding with deletion
 * @param {string} message - Confirmation message
 * @returns {Promise<boolean>} User confirmation
 */
function confirmAction(message) {
  const rl = createInterface();
  
  return new Promise(resolve => {
    rl.question(`${message} (y/N): `, answer => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}

/**
 * Delete users from the database
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @param {Array<string>} uids - User UIDs to delete
 * @returns {Promise<number>} Number of deleted users
 */
async function deleteUsers(client, uids) {
  if (!uids || uids.length === 0) {
    return 0;
  }
  
  // We'll use individual delete mutations for each user
  for (const uid of uids) {
    const txn = client.newTxn();
    try {
      // Create a deletion mutation using JSON format
      const mu = new Mutation();
      
      // Format needed for deletion: array with object containing uid
      const deleteData = [{
        uid: uid
      }];
      
      mu.setDeleteJson(deleteData);
      mu.setCommitNow(true);
      
      await txn.mutate(mu);
      console.log(`Successfully deleted user: ${uid}`);
    } catch (error) {
      console.error(`Error deleting user ${uid}:`, error);
    } finally {
      await txn.discard();
    }
  }
  
  return uids.length;
}

async function main() {
  console.log('Preparing to clear users from the database...');
  
  const client = createDgraphClient();
  
  try {
    // Find all users in the database
    const query = `{
      users(func: has(email)) {
        uid
        email
        dgraph.type
      }
    }`;
    
    const result = await executeQuery(client, query);
    const users = result.users || [];
    
    if (users.length === 0) {
      console.log('No users found in the database.');
      return;
    }
    
    console.log(`Found ${users.length} users to delete:`);
    users.forEach((user, index) => {
      console.log(`${index + 1}. User ID: ${user.uid}, Email: ${user.email || 'Not available'}`);
    });
    
    // Get confirmation before proceeding
    const confirmed = await confirmAction(
      `\n⚠️  WARNING: You are about to delete ${users.length} users. This action cannot be undone.\nDo you want to continue?`
    );
    
    if (!confirmed) {
      console.log('Operation cancelled.');
      return;
    }
    
    // Extract user UIDs for deletion
    const userUids = users.map(user => user.uid);
    
    // Delete the users
    console.log('\nDeleting users...');
    const deletedCount = await deleteUsers(client, userUids);
    
    console.log(`Successfully deleted ${deletedCount} users from the database.`);
    
    // Verify deletion
    const verifyQuery = `{
      remainingUsers(func: has(email)) {
        count(uid)
      }
    }`;
    
    const verifyResult = await executeQuery(client, verifyQuery);
    const remainingCount = verifyResult.remainingUsers?.[0]?.['count(uid)'] || 0;
    
    console.log(`\nVerification: ${remainingCount} users remaining in the database.`);
    
  } catch (error) {
    console.error('Error clearing users:', error);
  } finally {
    await closeConnection(client);
  }
}

// Check if script is being run directly
if (process.argv[1].endsWith('users-clear.mjs')) {
  // Run the main function
  main().catch(error => {
    console.error("Error in main function:", error);
    process.exit(1);
  });
}
