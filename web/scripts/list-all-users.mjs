import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Create a Dgraph client
function createDgraphClient() {
  // Create client stub with proper gRPC credentials
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
  );

  // Create client
  return new dgraph.DgraphClient(clientStub);
}

const client = createDgraphClient();

/**
 * Execute a DQL query
 * @param {string} query - The DQL query
 * @param {Object} vars - Variables for the query
 * @returns {Promise<Object>} - Query result
 */
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    const res = await txn.queryWithVars(query, vars);
    const jsonData = res.getJson();
    
    if (typeof jsonData === 'string') {
      return JSON.parse(jsonData);
    } else if (typeof jsonData === 'object') {
      return jsonData;
    } else {
      throw new Error(`Unexpected response type: ${typeof jsonData}`);
    }
  } catch (error) {
    console.error("Error executing query:", error);
    throw error;
  } finally {
    await txn.discard();
  }
}

/**
 * Get all users from the database with their emails
 */
async function getAllUsers() {
  const query = `
    {
      users(func: type(User)) {
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
  
  try {
    const result = await executeDQLQuery(query);
    
    // Extract users from the result
    let users = [];
    if (result && result.users && Array.isArray(result.users)) {
      users = result.users;
    } else if (typeof result === 'object') {
      // Try to parse the response if it's not in the expected format
      const jsonStr = JSON.stringify(result);
      try {
        const parsedData = JSON.parse(jsonStr);
        if (parsedData.users && Array.isArray(parsedData.users)) {
          users = parsedData.users;
        }
      } catch (error) {
        console.error("Error parsing JSON:", error);
      }
    }
    
    // If we still don't have users, try to extract from the raw response
    if (users.length === 0 && result && result.u && Array.isArray(result.u) && result.u[0]) {
      try {
        // The first element of u might be a Uint8Array containing the JSON response
        if (result.u[0] instanceof Uint8Array) {
          const jsonStr = Buffer.from(result.u[0]).toString('utf8');
          const parsedData = JSON.parse(jsonStr);
          if (parsedData.users && Array.isArray(parsedData.users)) {
            users = parsedData.users;
          }
        }
      } catch (error) {
        console.error("Error parsing Uint8Array:", error);
      }
    }
    
    return users;
  } catch (error) {
    console.error("Error querying all users:", error);
    return [];
  }
}

// Main function
async function main() {
  try {
    console.log("Fetching all users from the database...");
    const users = await getAllUsers();
    
    if (users.length === 0) {
      console.log("No users found in the database.");
      return;
    }
    
    console.log(`Found ${users.length} users in the database.`);
    
    // Display all users with their emails
    users.forEach((user, index) => {
      console.log(`\nUser ${index + 1}:`);
      console.log(`- UID: ${user.uid}`);
      console.log(`- DID: ${user.did || 'N/A'}`);
      console.log(`- Email: ${user.email || 'N/A'}`);
      console.log(`- Name: ${user.name || 'N/A'}`);
      console.log(`- Has WebAuthn: ${user.hasWebAuthn}`);
      console.log(`- Has Passphrase: ${user.hasPassphrase}`);
      
      // Check if roles are properly assigned
      if (user.roles && user.roles.length > 0) {
        console.log(`- Roles: ${user.roles.map(r => r.name).join(', ')}`);
      } else {
        console.log("- Roles: None");
      }
    });
  } catch (error) {
    console.error("Error in main function:", error);
    process.exit(1);
  }
}

// Run the main function
main().catch(error => {
  console.error("Error in main function:", error);
  process.exit(1);
});
