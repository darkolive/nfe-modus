/**
 * Database utilities for Dgraph operations
 * Consolidates common functionality for database interaction
 */
import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

/**
 * Create a Dgraph client
 * @returns {dgraph.DgraphClient} Configured Dgraph client
 */
export function createDgraphClient() {
  const clientStub = new dgraph.DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
  );
  
  return new dgraph.DgraphClient(clientStub);
}

/**
 * Execute a DQL query with read-only transaction
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @param {string} query - DQL query
 * @param {Object} vars - Query variables
 * @returns {Promise<Object>} Query results
 */
export async function executeQuery(client, query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    const res = vars ? await txn.queryWithVars(query, vars) : await txn.query(query);
    const jsonData = res.getJson();
    return jsonData;
  } catch (error) {
    console.error("Error executing query:", error);
    throw error;
  } finally {
    await txn.discard();
  }
}

/**
 * Execute a mutation with a new transaction
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @param {function(dgraph.Mutation): void} mutationFn - Function to set up the mutation
 * @returns {Promise<Object>} Mutation response
 */
export async function executeMutation(client, mutationFn) {
  const txn = client.newTxn();
  try {
    const mu = new dgraph.Mutation();
    mutationFn(mu);
    const response = await txn.mutate(mu);
    await txn.commit();
    return response;
  } catch (error) {
    console.error("Error executing mutation:", error);
    await txn.discard();
    throw error;
  }
}

/**
 * Get all users with comprehensive information
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @returns {Promise<Array>} Array of user objects
 */
export async function getAllUsers(client) {
  const query = `{
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
      dgraph.type
      
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
      }
    }
  }`;
  
  const result = await executeQuery(client, query);
  return result.users || [];
}

/**
 * Check if users have the correct type predicate
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @returns {Promise<{typedUsers: Array, untypedUsers: Array}>} Users with and without types
 */
export async function checkUserTypes(client) {
  // Query for users with email
  const allUsersQuery = `{
    allUsers(func: has(email)) {
      uid
      email
      dgraph.type
    }
  }`;
  
  // Query for users with User type
  const typedUsersQuery = `{
    typedUsers(func: type(User)) {
      uid
      email
    }
  }`;
  
  const allUsersResult = await executeQuery(client, allUsersQuery);
  const typedUsersResult = await executeQuery(client, typedUsersQuery);
  
  const allUsers = allUsersResult.allUsers || [];
  const typedUsers = typedUsersResult.typedUsers || [];
  
  // Find users without the User type
  const typedUserIds = new Set(typedUsers.map(user => user.uid));
  const untypedUsers = allUsers.filter(user => !typedUserIds.has(user.uid));
  
  return {
    typedUsers,
    untypedUsers
  };
}

/**
 * Fix user types by adding the User type predicate
 * @param {dgraph.DgraphClient} client - Dgraph client
 * @returns {Promise<number>} Number of fixed users
 */
export async function fixUserTypes(client) {
  const { untypedUsers } = await checkUserTypes(client);
  
  if (untypedUsers.length === 0) {
    return 0;
  }
  
  // Create NQuads to add the User type
  const nquads = untypedUsers.map(user => 
    `<${user.uid}> <dgraph.type> "User" .`
  ).join('\n');
  
  await executeMutation(client, (mu) => {
    mu.setSetNquads(nquads);
  });
  
  return untypedUsers.length;
}

/**
 * Close the client connection
 * @param {dgraph.DgraphClientStub} clientStub - Client stub to close
 */
export async function closeConnection(client) {
  if (client && client._clientStub) {
    await client._clientStub.close();
    console.log("Connection closed");
  }
}
