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
 * Delete all users from the database
 */
async function clearAllUsers() {
  console.log("Deleting all users from the database...");
  
  // First, get all user UIDs
  const queryTxn = client.newTxn({ readOnly: true });
  let userUids = [];
  
  try {
    const query = `
      {
        users(func: type(User)) {
          uid
          did
          email
        }
      }
    `;
    
    const res = await queryTxn.query(query);
    
    // Handle different response formats
    let data;
    const jsonData = res.getJson();
    
    if (typeof jsonData === 'string') {
      data = JSON.parse(jsonData);
    } else if (typeof jsonData === 'object') {
      // If it's already an object, use it directly
      data = jsonData;
    } else {
      // Try to extract from Uint8Array if present
      if (res.u && Array.isArray(res.u) && res.u[0] instanceof Uint8Array) {
        const jsonStr = Buffer.from(res.u[0]).toString('utf8');
        data = JSON.parse(jsonStr);
      } else {
        throw new Error(`Unexpected response type: ${typeof jsonData}`);
      }
    }
    
    if (data.users && Array.isArray(data.users)) {
      userUids = data.users.map(user => user.uid);
      console.log(`Found ${userUids.length} users to delete.`);
      
      if (userUids.length > 0) {
        // Sample of users to be deleted
        console.log("Sample users to be deleted:");
        data.users.slice(0, 3).forEach(user => {
          console.log(`- UID: ${user.uid}, DID: ${user.did || 'N/A'}, Email: ${user.email || 'N/A'}`);
        });
      }
    } else {
      console.log("No users found in the database.");
      return;
    }
  } catch (error) {
    console.error("Error querying users:", error);
    return;
  } finally {
    await queryTxn.discard();
  }
  
  if (userUids.length === 0) {
    console.log("No users to delete.");
    return;
  }
  
  // Now delete the users
  const deleteTxn = client.newTxn();
  
  try {
    // Create RDF triples for deletion
    let nquads = '';
    userUids.forEach(uid => {
      nquads += `<${uid}> * * .\n`;
    });
    
    console.log("Deleting with the following nquads:");
    console.log(nquads);
    
    const mu = new dgraph.Mutation();
    mu.setDelNquads(nquads);
    await deleteTxn.mutate(mu);
    await deleteTxn.commit();
    
    console.log(`Successfully deleted ${userUids.length} users.`);
  } catch (error) {
    console.error("Error deleting users:", error);
  } finally {
    await deleteTxn.discard();
  }
  
  // Verify deletion
  const verifyTxn = client.newTxn({ readOnly: true });
  
  try {
    const query = `
      {
        users(func: type(User)) {
          uid
        }
      }
    `;
    
    const res = await verifyTxn.query(query);
    
    // Handle different response formats
    let data;
    const jsonData = res.getJson();
    
    if (typeof jsonData === 'string') {
      data = JSON.parse(jsonData);
    } else if (typeof jsonData === 'object') {
      // If it's already an object, use it directly
      data = jsonData;
    } else {
      // Try to extract from Uint8Array if present
      if (res.u && Array.isArray(res.u) && res.u[0] instanceof Uint8Array) {
        const jsonStr = Buffer.from(res.u[0]).toString('utf8');
        data = JSON.parse(jsonStr);
      } else {
        throw new Error(`Unexpected response type: ${typeof jsonData}`);
      }
    }
    
    if (data.users && Array.isArray(data.users)) {
      console.log(`Verification: ${data.users.length} users remain in the database.`);
    } else {
      console.log("Verification: No users remain in the database.");
    }
  } catch (error) {
    console.error("Error verifying deletion:", error);
  } finally {
    await verifyTxn.discard();
  }
}

// Main function
async function main() {
  try {
    await clearAllUsers();
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
