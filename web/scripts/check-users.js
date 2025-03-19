// Check if any users exist in the database
import * as dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';

async function checkUsers() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    console.log('Querying all users...');
    const txn = dgraphClient.newTxn({ readOnly: true });
    
    // Basic query to find all users
    const query = `
      {
        allUsers(func: has(email)) {
          uid
          email
          dgraph_type
        }
      }
    `;
    
    const res = await txn.query(query);
    const users = res.getJson();
    console.log('Users found:', JSON.stringify(users, null, 2));
    
    // Check for predicates with the User type
    const typeQuery = `
      {
        userTypes(func: eq(dgraph_type, "User")) {
          uid
          email
        }
      }
    `;
    
    const typeRes = await txn.query(typeQuery);
    const userTypes = typeRes.getJson();
    console.log('Users by type:', JSON.stringify(userTypes, null, 2));
    
    // Check all credentials
    const credQuery = `
      {
        credentials(func: has(credentialID)) {
          uid
          credentialID
          deviceName
          userId
        }
      }
    `;
    
    const credRes = await txn.query(credQuery);
    const creds = credRes.getJson();
    console.log('Credentials:', JSON.stringify(creds, null, 2));
    
  } catch (error) {
    console.error('Error querying users:', error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

checkUsers().catch(console.error);
