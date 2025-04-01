// Reset Dgraph database script
import dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';

async function resetDatabase() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    console.log('Dropping all data from Dgraph...');
    const op = new dgraph.Operation();
    op.setDropAll(true);
    await dgraphClient.alter(op);
    console.log('✅ Successfully dropped all data from Dgraph');

    // Set schema (optional - uncomment if you want to reinitialize schema)
    // const schema = `...your schema...`;
    // const operation = new dgraph.Operation();
    // operation.setSchema(schema);
    // await dgraphClient.alter(operation);
    // console.log('✅ Successfully reinitialized schema');
  } catch (error) {
    console.error('❌ Error dropping data:', error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

resetDatabase().catch(console.error);
