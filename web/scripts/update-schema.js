// Update Dgraph schema script
import * as dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';
import fs from 'fs';
import path from 'path';

async function updateSchema() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    console.log('Reading schema file...');
    // Read from project root directory
    const schemaPath = path.resolve(process.cwd(), '..', 'schema.dgraph');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    console.log('Updating schema in Dgraph...');
    const op = new dgraph.Operation();
    op.setSchema(schema);
    await dgraphClient.alter(op);
    console.log('✅ Successfully updated schema in Dgraph');
  } catch (error) {
    console.error('❌ Error updating schema:', error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

updateSchema().catch(console.error);
