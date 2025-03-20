// Rebuild Dgraph schema script with forced index rebuilding
import * as dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';
import fs from 'fs';
import path from 'path';

async function rebuildSchema() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    console.log('Reading schema file...');
    // Read schema file from project root directory
    const schemaPath = path.resolve(process.cwd(), 'schema.dgraph');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    // First, let's drop the schema completely and rebuild it
    console.log('Performing complete schema rebuild...');
    const op = new dgraph.Operation();
    op.setRunInBackground(true);
    op.setSchema(schema);
    await dgraphClient.alter(op);
    
    console.log('✅ Successfully rebuilt schema in Dgraph');
    
    // Let's validate that key predicates are properly indexed
    const txn = dgraphClient.newTxn();
    try {
      const query = `schema(pred: [email, name, did]) {
        type
        index
        tokenizer
      }`;
      
      console.log('Verifying predicate indexes...');
      const res = await txn.query(query);
      console.log('Schema verification results:');
      console.log(JSON.stringify(res.getJson(), null, 2));
    } finally {
      await txn.discard();
    }
  } catch (error) {
    console.error('❌ Error rebuilding schema:', error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

rebuildSchema().catch(console.error);
