// Fix roles in Dgraph database
import dgraph from 'dgraph-js';
import * as grpc from '@grpc/grpc-js';

async function fixRoles() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    // First, ensure the name field has the right index
    console.log('Updating schema for name field...');
    const nameIndexSchema = `
      # Make sure name field has an exact index for querying
      name: string @index(exact) .
    `;

    const nameOp = new dgraph.Operation();
    nameOp.setSchema(nameIndexSchema);
    await dgraphClient.alter(nameOp);
    console.log('✅ Successfully updated name index');

    // Then add the type definition
    console.log('Updating Role type definition...');
    const typeSchema = `
      # Type definition for Role
      type Role {
        name
        permissions
        createdAt
        updatedAt
        users
      }
    `;

    const typeOp = new dgraph.Operation();
    typeOp.setSchema(typeSchema);
    await dgraphClient.alter(typeOp);
    console.log('✅ Successfully updated Role type definition');

    // 2. Create admin role with proper type
    const adminTxn = dgraphClient.newTxn();
    try {
      const adminMutation = new dgraph.Mutation();
      adminMutation.setSetJson({
        uid: "_:admin_role",
        "dgraph.type": "Role",
        name: "admin",
        permissions: ["admin:*"],
        createdAt: new Date().toISOString()
      });
      await adminTxn.mutate(adminMutation);
      await adminTxn.commit();
      console.log('✅ Created admin role');
      
      // 3. Create registered role with proper type
      const regTxn = dgraphClient.newTxn();
      try {
        const regMutation = new dgraph.Mutation();
        regMutation.setSetJson({
          uid: "_:registered_role",
          "dgraph.type": "Role",
          name: "registered",
          permissions: ["user:read", "user:write"],
          createdAt: new Date().toISOString()
        });
        await regTxn.mutate(regMutation);
        await regTxn.commit();
        console.log('✅ Created registered role');
      } catch (error) {
        console.error('❌ Error creating registered role:', error);
      } finally {
        await regTxn.discard();
      }
    } catch (error) {
      console.error('❌ Error creating admin role:', error);
    } finally {
      await adminTxn.discard();
    }

    // 4. Verify we can query the roles - fixed to properly handle response
    console.log('Verifying role creation...');
    const query = `
      {
        roles(func: type(Role)) {
          uid
          name
          permissions
        }
      }
    `;
    
    const txn = dgraphClient.newTxn({ readOnly: true });
    try {
      const response = await txn.query(query);
      const jsonStr = response.getJson();
      console.log('Query response:', jsonStr);
      
      if (jsonStr) {
        const jsonObj = JSON.parse(jsonStr);
        const roles = jsonObj.roles || [];
        
        console.log(`Found ${roles.length} roles:`);
        roles.forEach(role => {
          const permissions = role.permissions || [];
          console.log(`- ${role.name}: ${permissions.join(', ') || 'no permissions'}`);
        });
      } else {
        console.log('No data returned from query');
      }
    } catch (error) {
      console.error('❌ Error querying roles:', error);
    } finally {
      await txn.discard();
    }

    console.log('Role fixing complete!');
  } catch (error) {
    console.error('❌ Error during role fixing:', error);
    console.error(error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

fixRoles().catch(console.error);
