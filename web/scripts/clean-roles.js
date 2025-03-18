// Clean up duplicate roles in Dgraph database
const dgraph = require('dgraph-js');
const grpc = require('@grpc/grpc-js');

async function cleanRoles() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    // 1. First, query all roles to see what we have
    console.log('Querying current roles...');
    const queryTxn = dgraphClient.newTxn({ readOnly: true });
    
    try {
      const query = `
        {
          roles(func: type(Role)) {
            uid
            name
            permissions
            createdAt
          }
        }
      `;
      
      const response = await queryTxn.query(query);
      const jsonObj = response.getJson();
      console.log('Query response raw:', jsonObj);
      
      const roles = jsonObj.roles || [];
      
      console.log(`Found ${roles.length} roles total`);
      
      // Group roles by name
      const rolesByName = {};
      roles.forEach(role => {
        if (!rolesByName[role.name]) {
          rolesByName[role.name] = [];
        }
        rolesByName[role.name].push(role);
      });
      
      // For each role name, keep the newest one (by createdAt) and delete the rest
      for (const [name, roleGroup] of Object.entries(rolesByName)) {
        console.log(`\nProcessing ${roleGroup.length} "${name}" roles`);
        
        if (roleGroup.length <= 1) {
          console.log(`Only one "${name}" role exists, no cleanup needed`);
          continue;
        }
        
        // Sort by createdAt, newest first
        roleGroup.sort((a, b) => {
          return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
        });
        
        // Keep the first one (newest)
        const keepRole = roleGroup[0];
        console.log(`Keeping "${name}" role with UID ${keepRole.uid}`);
        
        // Delete the rest
        const rolesToDelete = roleGroup.slice(1);
        console.log(`Deleting ${rolesToDelete.length} duplicate "${name}" roles`);
        
        for (const roleToDelete of rolesToDelete) {
          const deleteTxn = dgraphClient.newTxn();
          try {
            const mutation = new dgraph.Mutation();
            mutation.setDeleteJson({
              uid: roleToDelete.uid
            });
            
            console.log(`Deleting role "${name}" with UID ${roleToDelete.uid}`);
            await deleteTxn.mutate(mutation);
            await deleteTxn.commit();
            console.log(`✅ Deleted role "${name}" with UID ${roleToDelete.uid}`);
          } catch (error) {
            console.error(`❌ Error deleting role ${roleToDelete.uid}:`, error);
          } finally {
            await deleteTxn.discard();
          }
        }
      }
      
      // Verify roles after cleanup
      console.log('\nVerifying roles after cleanup...');
      const verifyTxn = dgraphClient.newTxn({ readOnly: true });
      try {
        const verifyResponse = await verifyTxn.query(query);
        const verifyJson = verifyResponse.getJson();
        const verifyRoles = verifyJson.roles || [];
        
        console.log(`Found ${verifyRoles.length} roles after cleanup:`);
        verifyRoles.forEach(role => {
          const permissions = role.permissions || [];
          console.log(`- ${role.name} (${role.uid}): ${permissions.join(', ') || 'no permissions'}`);
        });
      } catch (error) {
        console.error('❌ Error verifying roles after cleanup:', error);
      } finally {
        await verifyTxn.discard();
      }
      
    } catch (error) {
      console.error('❌ Error querying roles:', error);
      console.error(error);
    } finally {
      await queryTxn.discard();
    }

    console.log('\nRole cleanup complete!');
  } catch (error) {
    console.error('❌ Error during role cleanup:', error);
    console.error(error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

cleanRoles().catch(console.error);
