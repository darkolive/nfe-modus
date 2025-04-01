#!/usr/bin/env node
/**
 * Fix user records in the Dgraph database
 * - Adds proper type predicates (dgraph.type: "User")
 * - Ensures all users have required fields
 */
import { createDgraphClient, checkUserTypes, fixUserTypes, closeConnection } from './db-utils.mjs';

async function main() {
  console.log('Analyzing user records in the database...');
  
  const client = createDgraphClient();
  
  try {
    // Check for users with missing type predicates
    const { typedUsers, untypedUsers } = await checkUserTypes(client);
    
    console.log(`Found ${typedUsers.length} users with proper type.`);
    console.log(`Found ${untypedUsers.length} users missing the User type.`);
    
    if (untypedUsers.length === 0) {
      console.log('All users have the correct type predicate. No action needed.');
      return;
    }
    
    // Display untyped user information
    console.log('\nUsers missing type predicate:');
    untypedUsers.forEach(user => {
      console.log(`- User ID: ${user.uid}, Email: ${user.email || 'Not available'}`);
    });
    
    // Fix the user types
    console.log('\nFixing user type predicates...');
    const fixedCount = await fixUserTypes(client);
    
    console.log(`Successfully updated ${fixedCount} user records.`);
    
    // Verify the fix
    const afterFix = await checkUserTypes(client);
    console.log(`\nVerification: ${afterFix.typedUsers.length} users now have proper type.`);
    console.log(`Remaining untyped users: ${afterFix.untypedUsers.length}`);
    
    if (afterFix.untypedUsers.length > 0) {
      console.log('⚠️ Some users could not be fixed. Manual intervention may be required.');
    } else {
      console.log('✅ All users now have the correct type predicate.');
    }
    
  } catch (error) {
    console.error('Error fixing user records:', error);
  } finally {
    await closeConnection(client);
  }
}

// Run the main function
main().catch(error => {
  console.error("Error in main function:", error);
  process.exit(1);
});
