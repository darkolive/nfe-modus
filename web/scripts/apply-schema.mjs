#!/usr/bin/env node

/**
 * Script to apply the Dgraph schema from schema.dgraph file
 * This ensures all required indexes are created
 */

import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';

const DGRAPH_ENDPOINT = 'http://localhost:8080/alter';

async function readSchemaFile() {
  try {
    // Go up one directory from /web/scripts to root, then read schema.dgraph
    const schemaPath = path.resolve(process.cwd(), '..', 'schema.dgraph');
    console.log(`Reading schema from: ${schemaPath}`);
    return fs.readFileSync(schemaPath, 'utf8');
  } catch (error) {
    console.error('Failed to read schema file:', error);
    process.exit(1);
  }
}

async function updateSchema(schema) {
  try {
    console.log('Applying schema to Dgraph...');
    const response = await fetch(DGRAPH_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/rdf',
      },
      body: schema,
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('Schema applied successfully!');
      console.log(result);
      return true;
    } else {
      console.error('Failed to apply schema:', result);
      return false;
    }
  } catch (error) {
    console.error('Error applying schema:', error);
    return false;
  }
}

// Add User and Role types explicitly if they're missing from the schema file
function ensureUserAndRoleTypes(schema) {
  let updatedSchema = schema;
  
  // Add User type if missing
  if (!schema.includes('type <User>') && !schema.includes('type User')) {
    const userType = `
type User {
  did
  email
  active
  isAdmin
  hasPassphrase
  hasWebAuthn
  failedLoginAttempts
  lockedUntil
  joinedAt
  lastAuthTime
  roles
  devices
  verified
  status
}
`;
    updatedSchema += userType;
  }
  
  // Add Role type if missing
  if (!schema.includes('type <Role>') && !schema.includes('type Role')) {
    const roleType = `
type Role {
  name
  permissions
  createdAt
  updatedAt
  users
}
`;
    updatedSchema += roleType;
  }
  
  return updatedSchema;
}

// Ensure all critical indexes are defined
function ensureCriticalIndexes(schema) {
  let updatedSchema = schema;
  const requiredIndexes = [
    '<email>: string @index(exact) .',
    '<name>: string @index(exact) .',
    '<did>: string @index(exact) @index(hash) .',
  ];
  
  for (const indexDef of requiredIndexes) {
    if (!schema.includes(indexDef)) {
      // Check if predicate exists but without proper index
      const predicateName = indexDef.split(':')[0].replace('<', '').replace('>', '').trim();
      const predicateRegex = new RegExp(`<${predicateName}>:\\s*\\w+\\s*\\.`, 'i');
      
      if (predicateRegex.test(schema)) {
        // Replace existing predicate definition with one that has indexes
        updatedSchema = updatedSchema.replace(predicateRegex, indexDef);
      } else {
        // Add new predicate definition
        updatedSchema += '\n' + indexDef;
      }
    }
  }
  
  return updatedSchema;
}

async function run() {
  try {
    let schema = await readSchemaFile();
    schema = ensureUserAndRoleTypes(schema);
    schema = ensureCriticalIndexes(schema);
    
    console.log('Schema to be applied:');
    console.log('----------------------------------------');
    console.log(schema);
    console.log('----------------------------------------');
    
    const success = await updateSchema(schema);
    
    if (success) {
      console.log('Schema update completed successfully!');
    } else {
      console.error('Schema update failed. Please check the errors above.');
      process.exit(1);
    }
  } catch (error) {
    console.error('Unexpected error:', error);
    process.exit(1);
  }
}

run();
