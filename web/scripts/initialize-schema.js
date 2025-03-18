// Initialize Dgraph schema
const dgraph = require('dgraph-js');
const grpc = require('@grpc/grpc-js');

async function initializeSchema() {
  console.log('Connecting to Dgraph...');
  const clientStub = new dgraph.DgraphClientStub(
    'localhost:9080',
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);
  
  try {
    console.log('Initializing Dgraph schema...');
    
    // Define schema using the correct Dgraph syntax
    const schema = `
      # Predicates
      did: string @index(exact) .
      email: string @index(exact) .
      name: string .
      verified: bool .
      emailVerified: datetime .
      dateJoined: datetime @index(day) .
      lastAuthTime: datetime @index(hour) .
      status: string .
      hasWebAuthn: bool .
      hasPassphrase: bool .
      passwordHash: string .
      passwordSalt: string .
      recoveryEmail: string @index(exact) .
      mfaEnabled: bool .
      mfaMethod: string .
      mfaSecret: string .
      failedLoginAttempts: int .
      lastFailedLogin: datetime .
      lockedUntil: datetime .
      createdAt: datetime .
      updatedAt: datetime .

      credentialID: string @index(exact) .
      credentialPublicKey: string .
      counter: int .
      transports: [string] .
      lastUsed: datetime .
      deviceName: string .
      isBiometric: bool .
      deviceType: string .
      deviceInfo: string .
      userId: string @index(hash) .

      permissions: [string] .
      challenge: string @index(exact) .
      created: datetime .
      expires: datetime .

      # Relationships
      devices: [uid] @reverse .
      roles: [uid] @reverse .
      user: uid @reverse .
      users: [uid] @reverse .

      # Type definitions
      type User {
        did
        email
        name
        verified
        emailVerified
        dateJoined
        lastAuthTime
        status
        hasWebAuthn
        hasPassphrase
        passwordHash
        passwordSalt
        recoveryEmail
        mfaEnabled
        mfaMethod
        mfaSecret
        failedLoginAttempts
        lastFailedLogin
        lockedUntil
        roles
        createdAt
        updatedAt
        devices
      }

      type Device {
        credentialID
        credentialPublicKey
        counter
        transports
        lastUsed
        deviceName
        isBiometric
        deviceType
        deviceInfo
        userId
        createdAt
        updatedAt
        user
      }

      type Role {
        name
        permissions
        createdAt
        updatedAt
        users
      }

      type Challenge {
        email
        challenge
        created
        expires
      }
    `;

    const op = new dgraph.Operation();
    op.setSchema(schema);
    await dgraphClient.alter(op);
    console.log('✅ Successfully initialized Dgraph schema');

    // Initialize system roles
    console.log('Initializing system roles...');
    
    // Create admin role
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
    } catch (error) {
      console.error('❌ Error creating admin role:', error);
    } finally {
      await adminTxn.discard();
    }
    
    // Create registered role
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

    console.log('Schema initialization complete!');
  } catch (error) {
    console.error('❌ Error during schema initialization:', error);
    console.error(error);
  } finally {
    clientStub.close();
    console.log('Connection closed');
  }
}

initializeSchema().catch(console.error);
