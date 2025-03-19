import { DgraphClient, DgraphClientStub } from "dgraph-js";
import { credentials } from "@grpc/grpc-js";

async function queryUserRoles(email) {
  // Create client stub
  const clientStub = new DgraphClientStub(
    process.env.DGRAPH_URL || "localhost:9080",
    process.env.DGRAPH_TLS === "true"
      ? credentials.createSsl()
      : credentials.createInsecure()
  );

  // Create client
  const client = new DgraphClient(clientStub);

  try {
    const txn = client.newTxn({ readOnly: true });

    // Query for user with roles
    const query = `
      query getUser($email: string) {
        users(func: eq(email, $email)) @filter(type(User)) {
          uid
          email
          did
          verified
          emailVerified
          dateJoined
          status
          hasWebAuthn
          hasPassphrase
          failedLoginAttempts
          createdAt
          roles {
            uid
            name
            permissions {
              uid
              action
            }
          }
          devices {
            uid
            credentialID
            deviceName
            deviceType
            lastUsed
          }
        }
      }
    `;

    const vars = { $email: email };
    const res = await txn.queryWithVars(query, vars);

    // Parse the response properly
    const data = res.getJson();
    const parsed = JSON.parse(data);
    const users = parsed.users || [];

    console.log(JSON.stringify(users, null, 2));

    // Check if roles are present
    if (users && users.length > 0) {
      if (users[0].roles && users[0].roles.length > 0) {
        console.log(`\nUser has ${users[0].roles.length} role(s):`);
        users[0].roles.forEach((role) => {
          console.log(`- ${role.name} (${role.uid})`);
        });
      } else {
        console.log("\nUser has no roles assigned.");
      }

      // Check WebAuthn devices
      if (users[0].devices && users[0].devices.length > 0) {
        console.log(
          `\nUser has ${users[0].devices.length} WebAuthn device(s).`
        );
      } else {
        console.log("\nUser has no WebAuthn devices.");
      }
    } else {
      console.log("No user found with this email.");
    }
  } catch (error) {
    console.error("Error querying user:", error);
  } finally {
    clientStub.close();
  }
}

// Get email from command line arguments
const email = process.argv[2];
if (!email) {
  console.error("Please provide an email address as an argument.");
  process.exit(1);
}

queryUserRoles(email);
