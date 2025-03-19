// Reset Dgraph database script
import dgraph from "../web/node_modules/dgraph-js";
import * as grpc from "../web/node_modules/@grpc/grpc-js";
import { v4 as uuidv4 } from "../web/node_modules/uuid";
import logger from "../web/src/lib/logger";

async function resetDatabase() {
  console.log("Connecting to Dgraph...");
  const clientStub = new dgraph.DgraphClientStub(
    "localhost:9080",
    grpc.credentials.createInsecure()
  );
  const dgraphClient = new dgraph.DgraphClient(clientStub);

  try {
    console.log("Dropping all data from Dgraph...");
    const op = new dgraph.Operation();
    op.setDropAll(true);
    await dgraphClient.alter(op);
    console.log("✅ Successfully dropped all data from Dgraph");

    // Initialize system roles
    console.log("Initializing system roles...");

    // Create admin role
    const adminTxn = dgraphClient.newTxn();
    try {
      const adminMutation = new dgraph.Mutation();
      adminMutation.setSetJson({
        uid: "_:admin_role",
        "dgraph.type": "Role",
        name: "admin",
        permissions: ["admin:*"],
        createdAt: new Date().toISOString(),
      });
      await adminTxn.mutate(adminMutation);
      await adminTxn.commit();
      console.log("✅ Created admin role");
    } catch (error) {
      console.error("❌ Error creating admin role:", error);
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
        createdAt: new Date().toISOString(),
      });
      await regTxn.mutate(regMutation);
      await regTxn.commit();
      console.log("✅ Created registered role");
    } catch (error) {
      console.error("❌ Error creating registered role:", error);
    } finally {
      await regTxn.discard();
    }

    console.log("Database reset complete!");
  } catch (error) {
    console.error("❌ Error during database reset:", error);
  } finally {
    clientStub.close();
    console.log("Connection closed");
  }
}

resetDatabase().catch(console.error);
