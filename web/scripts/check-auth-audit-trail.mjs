import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from "dotenv";
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

// Get the directory of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from the web directory
const envPath = path.resolve(__dirname, '../.env');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else {
  dotenv.config();
  console.warn("Warning: .env file not found in web directory. Using default environment variables.");
}

// Create a Dgraph client
function createDgraphClient() {
  const dgraphUrl = process.env.DGRAPH_URL || "localhost:9080";
  const useTls = process.env.DGRAPH_TLS === "true";
  
  console.log(`Connecting to Dgraph at ${dgraphUrl} with TLS ${useTls ? 'enabled' : 'disabled'}`);
  
  // Create client stub with proper gRPC credentials
  const clientStub = new dgraph.DgraphClientStub(
    dgraphUrl,
    useTls ? credentials.createSsl() : credentials.createInsecure()
  );

  // Create client
  return new dgraph.DgraphClient(clientStub);
}

const client = createDgraphClient();

/**
 * Execute a DQL query
 * @param {string} query - The DQL query
 * @param {Object} vars - Variables for the query
 * @returns {Promise<Object>} - Query result
 */
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    const res = await txn.queryWithVars(query, vars);
    return res.getJson();
  } catch (error) {
    console.error("Error executing query:", error);
    throw error;
  } finally {
    await txn.discard();
  }
}

/**
 * Get authentication audit logs
 * @param {number} limit - Maximum number of logs to retrieve
 * @param {number} days - Number of days to look back
 * @param {string} operationType - Optional filter for operation type (login, registration, etc.)
 */
async function getAuthAuditLogs(limit = 50, days = 7, operationType = null) {
  // Calculate the date from days ago
  const daysAgo = new Date();
  daysAgo.setDate(daysAgo.getDate() - days);
  const daysAgoISOString = daysAgo.toISOString();

  let operationFilter = '';
  if (operationType) {
    operationFilter = `AND eq(operationType, "${operationType}")`;
  }

  const query = `
    query getAuditLogs($daysAgo: string, $limit: int) {
      auditLogs(func: type(AuditLog), orderdesc: auditTimestamp, first: $limit) @filter(ge(auditTimestamp, $daysAgo) ${operationFilter} AND (
        eq(operationType, "authentication") OR 
        eq(operationType, "login") OR
        eq(operationType, "register") OR
        eq(operationType, "registration") OR
        has(action) AND regexp(action, /^(PASSPHRASE|WEBAUTHN|OTP|TOKEN|LOGIN|REGISTER)/)
      )) {
        uid
        action
        actorId
        actorType
        resourceId
        resourceType
        operationType
        requestPath
        requestMethod
        responseStatus
        clientIp
        auditTimestamp
        sessionId
        userAgent
        success
        sensitiveOperation
        complianceFlags
        details
      }
    }
  `;
  
  try {
    const result = await executeDQLQuery(query, { $daysAgo: daysAgoISOString, $limit: limit.toString() });
    return result.auditLogs || [];
  } catch (error) {
    console.error("Error retrieving audit logs:", error);
    return [];
  }
}

/**
 * Get user information by ID
 * @param {string} userId - User ID to look up
 */
async function getUserById(userId) {
  if (!userId || userId === 'unknown') {
    return { email: 'unknown', did: 'unknown' };
  }

  const query = `
    query getUser($userId: string) {
      user(func: uid($userId)) @filter(type(User)) {
        uid
        email
        did
        name
      }
    }
  `;
  
  try {
    const result = await executeDQLQuery(query, { $userId: userId });
    return result.user && result.user.length > 0 ? result.user[0] : { email: 'unknown', did: 'unknown' };
  } catch (error) {
    console.error("Error retrieving user:", error);
    return { email: 'unknown', did: 'unknown' };
  }
}

/**
 * Format date for display
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date
 */
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  
  try {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
  } catch {
    return dateString;
  }
}

/**
 * Extract browser and OS from user agent
 * @param {string} userAgent - User agent string
 * @returns {string} - Simplified browser and OS
 */
function parseUserAgent(userAgent) {
  if (!userAgent || userAgent === 'unknown') {
    return 'Unknown';
  }

  let browser = 'Unknown';
  let os = 'Unknown';

  // Detect browser
  if (userAgent.includes('Firefox/')) {
    browser = 'Firefox';
  } else if (userAgent.includes('Chrome/') && !userAgent.includes('Edg/')) {
    browser = 'Chrome';
  } else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome/')) {
    browser = 'Safari';
  } else if (userAgent.includes('Edg/')) {
    browser = 'Edge';
  } else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) {
    browser = 'Internet Explorer';
  }

  // Detect OS
  if (userAgent.includes('Windows')) {
    os = 'Windows';
  } else if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
    os = 'macOS';
  } else if (userAgent.includes('Linux')) {
    os = 'Linux';
  } else if (userAgent.includes('Android')) {
    os = 'Android';
  } else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('iPod')) {
    os = 'iOS';
  }

  return `${browser} on ${os}`;
}

/**
 * Format details for better readability
 * @param {string} details - JSON string or plain text
 * @returns {string} - Formatted details
 */
function formatDetails(details) {
  if (!details) return 'No details';
  
  try {
    const parsedDetails = JSON.parse(details);
    return Object.entries(parsedDetails)
      .map(([key, value]) => {
        // Mask sensitive information
        if (key === 'email' && typeof value === 'string') {
          const [username, domain] = value.split('@');
          if (username && domain) {
            return `${key}: ${username.substring(0, 2)}***@${domain}`;
          }
        }
        
        // Format other values
        if (typeof value === 'object' && value !== null) {
          return `${key}: ${JSON.stringify(value)}`;
        }
        return `${key}: ${value}`;
      })
      .join(', ');
  } catch (error) {
    console.error("Error parsing details:", error);
    return details;
  }
}

/**
 * Format compliance flags for display
 * @param {Array} flags - Array of compliance flags
 * @returns {string} - Formatted flags
 */
function formatComplianceFlags(flags) {
  if (!flags || !Array.isArray(flags) || flags.length === 0) {
    return 'None';
  }
  return flags.join(', ');
}

/**
 * Group audit logs by operation type
 * @param {Array} logs - Audit logs
 * @returns {Object} - Grouped logs
 */
function groupLogsByOperation(logs) {
  const grouped = {};
  
  for (const log of logs) {
    const key = log.operationType || 'unknown';
    if (!grouped[key]) {
      grouped[key] = [];
    }
    grouped[key].push(log);
  }
  
  return grouped;
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);
  const limit = parseInt(args[0]) || 50;
  const days = parseInt(args[1]) || 7;
  const operationType = args[2] || null;
  
  console.log(`Retrieving up to ${limit} authentication audit logs from the last ${days} days${operationType ? ` for operation type: ${operationType}` : ''}`);
  
  const logs = await getAuthAuditLogs(limit, days, operationType);
  
  if (logs.length === 0) {
    console.log("No authentication audit logs found for the specified criteria.");
    return;
  }
  
  console.log(`Found ${logs.length} authentication audit logs.`);
  
  // Group logs by operation type for better readability
  const groupedLogs = groupLogsByOperation(logs);
  
  // Process each group
  for (const [operationType, operationLogs] of Object.entries(groupedLogs)) {
    console.log(`\n=== ${operationType.toUpperCase()} OPERATIONS (${operationLogs.length}) ===`);
    
    // Process each log in the group
    for (const log of operationLogs) {
      const user = await getUserById(log.actorId);
      
      console.log(`\n[${formatDate(log.auditTimestamp)}] ${log.action} (${log.success ? 'SUCCESS' : 'FAILURE'})`);
      console.log(`User: ${user.email || 'unknown'} (${log.actorId})`);
      console.log(`Request: ${log.requestMethod || 'N/A'} ${log.requestPath || 'N/A'} (Status: ${log.responseStatus || 'N/A'})`);
      console.log(`Client: ${log.clientIp || 'unknown'} - ${parseUserAgent(log.userAgent)}`);
      
      if (log.complianceFlags) {
        console.log(`Compliance: ${formatComplianceFlags(log.complianceFlags)}`);
      }
      
      if (log.details) {
        console.log(`Details: ${formatDetails(log.details)}`);
      }
      
      console.log('-'.repeat(80));
    }
  }
  
  // Summary statistics
  const successCount = logs.filter(log => log.success).length;
  const failureCount = logs.filter(log => !log.success).length;
  
  console.log(`\n=== SUMMARY ===`);
  console.log(`Total logs: ${logs.length}`);
  console.log(`Successful operations: ${successCount} (${Math.round(successCount / logs.length * 100)}%)`);
  console.log(`Failed operations: ${failureCount} (${Math.round(failureCount / logs.length * 100)}%)`);
  
  // Operation type breakdown
  console.log(`\nOperation types:`);
  for (const [type, typeLogs] of Object.entries(groupedLogs)) {
    console.log(`- ${type}: ${typeLogs.length} logs`);
  }
}

// Run the main function
main().catch(error => {
  console.error("Error in main function:", error);
  process.exit(1);
});
