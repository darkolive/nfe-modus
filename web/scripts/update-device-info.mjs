import * as dgraph from 'dgraph-js';
import { credentials } from "@grpc/grpc-js";
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Parse command line arguments
const args = process.argv.slice(2);

// Create Dgraph client
const clientStub = new dgraph.DgraphClientStub(
  process.env.DGRAPH_URL || "localhost:9080",
  process.env.DGRAPH_TLS === "true" ? credentials.createSsl() : credentials.createInsecure()
);
const client = new dgraph.DgraphClient(clientStub);

// Execute DQL query
async function executeDQLQuery(query, vars = {}) {
  const txn = client.newTxn({ readOnly: true });
  try {
    console.log("Executing query: \n", query, "\n");
    console.log("With variables:", JSON.stringify(vars));
    const res = await txn.queryWithVars(query, vars);
    const json = res.getJson();
    console.log("JSON data type:", typeof json);
    console.log("Parsed JSON data:", JSON.stringify(json, null, 2));
    return json;
  } catch (error) {
    console.error("Query error:", error);
    throw error;
  } finally {
    await txn.discard();
  }
}

// Update device information
async function updateDeviceInfo(deviceUid, deviceName, deviceType, deviceInfo) {
  const txn = client.newTxn();
  try {
    console.log(`Updating device ${deviceUid} with name: ${deviceName}, type: ${deviceType}`);
    
    const mu = new dgraph.Mutation();
    mu.setSetJson({
      uid: deviceUid,
      deviceName: deviceName,
      deviceType: deviceType,
      deviceInfo: deviceInfo,
      updatedAt: new Date().toISOString()
    });
    
    await txn.mutate(mu);
    await txn.commit();
    
    console.log(`Device ${deviceUid} updated successfully`);
    return true;
  } catch (error) {
    console.error(`Error updating device ${deviceUid}:`, error);
    return false;
  } finally {
    try {
      await txn.discard();
    } catch (discardError) {
      console.error("Error discarding transaction:", discardError);
    }
  }
}

// Get all devices
async function getAllDevices() {
  const result = await executeDQLQuery(`
    {
      devices(func: type(Device)) {
        uid
        credentialID
        deviceName
        deviceType
        deviceInfo
        isBiometric
        lastUsed
        createdAt
        updatedAt
        ~devices {
          uid
          email
        }
      }
    }
  `);
  
  return result.devices || [];
}

// Get a specific device
async function getDevice(deviceUid) {
  const result = await executeDQLQuery(`
    {
      device(func: uid(${deviceUid})) {
        uid
        credentialID
        deviceName
        deviceType
        deviceInfo
        isBiometric
        lastUsed
        createdAt
        updatedAt
        ~devices {
          uid
          email
        }
      }
    }
  `);
  
  return result.device && result.device.length > 0 ? result.device[0] : null;
}

// Detect device type from user agent string
function detectDeviceTypeFromUserAgent(userAgent) {
  let deviceName = "Unknown device";
  let deviceType = "unknown";
  
  if (!userAgent) {
    return { deviceName, deviceType };
  }
  
  // Mobile devices
  if (/iPhone/.test(userAgent)) {
    deviceType = "ios";
    deviceName = "iPhone";
  } else if (/iPad/.test(userAgent)) {
    deviceType = "ios";
    deviceName = "iPad";
  } else if (/iPod/.test(userAgent)) {
    deviceType = "ios";
    deviceName = "iPod";
  } else if (/Android/.test(userAgent)) {
    deviceType = "android";
    
    // Try to extract Android device model
    const androidModelMatch = userAgent.match(/Android [0-9\.]+; ([^;)]+)/);
    if (androidModelMatch && androidModelMatch[1]) {
      deviceName = androidModelMatch[1].trim();
    } else {
      deviceName = "Android Device";
    }
  }
  // Desktop devices
  else if (/Windows/.test(userAgent)) {
    deviceType = "windows";
    
    if (/Windows NT 10/.test(userAgent)) {
      deviceName = "Windows 10";
    } else if (/Windows NT 6\.3/.test(userAgent)) {
      deviceName = "Windows 8.1";
    } else if (/Windows NT 6\.2/.test(userAgent)) {
      deviceName = "Windows 8";
    } else if (/Windows NT 6\.1/.test(userAgent)) {
      deviceName = "Windows 7";
    } else {
      deviceName = "Windows PC";
    }
  } else if (/Macintosh|Mac OS X/.test(userAgent)) {
    deviceType = "mac";
    
    if (/Mac OS X 10[._]15/.test(userAgent)) {
      deviceName = "macOS Catalina";
    } else if (/Mac OS X 10[._]14/.test(userAgent)) {
      deviceName = "macOS Mojave";
    } else if (/Mac OS X 10[._]13/.test(userAgent)) {
      deviceName = "macOS High Sierra";
    } else {
      deviceName = "Mac";
    }
  } else if (/Linux/.test(userAgent)) {
    deviceType = "linux";
    
    if (/Ubuntu/.test(userAgent)) {
      deviceName = "Ubuntu";
    } else {
      deviceName = "Linux PC";
    }
  }
  // Browsers - if we couldn't identify the OS, at least identify the browser
  else if (/Chrome/.test(userAgent) && !/Chromium|Edge/.test(userAgent)) {
    deviceName = "Chrome Browser";
  } else if (/Firefox/.test(userAgent)) {
    deviceName = "Firefox Browser";
  } else if (/Safari/.test(userAgent)) {
    deviceName = "Safari Browser";
  } else if (/Edge/.test(userAgent)) {
    deviceName = "Edge Browser";
  }
  
  return { deviceName, deviceType, deviceInfo: userAgent };
}

// Detect device type from device info or credential ID
function detectDeviceType(device) {
  // Default values
  let deviceName = device.deviceName || "Unknown device";
  let deviceType = device.deviceType || "unknown";
  let deviceInfo = device.deviceInfo || "";
  
  // If device already has good info, don't change it
  if (deviceType !== "unknown" && deviceName !== "Unknown device" && deviceName !== "") {
    return { deviceName, deviceType, deviceInfo };
  }
  
  // Try to detect from device info if it looks like a user agent string
  if (deviceInfo && (
    deviceInfo.includes("Mozilla") || 
    deviceInfo.includes("AppleWebKit") || 
    deviceInfo.includes("Chrome") || 
    deviceInfo.includes("Safari")
  )) {
    const detected = detectDeviceTypeFromUserAgent(deviceInfo);
    deviceType = detected.deviceType;
    deviceName = detected.deviceName;
    return { deviceName, deviceType, deviceInfo };
  }
  
  // Try to infer from credential ID (this is a simple heuristic and may not be accurate)
  const credentialID = device.credentialID || "";
  const decodedCredential = Buffer.from(credentialID, 'base64').toString('utf8');
  
  if (decodedCredential.includes("apple") || decodedCredential.includes("iphone") || decodedCredential.includes("ipad")) {
    deviceType = "ios";
    deviceName = deviceName === "Unknown device" ? "iOS Device" : deviceName;
  } else if (decodedCredential.includes("android")) {
    deviceType = "android";
    deviceName = deviceName === "Unknown device" ? "Android Device" : deviceName;
  } else if (decodedCredential.includes("windows")) {
    deviceType = "windows";
    deviceName = deviceName === "Unknown device" ? "Windows Device" : deviceName;
  } else if (decodedCredential.includes("mac")) {
    deviceType = "mac";
    deviceName = deviceName === "Unknown device" ? "Mac Device" : deviceName;
  }
  
  return { deviceName, deviceType, deviceInfo };
}

// Print usage information
function printUsage() {
  console.log("Usage:");
  console.log("  node update-device-info.mjs                     # Update all devices with auto-detection");
  console.log("  node update-device-info.mjs <deviceUid>         # Update a specific device with auto-detection");
  console.log("  node update-device-info.mjs <deviceUid> <type> <name> # Update a specific device with given type and name");
  console.log("  node update-device-info.mjs --all <type> <name> # Update all devices with given type and name");
  console.log("\nDevice Types:");
  console.log("  ios, android, windows, mac, linux, unknown");
}

// Main function
async function main() {
  try {
    console.log("===== UPDATING DEVICE INFORMATION =====");
    
    // Handle specific command line arguments
    if (args.length > 0 && args[0] === "--help") {
      printUsage();
      return;
    }
    
    // Update all devices with a specific type and name
    if (args.length >= 3 && args[0] === "--all") {
      const specifiedType = args[1];
      const specifiedName = args[2];
      const devices = await getAllDevices();
      console.log(`Found ${devices.length} devices, updating all with type: ${specifiedType}, name: ${specifiedName}`);
      
      let updatedCount = 0;
      for (const device of devices) {
        const success = await updateDeviceInfo(
          device.uid, 
          specifiedName, 
          specifiedType, 
          device.deviceInfo || ""
        );
        if (success) {
          updatedCount++;
        }
      }
      
      console.log(`\n===== UPDATE SUMMARY =====`);
      console.log(`Total devices: ${devices.length}`);
      console.log(`Updated: ${updatedCount}`);
      return;
    }
    
    // Update a specific device with given type and name
    if (args.length >= 3) {
      const specificDeviceUid = args[0];
      const specifiedType = args[1];
      const specifiedName = args[2];
      
      const device = await getDevice(specificDeviceUid);
      if (!device) {
        console.error(`Device with UID ${specificDeviceUid} not found`);
        return;
      }
      
      console.log(`Updating device ${specificDeviceUid} with type: ${specifiedType}, name: ${specifiedName}`);
      const success = await updateDeviceInfo(
        specificDeviceUid, 
        specifiedName, 
        specifiedType, 
        device.deviceInfo || ""
      );
      
      console.log(`\n===== UPDATE SUMMARY =====`);
      console.log(`Device: ${specificDeviceUid}`);
      console.log(`Updated: ${success ? "Yes" : "No"}`);
      return;
    }
    
    // Update a specific device with auto-detection
    if (args.length === 1) {
      const specificDeviceUid = args[0];
      const device = await getDevice(specificDeviceUid);
      
      if (!device) {
        console.error(`Device with UID ${specificDeviceUid} not found`);
        return;
      }
      
      console.log(`Found device: ${JSON.stringify(device, null, 2)}`);
      
      // Detect better device info
      const { deviceName, deviceType, deviceInfo } = detectDeviceType(device);
      
      // Update if we have better info
      if (deviceType !== device.deviceType || deviceName !== device.deviceName) {
        const success = await updateDeviceInfo(device.uid, deviceName, deviceType, deviceInfo);
        console.log(`\n===== UPDATE SUMMARY =====`);
        console.log(`Device: ${device.uid}`);
        console.log(`Updated: ${success ? "Yes" : "No"}`);
        console.log(`New type: ${deviceType}`);
        console.log(`New name: ${deviceName}`);
      } else {
        console.log(`No better info available for device ${device.uid}`);
        console.log(`\n===== UPDATE SUMMARY =====`);
        console.log(`Device: ${device.uid}`);
        console.log(`Updated: No (no better info available)`);
      }
      
      return;
    }
    
    // Default: Update all devices with auto-detection
    const devices = await getAllDevices();
    console.log(`Found ${devices.length} devices`);
    
    // Update each device with unknown info
    let updatedCount = 0;
    let skippedCount = 0;
    
    for (const device of devices) {
      if (device.deviceType === "unknown" || device.deviceName === "Unknown device" || !device.deviceInfo) {
        // Detect better device info
        const { deviceName, deviceType, deviceInfo } = detectDeviceType(device);
        
        // Update if we have better info
        if (deviceType !== device.deviceType || deviceName !== device.deviceName || deviceInfo !== device.deviceInfo) {
          const success = await updateDeviceInfo(device.uid, deviceName, deviceType, deviceInfo);
          if (success) {
            updatedCount++;
            console.log(`Updated device ${device.uid}: ${deviceName} (${deviceType})`);
          }
        } else {
          skippedCount++;
          console.log(`Skipped device ${device.uid}: No better info available`);
        }
      } else {
        skippedCount++;
        console.log(`Skipped device ${device.uid}: Already has good info`);
      }
    }
    
    console.log("\n===== UPDATE SUMMARY =====");
    console.log(`Total devices: ${devices.length}`);
    console.log(`Updated: ${updatedCount}`);
    console.log(`Skipped: ${skippedCount}`);
    
  } catch (error) {
    console.error("Error:", error);
  } finally {
    clientStub.close();
  }
}

// Run the main function
main();
