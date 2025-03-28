#!/usr/bin/env node

import fetch from 'node-fetch';

// Replace with your API endpoint
const API_ENDPOINT = 'http://localhost:3000';

// Test user email
const TEST_EMAIL = 'darren@darkolive.co.uk';

// Function to test password recovery
async function testPasswordRecovery() {
  console.log('Step 1: Testing password recovery request...');
  
  try {
    const response = await fetch(`${API_ENDPOINT}/auth/recover`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: TEST_EMAIL,
        verificationCookie: '', // Should be obtained from a successful email verification
        clientIp: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test)',
        sessionId: 'test-session-id'
      }),
    });

    const data = await response.json();
    console.log('Recovery Response:', data);
    
    if (data.success) {
      console.log('✅ Password recovery request successful!');
      console.log('Now check the console logs to find the reset token that was generated');
      console.log('You should see a log entry with resetToken value. Copy this for the next step.');
    } else {
      console.log('❌ Password recovery request failed:', data.error);
    }
  } catch (error) {
    console.error('Error during recovery request:', error);
  }
}

// Function to test password reset with token
async function testPasswordReset(resetToken) {
  if (!resetToken) {
    console.error('❌ Reset token is required to test password reset.');
    console.log('Please run the recovery first and note the token from the logs.');
    return;
  }

  console.log('Step 2: Testing password reset with token...');
  
  try {
    const response = await fetch(`${API_ENDPOINT}/auth/reset`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        resetToken: resetToken,
        email: TEST_EMAIL,
        passphrase: 'NewSecurePassword123!',
        clientIp: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test)',
        sessionId: 'test-session-id'
      }),
    });

    const data = await response.json();
    console.log('Reset Response:', data);
    
    if (data.success) {
      console.log('✅ Password reset successful!');
    } else {
      console.log('❌ Password reset failed:', data.error);
    }
  } catch (error) {
    console.error('Error during password reset:', error);
  }
}

// Main function
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  
  if (command === 'recover') {
    await testPasswordRecovery();
  } else if (command === 'reset') {
    const resetToken = args[1];
    if (!resetToken) {
      console.error('❌ Reset token is required for the reset command.');
      console.log('Usage: node test-password-reset.mjs reset <reset-token>');
      return;
    }
    await testPasswordReset(resetToken);
  } else {
    console.log('Usage:');
    console.log('  To test recovery: node test-password-reset.mjs recover');
    console.log('  To test reset: node test-password-reset.mjs reset <reset-token>');
  }
}

main().catch(console.error);
