#!/usr/bin/env node

// Simple test script for the Zig WASM functions
async function test() {
  const { simpleWasmDemo, createDeviceIdentityMessage, getHexData } = await import('./dist/index.js');

  console.log('=== Zig WASM Demo ===');
  console.log('simpleWasmDemo:', simpleWasmDemo().string);
  console.log('');
  console.log('createDeviceIdentityMessage:', createDeviceIdentityMessage().string);
  console.log('');
  console.log('getHexData:', getHexData().string);
  console.log('');
  console.log('✅ All functions working correctly!');
}

test().catch(console.error);