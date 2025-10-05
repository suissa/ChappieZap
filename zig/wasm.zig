const std = @import("std");
// NOTE: Imports from src/ directory are disabled due to zigar compatibility
// issues with Zig 0.15.1. This is temporary until zigar supports the latest Zig.
// const utils = @import("../src/utils.zig");

// Simple WASM demo that doesn't use protobuf
pub fn simpleWasmDemo() []const u8 {
    return "Hello from Zig WASM! Protobuf demo compiled to WebAssembly.";
}

// Function that demonstrates protobuf-like functionality
pub fn createDeviceIdentityMessage() []const u8 {
    return "ADVDeviceIdentity: rawId=12345, timestamp=1640995200, keyIndex=1, accountType=E2EE, deviceType=E2EE";
}

// Function that returns hex-encoded data
pub fn getHexData() []const u8 {
    return "08b9601080b3be8e06180120002800";
}

// NOTE: These functions would use imported utilities once zigar supports Zig 0.15.1
// pub fn getDeviceInfo() []const u8 {
//     return utils.formatDeviceInfo(12345, 1640995200, 1);
// }
//
// pub fn getDataChecksum() []const u8 {
//     const data = "test data";
//     const checksum = utils.calculateChecksum(data);
//     return std.fmt.comptimePrint("Checksum of '{}': {}", .{ std.fmt.fmtSliceEscapeLower(data), checksum });
// }
