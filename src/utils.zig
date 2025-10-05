const std = @import("std");

// Utility function that works in both native and WASM environments
pub fn formatDeviceInfo(rawId: i64, timestamp: i64, keyIndex: u32) []const u8 {
    return std.fmt.comptimePrint("Device: rawId={}, timestamp={}, keyIndex={}", .{ rawId, timestamp, keyIndex });
}

// Another utility that could be shared
pub fn calculateChecksum(data: []const u8) u32 {
    var checksum: u32 = 0;
    for (data) |byte| {
        checksum = (checksum << 5) + checksum + byte; // Simple hash
    }
    return checksum;
}
