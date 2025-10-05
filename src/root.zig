const std = @import("std");
const protobuf = @import("protobuf");
const whatsapp = @import("gen/whatsapp.pb.zig");

pub fn demonstrateProtobuf() !void {
    const allocator = std.heap.page_allocator;

    var device = whatsapp.ADVDeviceIdentity{
        .rawId = 12345,
        .timestamp = 1640995200,
        .keyIndex = 1,
        .accountType = .E2EE,
        .deviceType = .E2EE,
    };

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try device.encode(&writer.writer, allocator);

    const encoded_data = writer.written();

    var reader: std.Io.Reader = .fixed(encoded_data);
    var decoded_device = try whatsapp.ADVDeviceIdentity.decode(&reader, allocator);
    defer decoded_device.deinit(allocator);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Protobuf demo: Encoded {} bytes\n", .{encoded_data.len});
    try stdout.print("Protobuf demo: Hex data: ", .{});
    try stdout.printHex(encoded_data, .lower);
    try stdout.print("\n", .{});
    try stdout.print("Protobuf demo: Successfully encoded and decoded ADVDeviceIdentity message!\n", .{});
    try stdout.flush();
}

test "protobuf encoding/decoding" {
    const allocator = std.testing.allocator;

    var original = whatsapp.ADVDeviceIdentity{
        .rawId = 42,
        .timestamp = 1234567890,
        .keyIndex = 5,
        .accountType = .E2EE,
        .deviceType = .HOSTED,
    };

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try original.encode(&writer.writer, allocator);
    const encoded = writer.written();

    var reader: std.Io.Reader = .fixed(encoded);
    var decoded = try whatsapp.ADVDeviceIdentity.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(original.rawId, decoded.rawId);
    try std.testing.expectEqual(original.timestamp, decoded.timestamp);
    try std.testing.expectEqual(original.keyIndex, decoded.keyIndex);
    try std.testing.expectEqual(original.accountType, decoded.accountType);
    try std.testing.expectEqual(original.deviceType, decoded.deviceType);
}
