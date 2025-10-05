const std = @import("std");
const protobuf = @import("protobuf");
const whatsapp = @import("gen/whatsapp.pb.zig");
const binary = @import("binary");

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
    for (encoded_data) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});
    try stdout.print("Protobuf demo: Successfully encoded and decoded ADVDeviceIdentity message!\n", .{});
    try stdout.flush();
}

pub fn demonstrateProtobufToString(allocator: std.mem.Allocator) ![]u8 {
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

    // Create a string buffer for the result
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const result_writer = fbs.writer();

    try result_writer.print("Protobuf demo: Encoded {} bytes\n", .{encoded_data.len});
    try result_writer.print("Protobuf demo: Hex data: ", .{});
    for (encoded_data) |byte| {
        try result_writer.print("{x:0>2}", .{byte});
    }
    try result_writer.print("\n", .{});
    try result_writer.print("Protobuf demo: Successfully encoded and decoded ADVDeviceIdentity message!\n", .{});

    const result_len = fbs.pos;
    return allocator.dupe(u8, buffer[0..result_len]);
}

pub fn demonstrateBinary() !void {
    const allocator = std.heap.page_allocator;

    // Demonstrate varint encoding/decoding
    var buffer: [20]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);

    const value: u64 = 123456789;
    const bytes_written = try binary.encodeVarint(value, &writer);
    const encoded = writer.getWritten();

    var reader = binary.BinaryReader.init(encoded);
    const decoded = try binary.decodeVarint(&reader);

    // Demonstrate string encoding/decoding
    var str_buffer: [100]u8 = undefined;
    var str_writer = binary.BinaryWriter.init(&str_buffer);

    const test_string = "Hello, WhatsApp Binary Protocol! 🚀";
    const str_bytes_written = try binary.encodeString(test_string, &str_writer);
    const str_encoded = str_writer.getWritten();

    var str_reader = binary.BinaryReader.init(str_encoded);
    const decoded_string = try binary.decodeString(&str_reader, allocator);
    defer allocator.free(decoded_string);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Binary demo: Varint {} encoded in {} bytes: ", .{ value, bytes_written });
    for (encoded) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print(" -> decoded: {}\n", .{decoded});

    try stdout.print("Binary demo: String '{s}' encoded in {} bytes\n", .{ test_string, str_bytes_written });
    try stdout.print("Binary demo: Decoded string: '{s}'\n", .{decoded_string});
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
