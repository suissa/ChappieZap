const std = @import("std");
const protobuf = @import("protobuf");
const whatsapp = @import("gen/whatsapp.pb.zig");
const binary = @import("binary");
const whatsapp_ws = @import("whatsapp_websocket");

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

pub fn demonstrateTokensAndNodes() !void {
    const allocator = std.heap.page_allocator;

    // Initialize tokens
    try binary.initTokens(allocator);

    // Demonstrate token lookup
    const iq_token = binary.getSingleByteToken("iq");
    const read_self_token = binary.getDoubleByteToken("read-self");

    // Create a sample WhatsApp message node
    var message_node = try binary.Node.init(allocator, "message");
    defer message_node.deinit();

    try message_node.addAttribute("type", "chat");
    try message_node.addAttribute("id", "msg-123");

    // Encode the node
    var buffer: [1024]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeNode(&message_node, &writer);
    const encoded = writer.getWritten();

    // Decode the node
    var reader = binary.BinaryReader.init(encoded);
    var decoded_node = try binary.decodeNode(&reader, allocator);
    defer decoded_node.deinit();

    var stdout_buffer: [2048]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Tokens demo: 'iq' token = {}\n", .{iq_token.?});
    try stdout.print("Tokens demo: 'read-self' token = page {}, token {}\n", .{ read_self_token.?[0], read_self_token.?[1] });

    try stdout.print("Node demo: Encoded message node ({} bytes): ", .{encoded.len});
    for (encoded) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    try stdout.print("Node demo: Decoded tag: '{s}'\n", .{decoded_node.tag});
    try stdout.print("Node demo: Attributes:\n", .{});
    for (decoded_node.attributes.items) |attr| {
        try stdout.print("  {s} = '{s}'\n", .{ attr.key, attr.value });
    }
    try stdout.flush();
}

pub fn demonstrateJidsAndChildren() !void {
    const allocator = std.heap.page_allocator;

    // Initialize tokens
    try binary.initTokens(allocator);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Demonstrate JID parsing
    try stdout.print("JID demo: Parsing WhatsApp JIDs\n", .{});

    const jid_strings = [_][]const u8{
        "1234567890@s.whatsapp.net",
        "1234567890-9876543210@g.us",
        "status@broadcast",
        "user@domain.com/resource",
    };

    for (jid_strings) |jid_str| {
        var jid = try binary.JID.parse(jid_str, allocator);
        defer jid.deinit();

        const jid_back = try jid.toString(allocator);
        defer allocator.free(jid_back);

        try stdout.print("  '{s}' -> user='{s}', server='{s}'", .{ jid_str, jid.user, jid.server });
        if (jid.device > 0) {
            try stdout.print(", device={}", .{jid.device});
        }
        if (jid.integrator > 0) {
            try stdout.print(", integrator={}", .{jid.integrator});
        }
        try stdout.print(" (group: {}, broadcast: {}, interop: {}, messenger: {})\n", .{ jid.isGroup(), jid.isBroadcast(), jid.isInterop(), jid.isMessenger() });
    }

    // Demonstrate node with children
    try stdout.print("\nNode demo: Creating node with children\n", .{});

    // Create a parent envelope
    var envelope = try binary.Node.init(allocator, "envelope");
    defer envelope.deinit();

    try envelope.addAttribute("xmlns", "jabber:client");

    // Create a message child
    var message = try binary.Node.init(allocator, "message");

    try message.addAttribute("to", "recipient@s.whatsapp.net");
    try message.addAttribute("type", "chat");
    try message.setContentBytes("Hello from nested message!");

    // Create a presence child
    var presence = try binary.Node.init(allocator, "presence");

    try presence.addAttribute("type", "available");

    // Add children to envelope (envelope now owns them)
    try envelope.addChild(&message);
    try envelope.addChild(&presence);

    // Encode the envelope with children
    var buffer: [2048]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeNode(&envelope, &writer);
    const encoded = writer.getWritten();

    // Decode the envelope
    var reader = binary.BinaryReader.init(encoded);
    var decoded_envelope = try binary.decodeNode(&reader, allocator);
    defer decoded_envelope.deinit();

    try stdout.print("  Encoded envelope with children ({} bytes)\n", .{encoded.len});
    try stdout.print("  Decoded envelope: tag='{s}', {} attributes", .{
        decoded_envelope.tag,
        decoded_envelope.attributes.items.len,
    });
    if (decoded_envelope.content) |content| {
        if (content == .Nodes) {
            try stdout.print(", {} children", .{content.Nodes.items.len});
        }
    }
    try stdout.print("\n", .{});

    // Show child details
    if (decoded_envelope.content) |content| {
        if (content == .Nodes) {
            for (content.Nodes.items, 0..) |*child, i| {
                try stdout.print("    Child {}: tag='{s}', {} attributes", .{ i + 1, child.tag, child.attributes.items.len });
                if (child.getContentBytes()) |child_content| {
                    try stdout.print(", content='{s}'", .{child_content});
                }
                try stdout.print("\n", .{});
            }
        }
    }

    try stdout.flush();
}

pub fn demonstrateWebSocket() !void {
    const allocator = std.heap.page_allocator;
    try whatsapp_ws.demonstrateWebSocket(allocator);
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
