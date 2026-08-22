const std = @import("std");
const binary = @import("binary");

test "BinaryWriter basic functionality" {
    var buffer: [10]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);

    try writer.writeByte(0x42);
    try writer.writeBytes(&[_]u8{ 0x01, 0x02, 0x03 });

    try std.testing.expectEqual(@as(usize, 4), writer.getPos());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x42, 0x01, 0x02, 0x03 }, writer.getWritten());
}

test "BinaryReader basic functionality" {
    const data = [_]u8{ 0x42, 0x01, 0x02, 0x03 };
    var reader = binary.BinaryReader.init(&data);

    try std.testing.expectEqual(@as(u8, 0x42), try reader.readByte());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, try reader.readBytes(3));
    try std.testing.expect(reader.isAtEnd());
}

test "varint encoding/decoding" {
    var buffer: [10]u8 = undefined;
    const test_values = [_]u64{ 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF };

    for (test_values) |value| {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.encodeVarint(value, &writer);
        const encoded = writer.getWritten();

        var reader = binary.BinaryReader.init(encoded);
        const decoded = try binary.decodeVarint(&reader);

        try std.testing.expectEqual(value, decoded);
        try std.testing.expectEqual(binary.getVarintSize(value), bytes_written);
    }
}

test "varint edge cases" {
    var buffer: [10]u8 = undefined;

    const max_u64 = std.math.maxInt(u64);
    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeVarint(max_u64, &writer);
    const encoded = writer.getWritten();

    var reader = binary.BinaryReader.init(encoded);
    const decoded = try binary.decodeVarint(&reader);
    try std.testing.expectEqual(max_u64, decoded);

    const overflow_data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var overflow_reader = binary.BinaryReader.init(&overflow_data);
    try std.testing.expectError(binary.BinaryError.InvalidVarint, binary.decodeVarint(&overflow_reader));
}

test "string encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_strings = [_][]const u8{
        "",
        "hello",
        "Hello, 世界!",
        "🚀 Unicode test",
        "g" ** 50,
    };

    for (test_strings) |test_str| {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.encodeString(test_str, &writer);
        const encoded = writer.getWritten();

        var reader = binary.BinaryReader.init(encoded);
        const decoded = try binary.decodeString(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualStrings(test_str, decoded);
        try std.testing.expectEqual(encoded.len, bytes_written);
    }
}

test "string encoding invalid UTF-8" {
    var buffer: [10]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);

    const invalid_utf8 = [_]u8{ 0xFF, 0xFE, 0xFD };
    try std.testing.expectError(binary.BinaryError.InvalidUtf8, binary.encodeString(&invalid_utf8, &writer));
}

test "string decoding invalid UTF-8" {
    const allocator = std.testing.allocator;
    const invalid_data = [_]u8{ binary.BINARY_8, 0x03, 0xFF, 0xFE, 0xFD };
    var reader = binary.BinaryReader.init(&invalid_data);

    try std.testing.expectError(binary.BinaryError.InvalidUtf8, binary.decodeString(&reader, allocator));
}

test "byte array encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_arrays = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0xFF, 0xFE, 0xFD },
        &[_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 },
        &[_]u8{0xFF} ** 50,
    };

    for (test_arrays) |test_bytes| {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.encodeBytes(test_bytes, &writer);
        const encoded = writer.getWritten();

        var reader = binary.BinaryReader.init(encoded);
        const decoded = try binary.decodeBytes(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, test_bytes, decoded);
        try std.testing.expectEqual(binary.getBytesEncodedSize(test_bytes), bytes_written);
    }
}

test "compression/decompression" {
    const test_data = [_][]const u8{
        "hello world",
        "Hello, World! This is a test string for compression.",
    };

    for (test_data) |data| {
        _ = data;
    }
}

test "single byte tokens" {
    const allocator = std.testing.allocator;
    try binary.initTokens(allocator);

    try std.testing.expectEqual(@as(?u8, 1), binary.getSingleByteToken("xmlstreamstart"));
    try std.testing.expectEqual(@as(?u8, 2), binary.getSingleByteToken("xmlstreamend"));
    try std.testing.expectEqual(@as(?u8, 3), binary.getSingleByteToken("s.whatsapp.net"));

    try std.testing.expectEqualStrings("xmlstreamstart", binary.getStringForSingleByteToken(1).?);
    try std.testing.expectEqualStrings("xmlstreamend", binary.getStringForSingleByteToken(2).?);
    try std.testing.expectEqualStrings("s.whatsapp.net", binary.getStringForSingleByteToken(3).?);

    try std.testing.expectEqual(@as(?u8, null), binary.getSingleByteToken("nonexistent"));
    try std.testing.expectEqual(@as(?[]const u8, null), binary.getStringForSingleByteToken(255));
}

test "writeString tokenization" {
    const allocator = std.testing.allocator;
    try binary.initTokens(allocator);

    var buffer: [100]u8 = undefined;

    {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.writeString("xmlstreamstart", &writer);
        const encoded = writer.getWritten();

        try std.testing.expectEqual(@as(usize, 1), bytes_written);
        try std.testing.expectEqual(@as(u8, 1), encoded[0]);
    }

    {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.writeString("read-self", &writer);
        const encoded = writer.getWritten();

        try std.testing.expectEqual(@as(usize, 2), bytes_written);
        try std.testing.expectEqual(binary.DICTIONARY_0, encoded[0]);
        try std.testing.expectEqual(@as(u8, 0), encoded[1]);
    }

    {
        var writer = binary.BinaryWriter.init(&buffer);
        const bytes_written = try binary.writeString("nonexistent", &writer);
        const encoded = writer.getWritten();

        try std.testing.expectEqual(@as(usize, 13), bytes_written);
        try std.testing.expectEqual(binary.BINARY_8, encoded[0]);
        try std.testing.expectEqual(@as(u8, 11), encoded[1]);
        try std.testing.expectEqualSlices(u8, "nonexistent", encoded[2..]);
    }
}

test "decoded tokenized node borrows static strings" {
    const allocator = std.testing.allocator;
    try binary.initTokens(allocator);

    try std.testing.expect(binary.getSingleByteToken("message") != null);
    try std.testing.expect(binary.getSingleByteToken("s.whatsapp.net") != null);

    var source = try binary.Node.init(allocator, "message");
    defer source.deinit();
    try source.addAttribute("to", "s.whatsapp.net");

    var buffer: [128]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeNode(&source, &writer);

    var reader = binary.BinaryReader.init(writer.getWritten());
    var decoded = try binary.decodeNode(&reader, allocator);
    defer decoded.deinit();

    try std.testing.expectEqualStrings("message", decoded.tag);
    try std.testing.expect(!decoded.tag_owned);
    try std.testing.expectEqual(@as(usize, 1), decoded.attributes.items.len);
    try std.testing.expectEqualStrings("to", decoded.attributes.items[0].key);
    try std.testing.expect(!decoded.attributes.items[0].key_owned);
    try std.testing.expectEqualStrings("s.whatsapp.net", decoded.attributes.items[0].value);
    try std.testing.expect(!decoded.attributes.items[0].value_owned);
}

test "node creation and deinitialization" {
    const allocator = std.testing.allocator;

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();

    try node.addAttribute("type", "chat");
    try node.addAttribute("id", "123");
    try node.setContentBytes("Hello World");

    try std.testing.expectEqualStrings("message", node.tag);
    try std.testing.expectEqual(@as(usize, 2), node.attributes.items.len);
    try std.testing.expectEqualStrings("chat", node.attributes.items[0].value);
    try std.testing.expectEqualStrings("Hello World", node.getContentBytes().?);
}

test "JID parsing and operations" {
    const allocator = std.testing.allocator;

    const test_jids = [_]struct {
        input: []const u8,
        expected_user: []const u8,
        expected_server: []const u8,
        expected_agent: u8,
        expected_device: u16,
        expected_integrator: u16,
        is_group: bool,
        is_broadcast: bool,
        is_interop: bool,
        is_messenger: bool,
    }{
        .{ .input = "1234567890@s.whatsapp.net", .expected_user = "1234567890", .expected_server = "s.whatsapp.net", .expected_agent = 0, .expected_device = 0, .expected_integrator = 0, .is_group = false, .is_broadcast = false, .is_interop = false, .is_messenger = false },
        .{ .input = "1234567890-9876543210@g.us", .expected_user = "1234567890-9876543210", .expected_server = "g.us", .expected_agent = 0, .expected_device = 0, .expected_integrator = 0, .is_group = true, .is_broadcast = false, .is_interop = false, .is_messenger = false },
        .{ .input = "status@broadcast", .expected_user = "status", .expected_server = "broadcast", .expected_agent = 0, .expected_device = 0, .expected_integrator = 0, .is_group = false, .is_broadcast = true, .is_interop = false, .is_messenger = false },
        .{ .input = "0.12345:56789@interop", .expected_user = "", .expected_server = "interop", .expected_agent = 0, .expected_device = 12345, .expected_integrator = 56789, .is_group = false, .is_broadcast = false, .is_interop = true, .is_messenger = false },
        .{ .input = "1.54321@messenger", .expected_user = "", .expected_server = "messenger", .expected_agent = 1, .expected_device = 54321, .expected_integrator = 0, .is_group = false, .is_broadcast = false, .is_interop = false, .is_messenger = true },
    };

    for (test_jids) |test_case| {
        var jid = try binary.JID.parse(test_case.input, allocator);
        defer jid.deinit();

        try std.testing.expectEqualStrings(test_case.expected_user, jid.user);
        try std.testing.expectEqualStrings(test_case.expected_server, jid.server);
        try std.testing.expectEqual(test_case.expected_agent, jid.agent);
        try std.testing.expectEqual(test_case.expected_device, jid.device);
        try std.testing.expectEqual(test_case.expected_integrator, jid.integrator);

        try std.testing.expectEqual(test_case.is_group, jid.isGroup());
        try std.testing.expectEqual(test_case.is_broadcast, jid.isBroadcast());
        try std.testing.expectEqual(test_case.is_interop, jid.isInterop());
        try std.testing.expectEqual(test_case.is_messenger, jid.isMessenger());

        const jid_str = try jid.toString(allocator);
        defer allocator.free(jid_str);
        try std.testing.expectEqualStrings(test_case.input, jid_str);
    }
}

test "JID_PAIR server-only JID (empty user)" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buf);

    try writer.writeByte(binary.JID_PAIR);
    try writer.writeByte(binary.LIST_EMPTY);
    try writer.writeByte(binary.getSingleByteToken("s.whatsapp.net") orelse unreachable);

    var reader = binary.BinaryReader.init(writer.getWritten());
    const decoded = try binary.decodeString(&reader, allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("s.whatsapp.net", decoded);
}

test "JID toString server-only" {
    const allocator = std.testing.allocator;

    const jid = binary.JID{
        .user = "",
        .server = "s.whatsapp.net",
        .agent = 0,
        .device = 0,
        .integrator = 0,
        .allocator = allocator,
    };
    const str = try jid.toString(allocator);
    defer allocator.free(str);
    try std.testing.expectEqualStrings("s.whatsapp.net", str);
}

test "JID toString with device" {
    const allocator = std.testing.allocator;

    const jid = binary.JID{
        .user = "559980000001",
        .server = "s.whatsapp.net",
        .agent = 0,
        .device = 33,
        .integrator = 0,
        .allocator = allocator,
    };
    const str = try jid.toString(allocator);
    defer allocator.free(str);
    try std.testing.expectEqualStrings("559980000001:33@s.whatsapp.net", str);
}

test "JID toString simple" {
    const allocator = std.testing.allocator;

    const jid = binary.JID{
        .user = "559980000001",
        .server = "s.whatsapp.net",
        .agent = 0,
        .device = 0,
        .integrator = 0,
        .allocator = allocator,
    };
    const str = try jid.toString(allocator);
    defer allocator.free(str);
    try std.testing.expectEqualStrings("559980000001@s.whatsapp.net", str);
}

test "node with children encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [2048]u8 = undefined;

    try binary.initTokens(allocator);

    var parent_node = try binary.Node.init(allocator, "envelope");
    defer parent_node.deinit();
    try parent_node.addAttribute("xmlns", "jabber:client");

    var message_node = try binary.Node.init(allocator, "message");
    try message_node.addAttribute("to", "recipient@s.whatsapp.net");
    try message_node.addAttribute("type", "chat");
    try message_node.setContentBytes("Hello from child node!");

    var presence_node = try binary.Node.init(allocator, "presence");
    try presence_node.addAttribute("type", "available");

    try parent_node.addChild(&message_node);
    try parent_node.addChild(&presence_node);

    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeNode(&parent_node, &writer);
    const encoded = writer.getWritten();

    var reader = binary.BinaryReader.init(encoded);
    var decoded_parent = try binary.decodeNode(&reader, allocator);
    defer decoded_parent.deinit();

    try std.testing.expectEqualStrings("envelope", decoded_parent.tag);
    try std.testing.expectEqual(@as(usize, 1), decoded_parent.attributes.items.len);
    try std.testing.expectEqualStrings("xmlns", decoded_parent.attributes.items[0].key);
    try std.testing.expectEqualStrings("jabber:client", decoded_parent.attributes.items[0].value);
    try std.testing.expect(decoded_parent.content != null);
    try std.testing.expect(decoded_parent.content.? == .Nodes);
    try std.testing.expectEqual(@as(usize, 2), decoded_parent.content.?.Nodes.items.len);

    const decoded_message = &decoded_parent.content.?.Nodes.items[0];
    try std.testing.expectEqualStrings("message", decoded_message.tag);
    try std.testing.expectEqual(@as(usize, 2), decoded_message.attributes.items.len);
    try std.testing.expectEqualStrings("Hello from child node!", decoded_message.getContentBytes().?);

    const decoded_presence = &decoded_parent.content.?.Nodes.items[1];
    try std.testing.expectEqualStrings("presence", decoded_presence.tag);
    try std.testing.expectEqual(@as(usize, 1), decoded_presence.attributes.items.len);
    try std.testing.expectEqualStrings("type", decoded_presence.attributes.items[0].key);
    try std.testing.expectEqualStrings("available", decoded_presence.attributes.items[0].value);
}

test "AD_JID with LID roundtrip" {
    const allocator = std.testing.allocator;
    var buffer: [256]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);

    const lid_device_jid = "124953718435910:50@lid";
    _ = try binary.encodeJid(lid_device_jid, &writer);
    const encoded = writer.getWritten();

    var reader = binary.BinaryReader.init(encoded);
    const decoded = try binary.decodeString(&reader, allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(lid_device_jid, decoded);
}
