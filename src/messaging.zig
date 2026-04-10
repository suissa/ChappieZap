const std = @import("std");
const binary = @import("binary");
const protobuf = @import("protobuf");
const signal = @import("signal");
const prekey_mod = @import("prekey");
const whatsapp = @import("whatsapp_proto");
const reporting = @import("reporting");
const fd = protobuf.fd;
const retained_message_capacity = 64 * 1024;
// Protobuf field numbers from wa.Message:
// field 1  = conversation (string)
// field 6  = extendedTextMessage (submessage) → field 1 = text
// field 31 = deviceSentMessage (submessage)   → field 2 = message (Message)

/// Build a prekey fetch IQ: <iq xmlns="encrypt" type="get"><key><user jid="..."/></key></iq>
pub fn buildFetchPrekeysIq(allocator: std.mem.Allocator, iq_id: []const u8, jids: []const []const u8) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();

    try iq.addAttributeBorrowed("id", iq_id);
    try iq.addAttributeBorrowed("type", "get");
    try iq.addAttributeBorrowed("xmlns", "encrypt");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    var key_node = binary.Node.initBorrowed(allocator, "key");
    defer key_node.deinit();

    for (jids) |jid| {
        var user_node = binary.Node.initBorrowed(allocator, "user");
        defer user_node.deinit();
        try user_node.addAttributeBorrowed("jid", jid);
        try key_node.addChild(&user_node);
    }

    try iq.addChild(&key_node);
    return iq;
}

/// Build a direct-message fanout stanza with one participant.
/// <message to="..." id="..." type="text">
///   <participants>
///     <to jid="..."><enc type="pkmsg|msg" v="2">ciphertext</enc></to>
///   </participants>
/// </message>
pub const DirectParticipant = struct {
    jid: []const u8,
    jid_owned: ?[]u8 = null,
    ciphertext: []const u8,
    is_prekey: bool,
};

pub const ReportingContext = reporting.ReportingContext;

const OutboundMessage = struct {
    conversation: ?[]const u8 = null,
    deviceSentMessage: ?OutboundDeviceSentMessage = null,
    messageContextInfo: ?OutboundMessageContextInfo = null,

    pub const _desc_table = .{
        .conversation = fd(1, .{ .scalar = .string }),
        .deviceSentMessage = fd(31, .submessage),
        .messageContextInfo = fd(35, .submessage),
    };

    pub fn encode(
        self: @This(),
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) (std.Io.Writer.Error || std.mem.Allocator.Error)!void {
        return protobuf.encode(writer, allocator, self);
    }
};

const OutboundMessageContextInfo = struct {
    messageSecret: ?[]const u8 = null,
    reportingTokenVersion: ?i32 = null,

    pub const _desc_table = .{
        .messageSecret = fd(3, .{ .scalar = .bytes }),
        .reportingTokenVersion = fd(8, .{ .scalar = .int32 }),
    };

    pub fn encode(
        self: @This(),
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) (std.Io.Writer.Error || std.mem.Allocator.Error)!void {
        return protobuf.encode(writer, allocator, self);
    }
};

const OutboundDeviceSentMessage = struct {
    destinationJid: ?[]const u8 = null,
    message: ?*const OutboundMessage = null,
    phash: ?[]const u8 = null,

    pub const _desc_table = .{
        .destinationJid = fd(1, .{ .scalar = .string }),
        .message = fd(2, .submessage),
        .phash = fd(3, .{ .scalar = .string }),
    };

    pub fn encode(
        self: @This(),
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) (std.Io.Writer.Error || std.mem.Allocator.Error)!void {
        return protobuf.encode(writer, allocator, self);
    }
};

pub fn buildFanoutMessageNode(
    allocator: std.mem.Allocator,
    chat_jid: []const u8,
    msg_id: []const u8,
    participants_data: []const DirectParticipant,
    device_identity_bytes: ?[]const u8,
) !binary.Node {
    var any_prekey = false;
    for (participants_data) |participant| any_prekey = any_prekey or participant.is_prekey;

    var msg = binary.Node.initBorrowed(allocator, "message");
    errdefer msg.deinit();

    try msg.addAttributeBorrowed("to", chat_jid);
    try msg.addAttributeBorrowed("id", msg_id);
    try msg.addAttributeBorrowed("type", "text");

    var participants = binary.Node.initBorrowed(allocator, "participants");
    defer participants.deinit();

    for (participants_data) |participant| {
        var to_node = binary.Node.initBorrowed(allocator, "to");
        defer to_node.deinit();
        try to_node.addAttributeBorrowed("jid", participant.jid);

        var enc_node = binary.Node.initBorrowed(allocator, "enc");
        defer enc_node.deinit();
        try enc_node.addAttributeBorrowed("v", "2");
        try enc_node.addAttributeBorrowed("type", if (participant.is_prekey) "pkmsg" else "msg");
        try enc_node.setContentBytesBorrowed(participant.ciphertext);
        try to_node.addChild(&enc_node);
        try participants.addChild(&to_node);
    }

    try msg.addChild(&participants);

    if (any_prekey) {
        if (device_identity_bytes) |bytes| {
            var device_identity = binary.Node.initBorrowed(allocator, "device-identity");
            defer device_identity.deinit();
            try device_identity.setContentBytesBorrowed(bytes);
            try msg.addChild(&device_identity);
        }
    }

    return msg;
}

pub fn buildMessageNode(
    allocator: std.mem.Allocator,
    chat_jid: []const u8,
    participant_jid: []const u8,
    msg_id: []const u8,
    ciphertext: []const u8,
    is_prekey_msg: bool,
    device_identity_bytes: ?[]const u8,
) !binary.Node {
    return buildFanoutMessageNode(allocator, chat_jid, msg_id, &[_]DirectParticipant{.{
        .jid = participant_jid,
        .ciphertext = ciphertext,
        .is_prekey = is_prekey_msg,
    }}, device_identity_bytes);
}

/// Legacy mock-server compatible direct message shape:
/// <message to="..." id="..." type="text"><enc .../></message>
/// Optionally appends <device-identity/> for pkmsg.
/// Generate a simple message ID (simplified version)
pub fn generateMessageId(io: std.Io) [22]u8 {
    var random_bytes: [9]u8 = undefined;
    io.random(&random_bytes);

    var result: [22]u8 = undefined;
    result[0] = '3';
    result[1] = 'E';
    result[2] = 'B';
    result[3] = '0';

    const hex_chars = "0123456789ABCDEF";
    for (0..9) |i| {
        result[4 + i * 2] = hex_chars[random_bytes[i] >> 4];
        result[4 + i * 2 + 1] = hex_chars[random_bytes[i] & 0x0F];
    }
    return result;
}

/// Encode a text message as protobuf (simplified — just the conversation field)
/// This is a minimal Message protobuf with field 1 = conversation text
pub fn encodeTextMessage(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return encodeTextMessageWithContext(allocator, text, null);
}

pub fn encodeTextMessageInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    text: []const u8,
) ![]const u8 {
    return encodeTextMessageWithContextInto(out, allocator, text, null);
}

pub fn encodeTextMessageWithContext(
    allocator: std.mem.Allocator,
    text: []const u8,
    reporting_ctx: ?*const ReportingContext,
) ![]u8 {
    const msg = OutboundMessage{
        .conversation = text,
        .messageContextInfo = if (reporting_ctx) |ctx| .{
            .messageSecret = &ctx.message_secret,
            .reportingTokenVersion = ctx.version,
        } else null,
    };
    return encodeOutboundMessageAlloc(allocator, msg);
}

pub fn encodeTextMessageWithContextInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    text: []const u8,
    reporting_ctx: ?*const ReportingContext,
) ![]const u8 {
    const msg = OutboundMessage{
        .conversation = text,
        .messageContextInfo = if (reporting_ctx) |ctx| .{
            .messageSecret = &ctx.message_secret,
            .reportingTokenVersion = ctx.version,
        } else null,
    };
    return encodeOutboundMessageInto(out, allocator, msg);
}

/// Wrap a text message in DeviceSentMessage for self-chat / own-device sync.
pub fn encodeDeviceSentTextMessage(
    allocator: std.mem.Allocator,
    destination_jid: []const u8,
    text: []const u8,
) ![]u8 {
    return encodeDeviceSentTextMessageWithContext(allocator, destination_jid, text, null);
}

pub fn encodeDeviceSentTextMessageInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    destination_jid: []const u8,
    text: []const u8,
) ![]const u8 {
    return encodeDeviceSentTextMessageWithContextInto(out, allocator, destination_jid, text, null);
}

pub fn encodeDeviceSentTextMessageWithContext(
    allocator: std.mem.Allocator,
    destination_jid: []const u8,
    text: []const u8,
    reporting_ctx: ?*const ReportingContext,
) ![]u8 {
    const inner = OutboundMessage{
        .conversation = text,
        .messageContextInfo = if (reporting_ctx) |ctx| .{
            .messageSecret = &ctx.message_secret,
            .reportingTokenVersion = ctx.version,
        } else null,
    };
    const outer = OutboundMessage{
        .deviceSentMessage = .{
            .destinationJid = destination_jid,
            .message = &inner,
            .phash = "",
        },
    };
    return encodeOutboundMessageAlloc(allocator, outer);
}

pub fn encodeDeviceSentTextMessageWithContextInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    destination_jid: []const u8,
    text: []const u8,
    reporting_ctx: ?*const ReportingContext,
) ![]const u8 {
    const inner = OutboundMessage{
        .conversation = text,
        .messageContextInfo = if (reporting_ctx) |ctx| .{
            .messageSecret = &ctx.message_secret,
            .reportingTokenVersion = ctx.version,
        } else null,
    };
    const outer = OutboundMessage{
        .deviceSentMessage = .{
            .destinationJid = destination_jid,
            .message = &inner,
            .phash = "",
        },
    };
    return encodeOutboundMessageInto(out, allocator, outer);
}

pub fn generateReportingContextForText(
    allocator: std.mem.Allocator,
    io: std.Io,
    text: []const u8,
    stanza_id: []const u8,
    sender_jid: []const u8,
    remote_jid: []const u8,
) !ReportingContext {
    return reporting.generateReportingContextForText(
        encodeTextMessage,
        allocator,
        io,
        text,
        stanza_id,
        sender_jid,
        remote_jid,
    );
}

pub fn buildReportingNode(
    allocator: std.mem.Allocator,
    reporting_ctx: *const ReportingContext,
) !binary.Node {
    return reporting.buildReportingNode(allocator, reporting_ctx);
}

/// Decode protobuf Message and extract text content.
/// Handles DeviceSentMessage unwrapping (companion device messages)
pub fn decodeTextMessage(data: []const u8) ?[]const u8 {
    // Unwrap DeviceSentMessage (field 31) → inner Message (field 2)
    if (pbFindField(data, 31)) |dsm_bytes| {
        if (pbFindField(dsm_bytes, 2)) |inner_msg| {
            return extractText(inner_msg);
        }
    }
    return extractText(data);
}

fn extractText(msg_data: []const u8) ?[]const u8 {
    // Message.conversation (field 1)
    if (pbFindField(msg_data, 1)) |text| {
        if (text.len > 0) return text;
    }
    // Message.extendedTextMessage (field 6) → text (field 1)
    if (pbFindField(msg_data, 6)) |ext| {
        if (pbFindField(ext, 1)) |text| return text;
    }
    return null;
}

/// Find a length-delimited protobuf field by number. Returns the field's raw bytes.
fn pbFindField(data: []const u8, target: u32) ?[]const u8 {
    var pos: usize = 0;
    while (pos < data.len) {
        const tag = pbVarint(data, &pos) orelse return null;
        const field = @as(u32, @intCast(tag >> 3));
        const wtype = @as(u3, @intCast(tag & 7));
        if (field == target and wtype == 2) {
            const len: usize = @intCast(pbVarint(data, &pos) orelse return null);
            if (pos + len > data.len) return null;
            return data[pos .. pos + len];
        }
        // Skip
        switch (wtype) {
            0 => _ = pbVarint(data, &pos) orelse return null,
            1 => pos = if (pos + 8 <= data.len) pos + 8 else return null,
            2 => {
                const len: usize = @intCast(pbVarint(data, &pos) orelse return null);
                pos = if (pos + len <= data.len) pos + len else return null;
            },
            5 => pos = if (pos + 4 <= data.len) pos + 4 else return null,
            else => return null,
        }
    }
    return null;
}

fn pbVarint(data: []const u8, pos: *usize) ?u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < data.len) {
        const byte = data[pos.*];
        pos.* += 1;
        result |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return result;
        shift = std.math.add(u6, shift, 7) catch return null;
    }
    return null;
}

fn encodeOutboundMessageAlloc(allocator: std.mem.Allocator, msg: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    _ = try encodeOutboundMessageInto(&out, allocator, msg);
    return out.toOwnedSlice(allocator);
}

fn encodeOutboundMessageInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    msg: anytype,
) ![]const u8 {
    if (out.capacity > retained_message_capacity) {
        out.clearAndFree(allocator);
    }
    var writer = std.Io.Writer.Allocating.fromArrayList(allocator, out);
    errdefer writer.deinit();

    writer.clearRetainingCapacity();
    try msg.encode(&writer.writer, allocator);

    const written_len = writer.written().len;
    out.* = writer.toArrayList();
    return out.items[0..written_len];
}

test "buildMessageNode uses participants fanout shape" {
    const allocator = std.testing.allocator;

    var node = try buildMessageNode(
        allocator,
        "559984726662@s.whatsapp.net",
        "236395184570386@lid",
        "3EB0123456789ABCDEFFF0",
        &[_]u8{ 0x01, 0x02, 0x03 },
        false,
        null,
    );
    defer node.deinit();

    try std.testing.expectEqualStrings("message", node.tag);
    try std.testing.expectEqualStrings("559984726662@s.whatsapp.net", node.getAttribute("to") orelse "");
    try std.testing.expectEqualStrings("text", node.getAttribute("type") orelse "");
    try std.testing.expect(node.getContentNodes() != null);
    try std.testing.expect(node.getAttribute("t") == null);

    const children = node.getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 1), children.len);
    try std.testing.expectEqualStrings("participants", children[0].tag);

    const participant_children = children[0].getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 1), participant_children.len);
    try std.testing.expectEqualStrings("to", participant_children[0].tag);
    try std.testing.expectEqualStrings("236395184570386@lid", participant_children[0].getAttribute("jid") orelse "");

    const enc_children = participant_children[0].getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 1), enc_children.len);
    try std.testing.expectEqualStrings("enc", enc_children[0].tag);
    try std.testing.expectEqualStrings("2", enc_children[0].getAttribute("v") orelse "");
    try std.testing.expectEqualStrings("msg", enc_children[0].getAttribute("type") orelse "");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, enc_children[0].getContentBytes().?);
}

test "buildMessageNode adds device-identity for prekey messages" {
    const allocator = std.testing.allocator;

    const identity_bytes = [_]u8{ 0xAA, 0xBB };
    var node = try buildMessageNode(
        allocator,
        "559984726662@s.whatsapp.net",
        "236395184570386@lid",
        "3EB0123456789ABCDEFFF1",
        &[_]u8{0x01},
        true,
        &identity_bytes,
    );
    defer node.deinit();

    const children = node.getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("participants", children[0].tag);
    try std.testing.expectEqualStrings("device-identity", children[1].tag);
    try std.testing.expectEqualSlices(u8, &identity_bytes, children[1].getContentBytes().?);
}

test "buildFanoutMessageNode supports multiple participants" {
    const allocator = std.testing.allocator;

    const participants = [_]DirectParticipant{
        .{ .jid = "111@s.whatsapp.net", .ciphertext = &[_]u8{0x01}, .is_prekey = false },
        .{ .jid = "111:4@s.whatsapp.net", .ciphertext = &[_]u8{ 0x02, 0x03 }, .is_prekey = true },
    };
    const device_identity = [_]u8{0xAA};
    var node = try buildFanoutMessageNode(
        allocator,
        "111@s.whatsapp.net",
        "3EB0123456789ABCDEFFF3",
        &participants,
        &device_identity,
    );
    defer node.deinit();

    const children = node.getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("participants", children[0].tag);
    try std.testing.expectEqualStrings("device-identity", children[1].tag);

    const tos = children[0].getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 2), tos.len);
    try std.testing.expectEqualStrings("111@s.whatsapp.net", tos[0].getAttribute("jid") orelse "");
    try std.testing.expectEqualStrings("111:4@s.whatsapp.net", tos[1].getAttribute("jid") orelse "");
}

test "encodeDeviceSentTextMessage wraps payload in DeviceSentMessage" {
    const allocator = std.testing.allocator;

    const encoded = try encodeDeviceSentTextMessage(allocator, "236395184570386@lid", "pong");
    defer allocator.free(encoded);

    var reader: std.Io.Reader = .fixed(encoded);
    var msg = try whatsapp.Message.decode(&reader, allocator);
    defer msg.deinit(allocator);

    const dsm = msg.deviceSentMessage orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("236395184570386@lid", dsm.destinationJid orelse "");
    try std.testing.expectEqualStrings("", dsm.phash orelse "");
    try std.testing.expectEqualStrings("pong", dsm.message.?.conversation orelse "");
}

test "encodeTextMessageWithContext adds message context" {
    const allocator = std.testing.allocator;

    const reporting_ctx = ReportingContext{
        .message_secret = [_]u8{1} ** 32,
        .reporting_token = [_]u8{2} ** 16,
    };

    const encoded = try encodeTextMessageWithContext(allocator, "pong", &reporting_ctx);
    defer allocator.free(encoded);

    var reader: std.Io.Reader = .fixed(encoded);
    var msg = try whatsapp.Message.decode(&reader, allocator);
    defer msg.deinit(allocator);

    const ctx = msg.messageContextInfo orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &reporting_ctx.message_secret, ctx.messageSecret orelse &.{});
    try std.testing.expectEqual(@as(i32, 2), ctx.reportingTokenVersion orelse 0);
}

test "encodeTextMessage matches generated whatsapp.Message bytes" {
    const allocator = std.testing.allocator;

    const ours = try encodeTextMessage(allocator, "pong");
    defer allocator.free(ours);

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    const generated = whatsapp.Message{
        .conversation = "pong",
    };
    try generated.encode(&writer.writer, allocator);
    const expected = try writer.toOwnedSlice();
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, ours);
}

test "encodeDeviceSentTextMessage matches generated whatsapp.Message bytes" {
    const allocator = std.testing.allocator;

    const ours = try encodeDeviceSentTextMessage(allocator, "236395184570386@lid", "pong");
    defer allocator.free(ours);

    const inner = try allocator.create(whatsapp.Message);
    defer allocator.destroy(inner);
    inner.* = .{
        .conversation = "pong",
    };
    var generated = whatsapp.Message{
        .deviceSentMessage = .{
            .destinationJid = "236395184570386@lid",
            .message = inner,
            .phash = "",
        },
    };
    defer generated.deinit(allocator);

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try generated.encode(&writer.writer, allocator);
    const expected = try writer.toOwnedSlice();
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, ours);
}
