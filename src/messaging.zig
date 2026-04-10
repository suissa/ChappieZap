const std = @import("std");
const binary = @import("binary");
const signal = @import("signal");
const prekey_mod = @import("prekey");
// Protobuf field numbers from wa.Message:
// field 1  = conversation (string)
// field 6  = extendedTextMessage (submessage) → field 1 = text
// field 31 = deviceSentMessage (submessage)   → field 2 = message (Message)

/// Build a prekey fetch IQ: <iq xmlns="encrypt" type="get"><key><user jid="..."/></key></iq>
pub fn buildFetchPrekeysIq(allocator: std.mem.Allocator, iq_id: []const u8, jids: []const []const u8) !binary.Node {
    var iq = try binary.Node.init(allocator, "iq");
    errdefer iq.deinit();

    try iq.addAttribute("id", iq_id);
    try iq.addAttribute("type", "get");
    try iq.addAttribute("xmlns", "encrypt");
    try iq.addAttribute("to", "s.whatsapp.net");

    var key_node = try binary.Node.init(allocator, "key");
    defer key_node.deinit();

    for (jids) |jid| {
        var user_node = try binary.Node.init(allocator, "user");
        defer user_node.deinit();
        try user_node.addAttribute("jid", jid);
        try key_node.addChild(&user_node);
    }

    try iq.addChild(&key_node);
    return iq;
}

/// Build a message stanza with Signal-encrypted content
/// <message to="..." id="..." t="..." type="text"><enc type="pkmsg|msg" v="2">ciphertext</enc></message>
pub fn buildMessageNode(
    allocator: std.mem.Allocator,
    to_jid: []const u8,
    msg_id: []const u8,
    ciphertext: []const u8,
    is_prekey_msg: bool,
) !binary.Node {
    var msg = try binary.Node.init(allocator, "message");
    errdefer msg.deinit();

    try msg.addAttribute("to", to_jid);
    try msg.addAttribute("id", msg_id);
    try msg.addAttribute("type", "text");

    // Timestamp as string
    var ts_buf: [20]u8 = undefined;
    // Use a fixed timestamp for now since we don't have access to io.clock
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{@as(u64, 1700000000)}) catch "1700000000";
    try msg.addAttribute("t", ts_str);

    var enc_node = try binary.Node.init(allocator, "enc");
    defer enc_node.deinit();
    try enc_node.addAttribute("v", "2");
    try enc_node.addAttribute("type", if (is_prekey_msg) "pkmsg" else "msg");
    try enc_node.setContentBytes(ciphertext);
    try msg.addChild(&enc_node);

    return msg;
}

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
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    // Protobuf field 1 (conversation), wire type 2 (length-delimited)
    try buf.append(allocator, 0x0A);
    // Varint length
    var len = text.len;
    while (len >= 0x80) {
        try buf.append(allocator, @intCast((len & 0x7F) | 0x80));
        len >>= 7;
    }
    try buf.append(allocator, @intCast(len));
    try buf.appendSlice(allocator, text);

    return buf.toOwnedSlice(allocator);
}

/// Decode protobuf Message and extract text content.
/// Handles DeviceSentMessage unwrapping (companion device messages)
/// and ExtendedTextMessage. Matches Rust's text_content() + unwrap_device_sent().
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
