const std = @import("std");
const binary = @import("binary");
const signal = @import("signal");
const prekey_mod = @import("prekey");

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

/// Decode a text message from protobuf (extract conversation field 1)
pub fn decodeTextMessage(data: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < data.len) {
        if (pos >= data.len) break;
        const tag_byte = data[pos];
        pos += 1;
        const field_num = tag_byte >> 3;
        const wire_type = tag_byte & 0x07;

        if (field_num == 1 and wire_type == 2) {
            // Length-delimited: read varint length, then bytes
            var length: usize = 0;
            var shift: u5 = 0;
            while (pos < data.len) {
                const byte = data[pos];
                pos += 1;
                length |= @as(usize, byte & 0x7F) << shift;
                if (byte & 0x80 == 0) break;
                shift += 7;
            }
            if (pos + length <= data.len) {
                return data[pos .. pos + length];
            }
            return null;
        }

        // Skip other fields
        switch (wire_type) {
            0 => { // varint
                while (pos < data.len and data[pos] & 0x80 != 0) pos += 1;
                if (pos < data.len) pos += 1;
            },
            1 => pos += 8,
            2 => {
                var length: usize = 0;
                var shift: u5 = 0;
                while (pos < data.len) {
                    const byte = data[pos];
                    pos += 1;
                    length |= @as(usize, byte & 0x7F) << shift;
                    if (byte & 0x80 == 0) break;
                    shift += 7;
                }
                pos += length;
            },
            5 => pos += 4,
            else => break,
        }
    }
    return null;
}
