const std = @import("std");
const binary = @import("binary");

pub fn writeNodeHeader(
    writer: *binary.BinaryWriter,
    tag: []const u8,
    attr_count: usize,
    has_content: bool,
) binary.BinaryError!void {
    try writeListHeader(writer, 1 + attr_count * 2 + @intFromBool(has_content));
    _ = try binary.writeString(tag, writer);
}

pub fn writeListHeader(writer: *binary.BinaryWriter, count: usize) binary.BinaryError!void {
    if (count == 0) {
        try writer.writeByte(binary.LIST_EMPTY);
    } else if (count < 256) {
        try writer.writeByte(binary.LIST_8);
        try writer.writeByte(@intCast(count));
    } else {
        try writer.writeByte(binary.LIST_16);
        try writer.writeByte(@intCast(count >> 8));
        try writer.writeByte(@intCast(count & 0xFF));
    }
}

pub fn writeAttribute(
    writer: *binary.BinaryWriter,
    key: []const u8,
    value: []const u8,
) binary.BinaryError!void {
    _ = try binary.writeString(key, writer);

    const use_jid_encoding = isJidAttributeKey(key) and std.mem.indexOfScalar(u8, value, '@') != null;
    if (use_jid_encoding) {
        _ = binary.encodeJid(value, writer) catch try binary.writeString(value, writer);
    } else {
        _ = try binary.writeString(value, writer);
    }
}

fn isJidAttributeKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "to") or
        std.mem.eql(u8, key, "from") or
        std.mem.eql(u8, key, "jid") or
        std.mem.eql(u8, key, "participant") or
        std.mem.eql(u8, key, "recipient") or
        std.mem.eql(u8, key, "sender_lid") or
        std.mem.eql(u8, key, "participant_pn") or
        std.mem.eql(u8, key, "participant_lid") or
        std.mem.eql(u8, key, "peer_recipient_lid") or
        std.mem.eql(u8, key, "peer_recipient_pn") or
        std.mem.eql(u8, key, "pn_jid");
}
