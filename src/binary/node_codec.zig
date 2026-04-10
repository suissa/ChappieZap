const std = @import("std");
const defs = @import("constants.zig");
const codec = @import("codec.zig");
const node_mod = @import("node.zig");
const jid_wire = @import("jid_wire.zig");

pub const BinaryError = defs.BinaryError;
pub const LIST_EMPTY = defs.LIST_EMPTY;
pub const LIST_8 = defs.LIST_8;
pub const LIST_16 = defs.LIST_16;
pub const BINARY_8 = defs.BINARY_8;
pub const BINARY_20 = defs.BINARY_20;
pub const BINARY_32 = defs.BINARY_32;

pub const BinaryWriter = codec.BinaryWriter;
pub const BinaryReader = codec.BinaryReader;
pub const writeString = jid_wire.writeString;
pub const decodeString = jid_wire.decodeString;
pub const decodeStringBorrowingView = jid_wire.decodeStringBorrowingView;
pub const decodeStringView = jid_wire.decodeStringView;
pub const encodeJid = jid_wire.encodeJid;
pub const isJidAttributeKey = jid_wire.isJidAttributeKey;
pub const decodeBytes20 = codec.decodeBytes20;
pub const decodeBytes32 = codec.decodeBytes32;

pub const Attribute = node_mod.Attribute;
pub const NodeContent = node_mod.NodeContent;
pub const Node = node_mod.Node;
pub const DecodedString = jid_wire.DecodedString;

pub fn encodeNode(node: *const Node, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;
    const content_len: usize = if (node.content != null) 1 else 0;
    const list_len = 1 + (node.attributes.items.len * 2) + content_len;

    if (list_len == 0) {
        try writer.writeByte(LIST_EMPTY);
        total_bytes += 1;
    } else if (list_len < 256) {
        try writer.writeByte(LIST_8);
        try writer.writeByte(@as(u8, @intCast(list_len)));
        total_bytes += 2;
    } else {
        try writer.writeByte(LIST_16);
        try writer.writeByte(@as(u8, @intCast(list_len >> 8)));
        try writer.writeByte(@as(u8, @intCast(list_len & 0xFF)));
        total_bytes += 3;
    }

    const tag_bytes = try writeString(node.tag, writer);
    total_bytes += tag_bytes;

    for (node.attributes.items) |attr| {
        const key_bytes = try writeString(attr.key, writer);
        total_bytes += key_bytes;

        const value_bytes = if (isJidAttributeKey(attr.key) and std.mem.indexOfScalar(u8, attr.value, '@') != null)
            encodeJid(attr.value, writer) catch try writeString(attr.value, writer)
        else
            try writeString(attr.value, writer);
        total_bytes += value_bytes;
    }

    if (node.content) |content| {
        switch (content) {
            .Bytes => |bytes| {
                const content_bytes = bytes.bytes;
                if (content_bytes.len < 256) {
                    try writer.writeByte(BINARY_8);
                    try writer.writeByte(@intCast(content_bytes.len));
                    try writer.writeBytes(content_bytes);
                    total_bytes += 2 + content_bytes.len;
                } else if (content_bytes.len < (1 << 20)) {
                    try writer.writeByte(BINARY_20);
                    try writer.writeByte(@intCast((content_bytes.len >> 16) & 0xFF));
                    try writer.writeByte(@intCast((content_bytes.len >> 8) & 0xFF));
                    try writer.writeByte(@intCast(content_bytes.len & 0xFF));
                    try writer.writeBytes(content_bytes);
                    total_bytes += 4 + content_bytes.len;
                } else {
                    try writer.writeByte(BINARY_32);
                    try writer.writeByte(@intCast(content_bytes.len >> 24));
                    try writer.writeByte(@intCast((content_bytes.len >> 16) & 0xFF));
                    try writer.writeByte(@intCast((content_bytes.len >> 8) & 0xFF));
                    try writer.writeByte(@intCast(content_bytes.len & 0xFF));
                    try writer.writeBytes(content_bytes);
                    total_bytes += 5 + content_bytes.len;
                }
            },
            .Nodes => |nodes| {
                const nodes_bytes = try encodeNodeList(nodes.items, writer);
                total_bytes += nodes_bytes;
            },
        }
    }

    return total_bytes;
}

pub fn decodeNode(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!Node {
    return decodeNodeMode(reader, allocator, false);
}

pub fn decodeNodeBorrowingInput(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!Node {
    return decodeNodeMode(reader, allocator, true);
}

fn decodeNodeMode(
    reader: *BinaryReader,
    allocator: std.mem.Allocator,
    borrow_raw: bool,
) (BinaryError || std.mem.Allocator.Error)!Node {
    const tag = try reader.readByte();
    const list_size = switch (tag) {
        LIST_EMPTY => 0,
        LIST_8 => try reader.readByte(),
        LIST_16 => blk: {
            const high = try reader.readByte();
            const low = try reader.readByte();
            break :blk (@as(u16, high) << 8) | @as(u16, low);
        },
        else => return BinaryError.InvalidFormat,
    };

    if (list_size == 0) return BinaryError.InvalidFormat;

    const node_tag = if (borrow_raw)
        try decodeStringBorrowingView(reader, allocator)
    else
        try decodeStringView(reader, allocator);
    var node = if (node_tag.owned)
        Node.initOwned(allocator, node_tag.bytes)
    else
        Node.initBorrowed(allocator, node_tag.bytes);
    errdefer node.deinit();

    const attr_count = (list_size - 1) / 2;
    const has_content = (list_size - 1) % 2 == 1;
    if (attr_count != 0) {
        try node.attributes.ensureTotalCapacity(allocator, attr_count);
    }

    var i: usize = 0;
    while (i < attr_count) : (i += 1) {
        var key = if (borrow_raw)
            try decodeStringBorrowingView(reader, allocator)
        else
            try decodeStringView(reader, allocator);
        errdefer key.deinit(allocator);

        var value = if (borrow_raw)
            try decodeStringBorrowingView(reader, allocator)
        else
            try decodeStringView(reader, allocator);
        errdefer value.deinit(allocator);

        const attr = Attribute.initMixed(key.bytes, key.owned, value.bytes, value.owned);
        node.attributes.appendAssumeCapacity(attr);
        key.owned = false;
        value.owned = false;
    }

    if (has_content) {
        const content_tag = try reader.readByte();
        switch (content_tag) {
            LIST_EMPTY => {
                node.content = null;
            },
            LIST_8, LIST_16 => {
                reader.pos -= 1;
                const nodes = try decodeNodeListMode(reader, allocator, borrow_raw);
                node.content = .{ .Nodes = nodes };
            },
            BINARY_8 => {
                const len = try reader.readByte();
                const bytes = try reader.readBytes(len);
                node.content = .{ .Bytes = .{
                    .bytes = if (borrow_raw) bytes else try allocator.dupe(u8, bytes),
                    .owned = !borrow_raw,
                } };
            },
            BINARY_20 => {
                const bytes = if (borrow_raw)
                    try decodeBytes20Borrowed(reader)
                else
                    try decodeBytes20(reader, allocator);
                node.content = .{ .Bytes = .{
                    .bytes = bytes,
                    .owned = !borrow_raw,
                } };
            },
            BINARY_32 => {
                const bytes = if (borrow_raw)
                    try decodeBytes32Borrowed(reader)
                else
                    try decodeBytes32(reader, allocator);
                node.content = .{ .Bytes = .{
                    .bytes = bytes,
                    .owned = !borrow_raw,
                } };
            },
            else => {
                reader.pos -= 1;
                const str = if (borrow_raw)
                    try decodeStringBorrowingView(reader, allocator)
                else
                    try decodeStringView(reader, allocator);
                node.content = .{ .Bytes = .{
                    .bytes = str.bytes,
                    .owned = str.owned,
                } };
            },
        }
    } else {
        node.content = null;
    }

    return node;
}

pub fn encodeNodeList(nodes: []const Node, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;
    const len = nodes.len;

    if (len == 0) {
        try writer.writeByte(LIST_EMPTY);
        total_bytes += 1;
    } else if (len < 256) {
        try writer.writeByte(LIST_8);
        try writer.writeByte(@as(u8, @intCast(len)));
        total_bytes += 2;
    } else {
        try writer.writeByte(LIST_16);
        try writer.writeByte(@as(u8, @intCast(len >> 8)));
        try writer.writeByte(@as(u8, @intCast(len & 0xFF)));
        total_bytes += 3;
    }

    for (nodes) |*node| {
        const node_bytes = try encodeNode(node, writer);
        total_bytes += node_bytes;
    }

    return total_bytes;
}

pub fn decodeNodeList(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!std.ArrayList(Node) {
    return decodeNodeListMode(reader, allocator, false);
}

pub fn decodeNodeListBorrowingInput(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!std.ArrayList(Node) {
    return decodeNodeListMode(reader, allocator, true);
}

fn decodeNodeListMode(
    reader: *BinaryReader,
    allocator: std.mem.Allocator,
    borrow_raw: bool,
) (BinaryError || std.mem.Allocator.Error)!std.ArrayList(Node) {
    const tag = try reader.readByte();
    const count = switch (tag) {
        LIST_EMPTY => 0,
        LIST_8 => try reader.readByte(),
        LIST_16 => blk: {
            const high = try reader.readByte();
            const low = try reader.readByte();
            break :blk (@as(u16, high) << 8) | @as(u16, low);
        },
        else => return BinaryError.InvalidFormat,
    };

    var nodes = try std.ArrayList(Node).initCapacity(allocator, count);
    errdefer {
        for (nodes.items) |*n| n.deinit();
        nodes.deinit(allocator);
    }

    const slots = try nodes.addManyAsSlice(allocator, count);
    for (slots) |*slot| {
        slot.* = try decodeNodeMode(reader, allocator, borrow_raw);
    }

    return nodes;
}

fn decodeBytes20Borrowed(reader: *BinaryReader) BinaryError![]const u8 {
    const len_high = try reader.readByte();
    const len_mid = try reader.readByte();
    const len_low = try reader.readByte();
    const length = (@as(u32, len_high) << 16) | (@as(u32, len_mid) << 8) | @as(u32, len_low);
    return reader.readBytes(@as(usize, @intCast(length)));
}

fn decodeBytes32Borrowed(reader: *BinaryReader) BinaryError![]const u8 {
    const len_byte1 = try reader.readByte();
    const len_byte2 = try reader.readByte();
    const len_byte3 = try reader.readByte();
    const len_byte4 = try reader.readByte();
    const length = (@as(u32, len_byte1) << 24) |
        (@as(u32, len_byte2) << 16) |
        (@as(u32, len_byte3) << 8) |
        @as(u32, len_byte4);
    return reader.readBytes(@as(usize, @intCast(length)));
}
