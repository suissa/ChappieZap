const std = @import("std");
const jid_common = @import("jid_common");
const defs = @import("constants.zig");
const codec = @import("codec.zig");
const jid_mod = @import("jid.zig");
const token_mod = @import("tokens.zig");

pub const BinaryError = defs.BinaryError;
pub const LIST_EMPTY = defs.LIST_EMPTY;
pub const DICTIONARY_0 = defs.DICTIONARY_0;
pub const DICTIONARY_1 = defs.DICTIONARY_1;
pub const DICTIONARY_2 = defs.DICTIONARY_2;
pub const DICTIONARY_3 = defs.DICTIONARY_3;
pub const INTEROP_JID = defs.INTEROP_JID;
pub const FB_JID = defs.FB_JID;
pub const AD_JID = defs.AD_JID;
pub const JID_PAIR = defs.JID_PAIR;
pub const HEX_8 = defs.HEX_8;
pub const BINARY_8 = defs.BINARY_8;
pub const BINARY_20 = defs.BINARY_20;
pub const BINARY_32 = defs.BINARY_32;
pub const NIBBLE_8 = defs.NIBBLE_8;

pub const BinaryWriter = codec.BinaryWriter;
pub const BinaryReader = codec.BinaryReader;
pub const encodeStringRegular = codec.encodeStringRegular;
pub const decodeStringRegular = codec.decodeStringRegular;
pub const isDecimalDigits = codec.isDecimalDigits;
pub const isHexDigits = codec.isHexDigits;
pub const encodeNibble = codec.encodeNibble;
pub const decodeNibble = codec.decodeNibble;
pub const encodeHex = codec.encodeHex;
pub const decodeHex = codec.decodeHex;
pub const encodeBytes20 = codec.encodeBytes20;
pub const decodeBytes20 = codec.decodeBytes20;
pub const encodeBytes32 = codec.encodeBytes32;
pub const decodeBytes32 = codec.decodeBytes32;

pub const getSingleByteToken = token_mod.getSingleByteToken;
pub const getDoubleByteToken = token_mod.getDoubleByteToken;
pub const getStringForSingleByteToken = token_mod.getStringForSingleByteToken;
pub const getStringForDoubleByteToken = token_mod.getStringForDoubleByteToken;

pub const JID = jid_mod.JID;
const jid_attr_keys = .{
    "to",
    "from",
    "jid",
    "participant",
    "recipient",
    "sender_lid",
    "participant_pn",
    "participant_lid",
    "peer_recipient_lid",
    "peer_recipient_pn",
    "pn_jid",
};
pub const DecodedString = struct {
    bytes: []const u8,
    owned: bool,

    pub fn deinit(self: *const DecodedString, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.bytes);
    }

    pub fn intoOwned(self: DecodedString, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        if (self.owned) return @constCast(self.bytes);
        return allocator.dupe(u8, self.bytes);
    }
};

pub fn writeString(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (getSingleByteToken(str)) |token| {
        try writer.writeByte(token);
        return 1;
    } else if (getDoubleByteToken(str)) |double_token| {
        const page = double_token.@"0";
        const token_index = double_token.@"1";
        try writer.writeByte(DICTIONARY_0 + page);
        try writer.writeByte(token_index);
        return 2;
    } else {
        return try encodeString(str, writer);
    }
}

pub fn encodeString(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!std.unicode.utf8ValidateSlice(str)) return BinaryError.InvalidUtf8;

    if (isDecimalDigits(str)) {
        return try encodeNibble(str, writer);
    } else if (isHexDigits(str)) {
        return try encodeHex(str, writer);
    } else {
        return try encodeStringRegular(str, writer);
    }
}

pub fn decodeString(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const decoded = try decodeStringView(reader, allocator);
    return decoded.intoOwned(allocator);
}

pub fn decodeStringView(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!DecodedString {
    return decodeStringViewMode(reader, allocator, false);
}

pub fn decodeStringBorrowingView(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!DecodedString {
    return decodeStringViewMode(reader, allocator, true);
}

fn decodeStringViewMode(
    reader: *BinaryReader,
    allocator: std.mem.Allocator,
    borrow_raw: bool,
) (BinaryError || std.mem.Allocator.Error)!DecodedString {
    const marker = try reader.readByte();

    switch (marker) {
        LIST_EMPTY => return .{ .bytes = "", .owned = false },

        BINARY_8 => {
            const len = try reader.readByte();
            const bytes = try reader.readBytes(len);
            if (!std.unicode.utf8ValidateSlice(bytes)) return BinaryError.InvalidUtf8;
            if (borrow_raw) return .{ .bytes = bytes, .owned = false };
            return .{
                .bytes = try allocator.dupe(u8, bytes),
                .owned = true,
            };
        },
        BINARY_20 => {
            const bytes = if (borrow_raw)
                try decodeBytes20Borrowed(reader)
            else
                try decodeBytes20(reader, allocator);
            return .{
                .bytes = bytes,
                .owned = !borrow_raw,
            };
        },
        BINARY_32 => {
            const bytes = if (borrow_raw)
                try decodeBytes32Borrowed(reader)
            else
                try decodeBytes32(reader, allocator);
            return .{
                .bytes = bytes,
                .owned = !borrow_raw,
            };
        },

        NIBBLE_8 => return .{
            .bytes = try decodeNibble(reader, allocator),
            .owned = true,
        },
        HEX_8 => return .{
            .bytes = try decodeHex(reader, allocator),
            .owned = true,
        },
        JID_PAIR => {
            const user = try decodeStringViewMode(reader, allocator, borrow_raw);
            defer user.deinit(allocator);
            var server = try decodeStringViewMode(reader, allocator, borrow_raw);
            errdefer server.deinit(allocator);

            if (user.bytes.len > 0) {
                const joined = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ user.bytes, server.bytes });
                server.deinit(allocator);
                return .{ .bytes = joined, .owned = true };
            }
            return server;
        },
        AD_JID => {
            var jid = try decodeAdJid(reader, allocator);
            defer jid.deinit();
            return .{
                .bytes = try jid.toString(allocator),
                .owned = true,
            };
        },
        INTEROP_JID => {
            var jid = try decodeInteropJid(reader, allocator);
            defer jid.deinit();
            return .{
                .bytes = try jid.toString(allocator),
                .owned = true,
            };
        },
        FB_JID => {
            var jid = try decodeFbJid(reader, allocator);
            defer jid.deinit();
            return .{
                .bytes = try jid.toString(allocator),
                .owned = true,
            };
        },

        DICTIONARY_0, DICTIONARY_1, DICTIONARY_2, DICTIONARY_3 => |dict_marker| {
            const page = dict_marker - DICTIONARY_0;
            const token_index = try reader.readByte();
            const str = getStringForDoubleByteToken(page, token_index) orelse return BinaryError.InvalidToken;
            return .{ .bytes = str, .owned = false };
        },

        1...235 => |token| {
            const str = getStringForSingleByteToken(token) orelse return BinaryError.InvalidToken;
            return .{ .bytes = str, .owned = false };
        },

        else => return BinaryError.InvalidFormat,
    }
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

pub fn encodeJid(jid: []const u8, writer: *BinaryWriter) BinaryError!usize {
    const parts = jid_common.parse(jid) catch return BinaryError.InvalidFormat;

    const parsed = JID{
        .user = parts.bare_user,
        .server = parts.server,
        .agent = parts.agent,
        .device = parts.device,
        .integrator = parts.integrator,
        // SAFETY: this borrowed JID is only encoded, never deinitialized or used for allocation.
        .allocator = undefined,
    };
    return encodeJidStruct(&parsed, writer);
}

pub fn isJidAttributeKey(key: []const u8) bool {
    inline for (jid_attr_keys) |candidate| {
        if (std.mem.eql(u8, key, candidate)) return true;
    }
    return false;
}

pub fn decodeJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    return try decodeString(reader, allocator);
}

pub fn encodeJidStruct(jid: *const JID, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;

    if (jid.integrator > 0) {
        try writer.writeByte(INTEROP_JID);
        total_bytes += 1;

        const user_bytes = try encodeString(jid.user, writer);
        total_bytes += user_bytes;

        try writer.writeByte(@as(u8, @intCast(jid.device >> 8)));
        try writer.writeByte(@as(u8, @intCast(jid.device & 0xFF)));
        total_bytes += 2;

        try writer.writeByte(@as(u8, @intCast(jid.integrator >> 8)));
        try writer.writeByte(@as(u8, @intCast(jid.integrator & 0xFF)));
        total_bytes += 2;

        const server_bytes = try encodeString(jid.server, writer);
        total_bytes += server_bytes;
    } else if (jid.device > 0) {
        if (std.mem.eql(u8, jid.server, JID.MESSENGER_SERVER)) {
            try writer.writeByte(FB_JID);
            total_bytes += 1;

            const user_bytes = try encodeString(jid.user, writer);
            total_bytes += user_bytes;

            try writer.writeByte(@as(u8, @intCast(jid.device >> 8)));
            try writer.writeByte(@as(u8, @intCast(jid.device & 0xFF)));
            total_bytes += 2;

            const server_bytes = try encodeString(jid.server, writer);
            total_bytes += server_bytes;
        } else {
            try writer.writeByte(AD_JID);
            total_bytes += 1;

            var agent = jid.agent;
            if (std.mem.eql(u8, jid.server, "lid") or std.mem.eql(u8, jid.server, JID.HIDDEN_USER_SERVER)) {
                agent |= 1;
            } else if (std.mem.eql(u8, jid.server, "hosted.lid")) {
                agent |= 129;
            } else if (std.mem.eql(u8, jid.server, "hosted") or std.mem.eql(u8, jid.server, JID.HOSTED_SERVER)) {
                agent |= 128;
            }

            try writer.writeByte(agent);
            total_bytes += 1;

            try writer.writeByte(@as(u8, @intCast(jid.device)));
            total_bytes += 1;

            const user_bytes = try encodeString(jid.user, writer);
            total_bytes += user_bytes;
        }
    } else {
        try writer.writeByte(JID_PAIR);
        total_bytes += 1;

        const user_bytes = try encodeString(jid.user, writer);
        total_bytes += user_bytes;

        const server_bytes = try encodeString(jid.server, writer);
        total_bytes += server_bytes;
    }

    return total_bytes;
}

pub fn decodeJidStruct(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const jid_type = try reader.readByte();

    return switch (jid_type) {
        JID_PAIR => try decodeJidPair(reader, allocator),
        AD_JID => try decodeAdJid(reader, allocator),
        INTEROP_JID => try decodeInteropJid(reader, allocator),
        FB_JID => try decodeFbJid(reader, allocator),
        else => return BinaryError.InvalidFormat,
    };
}

fn decodeJidPair(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = 0,
        .integrator = 0,
        .allocator = allocator,
    };
}

fn decodeAdJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const agent = try reader.readByte();
    const device: u16 = try reader.readByte();

    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const server = switch (agent) {
        0 => JID.DEFAULT_USER_SERVER,
        1 => JID.HIDDEN_USER_SERVER,
        128 => JID.HOSTED_SERVER,
        129 => "hosted.lid",
        else => if ((agent & 128) != 0 and (agent & 1) == 0)
            JID.HOSTED_SERVER
        else
            return BinaryError.InvalidFormat,
    };

    return JID{
        .user = user,
        .server = try allocator.dupe(u8, server),
        .agent = agent,
        .device = device,
        .integrator = 0,
        .allocator = allocator,
    };
}

fn decodeInteropJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const device_high = try reader.readByte();
    const device_low = try reader.readByte();
    const device = (@as(u16, device_high) << 8) | @as(u16, device_low);

    const integrator_high = try reader.readByte();
    const integrator_low = try reader.readByte();
    const integrator = (@as(u16, integrator_high) << 8) | @as(u16, integrator_low);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    if (!std.mem.eql(u8, server, JID.INTEROP_SERVER)) {
        return BinaryError.InvalidFormat;
    }

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = device,
        .integrator = integrator,
        .allocator = allocator,
    };
}

fn decodeFbJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const device_high = try reader.readByte();
    const device_low = try reader.readByte();
    const device = (@as(u16, device_high) << 8) | @as(u16, device_low);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    if (!std.mem.eql(u8, server, JID.MESSENGER_SERVER)) {
        return BinaryError.InvalidFormat;
    }

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = device,
        .integrator = 0,
        .allocator = allocator,
    };
}

test "decodeStringView borrows token strings" {
    const allocator = std.testing.allocator;
    try token_mod.initTokens(allocator);

    var encoded = [_]u8{getSingleByteToken("s.whatsapp.net") orelse unreachable};
    var reader = BinaryReader.init(&encoded);
    const decoded = try decodeStringView(&reader, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("s.whatsapp.net", decoded.bytes);
    try std.testing.expect(!decoded.owned);
}

test "decodeStringView owns dynamic strings" {
    const allocator = std.testing.allocator;

    var encoded = [_]u8{
        BINARY_8,
        5,
        'h',
        'e',
        'l',
        'l',
        'o',
    };
    var reader = BinaryReader.init(&encoded);
    const decoded = try decodeStringView(&reader, allocator);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("hello", decoded.bytes);
    try std.testing.expect(decoded.owned);
}
