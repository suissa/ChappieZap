const std = @import("std");
const session_mod = @import("session.zig");

/// Signal Protocol message version
const SIGNAL_VERSION: u8 = 3;
const VERSION_BYTE: u8 = (SIGNAL_VERSION << 4) | 0x03;
const MAC_LENGTH: usize = 8;
const CURVE25519_KEY_TYPE_PREFIX: u8 = 0x05;

/// Serialize a SignalMessage to wire format:
/// [VERSION_BYTE][protobuf(ratchet_key, counter, prev_counter, ciphertext)][8-byte MAC]
pub fn serializeSignalMessage(allocator: std.mem.Allocator, msg: *const session_mod.EncryptedMessage) ![]u8 {
    const proto_len = signalMessageProtoLen(msg);
    const result = try allocator.alloc(u8, 1 + proto_len + MAC_LENGTH);

    var pos: usize = 0;
    result[pos] = VERSION_BYTE;
    pos += 1;

    writeCurve25519KeyField(result, &pos, 0x0A, &msg.ratchet_key);
    writeVarintField(result, &pos, 0x10, msg.counter);
    writeVarintField(result, &pos, 0x18, msg.previous_counter);
    writeBytesField(result, &pos, 0x22, msg.ciphertext);

    const mac = msg.computeMac(result[0..pos]);
    @memcpy(result[pos..][0..MAC_LENGTH], &mac);
    pos += MAC_LENGTH;

    std.debug.assert(pos == result.len);
    return result;
}

/// Serialize a PreKeySignalMessage:
/// [VERSION_BYTE][protobuf(reg_id, prekey_id, signed_prekey_id, base_key, identity_key, signal_message)]
pub fn serializePreKeySignalMessage(
    allocator: std.mem.Allocator,
    registration_id: u32,
    prekey_id: ?u32,
    signed_prekey_id: u32,
    base_key: [32]u8,
    identity_key: [32]u8,
    signal_message: []const u8,
) ![]u8 {
    const proto_len = preKeySignalMessageProtoLen(
        registration_id,
        prekey_id,
        signed_prekey_id,
        signal_message.len,
    );
    const result = try allocator.alloc(u8, 1 + proto_len);

    var pos: usize = 0;
    result[pos] = VERSION_BYTE;
    pos += 1;

    // Preserve the existing field write order exactly.
    writeVarintField(result, &pos, 0x28, registration_id);
    if (prekey_id) |pk_id| {
        writeVarintField(result, &pos, 0x08, pk_id);
    }
    writeVarintField(result, &pos, 0x30, signed_prekey_id);
    writeCurve25519KeyField(result, &pos, 0x12, &base_key);
    writeCurve25519KeyField(result, &pos, 0x1A, &identity_key);
    writeBytesField(result, &pos, 0x22, signal_message);

    std.debug.assert(pos == result.len);
    return result;
}

/// Parse a SignalMessage from wire format
pub const ParsedSignalMessage = struct {
    ratchet_key: [32]u8,
    counter: u32,
    previous_counter: u32,
    ciphertext: []const u8,
    mac: [8]u8,
};

pub fn parseSignalMessage(data: []const u8) !ParsedSignalMessage {
    if (data.len < 1 + MAC_LENGTH) return error.MessageTooShort;

    const version = data[0];
    if ((version >> 4) != SIGNAL_VERSION) return error.UnsupportedVersion;

    const mac = data[data.len - MAC_LENGTH ..][0..MAC_LENGTH].*;
    const proto_bytes = data[1 .. data.len - MAC_LENGTH];

    var result = ParsedSignalMessage{
        .ratchet_key = undefined,
        .counter = 0,
        .previous_counter = 0,
        .ciphertext = &.{},
        .mac = mac,
    };

    // Parse protobuf fields
    var pos: usize = 0;
    while (pos < proto_bytes.len) {
        const tag_byte = proto_bytes[pos];
        pos += 1;
        const field_num = tag_byte >> 3;
        const wire_type = tag_byte & 0x07;

        switch (field_num) {
            1 => { // ratchet_key (bytes)
                if (wire_type != 2) return error.InvalidWireType;
                const len = try readVarint(proto_bytes, &pos);
                if (len < 33 or pos + len > proto_bytes.len) return error.InvalidLength;
                // Skip 0x05 prefix
                if (proto_bytes[pos] != 0x05) return error.InvalidKeyPrefix;
                result.ratchet_key = proto_bytes[pos + 1 ..][0..32].*;
                pos += len;
            },
            2 => { // counter (varint)
                if (wire_type != 0) return error.InvalidWireType;
                result.counter = @intCast(try readVarint(proto_bytes, &pos));
            },
            3 => { // previous_counter (varint)
                if (wire_type != 0) return error.InvalidWireType;
                result.previous_counter = @intCast(try readVarint(proto_bytes, &pos));
            },
            4 => { // ciphertext (bytes)
                if (wire_type != 2) return error.InvalidWireType;
                const len = try readVarint(proto_bytes, &pos);
                if (pos + len > proto_bytes.len) return error.InvalidLength;
                result.ciphertext = proto_bytes[pos..][0..len];
                pos += len;
            },
            else => {
                // Skip unknown fields
                pos = try skipField(proto_bytes, pos, wire_type);
            },
        }
    }

    return result;
}

/// Parse a PreKeySignalMessage from wire format
pub const ParsedPreKeyMessage = struct {
    registration_id: u32,
    prekey_id: ?u32,
    signed_prekey_id: u32,
    base_key: [32]u8,
    identity_key: [32]u8,
    signal_message: []const u8,
};

pub fn parsePreKeySignalMessage(data: []const u8) !ParsedPreKeyMessage {
    if (data.len < 2) return error.MessageTooShort;

    const version = data[0];
    if ((version >> 4) != SIGNAL_VERSION) return error.UnsupportedVersion;

    var result = ParsedPreKeyMessage{
        .registration_id = 0,
        .prekey_id = null,
        .signed_prekey_id = 0,
        .base_key = undefined,
        .identity_key = undefined,
        .signal_message = &.{},
    };

    var pos: usize = 1;
    while (pos < data.len) {
        const tag_byte = data[pos];
        pos += 1;
        const field_num = tag_byte >> 3;
        const wire_type = tag_byte & 0x07;

        switch (field_num) {
            1 => { // prekey_id (varint)
                if (wire_type != 0) return error.InvalidWireType;
                result.prekey_id = @intCast(try readVarint(data, &pos));
            },
            2 => { // base_key (bytes)
                if (wire_type != 2) return error.InvalidWireType;
                const len = try readVarint(data, &pos);
                if (len < 33 or pos + len > data.len) return error.InvalidLength;
                if (data[pos] != 0x05) return error.InvalidKeyPrefix;
                result.base_key = data[pos + 1 ..][0..32].*;
                pos += len;
            },
            3 => { // identity_key (bytes)
                if (wire_type != 2) return error.InvalidWireType;
                const len = try readVarint(data, &pos);
                if (len < 33 or pos + len > data.len) return error.InvalidLength;
                if (data[pos] != 0x05) return error.InvalidKeyPrefix;
                result.identity_key = data[pos + 1 ..][0..32].*;
                pos += len;
            },
            4 => { // message (bytes)
                if (wire_type != 2) return error.InvalidWireType;
                const len = try readVarint(data, &pos);
                if (pos + len > data.len) return error.InvalidLength;
                result.signal_message = data[pos..][0..len];
                pos += len;
            },
            5 => { // registration_id (varint)
                if (wire_type != 0) return error.InvalidWireType;
                result.registration_id = @intCast(try readVarint(data, &pos));
            },
            6 => { // signed_prekey_id (varint)
                if (wire_type != 0) return error.InvalidWireType;
                result.signed_prekey_id = @intCast(try readVarint(data, &pos));
            },
            else => {
                pos = try skipField(data, pos, wire_type);
            },
        }
    }

    return result;
}

// --- Helpers ---

fn signalMessageProtoLen(msg: *const session_mod.EncryptedMessage) usize {
    return curve25519KeyFieldLen() +
        varintFieldLen(msg.counter) +
        varintFieldLen(msg.previous_counter) +
        bytesFieldLen(msg.ciphertext.len);
}

fn preKeySignalMessageProtoLen(
    registration_id: u32,
    prekey_id: ?u32,
    signed_prekey_id: u32,
    signal_message_len: usize,
) usize {
    return varintFieldLen(registration_id) +
        (if (prekey_id) |pk_id| varintFieldLen(pk_id) else 0) +
        varintFieldLen(signed_prekey_id) +
        curve25519KeyFieldLen() +
        curve25519KeyFieldLen() +
        bytesFieldLen(signal_message_len);
}

fn curve25519KeyFieldLen() usize {
    return 1 + 1 + 1 + 32;
}

fn varintFieldLen(value: u32) usize {
    return 1 + varintSize(value);
}

fn bytesFieldLen(data_len: usize) usize {
    return 1 + varintSize(data_len) + data_len;
}

fn varintSize(value: anytype) usize {
    var v: u64 = @intCast(value);
    var len: usize = 1;
    while (v >= 0x80) {
        len += 1;
        v >>= 7;
    }
    return len;
}

fn writeVarintField(out: []u8, pos: *usize, tag: u8, value: u32) void {
    out[pos.*] = tag;
    pos.* += 1;
    writeVarintInto(out, pos, value);
}

fn writeCurve25519KeyField(out: []u8, pos: *usize, tag: u8, key: *const [32]u8) void {
    out[pos.*] = tag;
    pos.* += 1;
    out[pos.*] = 33;
    pos.* += 1;
    out[pos.*] = CURVE25519_KEY_TYPE_PREFIX;
    pos.* += 1;
    @memcpy(out[pos.*..][0..key.len], key);
    pos.* += key.len;
}

fn writeBytesField(out: []u8, pos: *usize, tag: u8, data: []const u8) void {
    out[pos.*] = tag;
    pos.* += 1;
    writeVarintInto(out, pos, data.len);
    @memcpy(out[pos.*..][0..data.len], data);
    pos.* += data.len;
}

fn writeVarintInto(out: []u8, pos: *usize, value: anytype) void {
    var v: u64 = @intCast(value);
    while (v >= 0x80) {
        out[pos.*] = @intCast((v & 0x7F) | 0x80);
        pos.* += 1;
        v >>= 7;
    }
    out[pos.*] = @intCast(v);
    pos.* += 1;
}

fn appendVarint(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try list.append(allocator, @intCast((v & 0x7F) | 0x80));
        v >>= 7;
    }
    try list.append(allocator, @intCast(v));
}

fn readVarint(data: []const u8, pos: *usize) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < data.len) {
        const byte = data[pos.*];
        pos.* += 1;
        result |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return result;
        shift += 7;
        if (shift >= 64) return error.VarintTooLong;
    }
    return error.UnexpectedEof;
}

fn skipField(data: []const u8, pos: usize, wire_type: u8) !usize {
    var p = pos;
    switch (wire_type) {
        0 => { // varint
            while (p < data.len and data[p] & 0x80 != 0) p += 1;
            if (p < data.len) p += 1;
        },
        1 => p += 8, // 64-bit
        2 => { // length-delimited
            const len = try readVarint(data, &p);
            p += @intCast(len);
        },
        5 => p += 4, // 32-bit
        else => return error.UnknownWireType,
    }
    return p;
}

test "serializeSignalMessage matches legacy bytes" {
    const allocator = std.testing.allocator;

    const ciphertext = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
    const msg = session_mod.EncryptedMessage{
        .ratchet_key = makePattern32(0x10),
        .counter = 300,
        .previous_counter = 17,
        .ciphertext = @constCast(ciphertext),
        .sender_identity = makePattern32(0x30),
        .receiver_identity = makePattern32(0x50),
        .mac_key = makePattern32(0x70),
    };

    const actual = try serializeSignalMessage(allocator, &msg);
    defer allocator.free(actual);

    const expected = try serializeSignalMessageLegacy(allocator, &msg);
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, actual);

    const parsed = try parseSignalMessage(actual);
    try std.testing.expectEqual(msg.counter, parsed.counter);
    try std.testing.expectEqual(msg.previous_counter, parsed.previous_counter);
    try std.testing.expectEqualSlices(u8, &msg.ratchet_key, &parsed.ratchet_key);
    try std.testing.expectEqualSlices(u8, msg.ciphertext, parsed.ciphertext);
}

test "serializePreKeySignalMessage matches legacy bytes" {
    const allocator = std.testing.allocator;

    var inner_signal: [140]u8 = undefined;
    for (&inner_signal, 0..) |*byte, i| byte.* = @intCast((i * 3 + 7) & 0xFF);

    const actual = try serializePreKeySignalMessage(
        allocator,
        300,
        16384,
        65535,
        makePattern32(0x22),
        makePattern32(0x44),
        &inner_signal,
    );
    defer allocator.free(actual);

    const expected = try serializePreKeySignalMessageLegacy(
        allocator,
        300,
        16384,
        65535,
        makePattern32(0x22),
        makePattern32(0x44),
        &inner_signal,
    );
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, actual);

    const parsed = try parsePreKeySignalMessage(actual);
    try std.testing.expectEqual(@as(u32, 300), parsed.registration_id);
    try std.testing.expectEqual(@as(?u32, 16384), parsed.prekey_id);
    try std.testing.expectEqual(@as(u32, 65535), parsed.signed_prekey_id);
    try std.testing.expectEqualSlices(u8, &makePattern32(0x22), &parsed.base_key);
    try std.testing.expectEqualSlices(u8, &makePattern32(0x44), &parsed.identity_key);
    try std.testing.expectEqualSlices(u8, &inner_signal, parsed.signal_message);
}

fn makePattern32(start: u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (&out, 0..) |*byte, i| byte.* = start +% @as(u8, @intCast(i));
    return out;
}

fn serializeSignalMessageLegacy(
    allocator: std.mem.Allocator,
    msg: *const session_mod.EncryptedMessage,
) ![]u8 {
    var proto = std.ArrayList(u8).empty;
    defer proto.deinit(allocator);

    try proto.append(allocator, 0x0A);
    try proto.append(allocator, 33);
    try proto.append(allocator, CURVE25519_KEY_TYPE_PREFIX);
    try proto.appendSlice(allocator, &msg.ratchet_key);

    try proto.append(allocator, 0x10);
    try appendVarint(&proto, allocator, msg.counter);

    try proto.append(allocator, 0x18);
    try appendVarint(&proto, allocator, msg.previous_counter);

    try proto.append(allocator, 0x22);
    try appendVarint(&proto, allocator, @intCast(msg.ciphertext.len));
    try proto.appendSlice(allocator, msg.ciphertext);

    const msg_without_mac = try allocator.alloc(u8, 1 + proto.items.len);
    defer allocator.free(msg_without_mac);
    msg_without_mac[0] = VERSION_BYTE;
    @memcpy(msg_without_mac[1..], proto.items);

    const mac = msg.computeMac(msg_without_mac);

    const result = try allocator.alloc(u8, msg_without_mac.len + MAC_LENGTH);
    @memcpy(result[0..msg_without_mac.len], msg_without_mac);
    @memcpy(result[msg_without_mac.len..], &mac);
    return result;
}

fn serializePreKeySignalMessageLegacy(
    allocator: std.mem.Allocator,
    registration_id: u32,
    prekey_id: ?u32,
    signed_prekey_id: u32,
    base_key: [32]u8,
    identity_key: [32]u8,
    signal_message: []const u8,
) ![]u8 {
    var proto = std.ArrayList(u8).empty;
    defer proto.deinit(allocator);

    try proto.append(allocator, 0x28);
    try appendVarint(&proto, allocator, registration_id);

    if (prekey_id) |pk_id| {
        try proto.append(allocator, 0x08);
        try appendVarint(&proto, allocator, pk_id);
    }

    try proto.append(allocator, 0x30);
    try appendVarint(&proto, allocator, signed_prekey_id);

    try proto.append(allocator, 0x12);
    try proto.append(allocator, 33);
    try proto.append(allocator, CURVE25519_KEY_TYPE_PREFIX);
    try proto.appendSlice(allocator, &base_key);

    try proto.append(allocator, 0x1A);
    try proto.append(allocator, 33);
    try proto.append(allocator, CURVE25519_KEY_TYPE_PREFIX);
    try proto.appendSlice(allocator, &identity_key);

    try proto.append(allocator, 0x22);
    try appendVarint(&proto, allocator, @intCast(signal_message.len));
    try proto.appendSlice(allocator, signal_message);

    const result = try allocator.alloc(u8, 1 + proto.items.len);
    result[0] = VERSION_BYTE;
    @memcpy(result[1..], proto.items);
    return result;
}
