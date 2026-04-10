const std = @import("std");
const session_mod = @import("session.zig");

/// Signal Protocol message version
const SIGNAL_VERSION: u8 = 3;
const VERSION_BYTE: u8 = (SIGNAL_VERSION << 4) | 0x03;
const MAC_LENGTH: usize = 8;

/// Serialize a SignalMessage to wire format:
/// [VERSION_BYTE][protobuf(ratchet_key, counter, prev_counter, ciphertext)][8-byte MAC]
pub fn serializeSignalMessage(allocator: std.mem.Allocator, msg: *const session_mod.EncryptedMessage) ![]u8 {
    // Encode protobuf fields manually (Signal uses proto2 with specific field numbers)
    var proto = std.ArrayList(u8).empty;
    defer proto.deinit(allocator);

    // Field 1: ratchet_key (bytes), wire type 2 (length-delimited)
    // Key format: 0x05 prefix + 32 bytes
    try proto.append(allocator, 0x0A); // field 1, wire type 2
    try proto.append(allocator, 33); // length: 1 prefix + 32 key bytes
    try proto.append(allocator, 0x05); // Curve25519 key type prefix
    try proto.appendSlice(allocator, &msg.ratchet_key);

    // Field 2: counter (uint32), wire type 0 (varint)
    try proto.append(allocator, 0x10); // field 2, wire type 0
    try appendVarint(&proto, allocator, msg.counter);

    // Field 3: previous_counter (uint32), wire type 0 (varint)
    try proto.append(allocator, 0x18); // field 3, wire type 0
    try appendVarint(&proto, allocator, msg.previous_counter);

    // Field 4: ciphertext (bytes), wire type 2 (length-delimited)
    try proto.append(allocator, 0x22); // field 4, wire type 2
    try appendVarint(&proto, allocator, @intCast(msg.ciphertext.len));
    try proto.appendSlice(allocator, msg.ciphertext);

    // Build: VERSION_BYTE + proto_bytes
    const proto_bytes = proto.items;
    const msg_without_mac = try allocator.alloc(u8, 1 + proto_bytes.len);
    defer allocator.free(msg_without_mac);
    msg_without_mac[0] = VERSION_BYTE;
    @memcpy(msg_without_mac[1..], proto_bytes);

    // Compute MAC over the message (without MAC)
    const mac = msg.computeMac(msg_without_mac);

    // Final: VERSION_BYTE + proto_bytes + 8-byte MAC
    const result = try allocator.alloc(u8, msg_without_mac.len + MAC_LENGTH);
    @memcpy(result[0..msg_without_mac.len], msg_without_mac);
    @memcpy(result[msg_without_mac.len..], &mac);

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
    var proto = std.ArrayList(u8).empty;
    defer proto.deinit(allocator);

    // Field 5: registration_id (uint32), wire type 0
    try proto.append(allocator, 0x28); // field 5, wire type 0
    try appendVarint(&proto, allocator, registration_id);

    // Field 1: prekey_id (uint32), wire type 0 — optional
    if (prekey_id) |pk_id| {
        try proto.append(allocator, 0x08); // field 1, wire type 0
        try appendVarint(&proto, allocator, pk_id);
    }

    // Field 6: signed_prekey_id (uint32), wire type 0
    try proto.append(allocator, 0x30); // field 6, wire type 0
    try appendVarint(&proto, allocator, signed_prekey_id);

    // Field 2: base_key (bytes), wire type 2 — 0x05 prefix + 32 bytes
    try proto.append(allocator, 0x12); // field 2, wire type 2
    try proto.append(allocator, 33);
    try proto.append(allocator, 0x05);
    try proto.appendSlice(allocator, &base_key);

    // Field 3: identity_key (bytes), wire type 2 — 0x05 prefix + 32 bytes
    try proto.append(allocator, 0x1A); // field 3, wire type 2
    try proto.append(allocator, 33);
    try proto.append(allocator, 0x05);
    try proto.appendSlice(allocator, &identity_key);

    // Field 4: message (bytes), wire type 2 — the SignalMessage
    try proto.append(allocator, 0x22); // field 4, wire type 2
    try appendVarint(&proto, allocator, @intCast(signal_message.len));
    try proto.appendSlice(allocator, signal_message);

    // Build: VERSION_BYTE + proto_bytes
    const result = try allocator.alloc(u8, 1 + proto.items.len);
    result[0] = VERSION_BYTE;
    @memcpy(result[1..], proto.items);

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
