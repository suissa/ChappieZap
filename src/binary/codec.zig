const std = @import("std");
const defs = @import("constants.zig");

pub const BinaryError = defs.BinaryError;
pub const LIST_EMPTY = defs.LIST_EMPTY;
pub const HEX_8 = defs.HEX_8;
pub const BINARY_8 = defs.BINARY_8;
pub const BINARY_20 = defs.BINARY_20;
pub const BINARY_32 = defs.BINARY_32;
pub const NIBBLE_8 = defs.NIBBLE_8;

pub const BinaryWriter = struct {
    buffer: []u8,
    pos: usize,

    pub fn init(buffer: []u8) BinaryWriter {
        return .{
            .buffer = buffer,
            .pos = 0,
        };
    }

    pub fn writeByte(self: *BinaryWriter, byte: u8) BinaryError!void {
        if (self.pos >= self.buffer.len) return BinaryError.BufferTooSmall;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeBytes(self: *BinaryWriter, bytes: []const u8) BinaryError!void {
        if (self.pos + bytes.len > self.buffer.len) return BinaryError.BufferTooSmall;
        @memcpy(self.buffer[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getPos(self: BinaryWriter) usize {
        return self.pos;
    }

    pub fn getWritten(self: BinaryWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

pub const BinaryReader = struct {
    buffer: []const u8,
    pos: usize,

    pub fn init(buffer: []const u8) BinaryReader {
        return .{
            .buffer = buffer,
            .pos = 0,
        };
    }

    pub fn readByte(self: *BinaryReader) BinaryError!u8 {
        if (self.pos >= self.buffer.len) return BinaryError.InvalidFormat;
        const byte = self.buffer[self.pos];
        self.pos += 1;
        return byte;
    }

    pub fn readBytes(self: *BinaryReader, count: usize) BinaryError![]const u8 {
        if (self.pos + count > self.buffer.len) return BinaryError.InvalidFormat;
        const bytes = self.buffer[self.pos .. self.pos + count];
        self.pos += count;
        return bytes;
    }

    pub fn getPos(self: BinaryReader) usize {
        return self.pos;
    }

    pub fn isAtEnd(self: BinaryReader) bool {
        return self.pos >= self.buffer.len;
    }
};

pub fn encodeVarint(value: u64, writer: *BinaryWriter) BinaryError!usize {
    var val = value;
    var bytes_written: usize = 0;

    while (val >= 0x80) {
        try writer.writeByte(@as(u8, @intCast(val & 0x7F)) | 0x80);
        val >>= 7;
        bytes_written += 1;
    }

    try writer.writeByte(@as(u8, @intCast(val & 0x7F)));
    return bytes_written + 1;
}

pub fn decodeVarint(reader: *BinaryReader) BinaryError!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    while (true) {
        if (bytes_read >= 10) return BinaryError.InvalidVarint;

        const byte = try reader.readByte();
        bytes_read += 1;
        result |= @as(u64, byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) break;
        if (shift >= 63) return BinaryError.InvalidVarint;
        shift += 7;
    }

    return result;
}

pub fn getVarintSize(value: u64) usize {
    if (value == 0) return 1;

    var val = value;
    var size: usize = 0;
    while (val > 0) {
        size += 1;
        val >>= 7;
    }
    return size;
}

pub fn encodeStringRegular(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!std.unicode.utf8ValidateSlice(str)) return BinaryError.InvalidUtf8;

    if (str.len < 256) {
        try writer.writeByte(BINARY_8);
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 2 + str.len;
    } else if (str.len < (1 << 20)) {
        try writer.writeByte(BINARY_20);
        try writer.writeByte(@intCast(str.len >> 16));
        try writer.writeByte(@intCast(str.len >> 8));
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 4 + str.len;
    } else {
        try writer.writeByte(BINARY_32);
        try writer.writeByte(@intCast(str.len >> 24));
        try writer.writeByte(@intCast(str.len >> 16));
        try writer.writeByte(@intCast(str.len >> 8));
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 5 + str.len;
    }
}

pub fn decodeStringRegular(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const length = try decodeVarint(reader);
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));
    if (!std.unicode.utf8ValidateSlice(bytes)) return BinaryError.InvalidUtf8;
    return allocator.dupe(u8, bytes);
}

pub fn getStringEncodedSize(str: []const u8) usize {
    return getVarintSize(str.len) + str.len;
}

pub fn encodeBytes(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    const length_bytes = try encodeVarint(bytes.len, writer);
    try writer.writeBytes(bytes);
    return length_bytes + bytes.len;
}

pub fn decodeBytes(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const length = try decodeVarint(reader);
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));
    return allocator.dupe(u8, bytes);
}

pub fn getBytesEncodedSize(bytes: []const u8) usize {
    return getVarintSize(bytes.len) + bytes.len;
}

pub fn isDecimalDigits(str: []const u8) bool {
    for (str) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

pub fn isHexDigits(str: []const u8) bool {
    for (str) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn encodeNibble(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!isDecimalDigits(str)) return BinaryError.InvalidFormat;

    var total_bytes: usize = 0;
    try writer.writeByte(NIBBLE_8);
    total_bytes += 1;

    const packed_len = (str.len + 1) / 2;
    var length_byte: u8 = @intCast(packed_len);
    if (str.len % 2 == 1) length_byte |= 0x80;

    try writer.writeByte(length_byte);
    total_bytes += 1;

    var i: usize = 0;
    while (i < str.len) {
        const digit1: u4 = @intCast(str[i] - '0');
        i += 1;

        var byte: u8 = @intCast(@as(u8, digit1) << 4);
        if (i < str.len) {
            const digit2: u4 = @intCast(str[i] - '0');
            byte |= digit2;
            i += 1;
        }

        try writer.writeByte(byte);
        total_bytes += 1;
    }

    return total_bytes;
}

pub fn decodeNibble(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const length_byte = try reader.readByte();
    const packed_len = length_byte & 0x7F;
    const is_odd = (length_byte & 0x80) != 0;
    const original_len = packed_len * 2 - if (is_odd) @as(usize, 1) else @as(usize, 0);

    var result = try std.ArrayList(u8).initCapacity(allocator, original_len);
    defer result.deinit(allocator);

    var bytes_read: usize = 0;
    while (bytes_read < packed_len) {
        const byte = try reader.readByte();
        bytes_read += 1;

        const digit1 = (byte >> 4) & 0xF;
        const digit2 = byte & 0xF;

        try result.append(allocator, try unpackNibbleDigit(digit1));
        try result.append(allocator, try unpackNibbleDigit(digit2));
    }

    if (is_odd and result.items.len != 0) {
        _ = result.pop();
    }

    return result.toOwnedSlice(allocator);
}

pub fn encodeHex(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!isHexDigits(str)) return BinaryError.InvalidFormat;

    var total_bytes: usize = 0;
    try writer.writeByte(HEX_8);
    total_bytes += 1;

    const packed_len = (str.len + 1) / 2;
    var length_byte: u8 = @intCast(packed_len);
    if (str.len % 2 == 1) length_byte |= 0x80;

    try writer.writeByte(length_byte);
    total_bytes += 1;

    var i: usize = 0;
    while (i < str.len) {
        const digit1 = hexDigitToValue(str[i]);
        i += 1;

        var byte: u8 = @intCast(@as(u8, digit1) << 4);
        if (i < str.len) {
            const digit2 = hexDigitToValue(str[i]);
            byte |= digit2;
            i += 1;
        }

        try writer.writeByte(byte);
        total_bytes += 1;
    }

    return total_bytes;
}

fn hexDigitToValue(c: u8) u4 {
    return switch (c) {
        '0'...'9' => @as(u4, @intCast(c - '0')),
        'A'...'F' => @as(u4, @intCast(c - 'A' + 10)),
        'a'...'f' => @as(u4, @intCast(c - 'a' + 10)),
        else => 0,
    };
}

fn valueToHexDigit(value: u4) u8 {
    return switch (value) {
        0...9 => @as(u8, '0') + @as(u8, value),
        10...15 => @as(u8, 'A') + @as(u8, value - 10),
    };
}

pub fn decodeHex(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const length_byte = try reader.readByte();
    const packed_len = length_byte & 0x7F;
    const is_odd = (length_byte & 0x80) != 0;
    const original_len = packed_len * 2 - if (is_odd) @as(usize, 1) else @as(usize, 0);

    var result = try std.ArrayList(u8).initCapacity(allocator, original_len);
    defer result.deinit(allocator);

    var bytes_read: usize = 0;
    while (bytes_read < packed_len) {
        const byte = try reader.readByte();
        bytes_read += 1;

        const digit1: u4 = @intCast((byte >> 4) & 0xF);
        const digit2: u4 = @intCast(byte & 0xF);

        try result.append(allocator, valueToHexDigit(digit1));
        try result.append(allocator, valueToHexDigit(digit2));
    }

    if (is_odd and result.items.len != 0) {
        _ = result.pop();
    }

    return result.toOwnedSlice(allocator);
}

fn unpackNibbleDigit(value: u8) BinaryError!u8 {
    return switch (value) {
        0...9 => '0' + @as(u8, @intCast(value)),
        10 => '-',
        11 => '.',
        15 => 0,
        else => BinaryError.InvalidToken,
    };
}

test "decode nibble packed odd length trims filler nibble" {
    const allocator = std.testing.allocator;
    var reader = BinaryReader.init(&[_]u8{
        0x82,
        0x12,
        0x3F,
    });

    const decoded = try decodeNibble(&reader, allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("123", decoded);
}

test "decode hex packed odd length trims filler nibble" {
    const allocator = std.testing.allocator;
    var reader = BinaryReader.init(&[_]u8{
        0x82,
        0xAB,
        0xCF,
    });

    const decoded = try decodeHex(&reader, allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("ABC", decoded);
}

pub fn encodeBytes20(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (bytes.len >= (1 << 20)) return BinaryError.InvalidFormat;

    try writer.writeByte(BINARY_20);
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 16) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 8) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast(bytes.len & 0xFF)));
    try writer.writeBytes(bytes);
    return 4 + bytes.len;
}

pub fn decodeBytes20(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const len_high = try reader.readByte();
    const len_mid = try reader.readByte();
    const len_low = try reader.readByte();
    const length = (@as(u32, len_high) << 16) | (@as(u32, len_mid) << 8) | @as(u32, len_low);
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));
    return allocator.dupe(u8, bytes);
}

pub fn encodeBytes32(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    try writer.writeByte(BINARY_32);
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 24) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 16) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 8) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast(bytes.len & 0xFF)));
    try writer.writeBytes(bytes);
    return 5 + bytes.len;
}

pub fn decodeBytes32(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const len_byte1 = try reader.readByte();
    const len_byte2 = try reader.readByte();
    const len_byte3 = try reader.readByte();
    const len_byte4 = try reader.readByte();
    const length = (@as(u32, len_byte1) << 24) |
        (@as(u32, len_byte2) << 16) |
        (@as(u32, len_byte3) << 8) |
        @as(u32, len_byte4);
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));
    return allocator.dupe(u8, bytes);
}

pub fn compressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    var compress_buffer: [4096]u8 = undefined;
    var compressor = std.compress.flate.Compress.init(&output_writer.writer, &compress_buffer, .{
        .level = .default,
        .container = .gzip,
    });

    _ = try compressor.writer.write(data);
    try compressor.end();
    return allocator.dupe(u8, output_writer.written());
}

pub fn decompressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    var input_reader = std.Io.Reader.fixed(data);
    var decompress_buffer: [65536]u8 = undefined;
    var decompressor = std.compress.flate.Decompress.init(&input_reader, .gzip, &decompress_buffer);

    var buffer: [1024]u8 = undefined;
    while (true) {
        const bytes_read = decompressor.read(&buffer) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (bytes_read == 0) break;
        try output_writer.writer.writeAll(buffer[0..bytes_read]);
    }

    return allocator.dupe(u8, output_writer.written());
}
