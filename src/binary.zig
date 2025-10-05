const std = @import("std");

/// Binary encoding and decoding utilities for WhatsApp protocol
/// This module provides functions for encoding and decoding various data types
/// used in the WhatsApp binary protocol, including varints, strings, byte arrays,
/// and compression.

/// Error types for binary operations
pub const BinaryError = error{
    /// Buffer too small for encoding
    BufferTooSmall,
    /// Invalid varint encoding
    InvalidVarint,
    /// Invalid UTF-8 string
    InvalidUtf8,
    /// Compression/decompression error
    CompressionError,
    /// Invalid data format
    InvalidFormat,
    /// Write operation failed
    WriteFailed,
    /// Read operation failed
    ReadFailed,
};

/// Writer interface for binary encoding
pub const BinaryWriter = struct {
    buffer: []u8,
    pos: usize,

    /// Initialize a binary writer with a buffer
    pub fn init(buffer: []u8) BinaryWriter {
        return BinaryWriter{
            .buffer = buffer,
            .pos = 0,
        };
    }

    /// Write a single byte
    pub fn writeByte(self: *BinaryWriter, byte: u8) BinaryError!void {
        if (self.pos >= self.buffer.len) return BinaryError.BufferTooSmall;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    /// Write multiple bytes
    pub fn writeBytes(self: *BinaryWriter, bytes: []const u8) BinaryError!void {
        if (self.pos + bytes.len > self.buffer.len) return BinaryError.BufferTooSmall;
        @memcpy(self.buffer[self.pos..self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    /// Get the current position
    pub fn getPos(self: BinaryWriter) usize {
        return self.pos;
    }

    /// Get the written data
    pub fn getWritten(self: BinaryWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

/// Reader interface for binary decoding
pub const BinaryReader = struct {
    buffer: []const u8,
    pos: usize,

    /// Initialize a binary reader with a buffer
    pub fn init(buffer: []const u8) BinaryReader {
        return BinaryReader{
            .buffer = buffer,
            .pos = 0,
        };
    }

    /// Read a single byte
    pub fn readByte(self: *BinaryReader) BinaryError!u8 {
        if (self.pos >= self.buffer.len) return BinaryError.InvalidFormat;
        const byte = self.buffer[self.pos];
        self.pos += 1;
        return byte;
    }

    /// Read multiple bytes
    pub fn readBytes(self: *BinaryReader, count: usize) BinaryError![]const u8 {
        if (self.pos + count > self.buffer.len) return BinaryError.InvalidFormat;
        const bytes = self.buffer[self.pos..self.pos + count];
        self.pos += count;
        return bytes;
    }

    /// Get the current position
    pub fn getPos(self: BinaryReader) usize {
        return self.pos;
    }

    /// Check if at end of buffer
    pub fn isAtEnd(self: BinaryReader) bool {
        return self.pos >= self.buffer.len;
    }
};

// Core encoding/decoding functions will be implemented here
// - varint encoding/decoding
// - string encoding/decoding
// - byte array encoding/decoding
// - compression/decompression

/// Encode a u64 as a varint
/// Returns the number of bytes written
pub fn encodeVarint(value: u64, writer: *BinaryWriter) BinaryError!usize {
    var val = value;
    var bytes_written: usize = 0;

    while (val >= 0x80) {
        try writer.writeByte(@as(u8, @intCast(val & 0x7F)) | 0x80);
        val >>= 7;
        bytes_written += 1;
    }

    try writer.writeByte(@as(u8, @intCast(val & 0x7F)));
    bytes_written += 1;

    return bytes_written;
}

/// Decode a varint from the reader
/// Returns the decoded u64 value
pub fn decodeVarint(reader: *BinaryReader) BinaryError!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    while (true) {
        if (bytes_read >= 10) return BinaryError.InvalidVarint; // Maximum 10 bytes for u64

        const byte = try reader.readByte();
        bytes_read += 1;

        result |= @as(u64, byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) break;

        if (shift >= 63) return BinaryError.InvalidVarint;

        shift += 7;
    }

    return result;
}

/// Get the size of a varint encoding for a u64 value
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

/// Encode a string with length prefix
/// Returns the number of bytes written
pub fn encodeString(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    // Validate UTF-8
    if (!std.unicode.utf8ValidateSlice(str)) return BinaryError.InvalidUtf8;

    // Encode length as varint
    const length_bytes = try encodeVarint(str.len, writer);

    // Write string bytes
    try writer.writeBytes(str);

    return length_bytes + str.len;
}

/// Decode a string with length prefix
/// Returns the decoded string (caller owns the memory)
pub fn decodeString(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read length
    const length = try decodeVarint(reader);

    // Read string bytes
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));

    // Validate UTF-8
    if (!std.unicode.utf8ValidateSlice(bytes)) return BinaryError.InvalidUtf8;

    // Duplicate the string for the caller
    return allocator.dupe(u8, bytes);
}

/// Get the encoded size of a string
pub fn getStringEncodedSize(str: []const u8) usize {
    return getVarintSize(str.len) + str.len;
}

/// Encode a byte array with length prefix
/// Returns the number of bytes written
pub fn encodeBytes(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    // Encode length as varint
    const length_bytes = try encodeVarint(bytes.len, writer);

    // Write bytes
    try writer.writeBytes(bytes);

    return length_bytes + bytes.len;
}

/// Decode a byte array with length prefix
/// Returns the decoded bytes (caller owns the memory)
pub fn decodeBytes(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read length
    const length = try decodeVarint(reader);

    // Read bytes
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));

    // Duplicate the bytes for the caller
    return allocator.dupe(u8, bytes);
}

/// Get the encoded size of a byte array
pub fn getBytesEncodedSize(bytes: []const u8) usize {
    return getVarintSize(bytes.len) + bytes.len;
}

/// Compress data using zlib/deflate
/// Returns the compressed data (caller owns the memory)
pub fn compressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    // Use a buffer for compression
    var compress_buffer: [4096]u8 = undefined;

    var compressor = std.compress.flate.Compress.init(&output_writer.writer, &compress_buffer, .{
        .level = .default,
        .container = .gzip,
    });

    // Write data to compressor
    _ = try compressor.writer.write(data);

    // Finish compression
    try compressor.end();

    return allocator.dupe(u8, output_writer.written());
}

/// Decompress data using zlib/deflate
/// Returns the decompressed data (caller owns the memory)
pub fn decompressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    // Create a reader from the compressed data
    var input_reader = std.Io.Reader.fixed(data);

    // Buffer for decompression
    var decompress_buffer: [65536]u8 = undefined;

    var decompressor = std.compress.flate.Decompress.init(&input_reader, .gzip, &decompress_buffer);

    // Read all decompressed data
    var buffer: [1024]u8 = undefined;
    while (true) {
        const bytes_read = decompressor.reader.read(&buffer) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (bytes_read == 0) break;
        try output_writer.writer.writeAll(buffer[0..bytes_read]);
    }

    return allocator.dupe(u8, output_writer.written());
}

test "BinaryWriter basic functionality" {
    var buffer: [10]u8 = undefined;
    var writer = BinaryWriter.init(&buffer);

    try writer.writeByte(0x42);
    try writer.writeBytes(&[_]u8{ 0x01, 0x02, 0x03 });

    try std.testing.expectEqual(@as(usize, 4), writer.getPos());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x42, 0x01, 0x02, 0x03 }, writer.getWritten());
}

test "BinaryReader basic functionality" {
    const data = [_]u8{ 0x42, 0x01, 0x02, 0x03 };
    var reader = BinaryReader.init(&data);

    try std.testing.expectEqual(@as(u8, 0x42), try reader.readByte());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, try reader.readBytes(3));
    try std.testing.expect(reader.isAtEnd());
}

test "varint encoding/decoding" {
    var buffer: [10]u8 = undefined;

    // Test various values
    const test_values = [_]u64{ 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF };

    for (test_values) |value| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeVarint(value, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeVarint(&reader);

        try std.testing.expectEqual(value, decoded);
        try std.testing.expectEqual(getVarintSize(value), bytes_written);
    }
}

test "varint edge cases" {
    var buffer: [10]u8 = undefined;

    // Test maximum u64 value
    const max_u64 = std.math.maxInt(u64);
    var writer = BinaryWriter.init(&buffer);
    _ = try encodeVarint(max_u64, &writer);
    const encoded = writer.getWritten();

    var reader = BinaryReader.init(encoded);
    const decoded = try decodeVarint(&reader);
    try std.testing.expectEqual(max_u64, decoded);

    // Test that we don't overflow
    const overflow_data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var overflow_reader = BinaryReader.init(&overflow_data);
    try std.testing.expectError(BinaryError.InvalidVarint, decodeVarint(&overflow_reader));
}

test "string encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_strings = [_][]const u8{
        "",
        "hello",
        "Hello, 世界!",
        "🚀 Unicode test",
        "a" ** 50, // Long string
    };

    for (test_strings) |test_str| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeString(test_str, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeString(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualStrings(test_str, decoded);
        try std.testing.expectEqual(getStringEncodedSize(test_str), bytes_written);
    }
}

test "string encoding invalid UTF-8" {
    var buffer: [10]u8 = undefined;
    var writer = BinaryWriter.init(&buffer);

    // Invalid UTF-8 sequence
    const invalid_utf8 = [_]u8{ 0xFF, 0xFE, 0xFD };
    try std.testing.expectError(BinaryError.InvalidUtf8, encodeString(&invalid_utf8, &writer));
}

test "string decoding invalid UTF-8" {
    const allocator = std.testing.allocator;

    // Manually create invalid encoded data: length 3, followed by invalid UTF-8
    const invalid_data = [_]u8{ 0x03, 0xFF, 0xFE, 0xFD };
    var reader = BinaryReader.init(&invalid_data);

    try std.testing.expectError(BinaryError.InvalidUtf8, decodeString(&reader, allocator));
}

test "byte array encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_arrays = [_][]const u8{
        &[_]u8{},
        &[_]u8{ 0x00 },
        &[_]u8{ 0xFF, 0xFE, 0xFD }, // Invalid UTF-8 but valid bytes
        &[_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 },
        &[_]u8{ 0xFF } ** 50, // Long byte array
    };

    for (test_arrays) |test_bytes| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeBytes(test_bytes, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeBytes(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, test_bytes, decoded);
        try std.testing.expectEqual(getBytesEncodedSize(test_bytes), bytes_written);
    }
}

test "compression/decompression" {
    const allocator = std.testing.allocator;

    const test_data = [_][]const u8{
        "hello world",
        "Hello, World! This is a test string for compression.",
    };

    for (test_data) |data| {
        const compressed = try compressData(data, allocator);
        defer allocator.free(compressed);

        const decompressed = try decompressData(compressed, allocator);
        defer allocator.free(decompressed);

        try std.testing.expectEqualSlices(u8, data, decompressed);

        // Compressed data should be different from original (unless empty)
        if (data.len > 0) {
            try std.testing.expect(compressed.len != data.len or !std.mem.eql(u8, compressed, data));
        }
    }
}