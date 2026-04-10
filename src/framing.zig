const std = @import("std");

pub const FRAME_LENGTH_SIZE: usize = 3;
pub const FRAME_MAX_SIZE: usize = 2 << 23; // 16 MB

/// Encode a payload into a WhatsApp frame: [optional header][3-byte BE length][payload]
pub fn encodeFrame(allocator: std.mem.Allocator, payload: []const u8, header: ?[]const u8) ![]u8 {
    if (payload.len >= FRAME_MAX_SIZE) return error.FrameTooLarge;

    const header_len = if (header) |h| h.len else 0;
    const total = header_len + FRAME_LENGTH_SIZE + payload.len;
    const frame = try allocator.alloc(u8, total);
    var offset: usize = 0;

    if (header) |h| {
        @memcpy(frame[0..h.len], h);
        offset = h.len;
    }

    // 3-byte big-endian length (drop MSB of u32)
    const len_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(payload.len)));
    frame[offset] = len_bytes[1];
    frame[offset + 1] = len_bytes[2];
    frame[offset + 2] = len_bytes[3];
    offset += 3;

    @memcpy(frame[offset..][0..payload.len], payload);
    return frame;
}

/// Encode a payload into a WhatsApp frame, reusing caller-provided storage.
pub fn encodeFrameInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
    header: ?[]const u8,
) !void {
    if (payload.len >= FRAME_MAX_SIZE) return error.FrameTooLarge;

    const header_len = if (header) |h| h.len else 0;
    const total = header_len + FRAME_LENGTH_SIZE + payload.len;

    out.clearRetainingCapacity();
    const frame = try out.addManyAsSlice(allocator, total);
    var offset: usize = 0;

    if (header) |h| {
        @memcpy(frame[0..h.len], h);
        offset = h.len;
    }

    const len_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(payload.len)));
    frame[offset] = len_bytes[1];
    frame[offset + 1] = len_bytes[2];
    frame[offset + 2] = len_bytes[3];
    offset += 3;

    @memcpy(frame[offset..][0..payload.len], payload);
}

/// Streaming frame decoder — accumulates bytes and extracts complete frames.
pub const FrameDecoder = struct {
    buffer: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) FrameDecoder {
        return .{
            .buffer = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FrameDecoder) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn feed(self: *FrameDecoder, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, data);
    }

    /// Extract the next complete frame, or null if not enough data.
    pub fn decodeFrame(self: *FrameDecoder) ?[]const u8 {
        if (self.buffer.items.len < FRAME_LENGTH_SIZE) return null;

        const frame_len: usize = (@as(usize, self.buffer.items[0]) << 16) |
            (@as(usize, self.buffer.items[1]) << 8) |
            @as(usize, self.buffer.items[2]);

        if (frame_len > FRAME_MAX_SIZE) {
            // Invalid frame, skip the length prefix
            self.buffer.replaceRange(self.allocator, 0, FRAME_LENGTH_SIZE, &.{}) catch return null;
            return null;
        }

        const total_needed = FRAME_LENGTH_SIZE + frame_len;
        if (self.buffer.items.len < total_needed) return null;

        // Return slice into buffer (caller must use before next feed/decode)
        return self.buffer.items[FRAME_LENGTH_SIZE..total_needed];
    }

    /// Consume the last decoded frame from the buffer.
    /// Must be called after decodeFrame() returns non-null.
    pub fn consume(self: *FrameDecoder, frame_len: usize) void {
        const total = FRAME_LENGTH_SIZE + frame_len;
        self.buffer.replaceRange(self.allocator, 0, total, &.{}) catch {};
    }
};

test "encode frame no header" {
    const allocator = std.testing.allocator;
    const payload = &[_]u8{ 1, 2, 3, 4, 5 };
    const frame = try encodeFrame(allocator, payload, null);
    defer allocator.free(frame);

    try std.testing.expectEqual(@as(u8, 0), frame[0]);
    try std.testing.expectEqual(@as(u8, 0), frame[1]);
    try std.testing.expectEqual(@as(u8, 5), frame[2]);
    try std.testing.expectEqualSlices(u8, payload, frame[3..]);
}

test "encode frame with header" {
    const allocator = std.testing.allocator;
    const payload = &[_]u8{ 1, 2, 3 };
    const header = &[_]u8{ 0xAA, 0xBB };
    const frame = try encodeFrame(allocator, payload, header);
    defer allocator.free(frame);

    try std.testing.expectEqualSlices(u8, header, frame[0..2]);
    try std.testing.expectEqual(@as(u8, 0), frame[2]);
    try std.testing.expectEqual(@as(u8, 0), frame[3]);
    try std.testing.expectEqual(@as(u8, 3), frame[4]);
    try std.testing.expectEqualSlices(u8, payload, frame[5..]);
}

test "frame decoder" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    try decoder.feed(&[_]u8{ 0, 0, 5, 1, 2 });
    try std.testing.expect(decoder.decodeFrame() == null);

    try decoder.feed(&[_]u8{ 3, 4, 5 });
    const frame = decoder.decodeFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, frame);
    decoder.consume(frame.len);

    try std.testing.expect(decoder.decodeFrame() == null);
}

test "frame decoder multiple frames" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    try decoder.feed(&[_]u8{ 0, 0, 2, 0xAA, 0xBB, 0, 0, 3, 0xCC, 0xDD, 0xEE });

    const frame1 = decoder.decodeFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, frame1);
    decoder.consume(frame1.len);

    const frame2 = decoder.decodeFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xCC, 0xDD, 0xEE }, frame2);
    decoder.consume(frame2.len);

    try std.testing.expect(decoder.decodeFrame() == null);
}
