const std = @import("std");
const retained_codec_capacity = 64 * 1024;

pub fn unpackInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) ![]const u8 {
    if (data.len == 0) return error.EmptyFrame;
    if ((data[0] & 2) != 0) return zlibDecompressInto(out, allocator, data[1..]);
    return data[1..];
}

pub fn unpackOwned(
    scratch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) ![]u8 {
    const unpacked = try unpackInto(scratch, allocator, data);
    return allocator.dupe(u8, unpacked);
}

pub fn packInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) !void {
    resetReusableBuffer(out, allocator, 1 + data.len);
    const result = try out.addManyAsSlice(allocator, 1 + data.len);
    result[0] = 0;
    @memcpy(result[1..], data);
}

fn zlibDecompressInto(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    compressed: []const u8,
) ![]const u8 {
    const flate = std.compress.flate;
    var input_reader: std.Io.Reader = .fixed(compressed);
    var window_buf: [flate.max_window_len]u8 = undefined;
    var decompressor = flate.Decompress.init(&input_reader, .zlib, &window_buf);
    resetReusableBuffer(out, allocator, compressed.len);
    errdefer out.clearRetainingCapacity();
    while (true) {
        const chunk = decompressor.reader.peek(1) catch |err| switch (err) {
            error.ReadFailed => {
                if (decompressor.err) |e| return e;
                break;
            },
            else => return err,
        };
        if (chunk.len == 0) break;
        try out.appendSlice(allocator, chunk);
        decompressor.reader.toss(chunk.len);
    }
    return out.items;
}

fn resetReusableBuffer(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    needed: usize,
) void {
    if (out.capacity > retained_codec_capacity and needed <= retained_codec_capacity) {
        out.clearAndFree(allocator);
    } else {
        out.clearRetainingCapacity();
    }
}
