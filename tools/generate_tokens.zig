const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Read tokens.json using posix
    const json_file = try std.posix.open("src/tokens.json", .{}, 0);
    defer std.posix.close(json_file);

    var json_buf: [1024 * 1024]u8 = undefined;
    var total_read: usize = 0;
    while (true) {
        const n = try std.posix.read(json_file, json_buf[total_read..]);
        if (n == 0) break;
        total_read += n;
    }
    const json_content = json_buf[0..total_read];

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const single_byte = root.get("single_byte").?.array;
    const double_byte = root.get("double_byte").?.array;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("// AUTO-GENERATED - DO NOT EDIT\n// Generated from src/tokens.json\n\nconst std = @import(\"std\");\n\nconst TokenData = struct { page: u8, index: u8 };\n\n");

    // Single-byte tokens
    try w.print("// Single-byte tokens: {d} entries\npub const single_byte_tokens = [_][]const u8{{\n", .{single_byte.items.len});
    for (single_byte.items) |item| {
        try w.print("    \"{s}\",\n", .{item.string});
    }
    try w.writeAll("};\n\n");

    // Double-byte tokens
    try w.print("// Double-byte tokens: {d} pages\npub const double_byte_tokens = [_][256][]const u8{{\n", .{double_byte.items.len});
    for (double_byte.items) |page| {
        try w.writeAll("    .{\n");
        for (page.array.items) |item| {
            try w.print("        \"{s}\",\n", .{item.string});
        }
        try w.writeAll("    },\n");
    }
    try w.writeAll("};\n\n");

    // Comptime maps
    try w.print("pub const token_data = blk: {{\n    @setEvalBranchQuota(100000);\n    var single_kvs: [{d}]struct {{ []const u8, u8 }} = undefined;\n    for (single_byte_tokens, 0..) |token_str, i| {{\n        single_kvs[i] = .{{ token_str, @intCast(i) }};\n    }}\n    const single_map = std.StaticStringMap(u8).initComptime(single_kvs);\n", .{single_byte.items.len});

    var dc: usize = 0;
    for (double_byte.items) |page| dc += page.array.items.len;
    try w.print("    var double_kvs: [{d}]struct {{ []const u8, TokenData }} = undefined;\n    var double_idx: usize = 0;\n    for (double_byte_tokens, 0..) |page_array, page| {{\n        for (page_array, 0..) |token_str, idx| {{\n            double_kvs[double_idx] = .{{ token_str, TokenData{{ .page = @intCast(page), .index = @intCast(idx) }} }};\n            double_idx += 1;\n        }}\n    }}\n    const double_map = std.StaticStringMap(TokenData).initComptime(double_kvs[0..double_idx].*);\n    break :blk .{{ .single_map = single_map, .double_map = double_map }};\n}};\n", .{dc});

    // Write output
    const out_file = try std.posix.open("src/gen/tokens_generated.zig", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer std.posix.close(out_file);
    var written: usize = 0;
    while (written < buf.items.len) {
        written += try std.posix.write(out_file, buf.items[written..]);
    }

    std.debug.print("Generated src/gen/tokens_generated.zig ({d} single, {d} double pages)\n", .{ single_byte.items.len, double_byte.items.len });
}
