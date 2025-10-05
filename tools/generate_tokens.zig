const std = @import("std");

/// Generate compile-time token data from tokens.json
/// This script reads tokens.json and outputs a tokens_generated.zig file
pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Read tokens.json
    const cwd = std.fs.cwd();
    const json_content = try cwd.readFileAlloc(allocator, "src/tokens.json", 1024 * 1024);
    defer allocator.free(json_content);

    // Parse JSON
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_content,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value.object;
    const single_byte = root.get("single_byte").?.array;
    const double_byte = root.get("double_byte").?.array;

    // Create output file
    const out_file = try cwd.createFile("src/gen/tokens_generated.zig", .{});
    defer out_file.close();

    // Use a large buffer to hold the entire generated file
    var buffer_list: std.ArrayList(u8) = .empty;
    defer buffer_list.deinit(allocator);
    const writer = buffer_list.writer(allocator);

    // Generate header
    try writer.writeAll(
        \\// AUTO-GENERATED FILE - DO NOT EDIT
        \\// Generated from tokens.json by tools/generate_tokens.zig
        \\//
        \\// To regenerate: zig run tools/generate_tokens.zig
        \\
        \\const std = @import("std");
        \\
        \\/// Token data for double-byte tokens
        \\const TokenData = struct {
        \\    page: u8,
        \\    index: u8,
        \\};
        \\
        \\
    );

    // Generate single-byte token array
    try writer.print("// Single-byte tokens: {} entries\n", .{single_byte.items.len});
    try writer.writeAll("const single_byte_tokens = [_][]const u8{\n");
    for (single_byte.items) |item| {
        const str = item.string;
        try writer.print("    \"{s}\",\n", .{str});
    }
    try writer.writeAll("};\n\n");

    // Generate double-byte token arrays
    try writer.print("// Double-byte tokens: {} pages of 256 entries each\n", .{double_byte.items.len});
    try writer.writeAll("const double_byte_tokens = [_][256][]const u8{\n");
    for (double_byte.items, 0..) |page_array, page_idx| {
        try writer.print("    // Page {}\n", .{page_idx});
        try writer.writeAll("    .{\n");
        for (page_array.array.items) |item| {
            const str = item.string;
            try writer.print("        \"{s}\",\n", .{str});
        }
        try writer.writeAll("    },\n");
    }
    try writer.writeAll("};\n\n");

    // Generate compile-time initialization code
    try writer.writeAll(
        \\/// Compile-time initialized token data with StaticStringMap for fast lookups
        \\pub const token_data = blk: {
        \\    @setEvalBranchQuota(100000);
        \\    
        \\    // Build single-byte token lookup (string -> token index)
        \\    var single_kvs: [236]struct { []const u8, u8 } = undefined;
        \\    for (single_byte_tokens, 0..) |token_str, i| {
        \\        single_kvs[i] = .{ token_str, @intCast(i) };
        \\    }
        \\    const single_map = std.StaticStringMap(u8).initComptime(single_kvs);
        \\    
        \\    // Build double-byte token lookup (string -> page + index)
        \\    var double_kvs: [1024]struct { []const u8, TokenData } = undefined;
        \\    var double_idx: usize = 0;
        \\    for (double_byte_tokens, 0..) |page_array, page| {
        \\        for (page_array, 0..) |token_str, idx| {
        \\            double_kvs[double_idx] = .{ 
        \\                token_str, 
        \\                TokenData{ .page = @intCast(page), .index = @intCast(idx) },
        \\            };
        \\            double_idx += 1;
        \\        }
        \\    }
        \\    const double_map = std.StaticStringMap(TokenData).initComptime(double_kvs[0..double_idx].*);
        \\    
        \\    break :blk .{
        \\        .single_map = single_map,
        \\        .double_map = double_map,
        \\        .single_reverse = single_byte_tokens,
        \\        .double_reverse = double_byte_tokens,
        \\    };
        \\};
        \\
    );

    // Write buffer to file
    try out_file.writeAll(buffer_list.items);

    std.debug.print("✓ Generated src/tokens_generated.zig\n", .{});
    std.debug.print("  Single-byte tokens: {}\n", .{single_byte.items.len});
    var total_double: usize = 0;
    for (double_byte.items) |page_array| {
        total_double += page_array.array.items.len;
    }
    std.debug.print("  Double-byte tokens: {}\n", .{total_double});
    std.debug.print("  Total: {}\n", .{single_byte.items.len + total_double});
    std.debug.print("  File size: {} bytes\n", .{buffer_list.items.len});
}
