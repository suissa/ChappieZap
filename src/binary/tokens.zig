const std = @import("std");

const TokenData = struct {
    page: u8,
    index: u8,
};

const tokens_gen = @import("../gen/tokens_generated.zig");
const token_data = tokens_gen.token_data;

pub fn initTokens(_: std.mem.Allocator) !void {}

pub fn getSingleByteToken(str: []const u8) ?u8 {
    return token_data.single_map.get(str);
}

pub fn getDoubleByteToken(str: []const u8) ?struct { u8, u8 } {
    const data = token_data.double_map.get(str) orelse return null;
    return .{ data.page, data.index };
}

pub fn getStringForSingleByteToken(token: u8) ?[]const u8 {
    if (token >= tokens_gen.single_byte_tokens.len) return null;
    return tokens_gen.single_byte_tokens[token];
}

pub fn getStringForDoubleByteToken(page: u8, token: u8) ?[]const u8 {
    if (page >= tokens_gen.double_byte_tokens.len) return null;
    return tokens_gen.double_byte_tokens[page][token];
}
