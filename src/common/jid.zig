const std = @import("std");

pub const ParseError = error{ InvalidJid, InvalidNumber };

pub const Parts = struct {
    user_part: []const u8,
    bare_user: []const u8,
    server: []const u8,
    agent: u8 = 0,
    device: u16 = 0,
    integrator: u16 = 0,
    has_device: bool = false,
};

pub fn parse(jid: []const u8) ParseError!Parts {
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return error.InvalidJid;
    const user_part = jid[0..at];
    const server = jid[at + 1 ..];

    if (std.mem.indexOfScalar(u8, user_part, '.')) |dot| {
        if (std.mem.indexOfScalar(u8, user_part[dot + 1 ..], ':')) |colon_after_dot| {
            return .{
                .user_part = user_part,
                .bare_user = "",
                .server = server,
                .agent = std.fmt.parseInt(u8, user_part[0..dot], 10) catch return error.InvalidNumber,
                .device = std.fmt.parseInt(u16, user_part[dot + 1 .. dot + 1 + colon_after_dot], 10) catch return error.InvalidNumber,
                .integrator = std.fmt.parseInt(u16, user_part[dot + 1 + colon_after_dot + 1 ..], 10) catch return error.InvalidNumber,
                .has_device = true,
            };
        }

        return .{
            .user_part = user_part,
            .bare_user = "",
            .server = server,
            .agent = std.fmt.parseInt(u8, user_part[0..dot], 10) catch return error.InvalidNumber,
            .device = std.fmt.parseInt(u16, user_part[dot + 1 ..], 10) catch return error.InvalidNumber,
            .has_device = true,
        };
    }

    if (std.mem.indexOfScalar(u8, user_part, ':')) |colon| {
        const bare_user = user_part[0..colon];
        const remainder = user_part[colon + 1 ..];
        if (std.mem.indexOfScalar(u8, remainder, ':')) |second_colon| {
            return .{
                .user_part = user_part,
                .bare_user = bare_user,
                .server = server,
                .device = std.fmt.parseInt(u16, remainder[0..second_colon], 10) catch return error.InvalidNumber,
                .integrator = std.fmt.parseInt(u16, remainder[second_colon + 1 ..], 10) catch return error.InvalidNumber,
                .has_device = true,
            };
        }
        return .{
            .user_part = user_part,
            .bare_user = bare_user,
            .server = server,
            .device = std.fmt.parseInt(u16, remainder, 10) catch return error.InvalidNumber,
            .has_device = true,
        };
    }

    return .{
        .user_part = user_part,
        .bare_user = user_part,
        .server = server,
        .has_device = false,
    };
}

pub fn isPn(jid: []const u8) bool {
    const parts = parse(jid) catch return false;
    return std.mem.eql(u8, parts.server, "s.whatsapp.net");
}

pub fn isLid(jid: []const u8) bool {
    const parts = parse(jid) catch return false;
    return std.mem.eql(u8, parts.server, "lid");
}

pub fn sameUserServer(a: []const u8, b: []const u8) bool {
    const a_parts = parse(a) catch return false;
    const b_parts = parse(b) catch return false;
    return std.mem.eql(u8, a_parts.bare_user, b_parts.bare_user) and
        std.mem.eql(u8, a_parts.server, b_parts.server);
}

test "parse simple jid" {
    const parts = try parse("559980000001@s.whatsapp.net");
    try std.testing.expectEqualStrings("559980000001", parts.bare_user);
    try std.testing.expectEqualStrings("s.whatsapp.net", parts.server);
    try std.testing.expect(!parts.has_device);
}

test "parse device jid" {
    const parts = try parse("559980000001:33@s.whatsapp.net");
    try std.testing.expectEqualStrings("559980000001", parts.bare_user);
    try std.testing.expectEqual(@as(u16, 33), parts.device);
    try std.testing.expect(parts.has_device);
}

test "parse agent device jid" {
    const parts = try parse("1.54321@messenger");
    try std.testing.expectEqualStrings("", parts.bare_user);
    try std.testing.expectEqual(@as(u8, 1), parts.agent);
    try std.testing.expectEqual(@as(u16, 54321), parts.device);
    try std.testing.expectEqual(@as(u16, 0), parts.integrator);
}

test "parse interop jid" {
    const parts = try parse("0.12345:56789@interop");
    try std.testing.expectEqualStrings("", parts.bare_user);
    try std.testing.expectEqual(@as(u8, 0), parts.agent);
    try std.testing.expectEqual(@as(u16, 12345), parts.device);
    try std.testing.expectEqual(@as(u16, 56789), parts.integrator);
}

pub fn writeProtocolAddressKey(buf: []u8, jid: []const u8) ![]const u8 {
    const parts = try parse(jid);
    if (std.mem.endsWith(u8, parts.server, ".0")) {
        return std.fmt.bufPrint(buf, "{s}@{s}", .{ parts.user_part, parts.server });
    }
    const mapped_server = if (std.mem.eql(u8, parts.server, "s.whatsapp.net")) "c.us" else parts.server;

    if (parts.has_device) {
        return std.fmt.bufPrint(buf, "{s}:{d}@{s}.0", .{ parts.bare_user, parts.device, mapped_server });
    }
    return std.fmt.bufPrint(buf, "{s}@{s}.0", .{ parts.bare_user, mapped_server });
}

pub fn protocolAddressKeyAlloc(allocator: std.mem.Allocator, jid: []const u8) ![]u8 {
    var buf: [128]u8 = undefined;
    const key = try writeProtocolAddressKey(&buf, jid);
    return allocator.dupe(u8, key);
}

test "write protocol address key normalizes pn and lid" {
    var buf: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "559980000001@c.us.0",
        try writeProtocolAddressKey(&buf, "559980000001@s.whatsapp.net"),
    );
    try std.testing.expectEqualStrings(
        "559980000001:33@c.us.0",
        try writeProtocolAddressKey(&buf, "559980000001:33@s.whatsapp.net"),
    );
    try std.testing.expectEqualStrings(
        "100000012345678@lid.0",
        try writeProtocolAddressKey(&buf, "100000012345678@lid"),
    );
}
