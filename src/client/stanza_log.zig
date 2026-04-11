const std = @import("std");
const binary = @import("binary");
const log = @import("log");

pub fn logNode(comptime scope: []const u8, node: *const binary.Node) void {
    if (!log.enabled(.debug)) return;

    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    if (!appendFmt(&buf, &pos, "<{s}", .{node.tag})) return;
    for (node.attributes.items) |attr| {
        if (!appendFmt(&buf, &pos, " {s}=\"{s}\"", .{ attr.key, attr.value })) return;
    }

    if (node.getContentNodes()) |children| {
        if (!appendFmt(&buf, &pos, ">", .{})) return;
        for (children) |*child| {
            if (!appendFmt(&buf, &pos, "<{s}/>", .{child.tag})) return;
        }
        if (!appendFmt(&buf, &pos, "</{s}>", .{node.tag})) return;
    } else if (node.getContentBytes()) |bytes| {
        if (!appendFmt(&buf, &pos, "><!-- {d} bytes --></{s}>", .{ bytes.len, node.tag })) return;
    } else {
        if (!appendFmt(&buf, &pos, "/>", .{})) return;
    }

    log.debug(scope, "{s}", .{buf[0..pos]});
}

pub fn iqIdsMatch(actual: []const u8, expected: []const u8) bool {
    if (std.mem.eql(u8, actual, expected)) return true;
    if (actual.len == expected.len + 1 and actual[actual.len - 1] == 'F') {
        return std.mem.eql(u8, actual[0..expected.len], expected);
    }
    return false;
}

pub fn buildIqResultNode(
    allocator: std.mem.Allocator,
    id: ?[]const u8,
    to: []const u8,
) !binary.Node {
    var node = binary.Node.initBorrowed(allocator, "iq");
    errdefer node.deinit();

    try node.addAttributeBorrowed("to", to);
    if (id) |iq_id| try node.addAttributeBorrowed("id", iq_id);
    try node.addAttributeBorrowed("type", "result");

    return node;
}

pub fn shortHex(bytes: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    for (bytes, 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {
            @panic("shortHex buffer too small");
        };
    }
    return out;
}

pub fn allocHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {
            @panic("allocHex buffer too small");
        };
    }
    return out;
}

fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) bool {
    const written = std.fmt.bufPrint(buf[pos.*..], fmt, args) catch {
        if (pos.* + 15 <= buf.len) {
            @memcpy(buf[pos.* .. pos.* + 15], " ...<truncated>");
            pos.* += 15;
            return true;
        }
        return false;
    };
    pos.* += written.len;
    return true;
}

test "iq result encoding matches Rust wire order" {
    const allocator = std.testing.allocator;

    var node = try buildIqResultNode(allocator, "3610797473", "s.whatsapp.net");
    defer node.deinit();

    var buf: [64]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buf);
    _ = try binary.encodeNode(&node, &writer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xf8, 0x07, 0x19,
        0x11, 0x03, 0x08,
        0xff, 0x05, 0x36,
        0x10, 0x79, 0x74,
        0x73, 0x04, 0x14,
    }, writer.getWritten());
}

test "iqIdsMatch accepts whatsapp trailing F suffix" {
    try std.testing.expect(iqIdsMatch("2F", "2"));
    try std.testing.expect(iqIdsMatch("345F", "345"));
    try std.testing.expect(iqIdsMatch("7", "7"));
    try std.testing.expect(!iqIdsMatch("27F", "2"));
    try std.testing.expect(!iqIdsMatch("2X", "2"));
}
