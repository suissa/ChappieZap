const std = @import("std");
const binary = @import("binary");

const day_ms: i64 = 24 * 60 * 60 * 1000;
const week_ms: i64 = 7 * day_ms;
const offset_ms: i64 = 3 * day_ms;

pub fn calculateId(server_time_offset_ms: i64, now_ms: i64) i64 {
    const adjusted_now = now_ms + server_time_offset_ms;
    const raw = @mod(adjusted_now + offset_ms, week_ms);
    return raw;
}

pub fn nowMillis(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

pub fn updateServerTimeOffset(server_time_offset_ms: *i64, node: *const binary.Node, now_ms: i64) void {
    const t_val = node.getAttribute("t") orelse return;
    const server_time_s = std.fmt.parseInt(i64, t_val, 10) catch return;
    if (server_time_s <= 0) return;
    server_time_offset_ms.* = (server_time_s - @divTrunc(now_ms, 1000)) * 1000;
}

pub fn buildNode(allocator: std.mem.Allocator, server_time_offset_ms: i64, now_ms: i64) !binary.Node {
    var ib = binary.Node.initBorrowed(allocator, "ib");
    errdefer ib.deinit();

    var id_buf: [20]u8 = undefined;
    const id = try std.fmt.bufPrint(&id_buf, "{d}", .{calculateId(server_time_offset_ms, now_ms)});

    var session = binary.Node.initBorrowed(allocator, "unified_session");
    errdefer session.deinit();
    try session.addAttributeBorrowed("id", id);
    try ib.addChild(&session);
    return ib;
}

test "calculateId stays in weekly range" {
    const id = calculateId(0, 0);
    try std.testing.expect(id >= 0);
    try std.testing.expect(id < week_ms);
}
