const std = @import("std");

pub const keep_alive_interval_min = std.Io.Duration.fromSeconds(20);
pub const keep_alive_interval_max = std.Io.Duration.fromSeconds(40);
pub const keep_alive_response_deadline = std.Io.Duration.fromSeconds(30);
pub const dead_socket_time = std.Io.Duration.fromSeconds(90);

pub fn randomInterval(io: std.Io) std.Io.Duration {
    var bytes: [4]u8 = undefined;
    io.random(&bytes);
    const span_ms: u32 = @intCast(keep_alive_interval_max.toMilliseconds() - keep_alive_interval_min.toMilliseconds());
    const offset_ms = std.mem.readInt(u32, &bytes, .little) % (span_ms + 1);
    return std.Io.Duration.fromMilliseconds(keep_alive_interval_min.toMilliseconds() + offset_ms);
}

pub fn scheduleNext(io: std.Io, from: std.Io.Timestamp) std.Io.Timestamp {
    return from.addDuration(randomInterval(io));
}

pub fn msSince(timestamp: std.Io.Timestamp, now: std.Io.Timestamp) ?u64 {
    if (timestamp.nanoseconds == 0) return null;
    const elapsed_ms = timestamp.durationTo(now).toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(elapsed_ms);
}

pub fn isDeadSocket(
    last_sent: std.Io.Timestamp,
    last_received: std.Io.Timestamp,
    now: std.Io.Timestamp,
) bool {
    if (last_sent.nanoseconds == 0) return false;
    if (last_received.nanoseconds >= last_sent.nanoseconds) return false;
    return (msSince(last_sent, now) orelse 0) > dead_socket_time.toMilliseconds();
}

test "dead socket matches send without receive" {
    const now = std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s * 100);
    const last_sent = std.Io.Timestamp.fromNanoseconds(0);
    const last_received = std.Io.Timestamp.zero;

    try std.testing.expect(!isDeadSocket(last_sent, last_received, now));

    const sent = std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s * 5);
    try std.testing.expect(isDeadSocket(sent, std.Io.Timestamp.zero, now));
    try std.testing.expect(!isDeadSocket(sent, now, now));
}
