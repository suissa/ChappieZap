const std = @import("std");
const binary = @import("binary");
const keepalive = @import("keepalive.zig");
const stanza_processor = @import("stanza_processor.zig");
const transport = @import("transport.zig");
const unified_session = @import("unified_session.zig");

pub const PumpResult = enum {
    keep_going,
    done,
};

const KeepaliveState = struct {
    next_ping_at: std.Io.Timestamp,
    pending_id_len: usize = 0,
    pending_id_buf: [transport.iq_id_buffer_len]u8 = undefined,
    pending_deadline_at: std.Io.Timestamp,

    fn init(io: std.Io) KeepaliveState {
        const now = std.Io.Clock.awake.now(io);
        return .{
            .next_ping_at = keepalive.scheduleNext(io, now),
            .pending_deadline_at = now,
        };
    }

    fn pendingId(self: *const KeepaliveState) ?[]const u8 {
        if (self.pending_id_len == 0) return null;
        return self.pending_id_buf[0..self.pending_id_len];
    }

    fn clearPending(self: *KeepaliveState) void {
        self.pending_id_len = 0;
    }
};

pub fn waitForMessage(self: anytype, expected: anytype, timeout_ms: u32) !void {
    var state = expected;
    return pumpUntil(self, timeout_ms, struct {
        fn onNode(client: @TypeOf(self), ctx: *@TypeOf(state), node: *binary.Node) !PumpResult {
            if (std.mem.eql(u8, node.tag, "message")) {
                var processed = stanza_processor.processMessageNode(client, node);
                defer processed.deinit(client.allocator);
                if (ctx.matchesNode(client, node, processed.body)) {
                    return .done;
                }
            } else {
                client.processNode(node);
            }
            return .keep_going;
        }
    }.onNode, &state, error.TextNotFound);
}

pub fn waitForReceiptFrom(self: anytype, expected_from: []const u8, timeout_ms: u32) !void {
    const expected = expected_from;
    return pumpUntil(self, timeout_ms, struct {
        fn onNode(client: @TypeOf(self), ctx: *const []const u8, node: *binary.Node) !PumpResult {
            client.processNode(node);
            if (std.mem.eql(u8, node.tag, "receipt")) {
                const from = node.getAttribute("from") orelse return .keep_going;
                if (std.mem.eql(u8, from, ctx.*)) return .done;
            }
            return .keep_going;
        }
    }.onNode, &expected, error.TextNotFound);
}

pub fn runMessageLoop(self: anytype) void {
    const Self = @TypeOf(self);
    const Task = struct {
        fn readLoopTask(client: Self) void {
            var ka = KeepaliveState.init(client.io);
            while (true) {
                const now = std.Io.Clock.awake.now(client.io);
                const deadline = if (ka.pendingId() != null) ka.pending_deadline_at else ka.next_ping_at;
                const wait_ms: u32 = if (now.nanoseconds >= deadline.nanoseconds)
                    0
                else
                    @intCast(now.durationTo(deadline).toMilliseconds());

                var node = transport.receiveNodeTimeout(client, wait_ms) catch |err| switch (err) {
                    error.Timeout => {
                        const timeout_now = std.Io.Clock.awake.now(client.io);
                        if (ka.pendingId()) |_| {
                            if (keepalive.isDeadSocket(
                                client.last_data_sent_at,
                                client.last_data_received_at,
                                timeout_now,
                            )) {
                                client.emit(.disconnected);
                                return;
                            }
                            ka.clearPending();
                            ka.next_ping_at = keepalive.scheduleNext(client.io, timeout_now);
                            continue;
                        }

                        const keepalive_id = transport.sendKeepaliveInto(client, &ka.pending_id_buf) catch {
                            client.emit(.disconnected);
                            return;
                        };
                        ka.pending_id_len = keepalive_id.len;
                        const sent_at = std.Io.Clock.awake.now(client.io);
                        ka.pending_deadline_at = sent_at.addDuration(keepalive.keep_alive_response_deadline);
                        continue;
                    },
                    else => {
                        client.emit(.disconnected);
                        return;
                    },
                };
                defer node.deinit();

                const received_at = std.Io.Clock.awake.now(client.io);
                ka.next_ping_at = keepalive.scheduleNext(client.io, received_at);
                if (isKeepaliveResponse(&ka, &node)) {
                    unified_session.updateServerTimeOffset(
                        &client.server_time_offset_ms,
                        &node,
                        unified_session.nowMillis(client.io),
                    );
                    ka.clearPending();
                }
                client.processNode(&node);
            }
        }
    };

    var future = self.io.async(Task.readLoopTask, .{self});
    future.await(self.io);
}

fn isKeepaliveResponse(state: *const KeepaliveState, node: *const binary.Node) bool {
    const pending_id = state.pendingId() orelse return false;
    if (!std.mem.eql(u8, node.tag, "iq")) return false;
    if (!std.mem.eql(u8, node.getAttribute("type") orelse return false, "result")) return false;
    return std.mem.eql(u8, node.getAttribute("id") orelse return false, pending_id);
}

pub fn pumpUntil(
    self: anytype,
    timeout_ms: u32,
    on_node: anytype,
    ctx: anytype,
    timeout_err: anyerror,
) !void {
    const start = std.Io.Clock.awake.now(self.io);
    while (true) {
        const elapsed_ms = start.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
        if (elapsed_ms >= timeout_ms) return timeout_err;
        const remaining_ms: u32 = @intCast(timeout_ms - elapsed_ms);

        var node = transport.receiveNodeTimeout(self, remaining_ms) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        defer node.deinit();

        switch (try on_node(self, ctx, &node)) {
            .keep_going => {},
            .done => return,
        }
    }
}
