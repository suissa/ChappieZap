const std = @import("std");
const builtin = @import("builtin");
const whatszig = @import("whatszig");
const log = whatszig.log;

pub const std_options: std.Options = switch (builtin.mode) {
    .ReleaseSmall => .{
        .signal_stack_size = null,
        .allow_stack_tracing = false,
    },
    else => .{},
};

const RuntimeConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    tls: bool = false,
    path: []const u8 = "/ws/chat",
    push_name: []const u8 = "whatszig-benchmark",
    host_owned: ?[]const u8 = null,
    path_owned: ?[]const u8 = null,

    fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        if (self.host_owned) |owned| allocator.free(owned);
        if (self.path_owned) |owned| allocator.free(owned);
    }
};

var qr_count: usize = 0;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var runtime_config = try loadRuntimeConfig(allocator, init.environ_map);
    defer runtime_config.deinit(allocator);

    var client = try whatszig.Client.init(allocator, io, .{
        .host = runtime_config.host,
        .port = runtime_config.port,
        .tls = runtime_config.tls,
        .path = runtime_config.path,
        .push_name = runtime_config.push_name,
        .on_event = handleEvent,
    });
    defer client.deinit();

    log.info("Benchmark", "Starting benchmark bot on {s}://{s}:{d}{s}", .{
        if (runtime_config.tls) "wss" else "ws",
        runtime_config.host,
        runtime_config.port,
        runtime_config.path,
    });

    client.connectAndRun() catch |err| {
        log.err("Benchmark", "{}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace);
        }
    };
}

fn handleEvent(event: whatszig.Event, ctx: *anyopaque) void {
    const client: *whatszig.Client = @ptrCast(@alignCast(ctx));

    switch (event) {
        .qr_code => |qr| {
            qr_count += 1;
            if (qr_count == 1) {
                log.info("Benchmark", "QR: {s}", .{qr.code});
            }
        },
        .pair_success => |ps| {
            log.info("Benchmark", "Paired! phone={s} lid={s}", .{ ps.phone_jid, ps.lid });
        },
        .connected => |c| {
            log.info("Benchmark", "Connected! phone={s} lid={s}", .{ c.phone_jid, c.lid });
            log.info("Benchmark", "Waiting for \"ping\" messages", .{});
        },
        .message => |msg| {
            const body = msg.getBody() orelse return;
            if (!std.mem.eql(u8, body, "ping")) return;

            var reply_buf: [128]u8 = undefined;
            const reply = std.fmt.bufPrint(&reply_buf, "pong {s}", .{msg.id}) catch {
                log.err("Benchmark", "Reply buffer too small for message id {s}", .{msg.id});
                return;
            };

            log.info("Benchmark", "ping from {s} -> {s}", .{ msg.from, reply });
            client.sendMessageFast(msg.chat, reply) catch |err| {
                log.err("Benchmark", "Reply failed: {}", .{err});
            };
        },
        .disconnected => log.warn("Benchmark", "Disconnected", .{}),
        .login_failed => log.err("Benchmark", "Login failed", .{}),
    }
}

fn loadRuntimeConfig(
    allocator: std.mem.Allocator,
    environ_map: *std.process.Environ.Map,
) !RuntimeConfig {
    var config = RuntimeConfig{};

    const ws_url = environ_map.get("WHATSAPP_WS_URL") orelse return config;
    const uri = std.Uri.parse(ws_url) catch return error.InvalidUri;

    config.tls = std.mem.eql(u8, uri.scheme, "wss");
    config.port = uri.port orelse if (config.tls) 443 else 80;

    const host = try uri.getHostAlloc(allocator);
    config.host = host.bytes;
    config.host_owned = host.bytes;

    const path = if (uri.path.isEmpty())
        "/"
    else
        try uri.path.toRawMaybeAlloc(allocator);
    if (path.ptr != "/".ptr) config.path_owned = @constCast(path);

    if (uri.query) |query| {
        const raw_query = try query.toRawMaybeAlloc(allocator);
        const full_path = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, raw_query });
        if (config.path_owned) |owned| allocator.free(owned);
        if (raw_query.ptr != query.percent_encoded.ptr) allocator.free(@constCast(raw_query));
        config.path = full_path;
        config.path_owned = full_path;
    } else {
        config.path = path;
    }

    return config;
}
