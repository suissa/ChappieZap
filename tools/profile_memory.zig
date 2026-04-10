const std = @import("std");
const Client = @import("client").Client;
const ClientOptions = @import("client").ClientOptions;
const client_auth = @import("client").auth;
const client_payloads = @import("client").payloads;
const client_transport = @import("client").transport;
const ws = @import("websocket_client");
const socket_mod = @import("socket");
const handshake_mod = @import("handshake");

const opts = ClientOptions{
    .host = "localhost",
    .port = 8080,
    .tls = false,
};

const ConnectionMode = enum { pairing, login };

const Module = enum(u8) {
    client,
    binary,
    messaging,
    signal,
    socket,
    websocket_client,
    noise,
    framing,
    xed25519,
    addressing,
    prekey,
    pair,
    usync,
    handshake,
    node_handler,
    events,
    common,
    gen,
    log,
    tests,
    stdlib_other,
    other_repo,
    unknown,

    fn label(module: Module) []const u8 {
        return switch (module) {
            .client => "client",
            .binary => "binary",
            .messaging => "messaging",
            .signal => "signal",
            .socket => "socket",
            .websocket_client => "websocket_client",
            .noise => "noise",
            .framing => "framing",
            .xed25519 => "xed25519",
            .addressing => "addressing",
            .prekey => "prekey",
            .pair => "pair",
            .usync => "usync",
            .handshake => "handshake",
            .node_handler => "node_handler",
            .events => "events",
            .common => "common",
            .gen => "gen",
            .log => "log",
            .tests => "tests",
            .stdlib_other => "stdlib/other",
            .other_repo => "other_repo",
            .unknown => "unknown",
        };
    }
};

const AllocationRecord = struct {
    size: usize,
    alignment: std.mem.Alignment,
    site_index: usize,
};

const SiteStats = struct {
    ret_addr: usize,
    module: Module,
    current: usize = 0,
    peak: usize = 0,
    total: usize = 0,
    allocs: usize = 0,
    frees: usize = 0,
    file_name: ?[]u8 = null,
    line: u64 = 0,
};

const ModuleStats = struct {
    current: usize = 0,
    peak: usize = 0,
    total: usize = 0,
    allocs: usize = 0,
    frees: usize = 0,
};

const ModuleRow = struct {
    module: Module,
    stats: ModuleStats,
};

const TrackingAllocator = struct {
    backing: std.mem.Allocator,
    meta: std.mem.Allocator,
    io: std.Io,
    ptr_map: std.AutoHashMapUnmanaged(usize, AllocationRecord) = .empty,
    site_map: std.AutoHashMapUnmanaged(usize, usize) = .empty,
    sites: std.ArrayListUnmanaged(SiteStats) = .empty,
    module_stats: [@typeInfo(Module).@"enum".fields.len]ModuleStats =
        [_]ModuleStats{.{}} ** @typeInfo(Module).@"enum".fields.len,
    current_live: usize = 0,
    peak_live: usize = 0,
    total_allocated: usize = 0,
    total_alloc_calls: usize = 0,
    total_free_calls: usize = 0,

    fn init(backing: std.mem.Allocator, meta: std.mem.Allocator, io: std.Io) TrackingAllocator {
        return .{
            .backing = backing,
            .meta = meta,
            .io = io,
        };
    }

    fn deinit(self: *TrackingAllocator) void {
        for (self.sites.items) |site| {
            if (site.file_name) |file_name| self.meta.free(file_name);
        }
        self.ptr_map.deinit(self.meta);
        self.site_map.deinit(self.meta);
        self.sites.deinit(self.meta);
    }

    fn allocator(self: *TrackingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const memory = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.recordAlloc(@intFromPtr(memory), len, alignment, ret_addr) catch {
            self.backing.rawFree(memory[0..len], alignment, ret_addr);
            return null;
        };
        return memory;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.backing.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.recordResize(@intFromPtr(memory.ptr), new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const new_ptr = self.backing.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.recordRemap(@intFromPtr(memory.ptr), @intFromPtr(new_ptr), alignment, new_len) catch return null;
        return new_ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        self.recordFree(@intFromPtr(memory.ptr));
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    fn recordAlloc(
        self: *TrackingAllocator,
        ptr_addr: usize,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) !void {
        const site_index = try self.getOrCreateSite(ret_addr);
        try self.ptr_map.put(self.meta, ptr_addr, .{
            .size = len,
            .alignment = alignment,
            .site_index = site_index,
        });

        const site = &self.sites.items[site_index];
        site.current += len;
        site.peak = @max(site.peak, site.current);
        site.total += len;
        site.allocs += 1;

        const module_stats = &self.module_stats[@intFromEnum(site.module)];
        module_stats.current += len;
        module_stats.peak = @max(module_stats.peak, module_stats.current);
        module_stats.total += len;
        module_stats.allocs += 1;

        self.current_live += len;
        self.peak_live = @max(self.peak_live, self.current_live);
        self.total_allocated += len;
        self.total_alloc_calls += 1;
    }

    fn recordResize(self: *TrackingAllocator, ptr_addr: usize, new_len: usize) void {
        if (self.ptr_map.getPtr(ptr_addr)) |record| {
            const old_len = record.size;
            record.size = new_len;
            const site = &self.sites.items[record.site_index];
            const module_stats = &self.module_stats[@intFromEnum(site.module)];
            if (new_len >= old_len) {
                const delta = new_len - old_len;
                site.current += delta;
                site.peak = @max(site.peak, site.current);
                site.total += delta;
                module_stats.current += delta;
                module_stats.peak = @max(module_stats.peak, module_stats.current);
                module_stats.total += delta;
                self.current_live += delta;
                self.peak_live = @max(self.peak_live, self.current_live);
                self.total_allocated += delta;
            } else {
                const delta = old_len - new_len;
                site.current = site.current -| delta;
                module_stats.current = module_stats.current -| delta;
                self.current_live = self.current_live -| delta;
            }
        }
    }

    fn recordRemap(
        self: *TrackingAllocator,
        old_ptr_addr: usize,
        new_ptr_addr: usize,
        alignment: std.mem.Alignment,
        new_len: usize,
    ) !void {
        if (self.ptr_map.fetchRemove(old_ptr_addr)) |entry| {
            var updated = entry.value;
            updated.alignment = alignment;
            try self.ptr_map.put(self.meta, new_ptr_addr, updated);
            self.recordResize(new_ptr_addr, new_len);
        }
    }

    fn recordFree(self: *TrackingAllocator, ptr_addr: usize) void {
        if (self.ptr_map.fetchRemove(ptr_addr)) |entry| {
            const site = &self.sites.items[entry.value.site_index];
            site.current = site.current -| entry.value.size;
            site.frees += 1;

            const module_stats = &self.module_stats[@intFromEnum(site.module)];
            module_stats.current = module_stats.current -| entry.value.size;
            module_stats.frees += 1;

            self.current_live = self.current_live -| entry.value.size;
            self.total_free_calls += 1;
        }
    }

    fn getOrCreateSite(self: *TrackingAllocator, ret_addr: usize) !usize {
        const gop = try self.site_map.getOrPut(self.meta, ret_addr);
        if (gop.found_existing) return gop.value_ptr.*;

        const site_index = self.sites.items.len;
        try self.sites.append(self.meta, try self.resolveSite(ret_addr));
        gop.value_ptr.* = site_index;
        return site_index;
    }

    fn resolveSite(self: *TrackingAllocator, ret_addr: usize) !SiteStats {
        if (ret_addr == 0) {
            return .{
                .ret_addr = ret_addr,
                .module = .unknown,
            };
        }

        var fallback: ?SiteStats = null;
        if (std.debug.sys_can_stack_trace) {
            var stack_addrs: [16]usize = undefined;
            const stack = std.debug.captureCurrentStackTrace(
                .{ .first_address = ret_addr },
                &stack_addrs,
            );
            for (stack.instruction_addresses[0..stack.index]) |addr| {
                const site = try self.resolveAddress(addr) orelse continue;
                if (site.module != .other_repo and site.module != .stdlib_other and site.module != .tests) {
                    if (fallback) |kept| {
                        if (kept.file_name) |file_name| self.meta.free(file_name);
                    }
                    return site;
                }
                if (fallback == null) {
                    fallback = site;
                } else if (site.file_name) |file_name| {
                    self.meta.free(file_name);
                }
            }
        }

        return fallback orelse .{
            .ret_addr = ret_addr,
            .module = .unknown,
        };
    }

    fn resolveAddress(self: *TrackingAllocator, addr: usize) !?SiteStats {
        var site = SiteStats{
            .ret_addr = addr,
            .module = .unknown,
        };

        const debug_info = std.debug.getSelfDebugInfo() catch return null;
        const symbol = debug_info.getSymbol(self.io, addr) catch return null;
        defer if (symbol.source_location) |sl| std.debug.getDebugInfoAllocator().free(sl.file_name);

        if (symbol.source_location) |sl| {
            site.module = classifyModule(sl.file_name);
            site.line = sl.line;
            site.file_name = try self.meta.dupe(u8, sl.file_name);
            return site;
        }

        if (symbol.compile_unit_name) |compile_unit_name| {
            site.module = classifyModule(compile_unit_name);
            site.file_name = try self.meta.dupe(u8, compile_unit_name);
            return site;
        }

        site.module = .stdlib_other;
        return site;
    }
};

fn classifyModule(path: []const u8) Module {
    if (std.mem.indexOf(u8, path, "src/client/") != null or std.mem.endsWith(u8, path, "src/client.zig")) return .client;
    if (std.mem.indexOf(u8, path, "src/binary/") != null or std.mem.endsWith(u8, path, "src/binary.zig")) return .binary;
    if (std.mem.indexOf(u8, path, "src/messaging/") != null or std.mem.endsWith(u8, path, "src/messaging.zig")) return .messaging;
    if (std.mem.indexOf(u8, path, "src/signal/") != null) return .signal;
    if (std.mem.indexOf(u8, path, "src/common/") != null) return .common;
    if (std.mem.indexOf(u8, path, "src/gen/") != null) return .gen;
    if (std.mem.endsWith(u8, path, "src/socket.zig")) return .socket;
    if (std.mem.endsWith(u8, path, "src/websocket_client.zig")) return .websocket_client;
    if (std.mem.endsWith(u8, path, "src/noise.zig")) return .noise;
    if (std.mem.endsWith(u8, path, "src/framing.zig")) return .framing;
    if (std.mem.endsWith(u8, path, "src/xed25519.zig")) return .xed25519;
    if (std.mem.endsWith(u8, path, "src/addressing.zig")) return .addressing;
    if (std.mem.endsWith(u8, path, "src/prekey.zig")) return .prekey;
    if (std.mem.endsWith(u8, path, "src/pair.zig")) return .pair;
    if (std.mem.endsWith(u8, path, "src/usync.zig")) return .usync;
    if (std.mem.endsWith(u8, path, "src/handshake.zig")) return .handshake;
    if (std.mem.endsWith(u8, path, "src/node_handler.zig")) return .node_handler;
    if (std.mem.endsWith(u8, path, "src/events.zig")) return .events;
    if (std.mem.endsWith(u8, path, "src/log.zig")) return .log;
    if (std.mem.indexOf(u8, path, "tests/") != null) return .tests;
    if (std.mem.indexOf(u8, path, "/home/jlucaso/projects/zigwhats/") != null) return .other_repo;
    if (std.mem.indexOf(u8, path, "/lib/std/") != null or std.mem.indexOf(u8, path, "lib/std/") != null) return .stdlib_other;
    return .stdlib_other;
}

fn connectWithPayloadNoVersion(self: *Client, mode: ConnectionMode) !void {
    if (self.noise_socket) |*ns| ns.deinit();
    self.noise_socket = null;
    self.ws_client.deinit();
    self.ws_client = try ws.WebSocketClient.init(self.allocator, self.io);
    self.is_logged_in = false;

    if (self.options.tls) {
        if (self.options.tls_ca_cert_path) |cert_path| {
            try self.ws_client.addCaCertFileAbsolute(cert_path);
        }
    }
    try self.ws_client.connectOptions(
        self.options.host,
        self.options.port,
        self.options.path,
        &.{.{ .name = "Origin", .value = "https://web.whatsapp.com" }},
        self.options.tls,
    );

    const payload = switch (mode) {
        .pairing => try client_payloads.buildPairingPayload(self),
        .login => try client_payloads.buildLoginPayload(self),
    };
    defer self.allocator.free(payload);

    const cipher_pair = try handshake_mod.performHandshake(
        self.allocator,
        self.io,
        &self.ws_client,
        self.static_keypair,
        payload,
    );
    self.noise_socket = try socket_mod.NoiseSocket.init(
        self.allocator,
        cipher_pair.write_key,
        cipher_pair.read_key,
    );
}

fn connectAndLoginNoVersion(self: *Client) !void {
    try connectWithPayloadNoVersion(self, .pairing);
    try client_auth.handlePairingFlow(self);
    try connectWithPayloadNoVersion(self, .login);
    try client_auth.readUntilLogin(self);
    client_transport.sendActive(self);
    client_transport.uploadPrekeys(self) catch {};
}

pub fn main(init: std.process.Init) !void {
    var tracker = TrackingAllocator.init(std.heap.page_allocator, init.gpa, init.io);
    defer tracker.deinit();
    const allocator = tracker.allocator();
    const io = init.io;

    {
        var a = try Client.init(allocator, io, opts);
        defer a.deinit();
        try connectAndLoginNoVersion(&a);

        var b = try Client.init(allocator, io, opts);
        defer b.deinit();
        try connectAndLoginNoVersion(&b);

        const jid_a = a.phone_jid orelse return error.NoPairing;
        const jid_b = b.phone_jid orelse return error.NoPairing;

        try a.sendMessage(jid_b, "Hello from Zig!");
        try b.waitForMessage(.{
            .from = jid_a,
            .body_equals = "Hello from Zig!",
            .require_decrypted = true,
        }, 10_000);
    }

    {
        var client = try Client.init(allocator, io, opts);
        defer client.deinit();
        try connectAndLoginNoVersion(&client);

        try client.sendMessage("559980000001@s.whatsapp.net", "\xf0\x9f\xa6\x80ping");
        try client.waitForMessage(.{
            .from = "559980000001@s.whatsapp.net",
        }, 15_000);
    }

    printReport(&tracker);
}

fn printReport(tracker: *TrackingAllocator) void {
    std.debug.print("Memory profiling summary\n", .{});
    std.debug.print("  peak_live_bytes: {d}\n", .{tracker.peak_live});
    std.debug.print("  total_allocated_bytes: {d}\n", .{tracker.total_allocated});
    std.debug.print("  total_alloc_calls: {d}\n", .{tracker.total_alloc_calls});
    std.debug.print("  total_free_calls: {d}\n\n", .{tracker.total_free_calls});

    var module_rows: [@typeInfo(Module).@"enum".fields.len]ModuleRow = undefined;
    for (&module_rows, 0..) |*row, i| {
        row.* = .{
            .module = @enumFromInt(i),
            .stats = tracker.module_stats[i],
        };
    }
    sortModuleRows(&module_rows);

    std.debug.print(
        "{s: <18} {s: >12} {s: >12} {s: >14} {s: >10} {s: >10}\n",
        .{ "module", "current", "peak", "total", "allocs", "frees" },
    );
    std.debug.print(
        "{s}\n",
        .{"--------------------------------------------------------------------------------"},
    );
    for (module_rows) |row| {
        if (row.stats.total == 0 and row.stats.peak == 0) continue;
        std.debug.print(
            "{s: <18} {d: >12} {d: >12} {d: >14} {d: >10} {d: >10}\n",
            .{
                row.module.label(),
                row.stats.current,
                row.stats.peak,
                row.stats.total,
                row.stats.allocs,
                row.stats.frees,
            },
        );
    }

    const site_rows = tracker.meta.alloc(SiteStats, tracker.sites.items.len) catch return;
    defer tracker.meta.free(site_rows);
    @memcpy(site_rows, tracker.sites.items);
    sortSiteRows(site_rows);

    std.debug.print("\nTop allocation sites by peak live bytes\n", .{});
    std.debug.print(
        "{s: <18} {s: >12} {s: >14} {s: >10}  {s}\n",
        .{ "module", "peak", "total", "allocs", "site" },
    );
    std.debug.print(
        "{s}\n",
        .{"------------------------------------------------------------------------------------------------"},
    );

    var printed: usize = 0;
    for (site_rows) |site| {
        if (site.total == 0 or site.peak == 0) continue;
        std.debug.print(
            "{s: <18} {d: >12} {d: >14} {d: >10}  {s}:{d}\n",
            .{
                site.module.label(),
                site.peak,
                site.total,
                site.allocs,
                site.file_name orelse "?",
                site.line,
            },
        );
        printed += 1;
        if (printed == 15) break;
    }
}

fn sortModuleRows(rows: []ModuleRow) void {
    var i: usize = 0;
    while (i < rows.len) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < rows.len) : (j += 1) {
            if (rows[j].stats.peak > rows[best].stats.peak) best = j;
        }
        if (best != i) std.mem.swap(@TypeOf(rows[i]), &rows[i], &rows[best]);
    }
}

fn sortSiteRows(rows: []SiteStats) void {
    var i: usize = 0;
    while (i < rows.len) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < rows.len) : (j += 1) {
            if (rows[j].peak > rows[best].peak) best = j;
        }
        if (best != i) std.mem.swap(SiteStats, &rows[i], &rows[best]);
    }
}
