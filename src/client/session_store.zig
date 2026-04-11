const std = @import("std");
const signal = @import("signal");
const jid_common = @import("jid_common");
const jid_helpers = @import("jid_helpers.zig");

pub const session_shard_count: usize = 32;

pub const SessionShard = struct {
    mutex: std.Io.Mutex = .init,
    sessions: std.StringHashMap(signal.Session),

    fn init(allocator: std.mem.Allocator) SessionShard {
        return .{ .sessions = std.StringHashMap(signal.Session).init(allocator) };
    }

    fn deinit(self: *SessionShard, allocator: std.mem.Allocator) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            allocator.free(entry.key_ptr.*);
        }
        self.sessions.deinit();
    }
};

pub const LockedSession = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    shard: *SessionShard,
    key_buf: [128]u8 = undefined,
    key_len: usize,

    pub fn unlock(self: *const LockedSession) void {
        self.shard.mutex.unlock(self.io);
    }

    pub fn key(self: *const LockedSession) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    pub fn get(self: *LockedSession) ?*signal.Session {
        return self.shard.sessions.getPtr(self.key());
    }

    pub fn contains(self: *LockedSession) bool {
        return self.shard.sessions.contains(self.key());
    }

    pub fn put(self: *LockedSession, session: signal.Session) !void {
        try putSessionDupKey(self.allocator, self.shard, self.key(), session);
    }
};

pub fn initSessionShards(allocator: std.mem.Allocator) [session_shard_count]SessionShard {
    var shards: [session_shard_count]SessionShard = undefined;
    for (&shards) |*shard| shard.* = SessionShard.init(allocator);
    return shards;
}

pub fn deinitSessionShards(shards: *[session_shard_count]SessionShard, allocator: std.mem.Allocator) void {
    for (shards) |*shard| shard.deinit(allocator);
}

pub fn findSession(self: anytype, jid: []const u8) ?*signal.Session {
    var key_buf: [128]u8 = undefined;
    const key = canonicalSessionKey(&key_buf, jid) catch return null;
    return shardForKey(self, key).sessions.getPtr(key);
}

pub fn hasSession(self: anytype, jid: []const u8) bool {
    var locked = lockSession(self, jid) catch return false;
    defer locked.unlock();
    return locked.contains();
}

pub fn storeSession(self: anytype, jid: []const u8, session: signal.Session) !void {
    var locked = try lockSession(self, jid);
    defer locked.unlock();
    try locked.put(session);
}

pub fn syncIdentityAliases(self: anytype) void {
    self.phone_jid = if (self.address_book.phoneJid()) |jid| @constCast(jid) else null;
    self.lid = if (self.address_book.lidJid()) |jid| @constCast(jid) else null;
    self.device_id = self.address_book.deviceId();
}

pub fn migrateSessionsOnLidDiscovery(
    self: anytype,
    pn_jid: []const u8,
    lid_jid: []const u8,
) void {
    const pn_parts = jid_helpers.parseJidParts(pn_jid) orelse return;
    if (!std.mem.eql(u8, pn_parts.server, "s.whatsapp.net")) return;

    lockAllShards(self);
    defer unlockAllShards(self);

    var moves = std.ArrayList(struct {
        source_idx: usize,
        dest_idx: usize,
        from: []const u8,
        to: []u8,
    }).empty;
    defer {
        for (moves.items) |move| if (move.to.len != 0) self.allocator.free(move.to);
        moves.deinit(self.allocator);
    }

    for (&self.session_shards, 0..) |*shard, idx| {
        var it = shard.sessions.iterator();
        while (it.next()) |entry| {
            const session_key = entry.key_ptr.*;
            const at = std.mem.indexOfScalar(u8, session_key, '@') orelse continue;
            const user_part = session_key[0..at];
            const server_with_suffix = session_key[at + 1 ..];
            if (!std.mem.endsWith(u8, server_with_suffix, ".0")) continue;
            const server = server_with_suffix[0 .. server_with_suffix.len - 2];
            if (!std.mem.eql(u8, server, "c.us")) continue;

            const bare_user = if (std.mem.indexOfScalar(u8, user_part, ':')) |colon|
                user_part[0..colon]
            else
                user_part;
            if (!std.mem.eql(u8, bare_user, pn_parts.bare_user)) continue;

            const lid_user = lid_jid[0 .. std.mem.indexOfScalar(u8, lid_jid, '@') orelse lid_jid.len];
            const mapped = if (std.mem.indexOfScalar(u8, user_part, ':')) |colon|
                std.fmt.allocPrint(self.allocator, "{s}:{s}@lid.0", .{ lid_user, user_part[colon + 1 ..] }) catch continue
            else
                std.fmt.allocPrint(self.allocator, "{s}@lid.0", .{lid_user}) catch continue;
            moves.append(self.allocator, .{
                .source_idx = idx,
                .dest_idx = shardIndex(mapped),
                .from = entry.key_ptr.*, 
                .to = mapped,
            }) catch {
                self.allocator.free(mapped);
                return;
            };
        }
    }

    for (moves.items) |*move| {
        const source = &self.session_shards[move.source_idx];
        const dest = &self.session_shards[move.dest_idx];

        if (dest.sessions.contains(move.to)) {
            if (source.sessions.fetchRemove(move.from)) |kv| {
                var doomed = kv.value;
                doomed.deinit();
                self.allocator.free(kv.key);
            }
            self.allocator.free(move.to);
            move.to = "";
            continue;
        }

        const kv = source.sessions.fetchRemove(move.from) orelse {
            self.allocator.free(move.to);
            move.to = "";
            continue;
        };

        putSessionOwnedKey(dest, move.to, kv.value) catch {
            putSessionOwnedKey(source, kv.key, kv.value) catch {
                var doomed = kv.value;
                doomed.deinit();
                self.allocator.free(kv.key);
            };
            self.allocator.free(move.to);
            move.to = "";
            continue;
        };

        move.to = "";
        self.allocator.free(kv.key);
    }
}

pub fn lockSession(self: anytype, jid: []const u8) !LockedSession {
    var locked = LockedSession{
        .allocator = self.allocator,
        .io = self.io,
        .shard = undefined,
        .key_len = 0,
    };
    const key = try canonicalSessionKey(&locked.key_buf, jid);
    locked.key_len = key.len;
    locked.shard = &self.session_shards[shardIndex(key)];
    locked.shard.mutex.lockUncancelable(self.io);
    return locked;
}

fn canonicalSessionKey(buf: []u8, jid: []const u8) ![]const u8 {
    return jid_common.writeProtocolAddressKey(buf, jid);
}

fn shardIndex(key: []const u8) usize {
    return @intCast(std.hash.Wyhash.hash(0, key) % session_shard_count);
}

fn shardForKey(self: anytype, key: []const u8) *SessionShard {
    return &self.session_shards[shardIndex(key)];
}

fn putSessionDupKey(
    allocator: std.mem.Allocator,
    shard: *SessionShard,
    key: []const u8,
    session: signal.Session,
) !void {
    try shard.sessions.ensureUnusedCapacity(1);
    const gop = try shard.sessions.getOrPut(key);
    if (gop.found_existing) {
        gop.value_ptr.deinit();
    } else {
        gop.key_ptr.* = try allocator.dupe(u8, key);
        errdefer shard.sessions.removeByPtr(gop.key_ptr);
    }
    gop.value_ptr.* = session;
}

fn putSessionOwnedKey(
    shard: *SessionShard,
    owned_key: []const u8,
    session: signal.Session,
) !void {
    try shard.sessions.ensureUnusedCapacity(1);
    const gop = try shard.sessions.getOrPut(owned_key);
    if (gop.found_existing) {
        gop.value_ptr.deinit();
        gop.value_ptr.* = session;
        return;
    }
    gop.key_ptr.* = owned_key;
    gop.value_ptr.* = session;
}

fn lockAllShards(self: anytype) void {
    for (&self.session_shards) |*shard| shard.mutex.lockUncancelable(self.io);
}

fn unlockAllShards(self: anytype) void {
    var i = self.session_shards.len;
    while (i > 0) {
        i -= 1;
        self.session_shards[i].mutex.unlock(self.io);
    }
}

test "storeSession normalizes protocol-address key" {
    const allocator = std.testing.allocator;
    const Dummy = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        session_shards: [session_shard_count]SessionShard,
    };

    var ctx = Dummy{
        .allocator = allocator,
        .io = std.testing.io,
        .session_shards = initSessionShards(allocator),
    };
    defer deinitSessionShards(&ctx.session_shards, allocator);

    try storeSession(&ctx, "559980000001@s.whatsapp.net", std.mem.zeroes(signal.Session));
    try std.testing.expect(findSession(&ctx, "559980000001@s.whatsapp.net") != null);

    var found = false;
    for (&ctx.session_shards) |*shard| {
        if (shard.sessions.count() == 0) continue;
        const stored = shard.sessions.keys()[0];
        try std.testing.expectEqualStrings("559980000001@c.us.0", stored);
        found = true;
    }
    try std.testing.expect(found);
}

test "lockSession canonicalizes protocol-address key" {
    const allocator = std.testing.allocator;
    const Dummy = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        session_shards: [session_shard_count]SessionShard,
    };

    var ctx = Dummy{
        .allocator = allocator,
        .io = std.testing.io,
        .session_shards = initSessionShards(allocator),
    };
    defer deinitSessionShards(&ctx.session_shards, allocator);

    var guard = try lockSession(&ctx, "559980000001:33@s.whatsapp.net");
    defer guard.unlock();
    try std.testing.expectEqualStrings("559980000001:33@c.us.0", guard.key());
}

test "migrateSessionsOnLidDiscovery migrates sessions across shards" {
    const allocator = std.testing.allocator;
    const Dummy = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        session_shards: [session_shard_count]SessionShard,
    };

    var ctx = Dummy{
        .allocator = allocator,
        .io = std.testing.io,
        .session_shards = initSessionShards(allocator),
    };
    defer deinitSessionShards(&ctx.session_shards, allocator);

    try storeSession(&ctx, "559980000001@s.whatsapp.net", std.mem.zeroes(signal.Session));
    migrateSessionsOnLidDiscovery(&ctx, "559980000001@s.whatsapp.net", "100000012345678@lid");
    try std.testing.expect(findSession(&ctx, "100000012345678@lid") != null);
    try std.testing.expect(findSession(&ctx, "559980000001@s.whatsapp.net") == null);
}
