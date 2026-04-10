const std = @import("std");
const signal = @import("signal");
const addressing = @import("addressing");
const jid_helpers = @import("jid_helpers.zig");

pub fn findSession(self: anytype, jid: []const u8) ?*signal.Session {
    return self.sessions.getPtr(jid);
}

pub fn hasSession(self: anytype, jid: []const u8) bool {
    return self.sessions.contains(jid);
}

pub fn storeSession(self: anytype, jid: []const u8, session: signal.Session) !void {
    try self.sessions.ensureUnusedCapacity(1);
    const gop = try self.sessions.getOrPut(jid);
    if (gop.found_existing) {
        gop.value_ptr.deinit();
    } else {
        gop.key_ptr.* = try self.allocator.dupe(u8, jid);
        errdefer self.sessions.removeByPtr(gop.key_ptr);
    }
    gop.value_ptr.* = session;
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

    var moves = std.ArrayList(struct {
        from: []const u8,
        to: []u8,
    }).empty;
    defer {
        for (moves.items) |move| self.allocator.free(move.to);
        moves.deinit(self.allocator);
    }

    var it = self.sessions.iterator();
    while (it.next()) |entry| {
        const session_jid = entry.key_ptr.*;
        const parts = jid_helpers.parseJidParts(session_jid) orelse continue;
        if (!std.mem.eql(u8, parts.server, "s.whatsapp.net")) continue;
        if (!std.mem.eql(u8, parts.bare_user, pn_parts.bare_user)) continue;

        const mapped = addressing.AddressBook.withDeviceFromJid(self.allocator, lid_jid, session_jid) catch continue;
        moves.append(self.allocator, .{
            .from = entry.key_ptr.*,
            .to = mapped,
        }) catch {
            self.allocator.free(mapped);
            return;
        };
    }

    for (moves.items) |move| {
        if (self.sessions.contains(move.to)) {
            if (self.sessions.fetchRemove(move.from)) |kv| {
                var doomed = kv.value;
                doomed.deinit();
                self.allocator.free(kv.key);
            }
            continue;
        }

        const kv = self.sessions.fetchRemove(move.from) orelse continue;
        storeSession(self, move.to, kv.value) catch {
            storeSession(self, kv.key, kv.value) catch {
                var doomed = kv.value;
                doomed.deinit();
                self.allocator.free(kv.key);
            };
            self.allocator.free(kv.key);
            continue;
        };
        self.allocator.free(kv.key);
    }
}
