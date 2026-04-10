const std = @import("std");
const jid_common = @import("jid_common");

pub const Methods = struct {
    pub fn stripDeviceFromJid(
        allocator: std.mem.Allocator,
        jid: []const u8,
    ) ![]u8 {
        if (std.mem.indexOfScalar(u8, jid, ':')) |colon| {
            if (std.mem.indexOfScalar(u8, jid, '@')) |at| {
                return std.fmt.allocPrint(allocator, "{s}{s}", .{ jid[0..colon], jid[at..] });
            }
        }
        return allocator.dupe(u8, jid);
    }

    pub fn withDeviceFromJid(
        allocator: std.mem.Allocator,
        base_jid: []const u8,
        device_source_jid: []const u8,
    ) ![]u8 {
        const base_at = std.mem.indexOfScalar(u8, base_jid, '@') orelse return allocator.dupe(u8, base_jid);
        const source_at = std.mem.indexOfScalar(u8, device_source_jid, '@') orelse return allocator.dupe(u8, base_jid);
        const source_user = device_source_jid[0..source_at];
        const colon = std.mem.indexOfScalar(u8, source_user, ':') orelse return allocator.dupe(u8, base_jid);
        return std.fmt.allocPrint(allocator, "{s}:{s}{s}", .{
            base_jid[0..base_at],
            source_user[colon + 1 ..],
            base_jid[base_at..],
        });
    }

    pub fn jidMatchesUserServer(a: []const u8, b: []const u8) bool {
        return jid_common.sameUserServer(a, b);
    }

    pub fn isPnJid(jid: []const u8) bool {
        return jid_common.isPn(jid);
    }

    pub fn isLidJid(jid: []const u8) bool {
        return jid_common.isLid(jid);
    }
};

pub const ParsedJid = struct {
    bare_user: []const u8,
    server: []const u8,
    has_device: bool,
};

pub fn parseJid(jid: []const u8) ?ParsedJid {
    const parts = jid_common.parse(jid) catch return null;
    return .{
        .bare_user = parts.bare_user,
        .server = parts.server,
        .has_device = parts.has_device,
    };
}

pub fn bareUser(jid: []const u8) ?[]const u8 {
    return (parseJid(jid) orelse return null).bare_user;
}

pub fn jidHasDevice(jid: []const u8) bool {
    return (parseJid(jid) orelse return false).has_device;
}
