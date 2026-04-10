const std = @import("std");
const jid_ops = @import("jid_ops.zig");
const types = @import("types.zig");

pub const Methods = struct {
    pub fn isSelfChatJid(self: anytype, jid: []const u8) bool {
        if (self.own_lid_jid) |own_lid| if (jid_ops.Methods.jidMatchesUserServer(jid, own_lid)) return true;
        if (self.own_phone_jid) |own_phone| if (jid_ops.Methods.jidMatchesUserServer(jid, own_phone)) return true;
        return false;
    }

    pub fn isCurrentDeviceJid(self: anytype, jid: []const u8) bool {
        const own_phone = self.own_phone_jid orelse return false;
        var buf: [96]u8 = undefined;
        const at = std.mem.indexOfScalar(u8, own_phone, '@') orelse return false;
        const current = std.fmt.bufPrint(&buf, "{s}:{d}{s}", .{
            own_phone[0..at],
            self.own_device_id,
            own_phone[at..],
        }) catch return false;
        return std.mem.eql(u8, jid, current);
    }

    pub fn resolveEncryptionJid(self: anytype, chat_jid: []const u8) !types.ResolvedJid {
        if (isSelfChatJid(self, chat_jid)) {
            if (self.own_lid_jid) |own_lid| return .{ .value = own_lid };
            return .{ .value = chat_jid };
        }

        if (currentLidForJid(self, chat_jid)) |lid_jid| {
            if (jid_ops.jidHasDevice(chat_jid)) {
                const owned = try jid_ops.Methods.withDeviceFromJid(self.allocator, lid_jid, chat_jid);
                return .{ .value = owned, .owned = owned };
            }
            return .{ .value = lid_jid };
        }

        return .{ .value = chat_jid };
    }

    pub fn resolveOwnDeviceEncryptionJid(
        self: anytype,
        participant_jid: []const u8,
    ) !types.ResolvedJid {
        const own_phone = self.own_phone_jid orelse return .{ .value = participant_jid };
        const own_lid = self.own_lid_jid orelse return .{ .value = participant_jid };
        if (!jid_ops.Methods.jidMatchesUserServer(participant_jid, own_phone)) {
            return .{ .value = participant_jid };
        }
        if (jid_ops.jidHasDevice(participant_jid)) {
            const owned = try jid_ops.Methods.withDeviceFromJid(self.allocator, own_lid, participant_jid);
            return .{ .value = owned, .owned = owned };
        }
        return .{ .value = own_lid };
    }

    pub fn resolveIncomingEncryptionJid(
        self: anytype,
        from_jid: []const u8,
    ) !types.ResolvedJid {
        const own_phone = self.own_phone_jid;
        const own_lid = self.own_lid_jid;

        if (own_phone) |phone_jid| {
            if (jid_ops.Methods.jidMatchesUserServer(from_jid, phone_jid)) {
                if (own_lid) |lid_jid| {
                    if (jid_ops.jidHasDevice(from_jid)) {
                        const owned = try jid_ops.Methods.withDeviceFromJid(self.allocator, lid_jid, from_jid);
                        return .{ .value = owned, .owned = owned };
                    }
                    return .{ .value = lid_jid };
                }
            }
        }

        return resolveEncryptionJid(self, from_jid);
    }

    pub fn resolvePhoneJid(self: anytype, jid: []const u8) !types.ResolvedJid {
        const user = jid_ops.bareUser(jid) orelse return .{ .value = jid };
        const pn_jid = self.lid_to_pn.get(user) orelse return .{ .value = jid };
        if (jid_ops.jidHasDevice(jid)) {
            const owned = try jid_ops.Methods.withDeviceFromJid(self.allocator, pn_jid, jid);
            return .{ .value = owned, .owned = owned };
        }
        return .{ .value = pn_jid };
    }
};

fn currentLidForJid(self: anytype, jid: []const u8) ?[]const u8 {
    const user = jid_ops.bareUser(jid) orelse return null;
    return self.pn_to_lid.get(user);
}
