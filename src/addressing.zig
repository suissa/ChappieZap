const std = @import("std");
const binary = @import("binary");
const types = @import("addressing/types.zig");
const jid_ops = @import("addressing/jid_ops.zig");
const learn = @import("addressing/learn.zig");
const resolve = @import("addressing/resolve.zig");

pub const ResolvedJid = types.ResolvedJid;
pub const LearnedMapping = types.LearnedMapping;

pub const AddressBook = struct {
    allocator: std.mem.Allocator,
    own_phone_jid: ?[]const u8 = null,
    own_lid_jid: ?[]const u8 = null,
    own_device_id: u32 = 0,
    pn_to_lid: std.BufMap,
    lid_to_pn: std.BufMap,
    own_devices: std.BufSet,

    pub fn init(allocator: std.mem.Allocator) AddressBook {
        return .{
            .allocator = allocator,
            .pn_to_lid = std.BufMap.init(allocator),
            .lid_to_pn = std.BufMap.init(allocator),
            .own_devices = std.BufSet.init(allocator),
        };
    }

    pub fn deinit(self: *AddressBook) void {
        if (self.own_phone_jid) |p| self.allocator.free(p);
        if (self.own_lid_jid) |l| self.allocator.free(l);
        self.own_phone_jid = null;
        self.own_lid_jid = null;
        self.pn_to_lid.deinit();
        self.lid_to_pn.deinit();
        self.own_devices.deinit();
    }

    pub fn phoneJid(self: *const AddressBook) ?[]const u8 {
        return self.own_phone_jid;
    }

    pub fn lidJid(self: *const AddressBook) ?[]const u8 {
        return self.own_lid_jid;
    }

    pub fn deviceId(self: *const AddressBook) u32 {
        return self.own_device_id;
    }

    pub fn ownDeviceCount(self: *const AddressBook) usize {
        return self.own_devices.count();
    }

    pub fn ownDeviceIterator(self: *const AddressBook) std.BufSet.Iterator {
        return self.own_devices.iterator();
    }

    pub fn replaceOwnDevices(self: *AddressBook, jids: []const []const u8) !void {
        clearOwnDevices(self);
        for (jids) |jid| {
            try self.own_devices.insert(jid);
        }
    }

    pub fn setOwnIdentity(
        self: *AddressBook,
        phone_jid: []const u8,
        lid_jid: []const u8,
        device_id: u32,
    ) !void {
        _ = try learn.rememberMapping(self, lid_jid, phone_jid);
        if (self.own_phone_jid) |old| self.allocator.free(old);
        if (self.own_lid_jid) |old| self.allocator.free(old);
        self.own_phone_jid = try self.allocator.dupe(u8, phone_jid);
        self.own_lid_jid = try self.allocator.dupe(u8, lid_jid);
        self.own_device_id = device_id;
    }

    pub fn setOwnLid(self: *AddressBook, lid_jid: []const u8) !void {
        if (self.own_lid_jid) |old| self.allocator.free(old);
        self.own_lid_jid = try self.allocator.dupe(u8, lid_jid);
        if (self.own_phone_jid) |phone_jid| {
            _ = try learn.rememberMapping(self, lid_jid, phone_jid);
        }
    }

    pub fn isSelfChatJid(self: *const AddressBook, jid: []const u8) bool {
        return resolve.Methods.isSelfChatJid(self, jid);
    }

    pub fn isCurrentDeviceJid(self: *const AddressBook, jid: []const u8) bool {
        return resolve.Methods.isCurrentDeviceJid(self, jid);
    }

    pub fn maybeUpdateOwnDeviceList(self: *AddressBook, node: *const binary.Node) !bool {
        return learn.Methods.maybeUpdateOwnDeviceList(self, node);
    }

    pub fn rememberFromMessage(self: *AddressBook, node: *const binary.Node) !?LearnedMapping {
        return learn.Methods.rememberFromMessage(self, node);
    }

    pub fn rememberMappingJids(
        self: *AddressBook,
        pn_jid: []const u8,
        lid_jid: []const u8,
    ) !?LearnedMapping {
        return learn.Methods.rememberMappingJids(self, pn_jid, lid_jid);
    }

    pub fn resolveEncryptionJid(self: *const AddressBook, chat_jid: []const u8) !ResolvedJid {
        return resolve.Methods.resolveEncryptionJid(self, chat_jid);
    }

    pub fn resolveOwnDeviceEncryptionJid(
        self: *const AddressBook,
        participant_jid: []const u8,
    ) !ResolvedJid {
        return resolve.Methods.resolveOwnDeviceEncryptionJid(self, participant_jid);
    }

    pub fn resolveIncomingEncryptionJid(
        self: *const AddressBook,
        from_jid: []const u8,
    ) !ResolvedJid {
        return resolve.Methods.resolveIncomingEncryptionJid(self, from_jid);
    }

    pub fn resolvePhoneJid(
        self: *const AddressBook,
        jid: []const u8,
    ) !ResolvedJid {
        return resolve.Methods.resolvePhoneJid(self, jid);
    }

    pub fn stripDeviceFromJid(
        allocator: std.mem.Allocator,
        jid: []const u8,
    ) ![]u8 {
        return jid_ops.Methods.stripDeviceFromJid(allocator, jid);
    }

    pub fn withDeviceFromJid(
        allocator: std.mem.Allocator,
        base_jid: []const u8,
        device_source_jid: []const u8,
    ) ![]u8 {
        return jid_ops.Methods.withDeviceFromJid(allocator, base_jid, device_source_jid);
    }

    pub fn jidMatchesUserServer(a: []const u8, b: []const u8) bool {
        return jid_ops.Methods.jidMatchesUserServer(a, b);
    }

    pub fn isPnJid(jid: []const u8) bool {
        return jid_ops.Methods.isPnJid(jid);
    }

    pub fn isLidJid(jid: []const u8) bool {
        return jid_ops.Methods.isLidJid(jid);
    }
};

fn mapStoredJid(map: std.BufMap, jid: []const u8) ![]const u8 {
    const user = jid_ops.bareUser(jid) orelse return error.InvalidJid;
    return map.get(user) orelse return error.InvalidJid;
}

fn clearOwnDevices(self: *AddressBook) void {
    var it = self.own_devices.iterator();
    var doomed = std.ArrayList([]const u8).empty;
    defer doomed.deinit(self.allocator);
    while (it.next()) |key_ptr| {
        doomed.append(self.allocator, key_ptr.*) catch return;
    }
    for (doomed.items) |jid| self.own_devices.remove(jid);
}

test "remember mapping resolves pn to lid" {
    const allocator = std.testing.allocator;

    var book = AddressBook.init(allocator);
    defer book.deinit();

    const learned = try book.rememberMapping("100000012345678@lid", "559980000001@s.whatsapp.net");
    try std.testing.expect(learned != null);

    const resolved = try book.resolveEncryptionJid("559980000001@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("100000012345678@lid", resolved.value);
}

test "rememberFromMessage learns sender_lid mapping" {
    const allocator = std.testing.allocator;

    var book = AddressBook.init(allocator);
    defer book.deinit();

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("from", "559980000001@s.whatsapp.net");
    try node.addAttribute("sender_lid", "100000012345678@lid");

    const learned = try book.rememberFromMessage(&node);
    try std.testing.expect(learned != null);

    const resolved = try book.resolveIncomingEncryptionJid("559980000001@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("100000012345678@lid", resolved.value);
}

test "rememberFromMessage learns participant pn mapping" {
    const allocator = std.testing.allocator;

    var book = AddressBook.init(allocator);
    defer book.deinit();

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("from", "120363123456789012@g.us");
    try node.addAttribute("participant", "100000012345678@lid");
    try node.addAttribute("participant_pn", "559980000001@s.whatsapp.net");

    const learned = try book.rememberFromMessage(&node);
    try std.testing.expect(learned != null);

    const resolved = try book.resolveEncryptionJid("559980000001@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("100000012345678@lid", resolved.value);
}

test "resolve own pn device to own lid device" {
    const allocator = std.testing.allocator;

    var book = AddressBook.init(allocator);
    defer book.deinit();
    try book.setOwnIdentity("559984726662@s.whatsapp.net", "236395184570386@lid", 63);

    const resolved = try book.resolveOwnDeviceEncryptionJid("559984726662:4@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("236395184570386:4@lid", resolved.value);
}

test "resolve incoming self pn device uses own lid device" {
    const allocator = std.testing.allocator;

    var book = AddressBook.init(allocator);
    defer book.deinit();
    try book.setOwnIdentity("559984726662@s.whatsapp.net", "236395184570386@lid", 63);

    const resolved = try book.resolveIncomingEncryptionJid("559984726662:4@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("236395184570386:4@lid", resolved.value);
}
