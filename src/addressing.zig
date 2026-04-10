const std = @import("std");
const binary = @import("binary");

pub const ResolvedJid = struct {
    value: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: ResolvedJid, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

pub const LearnedMapping = struct {
    lid_jid: []const u8,
    pn_jid: []const u8,
};

pub const AddressBook = struct {
    allocator: std.mem.Allocator,
    own_phone_jid: ?[]u8 = null,
    own_lid_jid: ?[]u8 = null,
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
        if (self.own_phone_jid) |jid| self.allocator.free(jid);
        if (self.own_lid_jid) |jid| self.allocator.free(jid);
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

    pub fn setOwnIdentity(
        self: *AddressBook,
        phone_jid: []const u8,
        lid_jid: []const u8,
        device_id: u32,
    ) !void {
        const phone_bare = try stripDeviceFromJid(self.allocator, phone_jid);
        errdefer self.allocator.free(phone_bare);
        const lid_bare = try stripDeviceFromJid(self.allocator, lid_jid);
        errdefer self.allocator.free(lid_bare);

        if (self.own_phone_jid) |old| self.allocator.free(old);
        if (self.own_lid_jid) |old| self.allocator.free(old);
        self.own_phone_jid = phone_bare;
        self.own_lid_jid = lid_bare;
        self.own_device_id = device_id;

        _ = try self.rememberMapping(self.own_lid_jid.?, self.own_phone_jid.?);
    }

    pub fn setOwnLid(self: *AddressBook, lid_jid: []const u8) !void {
        const lid_bare = try stripDeviceFromJid(self.allocator, lid_jid);
        errdefer self.allocator.free(lid_bare);
        if (self.own_lid_jid) |old| self.allocator.free(old);
        self.own_lid_jid = lid_bare;
        if (self.own_phone_jid) |phone_jid| {
            _ = try self.rememberMapping(self.own_lid_jid.?, phone_jid);
        }
    }

    pub fn isSelfChatJid(self: *const AddressBook, jid: []const u8) bool {
        if (self.own_lid_jid) |own_lid| if (jidMatchesUserServer(jid, own_lid)) return true;
        if (self.own_phone_jid) |own_phone| if (jidMatchesUserServer(jid, own_phone)) return true;
        return false;
    }

    pub fn isCurrentDeviceJid(self: *const AddressBook, jid: []const u8) bool {
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

    pub fn maybeUpdateOwnDeviceList(self: *AddressBook, node: *const binary.Node) !bool {
        const ntype = node.getAttribute("type") orelse return false;
        if (!std.mem.eql(u8, ntype, "account_sync")) return false;
        const from = node.getAttribute("from") orelse return false;
        if (!self.isSelfChatJid(from)) return false;

        const children = node.getContentNodes() orelse return false;
        for (children) |*child| {
            if (!std.mem.eql(u8, child.tag, "devices")) continue;
            const device_children = child.getContentNodes() orelse return false;

            self.clearOwnDevices();
            for (device_children) |*device_node| {
                if (!std.mem.eql(u8, device_node.tag, "device")) continue;
                const jid = device_node.getAttribute("jid") orelse continue;
                try self.own_devices.insert(jid);
            }
            return true;
        }
        return false;
    }

    pub fn rememberFromMessage(self: *AddressBook, node: *const binary.Node) !?LearnedMapping {
        if (!std.mem.eql(u8, node.tag, "message")) return null;

        const from = node.getAttribute("from");
        if (from) |from_jid| {
            if (node.getAttribute("sender_lid")) |sender_lid| {
                if (isPnJid(from_jid) and isLidJid(sender_lid)) {
                    if (try self.rememberMapping(sender_lid, from_jid)) |mapping| return mapping;
                }
            }

            if (isLidJid(from_jid)) {
                if (node.getAttribute("peer_recipient_pn")) |peer_recipient_pn| {
                    if (isPnJid(peer_recipient_pn)) {
                        if (try self.rememberMapping(from_jid, peer_recipient_pn)) |mapping| return mapping;
                    }
                }
            }
        }

        if (node.getAttribute("participant")) |participant| {
            if (node.getAttribute("participant_pn")) |participant_pn| {
                if (isLidJid(participant) and isPnJid(participant_pn)) {
                    if (try self.rememberMapping(participant, participant_pn)) |mapping| return mapping;
                }
            }
        }

        return null;
    }

    pub fn rememberMappingJids(
        self: *AddressBook,
        pn_jid: []const u8,
        lid_jid: []const u8,
    ) !?LearnedMapping {
        return self.rememberMapping(lid_jid, pn_jid);
    }

    pub fn resolveEncryptionJid(self: *const AddressBook, chat_jid: []const u8) !ResolvedJid {
        if (self.isSelfChatJid(chat_jid)) {
            if (self.own_lid_jid) |own_lid| return .{ .value = own_lid };
            return .{ .value = chat_jid };
        }

        if (currentLidForJid(self, chat_jid)) |lid_jid| {
            if (jidHasDevice(chat_jid)) {
                const owned = try withDeviceFromJid(self.allocator, lid_jid, chat_jid);
                return .{ .value = owned, .owned = owned };
            }
            return .{ .value = lid_jid };
        }

        return .{ .value = chat_jid };
    }

    pub fn resolveOwnDeviceEncryptionJid(
        self: *const AddressBook,
        participant_jid: []const u8,
    ) !ResolvedJid {
        const own_phone = self.own_phone_jid orelse return .{ .value = participant_jid };
        const own_lid = self.own_lid_jid orelse return .{ .value = participant_jid };
        if (!jidMatchesUserServer(participant_jid, own_phone)) {
            return .{ .value = participant_jid };
        }
        if (jidHasDevice(participant_jid)) {
            const owned = try withDeviceFromJid(self.allocator, own_lid, participant_jid);
            return .{ .value = owned, .owned = owned };
        }
        return .{ .value = own_lid };
    }

    pub fn resolveIncomingEncryptionJid(
        self: *const AddressBook,
        from_jid: []const u8,
    ) !ResolvedJid {
        const own_phone = self.own_phone_jid;
        const own_lid = self.own_lid_jid;

        if (own_phone) |phone_jid| {
            if (jidMatchesUserServer(from_jid, phone_jid)) {
                if (own_lid) |lid_jid| {
                    if (jidHasDevice(from_jid)) {
                        const owned = try withDeviceFromJid(self.allocator, lid_jid, from_jid);
                        return .{ .value = owned, .owned = owned };
                    }
                    return .{ .value = lid_jid };
                }
            }
        }

        return self.resolveEncryptionJid(from_jid);
    }

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
        const a_parts = parseJid(a) orelse return false;
        const b_parts = parseJid(b) orelse return false;
        return std.mem.eql(u8, a_parts.bare_user, b_parts.bare_user) and
            std.mem.eql(u8, a_parts.server, b_parts.server);
    }

    pub fn isPnJid(jid: []const u8) bool {
        const parts = parseJid(jid) orelse return false;
        return std.mem.eql(u8, parts.server, "s.whatsapp.net");
    }

    pub fn isLidJid(jid: []const u8) bool {
        const parts = parseJid(jid) orelse return false;
        return std.mem.eql(u8, parts.server, "lid");
    }

    fn rememberMapping(
        self: *AddressBook,
        lid_jid: []const u8,
        pn_jid: []const u8,
    ) !?LearnedMapping {
        const lid_bare = try stripDeviceFromJid(self.allocator, lid_jid);
        defer self.allocator.free(lid_bare);
        const pn_bare = try stripDeviceFromJid(self.allocator, pn_jid);
        defer self.allocator.free(pn_bare);

        const lid_user = bareUser(lid_bare) orelse return null;
        const pn_user = bareUser(pn_bare) orelse return null;

        const existing_lid = self.pn_to_lid.get(pn_user);
        const existing_pn = self.lid_to_pn.get(lid_user);
        const changed = existing_lid == null or
            !std.mem.eql(u8, existing_lid.?, lid_bare) or
            existing_pn == null or
            !std.mem.eql(u8, existing_pn.?, pn_bare);

        try self.pn_to_lid.put(pn_user, lid_bare);
        try self.lid_to_pn.put(lid_user, pn_bare);

        if (!changed) return null;
        return .{
            .lid_jid = self.pn_to_lid.get(pn_user).?,
            .pn_jid = self.lid_to_pn.get(lid_user).?,
        };
    }

    fn currentLidForJid(self: *const AddressBook, jid: []const u8) ?[]const u8 {
        const user = bareUser(jid) orelse return null;
        return self.pn_to_lid.get(user);
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
};

const ParsedJid = struct {
    bare_user: []const u8,
    server: []const u8,
    has_device: bool,
};

fn parseJid(jid: []const u8) ?ParsedJid {
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return null;
    const user = jid[0..at];
    const bare_user = if (std.mem.indexOfScalar(u8, user, ':')) |colon| user[0..colon] else user;
    return .{
        .bare_user = bare_user,
        .server = jid[at + 1 ..],
        .has_device = std.mem.indexOfScalar(u8, user, ':') != null,
    };
}

fn bareUser(jid: []const u8) ?[]const u8 {
    return (parseJid(jid) orelse return null).bare_user;
}

fn jidHasDevice(jid: []const u8) bool {
    return (parseJid(jid) orelse return false).has_device;
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
