const std = @import("std");
const binary = @import("binary");
const jid_ops = @import("jid_ops.zig");
const types = @import("types.zig");

const JidKind = enum {
    pn,
    lid,
};

const MappingRule = struct {
    lid_attr: []const u8,
    lid_kind: JidKind,
    pn_attr: []const u8,
    pn_kind: JidKind,
};

const mapping_rules = .{
    MappingRule{
        .lid_attr = "sender_lid",
        .lid_kind = .lid,
        .pn_attr = "from",
        .pn_kind = .pn,
    },
    MappingRule{
        .lid_attr = "from",
        .lid_kind = .lid,
        .pn_attr = "peer_recipient_pn",
        .pn_kind = .pn,
    },
    MappingRule{
        .lid_attr = "participant",
        .lid_kind = .lid,
        .pn_attr = "participant_pn",
        .pn_kind = .pn,
    },
};

pub const Methods = struct {
    pub fn maybeUpdateOwnDeviceList(self: anytype, node: *const binary.Node) !bool {
        const ntype = node.getAttribute("type") orelse return false;
        if (!std.mem.eql(u8, ntype, "account_sync")) return false;
        const from = node.getAttribute("from") orelse return false;
        if (!self.isSelfChatJid(from)) return false;

        const children = node.getContentNodes() orelse return false;
        for (children) |*child| {
            if (!std.mem.eql(u8, child.tag, "devices")) continue;
            const device_children = child.getContentNodes() orelse return false;

            clearOwnDevices(self);
            for (device_children) |*device_node| {
                if (!std.mem.eql(u8, device_node.tag, "device")) continue;
                const jid = device_node.getAttribute("jid") orelse continue;
                try self.own_devices.insert(jid);
            }
            return true;
        }
        return false;
    }

    pub fn rememberFromMessage(self: anytype, node: *const binary.Node) !?types.LearnedMapping {
        if (!std.mem.eql(u8, node.tag, "message")) return null;

        inline for (mapping_rules) |rule| {
            if (node.getAttribute(rule.lid_attr)) |lid_jid| {
                if (node.getAttribute(rule.pn_attr)) |pn_jid| {
                    if (matchesJidKind(lid_jid, rule.lid_kind) and
                        matchesJidKind(pn_jid, rule.pn_kind))
                    {
                        if (try rememberMapping(self, lid_jid, pn_jid)) |mapping| {
                            return mapping;
                        }
                    }
                }
            }
        }

        return null;
    }

    pub fn rememberMappingJids(
        self: anytype,
        pn_jid: []const u8,
        lid_jid: []const u8,
    ) !?types.LearnedMapping {
        return rememberMapping(self, lid_jid, pn_jid);
    }
};

pub fn rememberMapping(
    self: anytype,
    lid_jid: []const u8,
    pn_jid: []const u8,
) !?types.LearnedMapping {
    const lid_bare = try jid_ops.Methods.stripDeviceFromJid(self.allocator, lid_jid);
    defer self.allocator.free(lid_bare);
    const pn_bare = try jid_ops.Methods.stripDeviceFromJid(self.allocator, pn_jid);
    defer self.allocator.free(pn_bare);

    const lid_user = jid_ops.bareUser(lid_bare) orelse return null;
    const pn_user = jid_ops.bareUser(pn_bare) orelse return null;

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

fn clearOwnDevices(self: anytype) void {
    var it = self.own_devices.iterator();
    var doomed = std.ArrayList([]const u8).empty;
    defer doomed.deinit(self.allocator);
    while (it.next()) |key_ptr| {
        doomed.append(self.allocator, key_ptr.*) catch return;
    }
    for (doomed.items) |jid| self.own_devices.remove(jid);
}

fn matchesJidKind(jid: []const u8, comptime kind: JidKind) bool {
    return switch (kind) {
        .pn => jid_ops.Methods.isPnJid(jid),
        .lid => jid_ops.Methods.isLidJid(jid),
    };
}
