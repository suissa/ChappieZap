const std = @import("std");
const binary = @import("binary");

pub const LidMapping = struct {
    pn_jid: []const u8,
    lid_jid: []const u8,
};

pub fn buildDeviceListIq(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    sid: []const u8,
    jids: []const []const u8,
) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();
    try iq.addAttributeBorrowed("id", iq_id);
    try iq.addAttributeBorrowed("type", "get");
    try iq.addAttributeBorrowed("xmlns", "usync");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    var usync = binary.Node.initBorrowed(allocator, "usync");
    defer usync.deinit();
    try usync.addAttributeBorrowed("sid", sid);
    try usync.addAttributeBorrowed("mode", "query");
    try usync.addAttributeBorrowed("last", "true");
    try usync.addAttributeBorrowed("index", "0");
    try usync.addAttributeBorrowed("context", "message");

    var query = binary.Node.initBorrowed(allocator, "query");
    defer query.deinit();
    var devices = binary.Node.initBorrowed(allocator, "devices");
    defer devices.deinit();
    try devices.addAttributeBorrowed("version", "2");
    try query.addChild(&devices);

    var list = binary.Node.initBorrowed(allocator, "list");
    defer list.deinit();
    for (jids) |jid| {
        var user = binary.Node.initBorrowed(allocator, "user");
        defer user.deinit();
        try user.addAttributeBorrowed("jid", jid);
        try list.addChild(&user);
    }

    try usync.addChild(&query);
    try usync.addChild(&list);
    try iq.addChild(&usync);
    return iq;
}

pub fn buildLidQueryIq(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    sid: []const u8,
    jids: []const []const u8,
) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();
    try iq.addAttributeBorrowed("id", iq_id);
    try iq.addAttributeBorrowed("type", "get");
    try iq.addAttributeBorrowed("xmlns", "usync");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    var usync = binary.Node.initBorrowed(allocator, "usync");
    defer usync.deinit();
    try usync.addAttributeBorrowed("sid", sid);
    try usync.addAttributeBorrowed("mode", "query");
    try usync.addAttributeBorrowed("last", "true");
    try usync.addAttributeBorrowed("index", "0");
    try usync.addAttributeBorrowed("context", "background");

    var query = binary.Node.initBorrowed(allocator, "query");
    defer query.deinit();
    var lid = binary.Node.initBorrowed(allocator, "lid");
    defer lid.deinit();
    try query.addChild(&lid);

    var list = binary.Node.initBorrowed(allocator, "list");
    defer list.deinit();
    for (jids) |jid| {
        var user = binary.Node.initBorrowed(allocator, "user");
        defer user.deinit();
        try user.addAttributeBorrowed("jid", jid);
        try list.addChild(&user);
    }

    try usync.addChild(&query);
    try usync.addChild(&list);
    try iq.addChild(&usync);
    return iq;
}

pub fn parseLidMappings(
    allocator: std.mem.Allocator,
    response: *const binary.Node,
) ![]LidMapping {
    var mappings = std.ArrayList(LidMapping).empty;
    errdefer {
        for (mappings.items) |mapping| {
            allocator.free(mapping.pn_jid);
            allocator.free(mapping.lid_jid);
        }
        mappings.deinit(allocator);
    }

    const usync = findChild(response, "usync") orelse return mappings.toOwnedSlice(allocator);
    const list = findChild(usync, "list") orelse return mappings.toOwnedSlice(allocator);
    const users = list.getContentNodes() orelse return mappings.toOwnedSlice(allocator);

    for (users) |*user| {
        if (!std.mem.eql(u8, user.tag, "user")) continue;
        const pn_jid = user.getAttribute("jid") orelse continue;
        if (!isPnJid(pn_jid)) continue;

        const lid = findChild(user, "lid") orelse continue;
        const lid_jid = lid.getAttribute("val") orelse continue;
        if (!isLidJid(lid_jid)) continue;

        try mappings.append(allocator, .{
            .pn_jid = try allocator.dupe(u8, pn_jid),
            .lid_jid = try allocator.dupe(u8, lid_jid),
        });
    }

    return mappings.toOwnedSlice(allocator);
}

pub fn parseDeviceJids(
    allocator: std.mem.Allocator,
    response: *const binary.Node,
) ![][]u8 {
    var out = std.ArrayList([]u8).empty;
    errdefer {
        for (out.items) |jid| allocator.free(jid);
        out.deinit(allocator);
    }

    const usync = findChild(response, "usync") orelse return out.toOwnedSlice(allocator);
    const list = findChild(usync, "list") orelse return out.toOwnedSlice(allocator);
    const users = list.getContentNodes() orelse return out.toOwnedSlice(allocator);

    for (users) |*user| {
        if (!std.mem.eql(u8, user.tag, "user")) continue;
        const base_jid = user.getAttribute("jid") orelse continue;
        const devices_parent = findChild(user, "devices") orelse continue;
        const device_list = findChild(devices_parent, "device-list") orelse continue;
        const device_nodes = device_list.getContentNodes() orelse continue;

        for (device_nodes) |*device_node| {
            if (!std.mem.eql(u8, device_node.tag, "device")) continue;
            const id_str = device_node.getAttribute("id") orelse continue;
            const device_id = std.fmt.parseInt(u16, id_str, 10) catch continue;
            try out.append(allocator, try withDeviceId(allocator, base_jid, device_id));
        }
    }

    return out.toOwnedSlice(allocator);
}

fn findChild(node: *const binary.Node, tag: []const u8) ?*const binary.Node {
    const children = node.getContentNodes() orelse return null;
    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, tag)) return child;
    }
    return null;
}

fn isPnJid(jid: []const u8) bool {
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return false;
    return std.mem.eql(u8, jid[at + 1 ..], "s.whatsapp.net");
}

fn isLidJid(jid: []const u8) bool {
    const at = std.mem.indexOfScalar(u8, jid, '@') orelse return false;
    return std.mem.eql(u8, jid[at + 1 ..], "lid");
}

fn withDeviceId(allocator: std.mem.Allocator, base_jid: []const u8, device_id: u16) ![]u8 {
    if (device_id == 0) return allocator.dupe(u8, base_jid);
    const at = std.mem.indexOfScalar(u8, base_jid, '@') orelse return allocator.dupe(u8, base_jid);
    return std.fmt.allocPrint(allocator, "{s}:{d}{s}", .{
        base_jid[0..at],
        device_id,
        base_jid[at..],
    });
}

test "build device list iq" {
    const allocator = std.testing.allocator;
    var iq = try buildDeviceListIq(allocator, "1", "1", &.{"559980000001@s.whatsapp.net"});
    defer iq.deinit();

    try std.testing.expectEqualStrings("iq", iq.tag);
    try std.testing.expectEqualStrings("usync", iq.getAttribute("xmlns") orelse "");
    const usync = iq.getContentNodes().?[0];
    try std.testing.expectEqualStrings("message", usync.getAttribute("context") orelse "");
}

test "build lid query iq" {
    const allocator = std.testing.allocator;
    var iq = try buildLidQueryIq(allocator, "1", "1", &.{"559980000001@s.whatsapp.net"});
    defer iq.deinit();

    try std.testing.expectEqualStrings("iq", iq.tag);
    try std.testing.expectEqualStrings("usync", iq.getAttribute("xmlns") orelse "");
    const children = iq.getContentNodes().?;
    try std.testing.expectEqual(@as(usize, 1), children.len);
    try std.testing.expectEqualStrings("usync", children[0].tag);
}
