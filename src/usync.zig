const std = @import("std");
const binary = @import("binary");

pub const LidMapping = struct {
    pn_jid: []const u8,
    lid_jid: []const u8,
};

pub fn buildLidQueryIq(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    sid: []const u8,
    jids: []const []const u8,
) !binary.Node {
    var iq = try binary.Node.init(allocator, "iq");
    errdefer iq.deinit();
    try iq.addAttribute("id", iq_id);
    try iq.addAttribute("type", "get");
    try iq.addAttribute("xmlns", "usync");
    try iq.addAttribute("to", "s.whatsapp.net");

    var usync = try binary.Node.init(allocator, "usync");
    defer usync.deinit();
    try usync.addAttribute("sid", sid);
    try usync.addAttribute("mode", "query");
    try usync.addAttribute("last", "true");
    try usync.addAttribute("index", "0");
    try usync.addAttribute("context", "background");

    var query = try binary.Node.init(allocator, "query");
    defer query.deinit();
    var lid = try binary.Node.init(allocator, "lid");
    defer lid.deinit();
    try query.addChild(&lid);

    var list = try binary.Node.init(allocator, "list");
    defer list.deinit();
    for (jids) |jid| {
        var user = try binary.Node.init(allocator, "user");
        defer user.deinit();
        try user.addAttribute("jid", jid);
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
