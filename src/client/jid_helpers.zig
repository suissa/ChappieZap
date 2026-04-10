const std = @import("std");
const binary = @import("binary");
const addressing = @import("addressing");
const jid_common = @import("jid_common");

pub const ParsedJidParts = struct {
    bare_user: []const u8,
    server: []const u8,
};

pub fn extractDeviceId(jid: []const u8) u32 {
    const colon = std.mem.indexOf(u8, jid, ":") orelse return 0;
    const at = std.mem.indexOf(u8, jid, "@") orelse return 0;
    if (colon >= at) return 0;
    return std.fmt.parseInt(u32, jid[colon + 1 .. at], 10) catch 0;
}

pub fn messageChatJid(address_book: *const addressing.AddressBook, node: *const binary.Node) []const u8 {
    const from = node.getAttribute("from") orelse return "";

    if (address_book.isSelfChatJid(from)) {
        if (node.getAttribute("recipient")) |recipient| return recipient;
    }

    return from;
}

pub fn parseJidParts(jid: []const u8) ?ParsedJidParts {
    const parts = jid_common.parse(jid) catch return null;
    return .{
        .bare_user = parts.bare_user,
        .server = parts.server,
    };
}

pub fn containsJid(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

pub fn isPnJid(jid: []const u8) bool {
    return jid_common.isPn(jid);
}

test "message chat jid uses recipient for self-sent device echoes" {
    const allocator = std.testing.allocator;

    var book = addressing.AddressBook.init(allocator);
    defer book.deinit();
    try book.setOwnIdentity("559984726662@s.whatsapp.net", "236395184570386@lid", 63);

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("from", "559984726662:4@s.whatsapp.net");
    try node.addAttribute("recipient", "559984726662@s.whatsapp.net");

    try std.testing.expectEqualStrings(
        "559984726662@s.whatsapp.net",
        messageChatJid(&book, &node),
    );
}
