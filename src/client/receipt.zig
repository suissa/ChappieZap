const std = @import("std");
const binary = @import("binary");
const addressing = @import("addressing");
const jid_common = @import("jid_common");
const jid_helpers = @import("jid_helpers.zig");

pub const DeliveryReceiptKind = enum {
    delivery,
    peer_msg,
};

pub const DeliveryReceiptAttrs = struct {
    id: []const u8,
    to: []const u8,
    participant: ?[]const u8 = null,
    kind: DeliveryReceiptKind,
};

pub fn deliveryReceiptKind(address_book: *const addressing.AddressBook, node: *const binary.Node) ?DeliveryReceiptKind {
    const id = node.getAttribute("id") orelse return null;
    if (id.len == 0) return null;

    const from = node.getAttribute("from") orelse return null;
    if (isStatusBroadcast(from) or isNewsletterJid(from)) return null;

    const is_peer = if (node.getAttribute("category")) |category|
        std.mem.eql(u8, category, "peer")
    else
        false;

    if (!is_peer and isFromMe(address_book, node)) return null;

    return if (is_peer) .peer_msg else .delivery;
}

pub fn deliveryReceiptAttrs(address_book: *const addressing.AddressBook, node: *const binary.Node) ?DeliveryReceiptAttrs {
    const kind = deliveryReceiptKind(address_book, node) orelse return null;
    return .{
        .id = node.getAttribute("id") orelse return null,
        .to = jid_helpers.messageChatJid(address_book, node),
        .participant = node.getAttribute("participant"),
        .kind = kind,
    };
}

pub fn buildDeliveryReceiptNode(
    allocator: std.mem.Allocator,
    address_book: *const addressing.AddressBook,
    node: *const binary.Node,
) !binary.Node {
    const attrs = deliveryReceiptAttrs(address_book, node) orelse return error.NoDeliveryReceipt;

    var receipt = binary.Node.initBorrowed(allocator, "receipt");
    errdefer receipt.deinit();

    try receipt.addAttributeBorrowed("id", attrs.id);
    try receipt.addAttributeBorrowed("to", attrs.to);

    if (attrs.kind == .peer_msg) {
        try receipt.addAttributeBorrowed("type", "peer_msg");
    }

    if (attrs.participant) |participant| {
        try receipt.addAttributeBorrowed("participant", participant);
    }

    return receipt;
}

fn isFromMe(address_book: *const addressing.AddressBook, node: *const binary.Node) bool {
    if (node.getAttribute("participant")) |participant| {
        if (address_book.isSelfChatJid(participant)) return true;
    }

    const from = node.getAttribute("from") orelse return false;
    return address_book.isSelfChatJid(from);
}

fn isStatusBroadcast(jid: []const u8) bool {
    return std.mem.eql(u8, jid, "status@broadcast");
}

fn isNewsletterJid(jid: []const u8) bool {
    const parts = jid_common.parse(jid) catch return false;
    return std.mem.eql(u8, parts.server, "newsletter");
}

test "deliveryReceiptKind skips own non-peer messages" {
    const allocator = std.testing.allocator;

    var book = addressing.AddressBook.init(allocator);
    defer book.deinit();
    try book.setOwnIdentity("559980000001@s.whatsapp.net", "100000012345678@lid", 33);

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("id", "MSG1");
    try node.addAttribute("from", "559980000001@s.whatsapp.net");

    try std.testing.expect(deliveryReceiptKind(&book, &node) == null);
}

test "deliveryReceiptKind allows peer self-synced messages" {
    const allocator = std.testing.allocator;

    var book = addressing.AddressBook.init(allocator);
    defer book.deinit();
    try book.setOwnIdentity("559980000001@s.whatsapp.net", "100000012345678@lid", 33);

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("id", "MSG1");
    try node.addAttribute("from", "559980000001@s.whatsapp.net");
    try node.addAttribute("category", "peer");

    try std.testing.expectEqual(DeliveryReceiptKind.peer_msg, deliveryReceiptKind(&book, &node).?);
}

test "deliveryReceiptKind skips status and newsletters" {
    const allocator = std.testing.allocator;

    var book = addressing.AddressBook.init(allocator);
    defer book.deinit();

    var status = try binary.Node.init(allocator, "message");
    defer status.deinit();
    try status.addAttribute("id", "MSG1");
    try status.addAttribute("from", "status@broadcast");
    try std.testing.expect(deliveryReceiptKind(&book, &status) == null);

    var newsletter = try binary.Node.init(allocator, "message");
    defer newsletter.deinit();
    try newsletter.addAttribute("id", "MSG2");
    try newsletter.addAttribute("from", "120363123456789012@newsletter");
    try std.testing.expect(deliveryReceiptKind(&book, &newsletter) == null);
}

test "buildDeliveryReceiptNode includes group participant" {
    const allocator = std.testing.allocator;

    var book = addressing.AddressBook.init(allocator);
    defer book.deinit();

    var node = try binary.Node.init(allocator, "message");
    defer node.deinit();
    try node.addAttribute("id", "MSG1");
    try node.addAttribute("from", "120363161500776365@g.us");
    try node.addAttribute("participant", "2439742808066@lid");

    var receipt = try buildDeliveryReceiptNode(allocator, &book, &node);
    defer receipt.deinit();

    try std.testing.expectEqualStrings("receipt", receipt.tag);
    try std.testing.expectEqualStrings("MSG1", receipt.getAttribute("id").?);
    try std.testing.expectEqualStrings("120363161500776365@g.us", receipt.getAttribute("to").?);
    try std.testing.expectEqualStrings("2439742808066@lid", receipt.getAttribute("participant").?);
    try std.testing.expect(receipt.getAttribute("type") == null);
}
