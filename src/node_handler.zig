const std = @import("std");
const binary = @import("binary");

/// Determine if a node should be acknowledged with <ack/>.
/// Matches Rust: message, receipt, notification, call — must have id + from.
pub fn shouldAck(node: *const binary.Node) bool {
    const tag = node.tag;
    const is_ackable = std.mem.eql(u8, tag, "message") or
        std.mem.eql(u8, tag, "receipt") or
        std.mem.eql(u8, tag, "notification") or
        std.mem.eql(u8, tag, "call");
    return is_ackable and node.getAttribute("id") != null and node.getAttribute("from") != null;
}

/// Build an <ack> node for the given stanza. Matches Rust build_ack_node logic.
pub fn buildAckNode(allocator: std.mem.Allocator, node: *const binary.Node) !binary.Node {
    var ack = try binary.Node.init(allocator, "ack");
    errdefer ack.deinit();

    try ack.addAttribute("class", node.tag);
    try ack.addAttribute("id", node.getAttribute("id") orelse return error.MissingId);
    try ack.addAttribute("to", node.getAttribute("from") orelse return error.MissingFrom);

    if (node.getAttribute("participant")) |p| try ack.addAttribute("participant", p);

    // Echo type for all EXCEPT "message" and encrypt+identity notifications
    if (!std.mem.eql(u8, node.tag, "message") and !isEncryptIdentityNotification(node)) {
        if (node.getAttribute("type")) |typ| try ack.addAttribute("type", typ);
    }

    return ack;
}

/// Check if a notification is type="encrypt" with <identity/> child.
fn isEncryptIdentityNotification(node: *const binary.Node) bool {
    if (!std.mem.eql(u8, node.tag, "notification")) return false;
    const typ = node.getAttribute("type") orelse return false;
    if (!std.mem.eql(u8, typ, "encrypt")) return false;
    if (node.getContentNodes()) |children| {
        for (children) |*child| {
            if (std.mem.eql(u8, child.tag, "identity")) return true;
        }
    }
    return false;
}
