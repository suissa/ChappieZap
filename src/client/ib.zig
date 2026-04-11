const std = @import("std");
const binary = @import("binary");
const client_transport = @import("transport.zig");
const log = @import("log");

pub fn handleIb(self: anytype, node: *const binary.Node) void {
    const children = node.getContentNodes() orelse return;
    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "dirty")) {
            handleDirty(self, child);
        } else if (std.mem.eql(u8, child.tag, "edge_routing")) {
            log.debug("Client/IB", "Received edge_routing", .{});
        } else if (std.mem.eql(u8, child.tag, "offline_preview")) {
            log.debug("Client/IB", "Received offline_preview", .{});
        } else if (std.mem.eql(u8, child.tag, "offline")) {
            log.debug("Client/IB", "Received offline end marker", .{});
        }
    }
}

fn handleDirty(self: anytype, node: *const binary.Node) void {
    const dirty_type = node.getAttribute("type") orelse {
        log.debug("Client/IB", "dirty without type", .{});
        return;
    };
    const timestamp = node.getAttribute("timestamp");
    if (!self.options.experimental_post_login_init) return;
    sendCleanDirty(self, dirty_type, timestamp) catch |err| {
        log.warn("Client/IB", "Failed to clean dirty bit type={s}: {}", .{ dirty_type, err });
    };
}

fn sendCleanDirty(self: anytype, dirty_type: []const u8, timestamp: ?[]const u8) !void {
    var iq = binary.Node.initBorrowed(self.allocator, "iq");
    defer iq.deinit();

    var id_buf: [client_transport.iq_id_buffer_len]u8 = undefined;
    const iq_id = try client_transport.nextIqIdInto(self, &id_buf);

    try iq.addAttributeBorrowed("id", iq_id);
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("xmlns", "urn:xmpp:whatsapp:dirty");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    var clean = binary.Node.initBorrowed(self.allocator, "clean");
    defer clean.deinit();
    try clean.addAttributeBorrowed("type", dirty_type);
    if (timestamp) |ts| try clean.addAttributeBorrowed("timestamp", ts);
    try iq.addChild(&clean);

    client_transport.sendNode(self, &iq) catch |err| {
        log.warn("Client/IB", "Failed to send clean dirty for type={s}: {}", .{ dirty_type, err });
    };
}
