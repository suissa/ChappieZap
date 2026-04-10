const std = @import("std");
const binary = @import("binary");
const decrypt_mod = @import("decrypt.zig");
const messaging = @import("messaging");
const ib = @import("ib.zig");
const node_handler = @import("node_handler");
const jid_helpers = @import("jid_helpers.zig");
const client_transport = @import("transport.zig");
const session_store = @import("session_store.zig");
const log = @import("log");

const DispatchStep = enum {
    iq,
    ib,
    notification,
    message,
    receipt,
};

const DispatchEntry = struct {
    tag: []const u8,
    step: DispatchStep,
    returns_early: bool,
};

const dispatch_table = [_]DispatchEntry{
    .{ .tag = "iq", .step = .iq, .returns_early = true },
    .{ .tag = "ib", .step = .ib, .returns_early = false },
    .{ .tag = "notification", .step = .notification, .returns_early = false },
    .{ .tag = "message", .step = .message, .returns_early = false },
    .{ .tag = "receipt", .step = .receipt, .returns_early = false },
};

pub fn processNode(self: anytype, node: *const binary.Node) void {
    const tag = node.tag;

    inline for (dispatch_table) |entry| {
        if (std.mem.eql(u8, tag, entry.tag)) {
            switch (entry.step) {
                .iq => handleIq(self, node),
                .ib => ib.handleIb(self, node),
                .notification => handleNotification(self, node),
                .message => handleMessage(self, node),
                .receipt => handleReceipt(self, node),
            }
            if (comptime entry.returns_early) return;
            break;
        }
    }

    if (node_handler.shouldAck(node)) {
        client_transport.sendAck(self, node) catch {};
    }
}

fn handleIq(self: anytype, node: *const binary.Node) void {
    const iq_type = node.getAttribute("type") orelse return;
    if (std.mem.eql(u8, iq_type, "get")) {
        client_transport.sendIqResult(self, node.getAttribute("id"), node.getAttribute("from") orelse "s.whatsapp.net");
    }
}

fn handleNotification(self: anytype, node: *const binary.Node) void {
    if (self.address_book.maybeUpdateOwnDeviceList(node) catch false) {
        log.debug("Client/Devices", "Updated own device list from account_sync: {d} device(s)", .{
            self.address_book.ownDeviceCount(),
        });
        var it = self.address_book.ownDeviceIterator();
        while (it.next()) |jid_ptr| {
            log.debug("Client/Devices", "  own device {s}", .{jid_ptr.*});
        }
    }
}

fn handleMessage(self: anytype, node: *const binary.Node) void {
    if (self.options.tls) {
        if (self.address_book.rememberFromMessage(node) catch null) |mapping| {
            session_store.migrateSessionsOnLidDiscovery(self, mapping.pn_jid, mapping.lid_jid);
        }
    }
    const decrypted = decrypt_mod.decryptMessageNode(self, node);
    defer if (decrypted) |d| self.allocator.free(d);

    var body: ?[]const u8 = null;
    if (decrypted) |d| body = messaging.decodeTextMessage(d);

    if (self._last_msg_from) |old| self.allocator.free(old);
    self._last_msg_from = self.allocator.dupe(u8, node.getAttribute("from") orelse "") catch null;
    if (self._last_msg_chat) |old| self.allocator.free(old);
    self._last_msg_chat = self.allocator.dupe(u8, jid_helpers.messageChatJid(&self.address_book, node)) catch null;
    if (self._last_msg_id) |old| self.allocator.free(old);
    self._last_msg_id = self.allocator.dupe(u8, node.getAttribute("id") orelse "") catch null;
    if (self._last_msg_text) |old| self.allocator.free(old);
    self._last_msg_text = if (body) |b| self.allocator.dupe(u8, b) catch null else null;
    self._last_msg_decrypted = body != null;

    self.emit(.{ .message = .{
        .from = node.getAttribute("from") orelse "",
        .chat = jid_helpers.messageChatJid(&self.address_book, node),
        .id = node.getAttribute("id") orelse "",
        .node = node,
        .body = body,
    } });
}

fn handleReceipt(self: anytype, node: *const binary.Node) void {
    if (self._last_receipt_from) |old| self.allocator.free(old);
    self._last_receipt_from = self.allocator.dupe(u8, node.getAttribute("from") orelse "") catch null;
}
