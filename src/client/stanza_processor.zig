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

pub const ProcessedMessage = struct {
    plaintext: ?[]u8 = null,
    body: ?[]const u8 = null,
    chat: []const u8,

    pub fn deinit(self: *ProcessedMessage, allocator: std.mem.Allocator) void {
        if (self.plaintext) |plaintext| allocator.free(plaintext);
        self.* = .{ .chat = "" };
    }
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
        client_transport.sendAck(self, node) catch |err| {
            if (isBenignSendShutdownError(err)) return;
            log.warn("Client/Recv", "Failed to send ack for <{s}>: {}", .{ node.tag, err });
        };
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

pub fn processMessageNode(self: anytype, node: *const binary.Node) ProcessedMessage {
    if (self.options.tls) {
        if (self.address_book.rememberFromMessage(node) catch null) |mapping| {
            session_store.migrateSessionsOnLidDiscovery(self, mapping.pn_jid, mapping.lid_jid);
        }
    }

    const chat = messageChatJidForMatch(self, node);
    const decrypted = decrypt_mod.decryptMessageNode(self, node);
    var processed = ProcessedMessage{ .plaintext = decrypted, .chat = chat };
    if (decrypted) |d| processed.body = messaging.decodeTextMessage(d);

    self.emit(.{ .message = .{
        .from = node.getAttribute("from") orelse "",
        .chat = chat,
        .id = node.getAttribute("id") orelse "",
        .node = node,
        .body = processed.body,
    } });

    if (decrypted != null) {
        client_transport.sendDeliveryReceipt(self, node) catch |err| {
            if (isBenignSendShutdownError(err)) return processed;
            if (err != error.NoDeliveryReceipt) {
                log.warn("Client/Receipt", "Failed to send delivery receipt for {s}: {}", .{
                    node.getAttribute("id") orelse "",
                    err,
                });
            }
        };
    }

    return processed;
}

fn handleMessage(self: anytype, node: *const binary.Node) void {
    var processed = processMessageNode(self, node);
    defer processed.deinit(self.allocator);
}

fn handleReceipt(_: anytype, _: *const binary.Node) void {}

pub fn messageChatJidForMatch(self: anytype, node: *const binary.Node) []const u8 {
    return jid_helpers.messageChatJid(&self.address_book, node);
}

fn isBenignSendShutdownError(err: anyerror) bool {
    return err == error.WriteFailed or err == error.NotConnected;
}
