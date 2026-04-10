const std = @import("std");
const binary = @import("binary");
const pair_mod = @import("pair");
const session_store = @import("session_store.zig");
const client_pump = @import("pump.zig");
const client_transport = @import("transport.zig");
const jid_helpers = @import("jid_helpers.zig");
const unified_session = @import("unified_session.zig");
const log = @import("log");

pub fn handlePairingFlow(self: anytype) !void {
    log.info("Client", "Waiting for pairing...", .{});
    var pair_sign_sent = false;
    return client_pump.pumpUntil(self, 30_000, struct {
        fn onNode(client: @TypeOf(self), pair_sent: *bool, node: *binary.Node) !client_pump.PumpResult {
            if (std.mem.eql(u8, node.tag, "failure")) return error.ServerRejected;

            if (std.mem.eql(u8, node.tag, "stream:error")) {
                if (pair_sent.*) return .done;
                return error.StreamError;
            }

            if (std.mem.eql(u8, node.tag, "iq")) {
                var handled = false;
                if (node.getContentNodes()) |children| {
                    for (children) |*child| {
                        if (std.mem.eql(u8, child.tag, "pair-device")) {
                            handled = true;
                            emitQrCodes(client, child);
                            client_transport.sendIqResult(
                                client,
                                node.getAttribute("id"),
                                node.getAttribute("from") orelse "s.whatsapp.net",
                            );
                        } else if (std.mem.eql(u8, child.tag, "pair-success")) {
                            try handlePairSuccess(client, node);
                            pair_sent.* = true;
                        }
                    }
                }
                if (!handled) client.processNode(node);
                return .keep_going;
            }

            client.processNode(node);
            return .keep_going;
        }
    }.onNode, &pair_sign_sent, error.PairingTimeout);
}

pub fn readUntilLogin(self: anytype) !void {
    var unit: void = {};
    client_pump.pumpUntil(self, 30_000, struct {
        fn onNode(client: @TypeOf(self), _: *void, node: *binary.Node) !client_pump.PumpResult {
            if (std.mem.eql(u8, node.tag, "success")) {
                client.is_logged_in = true;
                unified_session.updateServerTimeOffset(
                    &client.server_time_offset_ms,
                    node,
                    unified_session.nowMillis(client.io),
                );
                if (node.getAttribute("lid")) |lid| {
                    client.address_book.setOwnLid(lid) catch {};
                    session_store.syncIdentityAliases(client);
                }
                return .done;
            }

            if (std.mem.eql(u8, node.tag, "failure")) return error.LoginFailed;

            client.processNode(node);
            return .keep_going;
        }
    }.onNode, &unit, error.LoginFailed) catch |err| {
        self.emit(.login_failed);
        return err;
    };
}

fn emitQrCodes(self: anytype, pair_device_node: *const binary.Node) void {
    const b64 = std.base64.standard.Encoder;
    const children = pair_device_node.getContentNodes() orelse return;

    var noise_b64: [44]u8 = undefined;
    _ = b64.encode(&noise_b64, &self.static_keypair.x25519_public);
    var identity_b64: [44]u8 = undefined;
    _ = b64.encode(&identity_b64, &self.identity.key_pair.public);
    var adv_b64: [44]u8 = undefined;
    _ = b64.encode(&adv_b64, &self.adv_secret_key);

    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "ref")) {
            if (child.getContentBytes()) |ref_bytes| {
                const qr = std.fmt.allocPrint(self.allocator, "{s},{s},{s},{s}", .{
                    ref_bytes, &noise_b64, &identity_b64, &adv_b64,
                }) catch continue;
                defer self.allocator.free(qr);

                self.emit(.{ .qr_code = .{ .code = qr } });
            }
        }
    }
}

pub fn handlePairSuccess(self: anytype, node: *const binary.Node) !void {
    const info = pair_mod.parsePairSuccess(node) orelse return error.InvalidPairSuccess;

    self.device_id = jid_helpers.extractDeviceId(info.phone_jid);
    try self.address_book.setOwnIdentity(info.phone_jid, info.lid_jid, self.device_id);
    session_store.syncIdentityAliases(self);
    log.info("Client/Pair", "Paired! phone={s} lid={s} device_id={d}", .{
        self.phone_jid orelse "?", self.lid orelse "?", self.device_id,
    });

    self.emit(.{ .pair_success = .{
        .phone_jid = self.phone_jid orelse "",
        .lid = self.lid orelse "",
    } });

    const device_identity = info.device_identity orelse &[_]u8{};
    const pair_crypto = try pair_mod.doPairCrypto(
        self.allocator,
        self.io,
        self.identity,
        self.adv_secret_key,
        device_identity,
    );
    defer self.allocator.free(pair_crypto.self_signed_identity_bytes);
    if (self.account_device_identity) |old| self.allocator.free(old);
    self.account_device_identity = try self.allocator.dupe(
        u8,
        pair_crypto.self_signed_identity_bytes,
    );

    var response = try pair_mod.buildPairDeviceSignResponse(
        self.allocator,
        node.getAttribute("id") orelse "",
        pair_crypto.self_signed_identity_bytes,
        pair_crypto.key_index,
    );
    defer response.deinit();
    try client_transport.sendNode(self, &response);
}
