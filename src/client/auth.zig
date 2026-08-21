const std = @import("std");
const binary = @import("binary");
const pair_mod = @import("pair");
const pair_code_mod = @import("pair_code");
const session_store = @import("session_store.zig");
const client_pump = @import("pump.zig");
const client_transport = @import("transport.zig");
const jid_helpers = @import("jid_helpers.zig");
const unified_session = @import("unified_session.zig");
const log = @import("log");

pub fn handlePairingFlow(self: anytype) !void {
    log.info("Client", "Waiting for pairing...", .{});
    var pair_sign_sent = false;

    if (self.options.pairing_mode == .paircode) {
        if (self.options.pairing_phone_number) |raw_phone| {
            try startPairCodeFlow(self, raw_phone);
        } else {
            log.warn("Client", "paircode mode requires a phone number. Use: whatszig <phone> paircode", .{});
            return error.PhoneNumberRequired;
        }
    }

    return client_pump.pumpUntil(self, 60_000, struct {
        fn onNode(client: @TypeOf(self), pair_sent: *bool, node: *binary.Node) !client_pump.PumpResult {
            if (std.mem.eql(u8, node.tag, "failure")) return error.ServerRejected;

            if (std.mem.eql(u8, node.tag, "stream:error")) {
                if (pair_sent.*) return .done;
                return error.StreamError;
            }

            if (std.mem.eql(u8, node.tag, "notification")) {
                if (client.options.pairing_mode == .paircode) {
                    if (pair_code_mod.parsePrimaryHelloNotification(node)) |ph| {
                        try handlePrimaryHello(client, ph);
                    }
                }
                client.processNode(node);
                return .keep_going;
            }

            if (std.mem.eql(u8, node.tag, "iq")) {
                var handled = false;
                if (client.options.pairing_mode == .paircode) {
                    if (pair_code_mod.parseCompanionHelloResponse(node)) |pref| {
                        handled = true;
                        if (client.pair_code_ref) |old| client.allocator.free(old);
                        client.pair_code_ref = try client.allocator.dupe(u8, pref);
                        log.debug("Client/PairCode", "Received pairing ref ({d} bytes)", .{pref.len});
                    }
                }

                if (node.getContentNodes()) |children| {
                    for (children) |*child| {
                        if (std.mem.eql(u8, child.tag, "pair-device")) {
                            handled = true;
                            if (client.options.pairing_mode == .qrcode) {
                                emitQrCodes(client, child);
                            }
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

fn startPairCodeFlow(self: anytype, raw_phone: []const u8) !void {
    var phone_buf: [32]u8 = undefined;
    const phone = pair_code_mod.PairCodeUtils.sanitizePhoneNumber(raw_phone, &phone_buf);
    if (phone.len == 0) return error.InvalidPhoneNumber;

    const code = pair_code_mod.PairCodeUtils.generateCode(self.io);
    const eph = std.crypto.dh.X25519.KeyPair.generate(self.io);
    self.pair_code_str = code;
    self.pair_code_ephemeral = eph;
    if (self.pair_code_phone) |old| self.allocator.free(old);
    self.pair_code_phone = try self.allocator.dupe(u8, phone);

    const wrapped_eph = pair_code_mod.PairCodeUtils.encryptEphemeralPub(eph.public_key, &code, self.io);

    var id_buf: [32]u8 = undefined;
    const req_id = try client_transport.nextIqIdInto(self, &id_buf);

    var hello_iq = try pair_code_mod.buildCompanionHelloIq(
        self.allocator,
        phone,
        &self.static_keypair.x25519_public,
        &wrapped_eph,
        req_id,
    );
    defer hello_iq.deinit();

    try client_transport.sendNode(self, &hello_iq);

    var formatted_buf: [9]u8 = undefined;
    const formatted = pair_code_mod.PairCodeUtils.formatCode(&code, &formatted_buf);

    log.info("Client/PairCode", "Pairing code generated for +{s}: {s}", .{ phone, formatted });

    self.emit(.{ .pairing_code = .{
        .code = &code,
        .formatted_code = formatted,
        .phone = self.pair_code_phone.?,
    } });
}

fn handlePrimaryHello(self: anytype, ph: pair_code_mod.PrimaryHelloData) !void {
    log.info("Client/PairCode", "Primary device connected, completing handshake...", .{});
    const code = self.pair_code_str orelse return error.NoPairCode;
    const eph = self.pair_code_ephemeral orelse return error.NoPairCodeEphemeral;
    const phone = self.pair_code_phone orelse return error.NoPairCodePhone;

    const primary_eph_pub = try pair_code_mod.PairCodeUtils.decryptPrimaryEphemeralPub(
        ph.wrapped_ephemeral_pub,
        &code,
    );

    const bundle_res = try pair_code_mod.PairCodeUtils.prepareKeyBundle(
        eph.secret_key,
        self.identity.key_pair.private,
        self.identity.key_pair.public,
        primary_eph_pub,
        ph.primary_identity_pub,
        self.io,
    );

    self.adv_secret_key = bundle_res.new_adv_secret;

    var id_buf: [32]u8 = undefined;
    const req_id = try client_transport.nextIqIdInto(self, &id_buf);

    const pairing_ref = self.pair_code_ref orelse ph.pairing_ref;

    var finish_iq = try pair_code_mod.buildCompanionFinishIq(
        self.allocator,
        phone,
        &bundle_res.wrapped_bundle,
        &self.identity.key_pair.public,
        pairing_ref,
        req_id,
    );
    defer finish_iq.deinit();

    try client_transport.sendNode(self, &finish_iq);
    log.info("Client/PairCode", "Sent companion_finish, waiting for pair-success...", .{});
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
                    if (client.address_book.setOwnLid(lid)) {
                        session_store.syncIdentityAliases(client);
                    } else |err| {
                        log.warn("Client/Auth", "Failed to record own lid {s}: {}", .{ lid, err });
                    }
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
