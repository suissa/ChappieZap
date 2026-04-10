const std = @import("std");
const ws = @import("websocket_client");
const xed25519 = @import("xed25519");
const socket_mod = @import("socket");
const binary = @import("binary");
const signal = @import("signal");
const handshake_mod = @import("handshake");
const node_handler = @import("node_handler");
const prekey_mod = @import("prekey");
const messaging = @import("messaging");
const pair_mod = @import("pair");
const whatsapp = @import("whatsapp_proto");
const events = @import("events");
const log = @import("log");
const http = std.http;

pub const Event = events.Event;
pub const EventHandler = events.EventHandler;

pub const ClientOptions = struct {
    host: []const u8 = "web.whatsapp.com",
    port: u16 = 443,
    tls: bool = true,
    tls_ca_cert_path: ?[]const u8 = null,
    path: []const u8 = "/ws/chat",
    on_event: ?EventHandler = null,
    event_context: ?*anyopaque = null,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: ClientOptions,
    ws_client: ws.WebSocketClient,
    noise_socket: ?socket_mod.NoiseSocket = null,
    static_keypair: xed25519.XEd25519.KeyPair,
    iq_counter: u32 = 0,
    is_logged_in: bool = false,
    lid: ?[]u8 = null,
    phone_jid: ?[]u8 = null, // "559980000001@s.whatsapp.net"
    device_id: u32 = 0, // companion device ID from pairing (e.g. 33)

    identity: signal.IdentityKeyPair,
    signed_prekey: signal.SignedPreKey,
    prekeys: [10]signal.PreKey,
    registration_id: u32,
    adv_secret_key: [32]u8,
    app_version: AppVersion = .{},
    sessions: std.ArrayList(SessionEntry) = .empty,
    _last_msg_text: ?[]u8 = null,

    const AppVersion = struct {
        primary: u32 = 2,
        secondary: u32 = 3000,
        tertiary: u32 = 1037005288,
    };

    const SessionEntry = struct {
        jid: []u8,
        session: signal.Session,
    };

    /// Parameters for the PreKeySignalMessage wrapper.
    pub const PreKeyMsgParams = struct {
        registration_id: u32,
        prekey_id: ?u32,
        signed_prekey_id: u32,
        base_key: [32]u8,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: ClientOptions) !Client {
        const identity = signal.IdentityKeyPair.generate(io);
        const signed_pk = signal.SignedPreKey.generate(1, identity, io);
        var prekeys: [10]signal.PreKey = undefined;
        for (0..10) |i| prekeys[i] = signal.PreKey.generate(@intCast(i + 1), io);

        var adv_secret: [32]u8 = undefined;
        io.random(&adv_secret);

        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .ws_client = try ws.WebSocketClient.init(allocator, io),
            .static_keypair = xed25519.XEd25519.KeyPair.generate(io),
            .identity = identity,
            .signed_prekey = signed_pk,
            .prekeys = prekeys,
            .registration_id = signal.keys.generateRegistrationId(io),
            .adv_secret_key = adv_secret,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self._last_msg_text) |t| self.allocator.free(t);
        for (self.sessions.items) |*entry| {
            self.allocator.free(entry.jid);
            entry.session.deinit();
        }
        self.sessions.deinit(self.allocator);
        if (self.lid) |lid| self.allocator.free(lid);
        if (self.phone_jid) |pj| self.allocator.free(pj);
        if (self.noise_socket) |*ns| ns.deinit();
        self.ws_client.deinit();
    }

    // --- Public API ---

    /// Full connection flow: pair → reconnect → login → prekeys → event loop.
    /// Blocks until disconnected. Dispatches events to the handler.
    pub fn connectAndRun(self: *Client) !void {
        try self.connectWithPayload(.pairing);
        try self.handlePairingFlow();
        try self.connectWithPayload(.login);
        try self.readUntilLogin();

        self.emit(.{ .connected = .{
            .phone_jid = self.phone_jid orelse "",
            .lid = self.lid orelse "",
        } });

        self.sendActive();
        self.uploadPrekeys() catch {};

        self.runMessageLoop();
    }

    /// Connect, pair, login, upload prekeys. Does NOT start message loop.
    /// Use this for tests where you want manual control.
    pub fn connectAndLogin(self: *Client) !void {
        try self.connectWithPayload(.pairing);
        try self.handlePairingFlow();
        try self.connectWithPayload(.login);
        try self.readUntilLogin();
        self.sendActive();
        self.uploadPrekeys() catch {};
    }

    /// Send a text message to a JID. Handles session management automatically:
    /// fetches prekeys and establishes a session if needed, then encrypts and sends.
    pub fn sendMessage(self: *Client, to_jid: []const u8, text: []const u8) !void {
        if (self.findSession(to_jid) != null) {
            return self.sendEncrypted(to_jid, text, null);
        }
        // No session yet — fetch prekeys, create session, send as pkmsg
        const bundle = try self.fetchPrekeys(to_jid);
        const pk_params = try self.createSession(to_jid, bundle);
        return self.sendEncrypted(to_jid, text, pk_params);
    }

    /// Wait for an incoming message containing the expected text.
    /// Reads and processes nodes until the text matches or timeout.
    pub fn waitForText(self: *Client, expected: []const u8, timeout_ms: u32) !void {
        var attempts: usize = 0;
        while (attempts < 100) : (attempts += 1) {
            var node = self.receiveNodeTimeout(timeout_ms) catch continue;
            defer node.deinit();
            self.processNode(&node);
            if (self._last_msg_text) |text| {
                if (std.mem.eql(u8, text, expected)) return;
            }
        }
        return error.TextNotFound;
    }

    pub fn isConnected(self: *const Client) bool {
        return self.noise_socket != null and self.is_logged_in;
    }

    fn decryptMessageNode(self: *Client, node: *const binary.Node) ?[]u8 {
        const children = node.getContentNodes() orelse return null;
        const from_jid = node.getAttribute("from") orelse return null;

        for (children) |*child| {
            if (!std.mem.eql(u8, child.tag, "enc")) continue;
            const enc_type = child.getAttribute("type") orelse continue;
            const ciphertext = child.getContentBytes() orelse {
                log.debug("Client/Decrypt", "enc type={s}: no content bytes", .{enc_type});
                continue;
            };

            if (std.mem.eql(u8, enc_type, "pkmsg")) {
                return self.decryptPreKeyMessage(from_jid, ciphertext) catch |err| {
                    log.warn("Client/Decrypt", "pkmsg decrypt failed: {}", .{err});
                    return null;
                };
            } else if (std.mem.eql(u8, enc_type, "msg")) {
                return self.decryptSessionMessage(from_jid, ciphertext) catch |err| {
                    log.warn("Client/Decrypt", "msg decrypt failed: {}", .{err});
                    return null;
                };
            }
        }
        return null;
    }

    // --- Internal: Connection ---

    const ConnectionMode = enum { pairing, login };

    fn connectWithPayload(self: *Client, mode: ConnectionMode) !void {
        log.info("Client", "Connecting to {s}:{d} (mode={s})...", .{
            self.options.host,                            self.options.port,
            if (mode == .pairing) "pairing" else "login",
        });

        self.refreshAppVersion();

        // Reset connection state
        if (self.noise_socket) |*ns| ns.deinit();
        self.noise_socket = null;
        self.ws_client.deinit();
        self.ws_client = try ws.WebSocketClient.init(self.allocator, self.io);
        self.is_logged_in = false;

        log.debug("Client", "WebSocket connecting...", .{});
        if (self.options.tls) {
            if (self.options.tls_ca_cert_path) |cert_path| {
                try self.ws_client.addCaCertFileAbsolute(cert_path);
            }
        }
        try self.ws_client.connectOptions(
            self.options.host,
            self.options.port,
            self.options.path,
            &.{.{ .name = "Origin", .value = "https://web.whatsapp.com" }},
            self.options.tls,
        );
        log.debug("Client", "WebSocket connected, starting Noise handshake...", .{});

        const payload = switch (mode) {
            .pairing => try self.buildPairingPayload(),
            .login => try self.buildLoginPayload(),
        };
        defer self.allocator.free(payload);
        log.debug("Client", "ClientPayload built ({d} bytes, mode={s})", .{ payload.len, if (mode == .pairing) "pairing" else "login" });

        const cipher_pair = try handshake_mod.performHandshake(
            self.allocator,
            self.io,
            &self.ws_client,
            self.static_keypair,
            payload,
        );
        log.info("Client", "Noise handshake complete", .{});
        self.noise_socket = try socket_mod.NoiseSocket.init(
            self.allocator,
            cipher_pair.write_key,
            cipher_pair.read_key,
        );
    }

    fn buildPairingPayload(self: *Client) ![]u8 {
        const pd = try pair_mod.buildPairingData(
            self.identity,
            self.signed_prekey,
            self.registration_id,
            self.app_version,
        );

        const ident_hex = shortHex(pd.e_ident[0..8]);
        const skey_pub_hex = shortHex(pd.e_skey_val[0..8]);
        const skey_sig_hex = shortHex(pd.e_skey_sig[0..8]);
        const build_hash_hex = shortHex(pd.build_hash[0..8]);
        const noise_pub_hex = shortHex(self.static_keypair.x25519_public[0..8]);

        log.debug("PairPayload", "version={d}.{d}.{d} regid={d} ident={s} skey_id={d} skey_pub={s} skey_sig={s} build_hash={s} noise_pub={s}", .{
            self.app_version.primary,
            self.app_version.secondary,
            self.app_version.tertiary,
            self.registration_id,
            &ident_hex,
            self.signed_prekey.id,
            &skey_pub_hex,
            &skey_sig_hex,
            &build_hash_hex,
            &noise_pub_hex,
        });
        if (log.enabled(.debug)) {
            const ident_full = try allocHex(self.allocator, &pd.e_ident);
            defer self.allocator.free(ident_full);
            const skey_pub_full = try allocHex(self.allocator, &pd.e_skey_val);
            defer self.allocator.free(skey_pub_full);
            const skey_sig_full = try allocHex(self.allocator, &pd.e_skey_sig);
            defer self.allocator.free(skey_sig_full);
            log.debug("PairPayloadFull", "e_ident={s} e_skey_val={s} e_skey_sig={s}", .{
                ident_full, skey_pub_full, skey_sig_full,
            });
        }

        // Encode DeviceProps protobuf
        const device_props = pair_mod.makePairingDeviceProps();
        var dp_writer = std.Io.Writer.Allocating.init(self.allocator);
        defer dp_writer.deinit();
        try device_props.encode(&dp_writer.writer, self.allocator);
        const dp_owned = try dp_writer.toOwnedSlice();
        defer self.allocator.free(dp_owned);

        var payload = self.makeBasePayload();
        payload.passive = false;
        payload.pull = false;
        payload.devicePairingData = .{
            .eRegid = &pd.e_regid,
            .eKeytype = &pd.e_keytype,
            .eIdent = &pd.e_ident,
            .eSkeyId = &pd.e_skey_id,
            .eSkeyVal = &pd.e_skey_val,
            .eSkeySig = &pd.e_skey_sig,
            .buildHash = &pd.build_hash,
            .deviceProps = dp_owned,
        };
        _ = &payload;

        var writer = std.Io.Writer.Allocating.init(self.allocator);
        defer writer.deinit();
        try payload.encode(&writer.writer, self.allocator);
        return writer.toOwnedSlice();
    }

    /// Build login payload for reconnect — includes username (phone) and device ID.
    /// Matches Rust get_login_payload: username=phone_as_u64, device=33, passive=true.
    fn buildLoginPayload(self: *Client) ![]u8 {
        // Extract phone number from JID: "559980000001@s.whatsapp.net" → 559980000001
        var username: ?u64 = null;
        if (self.phone_jid) |pj| {
            if (std.mem.indexOf(u8, pj, "@")) |at| {
                username = std.fmt.parseInt(u64, pj[0..at], 10) catch null;
            }
        }

        log.debug("Client", "Building login payload: username={?}, device={d}", .{ username, self.device_id });

        var payload = self.makeBasePayload();
        payload.passive = true; // returning login is passive
        payload.username = username;
        payload.device = self.device_id;
        _ = &payload;

        var writer = std.Io.Writer.Allocating.init(self.allocator);
        defer writer.deinit();
        try payload.encode(&writer.writer, self.allocator);
        return writer.toOwnedSlice();
    }

    // --- Internal: Pairing ---

    fn handlePairingFlow(self: *Client) !void {
        log.info("Client", "Waiting for pairing...", .{});
        var pair_sign_sent = false;
        var count: usize = 0;
        while (count < 30) : (count += 1) {
            var node = try self.receiveNode();
            defer node.deinit();
            if (std.mem.eql(u8, node.tag, "failure")) {
                logNode("Client/Pair", &node);
                return error.ServerRejected;
            }

            if (std.mem.eql(u8, node.tag, "stream:error")) {
                // After pair-device-sign, any stream:error means "reconnect now"
                // (515 is expected, but ping timeout also triggers reconnect)
                if (pair_sign_sent) return;
                for (node.attributes.items) |attr| {
                    log.warn("Client/Pair", "  stream:error {s}={s}", .{ attr.key, attr.value });
                }
                return error.StreamError;
            }

            if (std.mem.eql(u8, node.tag, "iq")) {
                var handled = false;
                if (node.getContentNodes()) |children| {
                    for (children) |*child| {
                        if (std.mem.eql(u8, child.tag, "pair-device")) {
                            handled = true;
                            self.emitQrCodes(child);
                            self.sendIqResult(
                                node.getAttribute("id"),
                                node.getAttribute("from") orelse "s.whatsapp.net",
                            );
                        } else if (std.mem.eql(u8, child.tag, "pair-success")) {
                            try self.handlePairSuccess(&node);
                            pair_sign_sent = true;
                        }
                    }
                }
                if (!handled) self.processNode(&node);
                continue;
            }
            self.processNode(&node);
        }
        return error.PairingTimeout;
    }

    fn emitQrCodes(self: *Client, pair_device_node: *const binary.Node) void {
        const b64 = std.base64.standard.Encoder;
        const children = pair_device_node.getContentNodes() orelse return;

        // Encode our keys as base64 (32 bytes → 44 base64 chars)
        var noise_b64: [44]u8 = undefined;
        _ = b64.encode(&noise_b64, &self.static_keypair.x25519_public);
        var identity_b64: [44]u8 = undefined;
        _ = b64.encode(&identity_b64, &self.identity.key_pair.public);
        var adv_b64: [44]u8 = undefined;
        _ = b64.encode(&adv_b64, &self.adv_secret_key);

        for (children) |*child| {
            if (std.mem.eql(u8, child.tag, "ref")) {
                if (child.getContentBytes()) |ref_bytes| {
                    // ref_bytes is already a UTF-8 string (e.g. "2@abc..."), NOT binary data
                    // QR format: ref_string,noise_pub_b64,identity_pub_b64,adv_secret_b64
                    const qr = std.fmt.allocPrint(self.allocator, "{s},{s},{s},{s}", .{
                        ref_bytes, &noise_b64, &identity_b64, &adv_b64,
                    }) catch continue;
                    defer self.allocator.free(qr);

                    self.emit(.{ .qr_code = .{ .code = qr } });
                }
            }
        }
    }

    fn handlePairSuccess(self: *Client, node: *const binary.Node) !void {
        const info = pair_mod.parsePairSuccess(node) orelse return error.InvalidPairSuccess;

        // Extract device ID from raw JID: "559980000001:33@s.whatsapp.net" → 33
        self.device_id = extractDeviceId(info.phone_jid);

        if (self.phone_jid) |old| self.allocator.free(old);
        self.phone_jid = try stripDeviceFromJid(self.allocator, info.phone_jid);
        if (self.lid) |old| self.allocator.free(old);
        self.lid = try stripDeviceFromJid(self.allocator, info.lid_jid);
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

        var response = try pair_mod.buildPairDeviceSignResponse(
            self.allocator,
            node.getAttribute("id") orelse "",
            pair_crypto.self_signed_identity_bytes,
            pair_crypto.key_index,
        );
        defer response.deinit();
        try self.sendNode(&response);
    }

    // --- Internal: Login ---

    fn readUntilLogin(self: *Client) !void {
        // Use 10s timeout per read — if server doesn't send success within
        // a reasonable time, we stop instead of hanging forever.
        var count: usize = 0;
        while (count < 30) : (count += 1) {
            var node = self.receiveNodeTimeout(10_000) catch break;
            defer node.deinit();

            if (std.mem.eql(u8, node.tag, "success")) {
                self.is_logged_in = true;
                if (node.getAttribute("lid")) |lid| {
                    if (self.lid) |old| self.allocator.free(old);
                    self.lid = self.allocator.dupe(u8, lid) catch null;
                }
                break;
            }

            if (std.mem.eql(u8, node.tag, "failure")) {
                for (node.attributes.items) |attr| {
                    log.err("Client", "  failure: {s}={s}", .{ attr.key, attr.value });
                }
                return error.LoginFailed;
            }

            self.processNode(&node);
        }
        if (!self.is_logged_in) {
            self.emit(.login_failed);
            return error.LoginFailed;
        }
    }

    // --- Internal: Message Loop ---

    fn runMessageLoop(self: *Client) void {
        while (true) {
            var node = self.receiveNode() catch {
                self.emit(.disconnected);
                return;
            };
            defer node.deinit();
            self.processNode(&node);
        }
    }

    // --- Internal: Node Processing ---

    fn processNode(self: *Client, node: *const binary.Node) void {
        const tag = node.tag;

        if (std.mem.eql(u8, tag, "iq")) {
            const iq_type = node.getAttribute("type") orelse return;
            if (std.mem.eql(u8, iq_type, "get")) {
                self.sendIqResult(node.getAttribute("id"), node.getAttribute("from") orelse "s.whatsapp.net");
            }
            return;
        }

        if (std.mem.eql(u8, tag, "message")) {
            const decrypted = self.decryptMessageNode(node);
            defer if (decrypted) |d| self.allocator.free(d);

            var body: ?[]const u8 = null;
            if (decrypted) |d| body = messaging.decodeTextMessage(d);

            // Store for waitForText
            if (self._last_msg_text) |old| self.allocator.free(old);
            self._last_msg_text = if (body) |b| self.allocator.dupe(u8, b) catch null else null;

            self.emit(.{ .message = .{
                .from = node.getAttribute("from") orelse "",
                .chat = node.getAttribute("from") orelse "",
                .id = node.getAttribute("id") orelse "",
                .node = node,
                .body = body,
            } });
        }

        if (node_handler.shouldAck(node)) {
            var ack = node_handler.buildAckNode(self.allocator, node) catch return;
            defer ack.deinit();
            self.sendNode(&ack) catch {};
        }
    }

    // --- Internal: Message Send ---

    fn sendEncrypted(self: *Client, to_jid: []const u8, text: []const u8, prekey_params: ?PreKeyMsgParams) !void {
        const session = self.findSession(to_jid) orelse return error.NoSession;
        const plaintext = try messaging.encodeTextMessage(self.allocator, text);
        defer self.allocator.free(plaintext);
        var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
        defer encrypted_msg.deinit(self.allocator);
        const signal_msg_bytes = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg);
        defer self.allocator.free(signal_msg_bytes);

        var ciphertext: []u8 = undefined;
        if (prekey_params) |pk| {
            ciphertext = try signal.message.serializePreKeySignalMessage(
                self.allocator,
                pk.registration_id,
                pk.prekey_id,
                pk.signed_prekey_id,
                pk.base_key,
                self.identity.key_pair.public,
                signal_msg_bytes,
            );
        } else {
            ciphertext = try self.allocator.dupe(u8, signal_msg_bytes);
        }
        defer self.allocator.free(ciphertext);

        const msg_id_arr = messaging.generateMessageId(self.io);
        var msg_node = try messaging.buildMessageNode(self.allocator, to_jid, &msg_id_arr, ciphertext, prekey_params != null);
        defer msg_node.deinit();
        try self.sendNode(&msg_node);
    }

    fn fetchPrekeys(self: *Client, jid: []const u8) !prekey_mod.PreKeyBundle {
        const iq_id = try self.nextIqId();
        defer self.allocator.free(iq_id);
        var fetch_iq = try messaging.buildFetchPrekeysIq(self.allocator, iq_id, &.{jid});
        defer fetch_iq.deinit();
        try self.sendNode(&fetch_iq);

        var attempts: usize = 0;
        while (attempts < 20) : (attempts += 1) {
            var node = try self.receiveNodeTimeout(5_000);
            if (std.mem.eql(u8, node.tag, "iq")) {
                const node_id = node.getAttribute("id") orelse "";
                if (std.mem.eql(u8, node_id, iq_id)) {
                    defer node.deinit();
                    return parsePreKeyResponse(&node);
                }
            }
            self.processNode(&node);
            node.deinit();
        }
        return error.PreKeyFetchTimeout;
    }

    fn createSession(self: *Client, jid: []const u8, bundle: prekey_mod.PreKeyBundle) !PreKeyMsgParams {
        const base_key = signal.KeyPair.generate(self.io);
        const x3dh_result = try signal.ratchet.x3dh(
            self.identity,
            base_key,
            bundle.identity_key,
            bundle.signed_prekey_public,
            bundle.prekey_public,
        );
        const session = try signal.Session.initAsInitiator(
            self.allocator,
            x3dh_result,
            self.identity.key_pair.public,
            bundle.identity_key,
            base_key,
            bundle.signed_prekey_public,
            self.registration_id,
            bundle.registration_id,
        );
        try self.storeSession(jid, session);
        return .{
            .registration_id = self.registration_id,
            .prekey_id = bundle.prekey_id,
            .signed_prekey_id = bundle.signed_prekey_id,
            .base_key = base_key.public,
        };
    }

    // --- Internal: Signal Decrypt ---

    fn decryptPreKeyMessage(self: *Client, from_jid: []const u8, ciphertext: []const u8) ![]u8 {
        const pkmsg = try signal.message.parsePreKeySignalMessage(ciphertext);

        // Look up our one-time prekey by ID
        var our_otpk: ?signal.KeyPair = null;
        if (pkmsg.prekey_id) |pk_id| {
            for (&self.prekeys) |*pk| {
                if (pk.id == pk_id) {
                    our_otpk = pk.key_pair;
                    break;
                }
            }
        }

        if (pkmsg.signed_prekey_id != self.signed_prekey.id) return error.SignedPreKeyMismatch;

        // X3DH as responder
        const x3dh_result = try signal.ratchet.x3dhResponder(
            self.identity,
            self.signed_prekey.key_pair,
            our_otpk,
            pkmsg.identity_key,
            pkmsg.base_key,
        );

        // Create responder session
        var session = signal.Session.initAsResponder(
            self.allocator,
            x3dh_result,
            self.identity.key_pair.public,
            pkmsg.identity_key,
            self.signed_prekey.key_pair,
            self.registration_id,
            pkmsg.registration_id,
        );

        // Decrypt inner SignalMessage
        const plaintext = try self.decryptSignalMessage(&session, pkmsg.signal_message, pkmsg.identity_key);

        // Store session for future messages from this sender
        self.storeSession(from_jid, session) catch {};

        return plaintext;
    }

    fn decryptSessionMessage(self: *Client, from_jid: []const u8, ciphertext: []const u8) ![]u8 {
        const session = self.findSession(from_jid) orelse return error.NoSession;
        return self.decryptSignalMessage(session, ciphertext, session.remote_identity_public);
    }

    fn decryptSignalMessage(self: *Client, session: *signal.Session, data: []const u8, sender_identity: [32]u8) ![]u8 {
        const parsed = try signal.message.parseSignalMessage(data);

        // Build EncryptedMessage for session.decrypt (mac_key unused in decrypt path)
        var enc_msg = signal.session.EncryptedMessage{
            .ratchet_key = parsed.ratchet_key,
            .counter = parsed.counter,
            .previous_counter = parsed.previous_counter,
            .ciphertext = @constCast(parsed.ciphertext),
            .sender_identity = sender_identity,
            .receiver_identity = self.identity.key_pair.public,
            .mac_key = undefined,
        };

        return session.decrypt(self.allocator, &enc_msg, self.io);
    }

    fn findSession(self: *Client, jid: []const u8) ?*signal.Session {
        for (self.sessions.items) |*entry| {
            if (std.mem.eql(u8, entry.jid, jid)) return &entry.session;
        }
        return null;
    }

    fn storeSession(self: *Client, jid: []const u8, session: signal.Session) !void {
        for (self.sessions.items) |*entry| {
            if (std.mem.eql(u8, entry.jid, jid)) {
                entry.session.deinit();
                entry.session = session;
                return;
            }
        }
        const jid_owned = try self.allocator.dupe(u8, jid);
        try self.sessions.append(self.allocator, .{ .jid = jid_owned, .session = session });
    }

    // --- Internal: Prekey Parsing ---

    fn parsePreKeyResponse(node: *const binary.Node) !prekey_mod.PreKeyBundle {
        const children = node.getContentNodes() orelse return error.EmptyPreKeyResponse;
        for (children) |*child| {
            if (std.mem.eql(u8, child.tag, "list")) {
                if (child.getContentNodes()) |list_children| {
                    for (list_children) |*user_child| {
                        if (std.mem.eql(u8, user_child.tag, "user"))
                            return prekey_mod.parsePreKeyBundle(user_child);
                    }
                }
            } else if (std.mem.eql(u8, child.tag, "user")) {
                return prekey_mod.parsePreKeyBundle(child);
            }
        }
        return error.NoPreKeyBundle;
    }

    // --- Internal: Helpers ---

    fn emit(self: *Client, event: Event) void {
        if (self.options.on_event) |handler| {
            handler(event, self.options.event_context orelse @ptrCast(self));
        }
    }

    fn sendActive(self: *Client) void {
        var active_node = binary.Node.init(self.allocator, "active") catch return;
        defer active_node.deinit();
        const id = self.sendIq("set", "passive", "s.whatsapp.net", &active_node) catch return;
        self.allocator.free(id);
    }

    fn sendIqResult(self: *Client, id: ?[]const u8, to: []const u8) void {
        var r = buildIqResultNode(self.allocator, id, to) catch return;
        defer r.deinit();
        self.sendNode(&r) catch {};
    }

    fn makeBasePayload(self: *const Client) whatsapp.ClientPayload {
        return .{
            .userAgent = self.makeUserAgent(),
            .webInfo = .{ .webSubPlatform = .WEB_BROWSER },
            .connectType = .WIFI_UNKNOWN,
            .connectReason = .USER_ACTIVATED,
        };
    }

    fn makeUserAgent(self: *const Client) whatsapp.ClientPayload.UserAgent {
        return .{
            .platform = .WEB,
            .releaseChannel = .RELEASE,
            .appVersion = .{
                .primary = self.app_version.primary,
                .secondary = self.app_version.secondary,
                .tertiary = self.app_version.tertiary,
            },
            .mcc = "000",
            .mnc = "000",
            .osVersion = "0.1.0",
            .manufacturer = "",
            .device = "Desktop",
            .osBuildNumber = "0.1.0",
            .localeLanguageIso6391 = "en",
            .localeCountryIso31661Alpha2 = "en",
        };
    }

    pub fn nextIqId(self: *Client) ![]u8 {
        const id = self.iq_counter;
        self.iq_counter += 1;
        return std.fmt.allocPrint(self.allocator, "{d}", .{id});
    }

    pub fn sendIq(self: *Client, iq_type: []const u8, xmlns: []const u8, to: []const u8, content: ?*const binary.Node) ![]u8 {
        const id = try self.nextIqId();
        errdefer self.allocator.free(id);
        var iq = try binary.Node.init(self.allocator, "iq");
        defer iq.deinit();
        try iq.addAttribute("id", id);
        try iq.addAttribute("type", iq_type);
        try iq.addAttribute("xmlns", xmlns);
        try iq.addAttribute("to", to);
        if (content) |child| try iq.addChild(@constCast(child));
        try self.sendNode(&iq);
        return id;
    }

    pub fn uploadPrekeys(self: *Client) !void {
        const id = try self.nextIqId();
        defer self.allocator.free(id);
        var iq = try prekey_mod.buildUploadIq(
            self.allocator,
            id,
            self.identity,
            self.signed_prekey,
            &self.prekeys,
            self.registration_id,
        );
        defer iq.deinit();
        try self.sendNode(&iq);
    }

    fn refreshAppVersion(self: *Client) void {
        const latest = fetchLatestAppVersion(self.allocator, self.io) catch |err| {
            log.warn("Client", "Failed to fetch latest WA version: {}. Using {d}.{d}.{d}", .{
                err,
                self.app_version.primary,
                self.app_version.secondary,
                self.app_version.tertiary,
            });
            return;
        };

        if (latest.tertiary != self.app_version.tertiary) {
            log.info("Client", "Using WA version {d}.{d}.{d}", .{
                latest.primary, latest.secondary, latest.tertiary,
            });
        } else {
            log.debug("Client", "Using WA version {d}.{d}.{d}", .{
                latest.primary, latest.secondary, latest.tertiary,
            });
        }
        self.app_version = latest;
    }

    pub fn receiveNode(self: *Client) !binary.Node {
        return self.receiveNodeTimeout(null);
    }

    /// Receive a node with timeout in milliseconds. null = no timeout.
    pub fn receiveNodeTimeout(self: *Client, timeout_ms: ?u32) !binary.Node {
        const ns = &(self.noise_socket orelse return error.NotConnected);
        const frame = try ns.receiveWithTimeout(&self.ws_client, timeout_ms);
        defer self.allocator.free(frame);
        const unpacked = try unpack(self.allocator, frame);
        defer self.allocator.free(unpacked);
        var reader = binary.BinaryReader.init(unpacked);
        const node = try binary.decodeNode(&reader, self.allocator);
        logNode("Client/Recv", &node);
        return node;
    }

    pub fn sendNode(self: *Client, node: *const binary.Node) !void {
        logNode("Client/Send", node);
        var encode_buf: [65536]u8 = undefined;
        var writer = binary.BinaryWriter.init(&encode_buf);
        _ = try binary.encodeNode(node, &writer);
        const encoded = writer.getWritten();
        const frame_data = try pack(self.allocator, encoded);
        defer self.allocator.free(frame_data);
        log.debug("Client/Send", "--> Sending {d} bytes", .{frame_data.len});
        const ns = &(self.noise_socket orelse return error.NotConnected);
        try ns.send(&self.ws_client, frame_data);
    }
};

/// Log a node in Rust-compatible format: <tag attr1="val1" attr2="val2"/>
fn logNode(comptime scope: []const u8, node: *const binary.Node) void {
    if (!log.enabled(.debug)) return;

    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    if (!appendFmt(&buf, &pos, "<{s}", .{node.tag})) return;
    for (node.attributes.items) |attr| {
        if (!appendFmt(&buf, &pos, " {s}=\"{s}\"", .{ attr.key, attr.value })) return;
    }

    if (node.getContentNodes()) |children| {
        if (!appendFmt(&buf, &pos, ">", .{})) return;
        for (children) |*child| {
            if (!appendFmt(&buf, &pos, "<{s}/>", .{child.tag})) return;
        }
        if (!appendFmt(&buf, &pos, "</{s}>", .{node.tag})) return;
    } else if (node.getContentBytes()) |bytes| {
        if (!appendFmt(&buf, &pos, "><!-- {d} bytes --></{s}>", .{ bytes.len, node.tag })) return;
    } else {
        if (!appendFmt(&buf, &pos, "/>", .{})) return;
    }

    log.debug(scope, "{s}", .{buf[0..pos]});
}

fn appendFmt(buf: []u8, pos: *usize, comptime fmt: []const u8, args: anytype) bool {
    const written = std.fmt.bufPrint(buf[pos.*..], fmt, args) catch {
        if (pos.* + 15 <= buf.len) {
            @memcpy(buf[pos.* .. pos.* + 15], " ...<truncated>");
            pos.* += 15;
            return true;
        }
        return false;
    };
    pos.* += written.len;
    return true;
}

/// Extract device ID from JID: "559980000001:33@s.whatsapp.net" → 33, default 0
fn extractDeviceId(jid: []const u8) u32 {
    const colon = std.mem.indexOf(u8, jid, ":") orelse return 0;
    const at = std.mem.indexOf(u8, jid, "@") orelse return 0;
    if (colon >= at) return 0;
    return std.fmt.parseInt(u32, jid[colon + 1 .. at], 10) catch 0;
}

fn stripDeviceFromJid(allocator: std.mem.Allocator, jid: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, jid, ":")) |colon| {
        if (std.mem.indexOf(u8, jid, "@")) |at| {
            return std.fmt.allocPrint(allocator, "{s}{s}", .{ jid[0..colon], jid[at..] });
        }
    }
    return allocator.dupe(u8, jid);
}

fn buildIqResultNode(
    allocator: std.mem.Allocator,
    id: ?[]const u8,
    to: []const u8,
) !binary.Node {
    var node = try binary.Node.init(allocator, "iq");
    errdefer node.deinit();

    // Match the Rust reference exactly: to, id, type.
    try node.addAttribute("to", to);
    if (id) |iq_id| try node.addAttribute("id", iq_id);
    try node.addAttribute("type", "result");

    return node;
}

fn shortHex(bytes: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    for (bytes, 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    }
    return out;
}

fn allocHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    }
    return out;
}

fn fetchLatestAppVersion(allocator: std.mem.Allocator, io: std.Io) !Client.AppVersion {
    var http_client = http.Client{
        .allocator = allocator,
        .io = io,
    };
    defer http_client.deinit();

    const uri = try std.Uri.parse("https://web.whatsapp.com/sw.js");
    var req = try http_client.request(.GET, uri, .{
        .headers = .{},
        .extra_headers = &.{
            .{ .name = "sec-fetch-site", .value = "none" },
            .{ .name = "user-agent", .value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [0]u8 = .{};
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.VersionFetchFailed;

    var body_writer = std.Io.Writer.Allocating.init(allocator);
    defer body_writer.deinit();
    var transfer_buf: [4096]u8 = undefined;
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: http.Decompress = undefined;
    var body_reader = response.readerDecompressing(&transfer_buf, &decompress, &decompress_buf);
    _ = try body_reader.streamRemaining(&body_writer.writer);

    return parseSwJs(body_writer.written()) orelse error.VersionParseFailed;
}

fn parseSwJs(body: []const u8) ?Client.AppVersion {
    const key = "client_revision";
    const assets_key = "assets-manifest-";

    if (std.mem.indexOf(u8, body, key)) |start_index| {
        const suffix = body[start_index + key.len ..];
        var first_digit_index: ?usize = null;
        for (suffix, 0..) |c, i| {
            if (c >= '0' and c <= '9') {
                first_digit_index = i;
                break;
            }
        }
        if (first_digit_index) |digit_idx| {
            const number_slice = suffix[digit_idx..];
            var end_idx: usize = number_slice.len;
            for (number_slice, 0..) |c, i| {
                if (c < '0' or c > '9') {
                    end_idx = i;
                    break;
                }
            }
            const version_str = number_slice[0..end_idx];
            const revision = std.fmt.parseInt(u32, version_str, 10) catch return null;
            return .{ .tertiary = revision };
        }
    }

    if (std.mem.indexOf(u8, body, assets_key)) |_| return .{ .tertiary = 0 };

    return null;
}

pub fn unpack(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) return error.EmptyFrame;
    if ((data[0] & 2) != 0) return zlibDecompress(allocator, data[1..]);
    return allocator.dupe(u8, data[1..]);
}

pub fn pack(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, 1 + data.len);
    result[0] = 0;
    @memcpy(result[1..], data);
    return result;
}

fn zlibDecompress(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    const flate = std.compress.flate;
    var input_reader: std.Io.Reader = .fixed(compressed);
    var window_buf: [flate.max_window_len]u8 = undefined;
    var decompressor = flate.Decompress.init(&input_reader, .zlib, &window_buf);
    var result = std.ArrayList(u8).empty;
    errdefer result.deinit(allocator);
    while (true) {
        const chunk = decompressor.reader.peek(1) catch |err| switch (err) {
            error.ReadFailed => {
                if (decompressor.err) |e| return e;
                break;
            },
            else => return err,
        };
        if (chunk.len == 0) break;
        try result.appendSlice(allocator, chunk);
        decompressor.reader.toss(chunk.len);
    }
    return result.toOwnedSlice(allocator);
}

test "iq result encoding matches Rust wire order" {
    const allocator = std.testing.allocator;

    var node = try buildIqResultNode(allocator, "3610797473", "s.whatsapp.net");
    defer node.deinit();

    var buf: [64]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buf);
    _ = try binary.encodeNode(&node, &writer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xf8, 0x07, 0x19,
        0x11, 0x03, 0x08,
        0xff, 0x05, 0x36,
        0x10, 0x79, 0x74,
        0x73, 0x04, 0x14,
    }, writer.getWritten());
}

test "pairing payload keeps rust-compatible device props" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var client = try Client.init(allocator, io, .{});
    defer client.deinit();
    client.app_version = .{
        .primary = 2,
        .secondary = 3000,
        .tertiary = 1037005288,
    };

    const payload_bytes = try client.buildPairingPayload();
    defer allocator.free(payload_bytes);

    var payload_reader: std.Io.Reader = .fixed(payload_bytes);
    var payload = try whatsapp.ClientPayload.decode(&payload_reader, allocator);
    defer payload.deinit(allocator);

    const encoded_device_props = payload.devicePairingData.?.deviceProps orelse return error.TestUnexpectedResult;
    var device_props_reader: std.Io.Reader = .fixed(encoded_device_props);
    var device_props = try whatsapp.DeviceProps.decode(&device_props_reader, allocator);
    defer device_props.deinit(allocator);

    try std.testing.expectEqualStrings("rust", device_props.os orelse "");
}
