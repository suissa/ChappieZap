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

    const AppVersion = struct {
        primary: u32 = 2,
        secondary: u32 = 3000,
        tertiary: u32 = 1037005288,
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
        if (self.lid) |lid| self.allocator.free(lid);
        if (self.phone_jid) |pj| self.allocator.free(pj);
        if (self.noise_socket) |*ns| ns.deinit();
        self.ws_client.deinit();
    }

    // --- Public API ---

    /// Full connection flow: pair → reconnect → login → prekeys → event loop.
    /// Blocks until disconnected. Dispatches events to the handler.
    pub fn connectAndRun(self: *Client) !void {
        // Phase 1: Pairing (first connection)
        try self.connectWithPayload(.pairing);
        try self.handlePairingFlow();

        // Phase 2: Reconnect as returning login
        try self.connectWithPayload(.login);
        try self.readUntilLogin();

        self.emit(.{ .connected = .{
            .phone_jid = self.phone_jid orelse "",
            .lid = self.lid orelse "",
        } });

        // Phase 3: Post-login setup
        self.sendActive();
        self.uploadPrekeys() catch {};

        // Phase 4: Message loop (blocks forever)
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

    /// Send a text message to a JID.
    pub fn sendText(self: *Client, to: []const u8, text: []const u8) !void {
        const plaintext = try messaging.encodeTextMessage(self.allocator, text);
        defer self.allocator.free(plaintext);

        // For now, send unencrypted (mock server doesn't validate)
        // TODO: proper Signal encryption with session management
        const msg_id_arr = messaging.generateMessageId(self.io);
        var msg_node = try messaging.buildMessageNode(self.allocator, to, &msg_id_arr, plaintext, false);
        defer msg_node.deinit();
        try self.sendNode(&msg_node);
    }

    /// Send a text message with Signal encryption.
    pub fn sendTextMessage(
        self: *Client,
        session: *signal.Session,
        to_jid: []const u8,
        text: []const u8,
        is_prekey_msg: bool,
    ) !void {
        const plaintext = try messaging.encodeTextMessage(self.allocator, text);
        defer self.allocator.free(plaintext);
        var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
        defer encrypted_msg.deinit(self.allocator);
        const signal_msg_bytes = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg);
        defer self.allocator.free(signal_msg_bytes);

        var ciphertext: []u8 = undefined;
        if (is_prekey_msg) {
            ciphertext = try signal.message.serializePreKeySignalMessage(
                self.allocator,
                self.registration_id,
                self.prekeys[0].id,
                self.signed_prekey.id,
                self.identity.key_pair.public,
                self.identity.key_pair.public,
                signal_msg_bytes,
            );
        } else {
            ciphertext = try self.allocator.dupe(u8, signal_msg_bytes);
        }
        defer self.allocator.free(ciphertext);

        const msg_id_arr = messaging.generateMessageId(self.io);
        var msg_node = try messaging.buildMessageNode(self.allocator, to_jid, &msg_id_arr, ciphertext, is_prekey_msg);
        defer msg_node.deinit();
        try self.sendNode(&msg_node);
    }

    pub fn isConnected(self: *const Client) bool {
        return self.noise_socket != null and self.is_logged_in;
    }

    /// Wait for a message node (for tests). Processes other nodes.
    /// Wait for an incoming message, processing other nodes.
    /// timeout_ms per read attempt. max_attempts total reads.
    pub fn waitForMessage(self: *Client, max_attempts: usize) !binary.Node {
        return self.waitForMessageTimeout(max_attempts, 30_000);
    }

    pub fn waitForMessageTimeout(self: *Client, max_attempts: usize, timeout_ms: u32) !binary.Node {
        var attempts: usize = 0;
        while (attempts < max_attempts) : (attempts += 1) {
            var node = self.receiveNodeTimeout(timeout_ms) catch |err| {
                // Timeout just means no data yet — keep trying
                if (attempts + 1 < max_attempts) continue;
                return err;
            };
            if (std.mem.eql(u8, node.tag, "message")) return node;
            self.processNode(&node);
            node.deinit();
        }
        return error.MessageTimeout;
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
            self.allocator,
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
        const device_props = whatsapp.DeviceProps{
            // Match the Rust reference exactly. This field alone accounts for the
            // 1-byte ClientFinish delta seen against the real server.
            .os = "rust",
            .version = .{ .primary = 0, .secondary = 1, .tertiary = 0 },
            .platformType = .UNKNOWN,
            .requireFullSync = true,
            .historySyncConfig = .{
                .fullSyncDaysLimit = 30,
                .inlineInitialPayloadInE2EeMsg = true,
                .storageQuotaMb = 10240,
                .supportMessageAssociation = true,
            },
        };
        var dp_writer = std.Io.Writer.Allocating.init(self.allocator);
        defer dp_writer.deinit();
        try device_props.encode(&dp_writer.writer, self.allocator);
        const dp_bytes = dp_writer.written();
        const dp_owned = try self.allocator.dupe(u8, dp_bytes);
        defer self.allocator.free(dp_owned);

        var payload = whatsapp.ClientPayload{
            .passive = false,
            .pull = false,
            .userAgent = .{
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
            },
            .webInfo = .{ .webSubPlatform = .WEB_BROWSER },
            .connectType = .WIFI_UNKNOWN,
            .connectReason = .USER_ACTIVATED,
            .devicePairingData = .{
                .eRegid = &pd.e_regid,
                .eKeytype = &pd.e_keytype,
                .eIdent = &pd.e_ident,
                .eSkeyId = &pd.e_skey_id,
                .eSkeyVal = &pd.e_skey_val,
                .eSkeySig = &pd.e_skey_sig,
                .buildHash = &pd.build_hash,
                .deviceProps = dp_owned,
            },
        };
        _ = &payload;

        var writer = std.Io.Writer.Allocating.init(self.allocator);
        defer writer.deinit();
        try payload.encode(&writer.writer, self.allocator);
        return self.allocator.dupe(u8, writer.written());
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

        var payload = whatsapp.ClientPayload{
            .passive = true, // returning login is passive
            .username = username,
            .device = self.device_id,
            .userAgent = .{
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
            },
            .webInfo = .{ .webSubPlatform = .WEB_BROWSER },
            .connectType = .WIFI_UNKNOWN,
            .connectReason = .USER_ACTIVATED,
        };
        _ = &payload;

        var writer = std.Io.Writer.Allocating.init(self.allocator);
        defer writer.deinit();
        try payload.encode(&writer.writer, self.allocator);
        return self.allocator.dupe(u8, writer.written());
    }

    // --- Internal: Pairing ---

    fn handlePairingFlow(self: *Client) !void {
        log.info("Client", "Waiting for pairing...", .{});
        var count: usize = 0;
        while (count < 30) : (count += 1) {
            var node = try self.receiveNode();
            defer node.deinit();
            if (std.mem.eql(u8, node.tag, "failure")) {
                logNode("Client/Pair", &node);
                return error.ServerRejected;
            }

            // Log stream:error details
            if (std.mem.eql(u8, node.tag, "stream:error")) {
                for (node.attributes.items) |attr| {
                    log.warn("Client/Pair", "  stream:error {s}={s}", .{ attr.key, attr.value });
                }
                // 515 = expected reconnect after pair-device-sign completed
                if (node.getAttribute("code")) |code| {
                    if (std.mem.eql(u8, code, "515")) return;
                }
                // Other codes = server kicked us (QR timeout, etc.)
                return error.StreamError;
            }

            if (std.mem.eql(u8, node.tag, "iq")) {
                if (node.getContentNodes()) |children| {
                    for (children) |*child| {
                        if (std.mem.eql(u8, child.tag, "pair-device")) {
                            // Emit QR code event
                            self.emitQrCodes(child);
                            // The real server accepts the IQ result only when it matches
                            // the Rust wire format, including attribute order: to, id, type.
                            self.sendIqResult(
                                node.getAttribute("id"),
                                node.getAttribute("from") orelse "s.whatsapp.net",
                            );
                        } else if (std.mem.eql(u8, child.tag, "pair-success")) {
                            try self.handlePairSuccess(&node);
                            return;
                        }
                    }
                }
            }
            if (std.mem.eql(u8, node.tag, "stream:error")) return;
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

        // Read until stream:error 515
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            var next = self.receiveNode() catch return;
            defer next.deinit();
            if (std.mem.eql(u8, next.tag, "stream:error")) return;
        }
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
            self.emit(.{ .message = .{
                .from = node.getAttribute("from") orelse "",
                .chat = node.getAttribute("from") orelse "",
                .id = node.getAttribute("id") orelse "",
                .node = node,
            } });
        }

        if (node_handler.shouldAck(node)) {
            var ack = node_handler.buildAckNode(self.allocator, node) catch return;
            defer ack.deinit();
            self.sendNode(&ack) catch {};
        }
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
