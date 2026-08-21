const std = @import("std");
const ws = @import("websocket_client");
const xed25519 = @import("xed25519");
const socket_mod = @import("socket");
const binary = @import("binary");
const signal = @import("signal");
const messaging = @import("messaging");
const events = @import("events");
const addressing = @import("addressing");
const auth_flow = @import("client/auth.zig");
const payloads_mod = @import("client/client_payloads.zig");
const event_pump = @import("client/pump.zig");
const prekey_flow = @import("client/prekeys.zig");
const bootstrap = @import("client/bootstrap.zig");
const stanza_processor = @import("client/stanza_processor.zig");
const send_fanout = @import("client/send_fanout.zig");
const session_store = @import("client/session_store.zig");
const wire_transport = @import("client/transport.zig");
const log = @import("log");

pub const Event = events.Event;
pub const EventHandler = events.EventHandler;
pub const auth = auth_flow;
pub const payloads = payloads_mod;
pub const transport = wire_transport;

pub const ClientOptions = struct {
    host: []const u8 = "web.whatsapp.com",
    port: u16 = 443,
    tls: bool = true,
    tls_ca_cert_path: ?[]const u8 = null,
    path: []const u8 = "/ws/chat",
    push_name: []const u8 = "whatszig",
    pairing_phone_number: ?[]const u8 = null,
    experimental_post_login_init: bool = false,
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
    request_id_prefix_len: u8 = 0,
    request_id_prefix: [24]u8 = [_]u8{0} ** 24,
    is_logged_in: bool = false,
    address_book: addressing.AddressBook,
    lid: ?[]u8 = null,
    phone_jid: ?[]u8 = null, // "559980000001@s.whatsapp.net"
    device_id: u32 = 0, // companion device ID from pairing (e.g. 33)

    // Pair code state
    pair_code_ephemeral: ?std.crypto.dh.X25519.KeyPair = null,
    pair_code_str: ?[8]u8 = null,
    pair_code_ref: ?[]u8 = null,
    pair_code_phone: ?[]u8 = null,

    identity: signal.IdentityKeyPair,
    signed_prekey: signal.SignedPreKey,
    prekeys: [10]signal.PreKey,
    registration_id: u32,
    adv_secret_key: [32]u8,
    app_version: AppVersion = .{},
    account_device_identity: ?[]u8 = null,
    session_shards: [session_store.session_shard_count]session_store.SessionShard,
    send_text_buf: std.ArrayList(u8),
    send_text_aux_buf: std.ArrayList(u8),
    send_pack_buf: std.ArrayList(u8),
    recv_unpack_buf: std.ArrayList(u8),
    last_data_sent_at: std.Io.Timestamp = .zero,
    last_data_received_at: std.Io.Timestamp = .zero,
    server_time_offset_ms: i64 = 0,

    const AppVersion = struct {
        primary: u32 = 2,
        secondary: u32 = 3000,
        tertiary: u32 = 1037005288,
    };

    /// Parameters for the PreKeySignalMessage wrapper.
    pub const PreKeyMsgParams = struct {
        registration_id: u32,
        prekey_id: ?u32,
        signed_prekey_id: u32,
        base_key: [32]u8,
    };

    pub const MessageWait = struct {
        from: ?[]const u8 = null,
        chat: ?[]const u8 = null,
        id: ?[]const u8 = null,
        body_equals: ?[]const u8 = null,
        body_contains: ?[]const u8 = null,
        require_decrypted: ?bool = null,

        pub fn matchesNode(self: MessageWait, client: *const Client, node: *const binary.Node, body: ?[]const u8) bool {
            if (self.from) |expected| {
                const actual = node.getAttribute("from") orelse return false;
                if (!std.mem.eql(u8, actual, expected)) return false;
            }
            if (self.chat) |expected| {
                const actual = stanza_processor.messageChatJidForMatch(client, node);
                if (!std.mem.eql(u8, actual, expected)) return false;
            }
            if (self.id) |expected| {
                const actual = node.getAttribute("id") orelse return false;
                if (!std.mem.eql(u8, actual, expected)) return false;
            }
            if (self.body_equals) |expected| {
                const actual = body orelse return false;
                if (!std.mem.eql(u8, actual, expected)) return false;
            }
            if (self.body_contains) |expected| {
                const actual = body orelse return false;
                if (std.mem.indexOf(u8, actual, expected) == null) return false;
            }
            if (self.require_decrypted) |expected| {
                if ((body != null) != expected) return false;
            }
            return true;
        }
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: ClientOptions) !Client {
        const identity = signal.IdentityKeyPair.generate(io);
        const signed_pk = signal.SignedPreKey.generate(1, identity, io);
        var prekeys: [10]signal.PreKey = undefined;
        for (0..10) |i| prekeys[i] = signal.PreKey.generate(@intCast(i + 1), io);

        var adv_secret: [32]u8 = undefined;
        io.random(&adv_secret);
        var request_prefix_words: [2]u32 = undefined;
        io.random(std.mem.asBytes(&request_prefix_words));
        var request_id_prefix: [24]u8 = undefined;
        const request_id_prefix_slice = try std.fmt.bufPrint(&request_id_prefix, "{d}", .{
            request_prefix_words[0],
        });
        const address_book = addressing.AddressBook.init(allocator);

        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .ws_client = try ws.WebSocketClient.init(allocator, io),
            .address_book = address_book,
            .static_keypair = xed25519.XEd25519.KeyPair.generate(io),
            .request_id_prefix_len = @intCast(request_id_prefix_slice.len),
            .request_id_prefix = request_id_prefix,
            .identity = identity,
            .signed_prekey = signed_pk,
            .prekeys = prekeys,
            .registration_id = signal.keys.generateRegistrationId(io),
            .adv_secret_key = adv_secret,
            .session_shards = session_store.initSessionShards(allocator),
            .send_text_buf = .empty,
            .send_text_aux_buf = .empty,
            .send_pack_buf = .empty,
            .recv_unpack_buf = .empty,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.pair_code_phone) |p| self.allocator.free(p);
        if (self.pair_code_ref) |ref| self.allocator.free(ref);
        if (self.account_device_identity) |bytes| self.allocator.free(bytes);
        session_store.deinitSessionShards(&self.session_shards, self.allocator);
        self.send_text_buf.deinit(self.allocator);
        self.send_text_aux_buf.deinit(self.allocator);
        self.send_pack_buf.deinit(self.allocator);
        self.recv_unpack_buf.deinit(self.allocator);
        self.address_book.deinit();
        if (self.noise_socket) |*ns| ns.deinit();
        self.ws_client.deinit();
    }

    fn runExperimentalPostLoginBootstrap(self: *Client) void {
        if (!self.options.experimental_post_login_init) return;

        wire_transport.sendUnifiedSession(self) catch |err| {
            log.warn("Client", "Experimental post-login unified session failed: {}", .{err});
        };
        if (self.options.tls) {
            bootstrap.syncOwnDeviceList(self) catch |err| {
                log.warn("Client", "Experimental own-device sync failed: {}", .{err});
            };
        }
    }

    fn runExperimentalPostLoginPresence(self: *Client) void {
        if (!self.options.experimental_post_login_init) return;

        wire_transport.sendPresenceAvailable(self) catch |err| {
            log.warn("Client", "Experimental presence available failed: {}", .{err});
        };
    }

    // --- Public API ---

    /// Full connection flow: pair → reconnect → login → prekeys → event loop.
    /// Blocks until disconnected. Dispatches events to the handler.
    pub fn connectAndRun(self: *Client) !void {
        try wire_transport.connectWithPayload(self, .pairing);
        try auth_flow.handlePairingFlow(self);
        try wire_transport.connectWithPayload(self, .login);
        try auth_flow.readUntilLogin(self);
        self.runExperimentalPostLoginBootstrap();
        wire_transport.uploadPrekeysAndWait(self, 10_000) catch |err| {
            log.warn("Client", "Post-login prekey upload did not confirm: {}", .{err});
        };
        wire_transport.sendActiveAndWait(self, 10_000) catch |err| {
            log.warn("Client", "Post-login active IQ did not confirm: {}", .{err});
        };
        self.runExperimentalPostLoginPresence();

        self.emit(.{ .connected = .{
            .phone_jid = self.phone_jid orelse "",
            .lid = self.lid orelse "",
        } });

        event_pump.runMessageLoop(self);
    }

    /// Connect, pair, login, upload prekeys. Does NOT start message loop.
    /// Use this for tests where you want manual control.
    pub fn connectAndLogin(self: *Client) !void {
        try wire_transport.connectWithPayload(self, .pairing);
        try auth_flow.handlePairingFlow(self);
        try wire_transport.connectWithPayload(self, .login);
        try auth_flow.readUntilLogin(self);
        self.runExperimentalPostLoginBootstrap();
        wire_transport.uploadPrekeysAndWait(self, 10_000) catch |err| {
            log.warn("Client", "Post-login prekey upload did not confirm: {}", .{err});
        };
        wire_transport.sendActiveAndWait(self, 10_000) catch |err| {
            log.warn("Client", "Post-login active IQ did not confirm: {}", .{err});
        };
        self.runExperimentalPostLoginPresence();
    }

    /// Send a text message to a JID. Handles session management automatically:
    /// fetches prekeys and establishes a session if needed, then encrypts and sends.
    pub fn sendMessage(self: *Client, to_jid: []const u8, text: []const u8) !void {
        if (self.address_book.isSelfChatJid(to_jid) and self.address_book.ownDeviceCount() != 0) {
            return send_fanout.sendSelfChatFanout(self, to_jid, text);
        }
        return send_fanout.sendDirectMessageFanout(self, to_jid, text);
    }

    /// Send a direct text message through a single-recipient path.
    /// This avoids fanout/reporting overhead and is intended for hot reply paths.
    pub fn sendMessageFast(self: *Client, to_jid: []const u8, text: []const u8) !void {
        if (self.address_book.isSelfChatJid(to_jid) or std.mem.endsWith(u8, to_jid, "@g.us")) {
            return self.sendMessage(to_jid, text);
        }
        return send_fanout.sendDirectMessageSingle(self, to_jid, text);
    }

    /// Wait for an incoming message containing the expected text.
    /// Reads and processes nodes until the text matches or timeout.
    pub fn waitForText(self: *Client, expected: []const u8, timeout_ms: u32) !void {
        return event_pump.waitForMessage(self, .{ .body_equals = expected }, timeout_ms);
    }

    /// Wait for an incoming message whose decrypted body contains `expected`.
    pub fn waitForTextContains(self: *Client, expected: []const u8, timeout_ms: u32) !void {
        return event_pump.waitForMessage(self, .{ .body_contains = expected }, timeout_ms);
    }

    /// Wait for any incoming message whose `from` attribute matches `expected_from`.
    pub fn waitForMessageFrom(self: *Client, expected_from: []const u8, timeout_ms: u32) !void {
        return event_pump.waitForMessage(self, .{ .from = expected_from }, timeout_ms);
    }

    pub fn waitForMessage(self: *Client, expected: MessageWait, timeout_ms: u32) !void {
        return event_pump.waitForMessage(self, expected, timeout_ms);
    }

    pub fn waitForReceiptFrom(self: *Client, expected_from: []const u8, timeout_ms: u32) !void {
        return event_pump.waitForReceiptFrom(self, expected_from, timeout_ms);
    }

    pub fn isConnected(self: *const Client) bool {
        return self.noise_socket != null and self.is_logged_in;
    }

    // --- Internal: Pairing ---

    pub fn processNode(self: *Client, node: *const binary.Node) void {
        stanza_processor.processNode(self, node);
    }

    // --- Internal: Message Send ---

    pub fn sendEncrypted(
        self: *Client,
        chat_jid: []const u8,
        encryption_jid: []const u8,
        text: []const u8,
        prekey_params: ?PreKeyMsgParams,
    ) !void {
        var locked = try session_store.lockSession(self, encryption_jid);
        defer locked.unlock();
        const session = locked.get() orelse return error.NoSession;
        const plaintext = if (self.address_book.isSelfChatJid(chat_jid))
            try messaging.encodeDeviceSentTextMessageInto(&self.send_text_buf, self.allocator, chat_jid, text)
        else
            try messaging.encodeTextMessageInto(&self.send_text_buf, self.allocator, text);
        var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
        defer encrypted_msg.deinit(self.allocator);
        const ciphertext = if (prekey_params) |pk| blk: {
            const signal_msg_bytes = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg);
            defer self.allocator.free(signal_msg_bytes);
            break :blk try signal.message.serializePreKeySignalMessage(
                self.allocator,
                pk.registration_id,
                pk.prekey_id,
                pk.signed_prekey_id,
                pk.base_key,
                self.identity.key_pair.public,
                signal_msg_bytes,
            );
        } else try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg);
        defer self.allocator.free(ciphertext);

        const msg_id_arr = messaging.generateMessageId(self.io);
        var msg_node = try messaging.buildMessageNode(
            self.allocator,
            chat_jid,
            encryption_jid,
            &msg_id_arr,
            ciphertext,
            prekey_params != null,
            if (prekey_params != null) self.account_device_identity else null,
        );
        defer msg_node.deinit();
        try wire_transport.sendNode(self, &msg_node);
    }

    // --- Internal: Helpers ---

    pub fn emit(self: *Client, event: Event) void {
        if (self.options.on_event) |handler| {
            handler(event, self.options.event_context orelse @ptrCast(self));
        }
    }

    const PumpResult = event_pump.PumpResult;
};
