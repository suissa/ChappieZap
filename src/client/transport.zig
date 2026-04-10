const std = @import("std");
const ws = @import("websocket_client");
const socket_mod = @import("socket");
const binary = @import("binary");
const handshake_mod = @import("handshake");
const prekey_mod = @import("prekey");
const frame_codec = @import("frame_codec.zig");
const payloads_mod = @import("client_payloads.zig");
const stanza_encode = @import("stanza_encode");
const stanza_log = @import("stanza_log.zig");
const unified_session = @import("unified_session.zig");
const web_version = @import("web_version.zig");
const log = @import("log");

pub const ConnectionMode = enum { pairing, login };
pub const iq_id_buffer_len = 48;

pub fn connectWithPayload(self: anytype, mode: ConnectionMode) !void {
    log.info("Client", "Connecting to {s}:{d} (mode={s})...", .{
        self.options.host,
        self.options.port,
        if (mode == .pairing) "pairing" else "login",
    });

    web_version.refreshAppVersion(self, @TypeOf(self.app_version));

    if (self.noise_socket) |*ns| ns.deinit();
    self.noise_socket = null;
    self.ws_client.closeConnection();
    self.is_logged_in = false;
    self.last_data_sent_at = .zero;
    self.last_data_received_at = .zero;

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
        .pairing => try payloads_mod.buildPairingPayload(self),
        .login => try payloads_mod.buildLoginPayload(self),
    };
    defer self.allocator.free(payload);
    log.debug("Client", "ClientPayload built ({d} bytes, mode={s})", .{
        payload.len,
        if (mode == .pairing) "pairing" else "login",
    });

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

pub fn sendActive(self: anytype) void {
    var id_buf: [iq_id_buffer_len]u8 = undefined;
    const id = nextIqIdInto(self, &id_buf) catch return;
    sendActiveWithId(self, id) catch {};
}

pub fn sendActiveAndWait(self: anytype, timeout_ms: u32) !void {
    var id_buf: [iq_id_buffer_len]u8 = undefined;
    const id = try nextIqIdInto(self, &id_buf);
    try sendActiveWithId(self, id);
    try waitForIqResult(self, id, timeout_ms, error.ActiveIqTimeout);
}

pub fn sendKeepalive(self: anytype) void {
    var id_buf: [iq_id_buffer_len]u8 = undefined;
    const id = nextIqIdInto(self, &id_buf) catch return;
    sendKeepaliveWithId(self, id) catch {};
}

pub fn sendPresenceAvailable(self: anytype) !void {
    if (self.options.push_name.len == 0) return;

    var presence = binary.Node.initBorrowed(self.allocator, "presence");
    defer presence.deinit();
    try presence.addAttributeBorrowed("type", "available");
    try presence.addAttributeBorrowed("name", self.options.push_name);
    try sendNode(self, &presence);
}

pub fn sendKeepaliveInto(self: anytype, buf: []u8) ![]const u8 {
    const id = try nextIqIdInto(self, buf);
    try sendKeepaliveWithId(self, id);
    return id;
}

pub fn sendUnifiedSession(self: anytype) !void {
    var node = try unified_session.buildNode(
        self.allocator,
        self.server_time_offset_ms,
        unified_session.nowMillis(self.io),
    );
    defer node.deinit();
    try sendNode(self, &node);
}

pub fn sendIqResult(self: anytype, id: ?[]const u8, to: []const u8) void {
    sendIqResultDirect(self, id, to) catch {};
}

pub fn nextIqId(self: anytype) ![]u8 {
    var buf: [iq_id_buffer_len]u8 = undefined;
    const id = try nextIqIdInto(self, &buf);
    return self.allocator.dupe(u8, id);
}

pub fn nextIqIdInto(self: anytype, buf: []u8) ![]const u8 {
    const id = self.iq_counter;
    self.iq_counter += 1;
    return std.fmt.bufPrint(buf, "{d}", .{id});
}

pub fn sendIq(self: anytype, iq_type: []const u8, xmlns: []const u8, to: []const u8, content: ?*const binary.Node) ![]u8 {
    const id = try nextIqId(self);
    errdefer self.allocator.free(id);
    var iq = binary.Node.initBorrowed(self.allocator, "iq");
    defer iq.deinit();
    try iq.addAttributeBorrowed("id", id);
    try iq.addAttributeBorrowed("type", iq_type);
    try iq.addAttributeBorrowed("xmlns", xmlns);
    try iq.addAttributeBorrowed("to", to);
    if (content) |child| try iq.addChild(@constCast(child));
    try sendNode(self, &iq);
    return id;
}

pub fn uploadPrekeys(self: anytype) !void {
    var id_buf: [iq_id_buffer_len]u8 = undefined;
    const id = try nextIqIdInto(self, &id_buf);
    var iq = try prekey_mod.buildUploadIq(
        self.allocator,
        id,
        self.identity,
        self.signed_prekey,
        &self.prekeys,
        self.registration_id,
    );
    defer iq.deinit();
    try sendNode(self, &iq);
}

pub fn uploadPrekeysAndWait(self: anytype, timeout_ms: u32) !void {
    var id_buf: [iq_id_buffer_len]u8 = undefined;
    const id = try nextIqIdInto(self, &id_buf);
    const wait_id = id;

    var iq = try prekey_mod.buildUploadIq(
        self.allocator,
        id,
        self.identity,
        self.signed_prekey,
        &self.prekeys,
        self.registration_id,
    );
    defer iq.deinit();
    try sendNode(self, &iq);
    try waitForIqResult(self, wait_id, timeout_ms, error.PreKeyUploadTimeout);
}

fn waitForIqResult(
    self: anytype,
    expected_id: []const u8,
    timeout_ms: u32,
    timeout_err: anyerror,
) !void {
    const start = std.Io.Clock.awake.now(self.io);
    while (true) {
        const elapsed_ms = start.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
        if (elapsed_ms >= timeout_ms) return timeout_err;
        const remaining_ms: u32 = @intCast(timeout_ms - elapsed_ms);

        var node = receiveNodeTimeout(self, remaining_ms) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        defer node.deinit();

        if (std.mem.eql(u8, node.tag, "iq")) {
            const node_id = node.getAttribute("id") orelse "";
            const iq_type = node.getAttribute("type") orelse "";
            if (stanza_log.iqIdsMatch(node_id, expected_id) and std.mem.eql(u8, iq_type, "result")) {
                return;
            }
        }

        self.processNode(&node);
    }
}

pub fn receiveNode(self: anytype) !binary.Node {
    return receiveNodeTimeout(self, null);
}

pub fn receiveNodeTimeout(self: anytype, timeout_ms: ?u32) !binary.Node {
    const ns = &(self.noise_socket orelse return error.NotConnected);
    const start = if (timeout_ms != null) std.Io.Clock.awake.now(self.io) else null;

    while (true) {
        const remaining_ms = if (timeout_ms) |limit_ms| blk: {
            const elapsed_ms = start.?.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
            if (elapsed_ms >= limit_ms) return error.Timeout;
            break :blk @as(u32, @intCast(limit_ms - elapsed_ms));
        } else null;

        const frame = ns.receiveWithTimeoutBorrowed(&self.ws_client, remaining_ms) catch |err| switch (err) {
            error.CiphertextTooShort => {
                self.last_data_received_at = std.Io.Clock.awake.now(self.io);
                log.debug("Client/Recv", "Ignoring short non-Noise binary frame", .{});
                continue;
            },
            else => return err,
        };
        self.last_data_received_at = std.Io.Clock.awake.now(self.io);
        const unpacked = frame_codec.unpackInto(&self.recv_unpack_buf, self.allocator, frame) catch |err| switch (err) {
            error.EmptyFrame => {
                log.debug("Client/Recv", "Ignoring empty frame", .{});
                continue;
            },
            else => return err,
        };

        if (unpacked.len == 0) {
            log.debug("Client/Recv", "Ignoring empty WA payload", .{});
            continue;
        }

        var reader = binary.BinaryReader.init(unpacked);
        const node = binary.decodeNodeBorrowingInput(&reader, self.allocator) catch |err| {
            log.warn("Client/Recv", "Ignoring undecodable frame (payload {d} bytes): {}", .{
                unpacked.len,
                err,
            });
            continue;
        };
        stanza_log.logNode("Client/Recv", &node);
        return node;
    }
}

pub fn sendNode(self: anytype, node: *const binary.Node) !void {
    stanza_log.logNode("Client/Send", node);
    var encode_buf: [65536]u8 = undefined;
    var writer = binary.BinaryWriter.init(&encode_buf);
    _ = try binary.encodeNode(node, &writer);
    try sendEncodedNode(self, writer.getWritten());
}

pub fn sendEncodedNode(self: anytype, encoded: []const u8) !void {
    try frame_codec.packInto(&self.send_pack_buf, self.allocator, encoded);
    log.debug("Client/Send", "--> Sending {d} bytes", .{self.send_pack_buf.items.len});
    const ns = &(self.noise_socket orelse return error.NotConnected);
    try ns.send(&self.ws_client, self.send_pack_buf.items);
    self.last_data_sent_at = std.Io.Clock.awake.now(self.io);
}

pub fn sendAck(self: anytype, node: *const binary.Node) !void {
    var encode_buf: [256]u8 = undefined;
    var writer = binary.BinaryWriter.init(&encode_buf);
    try encodeAck(&writer, node);
    try sendEncodedNode(self, writer.getWritten());
}

fn sendIqResultDirect(self: anytype, id: ?[]const u8, to: []const u8) !void {
    var encode_buf: [256]u8 = undefined;
    var writer = binary.BinaryWriter.init(&encode_buf);
    try encodeIqResult(&writer, id, to);
    try sendEncodedNode(self, writer.getWritten());
}

fn sendActiveWithId(self: anytype, id: []const u8) !void {
    var active_node = binary.Node.initBorrowed(self.allocator, "active");
    defer active_node.deinit();

    var iq = binary.Node.initBorrowed(self.allocator, "iq");
    defer iq.deinit();
    try iq.addAttributeBorrowed("id", id);
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("xmlns", "passive");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");
    try iq.addChild(&active_node);
    try sendNode(self, &iq);
}

fn sendKeepaliveWithId(self: anytype, id: []const u8) !void {
    var encode_buf: [256]u8 = undefined;
    var writer = binary.BinaryWriter.init(&encode_buf);
    try encodeKeepaliveIq(&writer, id);
    try sendEncodedNode(self, writer.getWritten());
}

fn encodeIqResult(
    writer: *binary.BinaryWriter,
    id: ?[]const u8,
    to: []const u8,
) binary.BinaryError!void {
    const attr_count: usize = 2 + @as(usize, @intFromBool(id != null));
    try stanza_encode.writeNodeHeader(writer, "iq", attr_count, false);
    try stanza_encode.writeAttribute(writer, "to", to);
    if (id) |iq_id| try stanza_encode.writeAttribute(writer, "id", iq_id);
    try stanza_encode.writeAttribute(writer, "type", "result");
}

fn encodeActiveIq(
    writer: *binary.BinaryWriter,
    id: []const u8,
) binary.BinaryError!void {
    try stanza_encode.writeNodeHeader(writer, "iq", 4, true);
    try stanza_encode.writeAttribute(writer, "id", id);
    try stanza_encode.writeAttribute(writer, "type", "set");
    try stanza_encode.writeAttribute(writer, "xmlns", "passive");
    try stanza_encode.writeAttribute(writer, "to", "s.whatsapp.net");
    try stanza_encode.writeNodeHeader(writer, "active", 0, false);
}

fn encodeKeepaliveIq(
    writer: *binary.BinaryWriter,
    id: []const u8,
) binary.BinaryError!void {
    try stanza_encode.writeNodeHeader(writer, "iq", 4, false);
    try stanza_encode.writeAttribute(writer, "id", id);
    try stanza_encode.writeAttribute(writer, "type", "get");
    try stanza_encode.writeAttribute(writer, "xmlns", "w:p");
    try stanza_encode.writeAttribute(writer, "to", "s.whatsapp.net");
}

fn encodeAck(
    writer: *binary.BinaryWriter,
    node: *const binary.Node,
) (binary.BinaryError || error{ MissingId, MissingFrom })!void {
    const include_participant = node.getAttribute("participant") != null;
    const include_type = !std.mem.eql(u8, node.tag, "message") and
        !isEncryptIdentityNotification(node) and
        node.getAttribute("type") != null;
    const attr_count: usize = 3 +
        @as(usize, @intFromBool(include_participant)) +
        @as(usize, @intFromBool(include_type));

    try stanza_encode.writeNodeHeader(writer, "ack", attr_count, false);
    try stanza_encode.writeAttribute(writer, "class", node.tag);
    try stanza_encode.writeAttribute(writer, "id", node.getAttribute("id") orelse return error.MissingId);
    try stanza_encode.writeAttribute(writer, "to", node.getAttribute("from") orelse return error.MissingFrom);
    if (include_participant) {
        try stanza_encode.writeAttribute(writer, "participant", node.getAttribute("participant").?);
    }
    if (include_type) {
        try stanza_encode.writeAttribute(writer, "type", node.getAttribute("type").?);
    }
}

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

test "encodeIqResult matches node encoder" {
    const allocator = std.testing.allocator;

    var fast_buf: [128]u8 = undefined;
    var fast_writer = binary.BinaryWriter.init(&fast_buf);
    try encodeIqResult(&fast_writer, "3610797473", "s.whatsapp.net");

    var node = try stanza_log.buildIqResultNode(allocator, "3610797473", "s.whatsapp.net");
    defer node.deinit();

    var slow_buf: [128]u8 = undefined;
    var slow_writer = binary.BinaryWriter.init(&slow_buf);
    _ = try binary.encodeNode(&node, &slow_writer);

    try std.testing.expectEqualSlices(u8, slow_writer.getWritten(), fast_writer.getWritten());
}

test "encodeActiveIq matches node encoder" {
    const allocator = std.testing.allocator;

    var fast_buf: [128]u8 = undefined;
    var fast_writer = binary.BinaryWriter.init(&fast_buf);
    try encodeActiveIq(&fast_writer, "42");

    var active_node = binary.Node.initBorrowed(allocator, "active");
    defer active_node.deinit();

    var iq = binary.Node.initBorrowed(allocator, "iq");
    defer iq.deinit();
    try iq.addAttributeBorrowed("id", "42");
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("xmlns", "passive");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");
    try iq.addChild(&active_node);

    var slow_buf: [128]u8 = undefined;
    var slow_writer = binary.BinaryWriter.init(&slow_buf);
    _ = try binary.encodeNode(&iq, &slow_writer);

    try std.testing.expectEqualSlices(u8, slow_writer.getWritten(), fast_writer.getWritten());
}

test "encodeAck matches node encoder" {
    const allocator = std.testing.allocator;

    var incoming = try binary.Node.init(allocator, "receipt");
    defer incoming.deinit();
    try incoming.addAttribute("id", "123");
    try incoming.addAttribute("from", "559980000001@s.whatsapp.net");
    try incoming.addAttribute("participant", "559980000002@s.whatsapp.net");
    try incoming.addAttribute("type", "sender");

    var fast_buf: [256]u8 = undefined;
    var fast_writer = binary.BinaryWriter.init(&fast_buf);
    try encodeAck(&fast_writer, &incoming);

    var ack = binary.Node.initBorrowed(allocator, "ack");
    defer ack.deinit();
    try ack.addAttributeBorrowed("class", incoming.tag);
    try ack.addAttributeBorrowed("id", incoming.getAttribute("id").?);
    try ack.addAttributeBorrowed("to", incoming.getAttribute("from").?);
    try ack.addAttributeBorrowed("participant", incoming.getAttribute("participant").?);
    try ack.addAttributeBorrowed("type", incoming.getAttribute("type").?);

    var slow_buf: [256]u8 = undefined;
    var slow_writer = binary.BinaryWriter.init(&slow_buf);
    _ = try binary.encodeNode(&ack, &slow_writer);

    try std.testing.expectEqualSlices(u8, slow_writer.getWritten(), fast_writer.getWritten());
}

test "encodeKeepaliveIq matches node encoder" {
    const allocator = std.testing.allocator;

    var fast_buf: [128]u8 = undefined;
    var fast_writer = binary.BinaryWriter.init(&fast_buf);
    try encodeKeepaliveIq(&fast_writer, "7");

    var iq = binary.Node.initBorrowed(allocator, "iq");
    defer iq.deinit();
    try iq.addAttributeBorrowed("id", "7");
    try iq.addAttributeBorrowed("type", "get");
    try iq.addAttributeBorrowed("xmlns", "w:p");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    var slow_buf: [128]u8 = undefined;
    var slow_writer = binary.BinaryWriter.init(&slow_buf);
    _ = try binary.encodeNode(&iq, &slow_writer);

    try std.testing.expectEqualSlices(u8, slow_writer.getWritten(), fast_writer.getWritten());
}
