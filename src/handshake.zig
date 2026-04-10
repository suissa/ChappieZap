const std = @import("std");
const ws = @import("websocket_client");
const noise_mod = @import("noise");
const xed25519 = @import("xed25519");
const framing = @import("framing");
const socket_mod = @import("socket");
const whatsapp = @import("whatsapp_proto");
const log = @import("log");

const WA_CONN_HEADER = [_]u8{ 0x57, 0x41, 0x06, 0x03 };

/// Perform the Noise XX handshake over an established WebSocket connection.
/// Returns write/read cipher keys for post-handshake encryption.
pub fn performHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    ws_client: *ws.WebSocketClient,
    static_keypair: xed25519.XEd25519.KeyPair,
    client_payload: []const u8,
) !noise_mod.Noise.CipherPair {
    var handshake = try noise_mod.Noise.ClientHandshake.init(
        allocator,
        static_keypair,
        &WA_CONN_HEADER,
        io,
    );

    // --- ClientHello ---
    const ephemeral_pub = handshake.createClientHello();
    {
        const hello_bytes = try encodeProtobuf(allocator, whatsapp.HandshakeMessage{
            .clientHello = .{ .ephemeral = &ephemeral_pub },
        });
        defer allocator.free(hello_bytes);
        const framed = try framing.encodeFrame(allocator, hello_bytes, &WA_CONN_HEADER);
        defer allocator.free(framed);
        log.debug("Handshake", "--> Sending ClientHello ({d} bytes)", .{framed.len});
        try ws_client.writeBinary(framed);
    }

    // --- ServerHello ---
    var read_buf: [65536]u8 = undefined;
    const server_msg = try ws_client.readMessage(&read_buf) orelse return error.ConnectionClosed;
    log.debug("Handshake", "<-- Received ServerHello ({d} bytes)", .{server_msg.data.len});

    if (server_msg.data.len < 3) return error.InvalidServerResponse;
    const payload_len: usize = (@as(usize, server_msg.data[0]) << 16) |
        (@as(usize, server_msg.data[1]) << 8) | @as(usize, server_msg.data[2]);
    if (server_msg.data.len < 3 + payload_len) return error.InvalidServerResponseLength;

    var proto_reader: std.Io.Reader = .fixed(server_msg.data[3 .. 3 + payload_len]);
    var server_handshake = try whatsapp.HandshakeMessage.decode(&proto_reader, allocator);
    defer server_handshake.deinit(allocator);
    const server_hello = server_handshake.serverHello orelse return error.NoServerHello;

    // --- Process ServerHello + ClientFinish ---
    const client_finish = try handshake.processServerHello(.{
        .ephemeral = server_hello.ephemeral,
        .static = server_hello.static,
        .payload = server_hello.payload,
    }, client_payload);
    defer {
        if (client_finish.static) |s| allocator.free(s);
        if (client_finish.payload) |p| allocator.free(p);
    }

    {
        log.debug("Handshake", "--> Building ClientFinish", .{});
        const finish_bytes = try encodeProtobuf(allocator, whatsapp.HandshakeMessage{
            .clientFinish = .{
                .static = client_finish.static orelse &[_]u8{},
                .payload = client_finish.payload orelse &[_]u8{},
            },
        });
        defer allocator.free(finish_bytes);
        const framed = try framing.encodeFrame(allocator, finish_bytes, null);
        defer allocator.free(framed);
        log.debug("Handshake", "--> Sending ClientFinish ({d} bytes)", .{framed.len});
        try ws_client.writeBinary(framed);
    }

    return handshake.finish();
}

/// Build the default ClientPayload protobuf.
pub fn buildClientPayload(allocator: std.mem.Allocator) ![]u8 {
    return try encodeProtobuf(allocator, whatsapp.ClientPayload{
        .passive = false,
        .userAgent = .{
            .platform = .WEB,
            .releaseChannel = .RELEASE,
            .appVersion = .{ .primary = 2, .secondary = 3000, .tertiary = 1036994591 },
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
    });
}

fn encodeProtobuf(allocator: std.mem.Allocator, msg: anytype) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try msg.encode(&writer.writer, allocator);
    return allocator.dupe(u8, writer.written());
}
