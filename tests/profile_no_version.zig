const std = @import("std");
const Client = @import("client").Client;
const ClientOptions = @import("client").ClientOptions;
const ws = @import("websocket_client");
const socket_mod = @import("socket");
const handshake_mod = @import("handshake");
const client_auth = @import("client").auth;
const client_payloads = @import("client").payloads;
const client_transport = @import("client").transport;

const opts = ClientOptions{
    .host = "localhost",
    .port = 8080,
    .tls = false,
};

const ConnectionMode = enum { pairing, login };

fn connectWithPayloadNoVersion(self: *Client, mode: ConnectionMode) !void {
    if (self.noise_socket) |*ns| ns.deinit();
    self.noise_socket = null;
    self.ws_client.deinit();
    self.ws_client = try ws.WebSocketClient.init(self.allocator, self.io);
    self.is_logged_in = false;

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

    const payload = switch (mode) {
        .pairing => try client_payloads.buildPairingPayload(self),
        .login => try client_payloads.buildLoginPayload(self),
    };
    defer self.allocator.free(payload);

    const cipher_pair = try handshake_mod.performHandshake(
        self.allocator,
        self.io,
        &self.ws_client,
        self.static_keypair,
        payload,
    );
    self.noise_socket = try socket_mod.NoiseSocket.init(
        self.allocator,
        cipher_pair.write_key,
        cipher_pair.read_key,
    );
}

fn connectAndLoginNoVersion(self: *Client) !void {
    try connectWithPayloadNoVersion(self, .pairing);
    try client_auth.handlePairingFlow(self);
    try connectWithPayloadNoVersion(self, .login);
    try client_auth.readUntilLogin(self);
    client_transport.sendActive(self);
    client_transport.uploadPrekeys(self) catch {};
}

test "profile: A sends encrypted message to B" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var a = try Client.init(allocator, io, opts);
    defer a.deinit();
    try connectAndLoginNoVersion(&a);

    var b = try Client.init(allocator, io, opts);
    defer b.deinit();
    try connectAndLoginNoVersion(&b);

    const jid_a = a.phone_jid orelse return error.NoPairing;
    const jid_b = b.phone_jid orelse return error.NoPairing;

    try a.sendMessage(jid_b, "Hello from Zig!");
    try b.waitForMessage(.{
        .from = jid_a,
        .body_equals = "Hello from Zig!",
        .require_decrypted = true,
    }, 10_000);
}

test "profile: zig client talks to whatsapp-rust bot" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var client = try Client.init(allocator, io, opts);
    defer client.deinit();
    try connectAndLoginNoVersion(&client);

    try client.sendMessage("559980000001@s.whatsapp.net", "\xf0\x9f\xa6\x80ping");
    try client.waitForMessage(.{
        .from = "559980000001@s.whatsapp.net",
    }, 15_000);
}
