const std = @import("std");
const Client = @import("client").Client;
const ClientOptions = @import("client").ClientOptions;

const opts = ClientOptions{
    .host = "localhost",
    .port = 8080,
    .tls = false,
    .direct_message_mode = .legacy_single_enc,
};

test "e2e: A sends encrypted message to B" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var a = try Client.init(allocator, io, opts);
    defer a.deinit();
    try a.connectAndLogin();

    var b = try Client.init(allocator, io, opts);
    defer b.deinit();
    try b.connectAndLogin();

    const jid_b = b.phone_jid orelse return error.NoPairing;

    try a.sendMessage(jid_b, "Hello from Zig!");
    try b.waitForText("Hello from Zig!", 10_000);
}

test "e2e: zig client talks to whatsapp-rust bot" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var client = try Client.init(allocator, io, opts);
    defer client.deinit();
    try client.connectAndLogin();

    try client.sendMessage("559980000001@s.whatsapp.net", "\xf0\x9f\xa6\x80ping");
    try client.waitForTextContains("\xf0\x9f\x8f\x93 Pong!", 15_000);
}
