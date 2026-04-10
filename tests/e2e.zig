const std = @import("std");
const Client = @import("client").Client;
const ClientOptions = @import("client").ClientOptions;

const opts = ClientOptions{
    .host = "localhost",
    .port = 8080,
    .tls = false,
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
