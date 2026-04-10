const std = @import("std");
const Client = @import("client").Client;
const ClientOptions = @import("client").ClientOptions;
const signal = @import("signal");

const opts = ClientOptions{
    .host = "localhost",
    .port = 8080,
    .tls = false,
};

test "e2e: two clients exchange encrypted message" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var a = try Client.init(allocator, io, opts);
    defer a.deinit();
    try a.connectAndLogin();

    var b = try Client.init(allocator, io, opts);
    defer b.deinit();
    try b.connectAndLogin();

    try std.testing.expect(a.phone_jid != null);
    try std.testing.expect(b.phone_jid != null);
    const phone_b = b.phone_jid.?;
    std.debug.print("A={s} B={s}\n", .{ a.phone_jid.?, phone_b });

    // Signal session A→B
    const base_key = signal.KeyPair.generate(io);
    const x3dh = try signal.ratchet.x3dh(
        a.identity, base_key,
        b.identity.key_pair.public,
        b.signed_prekey.key_pair.public,
        b.prekeys[0].key_pair.public,
    );
    var sess = try signal.Session.initAsInitiator(
        allocator, x3dh,
        a.identity.key_pair.public, b.identity.key_pair.public,
        base_key, b.signed_prekey.key_pair.public,
        a.registration_id, b.registration_id,
    );
    defer sess.deinit();

    try a.sendTextMessage(&sess, phone_b, "Hello from Zig!", true);
    std.debug.print("Sent\n", .{});

    var msg = b.waitForMessage(20) catch |err| {
        std.debug.print("waitForMessage: {}\n", .{err});
        return err;
    };
    defer msg.deinit();

    try std.testing.expectEqualStrings("message", msg.tag);
    var found_enc = false;
    if (msg.getContentNodes()) |children| {
        for (children) |*child| {
            if (std.mem.eql(u8, child.tag, "enc")) found_enc = true;
        }
    }
    try std.testing.expect(found_enc);
    std.debug.print("SUCCESS!\n", .{});
}
