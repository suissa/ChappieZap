const std = @import("std");
const client_mod = @import("client");
const whatsapp = @import("whatsapp_proto");

test "pairing payload keeps zig device props" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var client = try client_mod.Client.init(allocator, io, .{});
    defer client.deinit();
    client.app_version = .{
        .primary = 2,
        .secondary = 3000,
        .tertiary = 1037005288,
    };

    const payload_bytes = try client_mod.payloads.buildPairingPayload(&client);
    defer allocator.free(payload_bytes);

    var payload_reader: std.Io.Reader = .fixed(payload_bytes);
    var payload = try whatsapp.ClientPayload.decode(&payload_reader, allocator);
    defer payload.deinit(allocator);

    const encoded_device_props = payload.devicePairingData.?.deviceProps orelse return error.TestUnexpectedResult;
    var device_props_reader: std.Io.Reader = .fixed(encoded_device_props);
    var device_props = try whatsapp.DeviceProps.decode(&device_props_reader, allocator);
    defer device_props.deinit(allocator);

    try std.testing.expectEqualStrings("zig", device_props.os orelse "");
}

test "resolveOwnDeviceEncryptionJid maps own pn device to lid device" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var client = try client_mod.Client.init(allocator, io, .{});
    defer client.deinit();
    try client.address_book.setOwnIdentity("559984726662@s.whatsapp.net", "236395184570386@lid", 63);

    const resolved = try client.address_book.resolveOwnDeviceEncryptionJid("559984726662:4@s.whatsapp.net");
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("236395184570386:4@lid", resolved.value);
}
