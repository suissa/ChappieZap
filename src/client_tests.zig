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

test "integration: QR code terminal visualization for WhatsApp payload" {
    const allocator = std.testing.allocator;
    const qr_mod = @import("qr");

    const wa_ref_payload = "2@G3fIM2jptT5skuwmY6MrqHQzMulSG1NmZ3xnknmJfJ+ngS1E/2xyYIhhYiLzvp7mAN6svFBitlNPFVzZMVMrtKTNWfk9KFzCxJo=,HCZQrJkun5/oq1VFM3/116j5RUvcZfj4Dki58tJ4z2M=,eYiHzu9i0DiFqd5oNx4fK8smz3PG127n2oSQI0CLVl8=,p/YT+AVM7VNNrU12mAcmHNN/WgEc7MUBE725BbSuodc=";

    var qr = try qr_mod.QrCode.encodeText(allocator, wa_ref_payload, .L);
    defer qr.deinit();

    // Verify matrix properties
    try std.testing.expect(qr.size >= 49); // At least Version 8 (49x49) for ~165 chars

    // Top-left finder pattern
    try std.testing.expect(qr.get(0, 0));
    try std.testing.expect(qr.get(6, 0));
    try std.testing.expect(qr.get(0, 6));

    // Render terminal representation
    const rendered = try qr.renderTerminal(allocator);
    defer allocator.free(rendered);

    try std.testing.expect(rendered.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\n") != null);
}

test "integration: phone number pairing full end-to-end cryptographic handshake" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const pair_code_mod = @import("pair_code");
    const X25519 = std.crypto.dh.X25519;
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

    // 1. User inputs phone number
    const user_phone_input = "+55 (15) 99195-7645";
    var phone_buf: [32]u8 = undefined;
    const phone = pair_code_mod.PairCodeUtils.sanitizePhoneNumber(user_phone_input, &phone_buf);
    try std.testing.expectEqualStrings("5515991957645", phone);

    // 2. Companion device initializes pair code flow (Stage 1)
    const code = pair_code_mod.PairCodeUtils.generateCode(io);
    try std.testing.expect(pair_code_mod.PairCodeUtils.validateCode(&code));

    var formatted_buf: [9]u8 = undefined;
    const formatted_code = pair_code_mod.PairCodeUtils.formatCode(&code, &formatted_buf);
    try std.testing.expectEqual(@as(usize, 9), formatted_code.len);
    try std.testing.expectEqual(@as(u8, '-'), formatted_code[4]);

    const companion_identity = X25519.KeyPair.generate(io);
    const companion_noise_static = X25519.KeyPair.generate(io);
    const companion_ephemeral = X25519.KeyPair.generate(io);

    const wrapped_companion_eph = pair_code_mod.PairCodeUtils.encryptEphemeralPub(
        companion_ephemeral.public_key,
        &code,
        io,
    );
    try std.testing.expectEqual(@as(usize, 80), wrapped_companion_eph.len);

    var hello_iq = try pair_code_mod.buildCompanionHelloIq(
        allocator,
        phone,
        &companion_noise_static.public_key,
        &wrapped_companion_eph,
        "req_hello_1",
    );
    defer hello_iq.deinit();

    // Verify IQ structure
    try std.testing.expectEqualStrings("iq", hello_iq.tag);
    try std.testing.expectEqualStrings("set", hello_iq.getAttribute("type").?);

    // 3. Server responds with pairing ref
    const mock_pairing_ref = "test_pairing_ref_bytes_987654";

    // 4. Primary device (Phone) receives pairing code from user and initiates Stage 2
    const primary_identity = X25519.KeyPair.generate(io);
    const primary_ephemeral = X25519.KeyPair.generate(io);

    // Primary encrypts its ephemeral public key with the same pairing code (using its own random salt/IV)
    const primary_wrapped_eph = pair_code_mod.PairCodeUtils.encryptEphemeralPub(
        primary_ephemeral.public_key,
        &code,
        io,
    );

    // 5. Companion device processes primary_hello notification
    const decrypted_primary_eph = try pair_code_mod.PairCodeUtils.decryptPrimaryEphemeralPub(
        &primary_wrapped_eph,
        &code,
    );
    try std.testing.expectEqualSlices(u8, &primary_ephemeral.public_key, &decrypted_primary_eph);

    // 6. Companion prepares key bundle and derives ADV secret
    const bundle_res = try pair_code_mod.PairCodeUtils.prepareKeyBundle(
        companion_ephemeral.secret_key,
        companion_identity.secret_key,
        companion_identity.public_key,
        decrypted_primary_eph,
        primary_identity.public_key,
        io,
    );

    // 7. Companion sends companion_finish IQ
    var finish_iq = try pair_code_mod.buildCompanionFinishIq(
        allocator,
        phone,
        &bundle_res.wrapped_bundle,
        &companion_identity.public_key,
        mock_pairing_ref,
        "req_finish_2",
    );
    defer finish_iq.deinit();

    try std.testing.expectEqualStrings("iq", finish_iq.tag);
    try std.testing.expectEqualStrings("req_finish_2", finish_iq.getAttribute("id").?);

    // 8. Primary verifies the key bundle from companion_finish:
    // Primary derives matching ephemeral shared secret: X25519(primary_ephemeral_priv, companion_ephemeral_pub)
    const primary_ephemeral_shared = try X25519.scalarmult(
        primary_ephemeral.secret_key,
        companion_ephemeral.public_key,
    );

    // Extract salt, IV and ciphertext from wrapped bundle
    const bundle_salt: *const [32]u8 = bundle_res.wrapped_bundle[0..32];
    const bundle_iv: *const [12]u8 = bundle_res.wrapped_bundle[32..44];
    const encrypted_bundle_with_tag = bundle_res.wrapped_bundle[44..156];
    const ciphertext = encrypted_bundle_with_tag[0..96];
    const tag: *const [16]u8 = encrypted_bundle_with_tag[96..112];

    const prk_enc = HkdfSha256.extract(bundle_salt, &primary_ephemeral_shared);
    var primary_enc_key: [32]u8 = undefined;
    HkdfSha256.expand(&primary_enc_key, "link_code_pairing_key_bundle_encryption_key", prk_enc);

    var decrypted_bundle: [96]u8 = undefined;
    try Aes256Gcm.decrypt(
        &decrypted_bundle,
        ciphertext,
        tag.*,
        "",
        bundle_iv.*,
        primary_enc_key,
    );

    // Verify companion identity public key inside decrypted bundle matches companion's key!
    try std.testing.expectEqualSlices(u8, &companion_identity.public_key, decrypted_bundle[0..32]);
    try std.testing.expectEqualSlices(u8, &primary_identity.public_key, decrypted_bundle[32..64]);
}
