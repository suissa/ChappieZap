const std = @import("std");
const binary = @import("binary");
const crypto = std.crypto;
const Aes256 = crypto.core.aes.Aes256;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const X25519 = crypto.dh.X25519;

pub const CROCKFORD_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTVWXYZ";
pub const PAIR_CODE_PBKDF2_ITERATIONS: u32 = 131_072;

pub const PairCodeUtils = struct {
    /// Generates a random 8-character pair code using Crockford Base32.
    pub fn generateCode(io: std.Io) [8]u8 {
        var bytes: [5]u8 = undefined;
        io.random(&bytes);
        return encodeCrockford(bytes);
    }

    /// Encodes 5 bytes (40 bits) into 8 Crockford Base32 characters.
    pub fn encodeCrockford(bytes: [5]u8) [8]u8 {
        var acc: u64 = 0;
        for (bytes) |b| {
            acc = (acc << 8) | @as(u64, b);
        }

        var result: [8]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            const shift: u6 = @intCast((7 - i) * 5);
            const index = (acc >> shift) & 0x1F;
            result[i] = CROCKFORD_ALPHABET[index];
        }
        return result;
    }

    /// Format code as "XXXX-XXXX" for user-friendly display.
    pub fn formatCode(code: []const u8, buf: *[9]u8) []const u8 {
        if (code.len != 8) return code;
        @memcpy(buf[0..4], code[0..4]);
        buf[4] = '-';
        @memcpy(buf[5..9], code[4..8]);
        return buf[0..9];
    }

    /// Validates an 8-character pair code.
    pub fn validateCode(code: []const u8) bool {
        if (code.len != 8) return false;
        for (code) |c| {
            const up = std.ascii.toUpper(c);
            if (std.mem.indexOfScalar(u8, CROCKFORD_ALPHABET, up) == null) {
                return false;
            }
        }
        return true;
    }

    /// Sanitizes phone number by removing non-digits.
    pub fn sanitizePhoneNumber(raw: []const u8, buf: []u8) []const u8 {
        var len: usize = 0;
        for (raw) |c| {
            if (std.ascii.isDigit(c) and len < buf.len) {
                buf[len] = c;
                len += 1;
            }
        }
        return buf[0..len];
    }

    /// Derives a 32-byte encryption key from code and salt using PBKDF2-HMAC-SHA256.
    pub fn deriveKey(code: []const u8, salt: *const [32]u8) [32]u8 {
        var key: [32]u8 = undefined;
        crypto.pwhash.pbkdf2(
            &key,
            code,
            salt,
            PAIR_CODE_PBKDF2_ITERATIONS,
            crypto.auth.hmac.sha2.HmacSha256,
        ) catch unreachable;
        return key;
    }

    /// AES-256-CTR stream cipher encrypt/decrypt.
    pub fn aes256Ctr(key: [32]u8, iv: [16]u8, in: []const u8, out: []u8) void {
        const aes = Aes256.initEnc(key);
        var counter = iv;
        var i: usize = 0;
        while (i < in.len) {
            var block: [16]u8 = undefined;
            aes.encrypt(&block, &counter);
            const chunk = @min(16, in.len - i);
            for (0..chunk) |j| {
                out[i + j] = in[i + j] ^ block[j];
            }
            i += chunk;

            // Increment 128-bit big-endian counter
            var k: usize = 16;
            while (k > 0) {
                k -= 1;
                counter[k] +%= 1;
                if (counter[k] != 0) break;
            }
        }
    }

    /// Encrypts the companion ephemeral public key for Stage 1.
    /// Returns salt(32) + iv(16) + ciphertext(32) = 80 bytes.
    pub fn encryptEphemeralPub(ephemeral_pub: [32]u8, code: []const u8, io: std.Io) [80]u8 {
        var salt: [32]u8 = undefined;
        var iv: [16]u8 = undefined;
        io.random(&salt);
        io.random(&iv);

        const key = deriveKey(code, &salt);
        var ciphertext: [32]u8 = undefined;
        aes256Ctr(key, iv, &ephemeral_pub, &ciphertext);

        var result: [80]u8 = undefined;
        @memcpy(result[0..32], &salt);
        @memcpy(result[32..48], &iv);
        @memcpy(result[48..80], &ciphertext);
        return result;
    }

    /// Decrypts the primary device's ephemeral public key received in Stage 2.
    pub fn decryptPrimaryEphemeralPub(wrapped: []const u8, code: []const u8) ![32]u8 {
        if (wrapped.len != 80) return error.InvalidWrappedData;

        const salt: *const [32]u8 = wrapped[0..32];
        const iv: *const [16]u8 = wrapped[32..48];
        const ciphertext = wrapped[48..80];

        const key = deriveKey(code, salt);
        var plaintext: [32]u8 = undefined;
        aes256Ctr(key, iv.*, ciphertext, &plaintext);
        return plaintext;
    }

    pub const KeyBundleResult = struct {
        wrapped_bundle: [156]u8,
        new_adv_secret: [32]u8,
    };

    /// Prepares encrypted key bundle and new ADV secret for Stage 2.
    pub fn prepareKeyBundle(
        ephemeral_priv: [32]u8,
        identity_priv: [32]u8,
        identity_pub: [32]u8,
        primary_ephemeral_pub: [32]u8,
        primary_identity_pub: [32]u8,
        io: std.Io,
    ) !KeyBundleResult {
        const ephemeral_shared = try X25519.scalarmult(ephemeral_priv, primary_ephemeral_pub);
        const identity_shared = try X25519.scalarmult(identity_priv, primary_identity_pub);

        var random_bytes: [32]u8 = undefined;
        io.random(&random_bytes);

        // Derive ADV secret: combined = ephemeral_shared(32) + identity_shared(32) + random_bytes(32)
        var combined_secret: [96]u8 = undefined;
        @memcpy(combined_secret[0..32], &ephemeral_shared);
        @memcpy(combined_secret[32..64], &identity_shared);
        @memcpy(combined_secret[64..96], &random_bytes);

        const prk_adv = HkdfSha256.extract(&.{}, &combined_secret);
        var new_adv_secret: [32]u8 = undefined;
        HkdfSha256.expand(&new_adv_secret, "adv_secret", prk_adv);

        // Plaintext bundle = identity_pub(32) + primary_identity_pub(32) + random_bytes(32)
        var bundle: [96]u8 = undefined;
        @memcpy(bundle[0..32], &identity_pub);
        @memcpy(bundle[32..64], &primary_identity_pub);
        @memcpy(bundle[64..96], &random_bytes);

        // Derive encryption key using HKDF
        var key_bundle_salt: [32]u8 = undefined;
        io.random(&key_bundle_salt);

        const prk_enc = HkdfSha256.extract(&key_bundle_salt, &ephemeral_shared);
        var enc_key: [32]u8 = undefined;
        HkdfSha256.expand(&enc_key, "link_code_pairing_key_bundle_encryption_key", prk_enc);

        // AES-GCM Encrypt
        var iv: [12]u8 = undefined;
        io.random(&iv);

        var encrypted_bundle: [112]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aes256Gcm.encrypt(
            encrypted_bundle[0..96],
            &tag,
            &bundle,
            "",
            iv,
            enc_key,
        );
        @memcpy(encrypted_bundle[96..112], &tag);

        // Wrapped bundle = salt(32) + iv(12) + encrypted_bundle(112) = 156 bytes
        var wrapped_bundle: [156]u8 = undefined;
        @memcpy(wrapped_bundle[0..32], &key_bundle_salt);
        @memcpy(wrapped_bundle[32..44], &iv);
        @memcpy(wrapped_bundle[44..156], &encrypted_bundle);

        return .{
            .wrapped_bundle = wrapped_bundle,
            .new_adv_secret = new_adv_secret,
        };
    }
};

// --- IQ builders and parsers ---

pub fn buildCompanionHelloIq(
    allocator: std.mem.Allocator,
    phone_number: []const u8,
    noise_static_pub: []const u8,
    wrapped_ephemeral: []const u8,
    req_id: []const u8,
) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();
    try iq.ensureAttributeCapacity(4);
    try iq.ensureChildCapacity(1);

    try iq.addAttributeBorrowed("xmlns", "md");
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");
    try iq.addAttribute("id", req_id);

    var reg = binary.Node.initBorrowed(allocator, "link_code_companion_reg");
    defer reg.deinit();
    try reg.ensureAttributeCapacity(3);
    try reg.ensureChildCapacity(5);

    const jid = try std.fmt.allocPrint(allocator, "{s}@s.whatsapp.net", .{phone_number});
    defer allocator.free(jid);
    try reg.addAttribute("jid", jid);
    try reg.addAttributeBorrowed("stage", "companion_hello");
    try reg.addAttributeBorrowed("should_show_push_notification", "true");

    // 1. link_code_pairing_wrapped_companion_ephemeral_pub
    var eph_node = binary.Node.initBorrowed(allocator, "link_code_pairing_wrapped_companion_ephemeral_pub");
    defer eph_node.deinit();
    try eph_node.setContentBytes(wrapped_ephemeral);
    try reg.addChild(&eph_node);

    // 2. companion_server_auth_key_pub
    var auth_node = binary.Node.initBorrowed(allocator, "companion_server_auth_key_pub");
    defer auth_node.deinit();
    try auth_node.setContentBytes(noise_static_pub);
    try reg.addChild(&auth_node);

    // 3. companion_platform_id
    var plat_id = binary.Node.initBorrowed(allocator, "companion_platform_id");
    defer plat_id.deinit();
    try plat_id.setContentBytesBorrowed("whatszig");
    try reg.addChild(&plat_id);

    // 4. companion_platform_display
    var plat_disp = binary.Node.initBorrowed(allocator, "companion_platform_display");
    defer plat_disp.deinit();
    try plat_disp.setContentBytesBorrowed("Linux (whatszig)");
    try reg.addChild(&plat_disp);

    // 5. link_code_pairing_nonce
    var nonce = binary.Node.initBorrowed(allocator, "link_code_pairing_nonce");
    defer nonce.deinit();
    const nonce_bytes = [_]u8{0};
    try nonce.setContentBytes(&nonce_bytes);
    try reg.addChild(&nonce);

    try iq.addChild(&reg);
    return iq;
}

pub fn parseCompanionHelloResponse(node: *const binary.Node) ?[]const u8 {
    const children = node.getContentNodes() orelse return null;
    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "link_code_companion_reg")) {
            const reg_children = child.getContentNodes() orelse continue;
            for (reg_children) |*reg_child| {
                if (std.mem.eql(u8, reg_child.tag, "link_code_pairing_ref")) {
                    return reg_child.getContentBytes();
                }
            }
        }
    }
    return null;
}

pub fn buildCompanionFinishIq(
    allocator: std.mem.Allocator,
    phone_number: []const u8,
    wrapped_key_bundle: []const u8,
    identity_pub: []const u8,
    pairing_ref: []const u8,
    req_id: []const u8,
) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();
    try iq.ensureAttributeCapacity(4);
    try iq.ensureChildCapacity(1);

    try iq.addAttributeBorrowed("xmlns", "md");
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");
    try iq.addAttribute("id", req_id);

    var reg = binary.Node.initBorrowed(allocator, "link_code_companion_reg");
    defer reg.deinit();
    try reg.ensureAttributeCapacity(2);
    try reg.ensureChildCapacity(3);

    const jid = try std.fmt.allocPrint(allocator, "{s}@s.whatsapp.net", .{phone_number});
    defer allocator.free(jid);
    try reg.addAttribute("jid", jid);
    try reg.addAttributeBorrowed("stage", "companion_finish");

    var bundle_node = binary.Node.initBorrowed(allocator, "link_code_pairing_wrapped_key_bundle");
    defer bundle_node.deinit();
    try bundle_node.setContentBytes(wrapped_key_bundle);
    try reg.addChild(&bundle_node);

    var id_node = binary.Node.initBorrowed(allocator, "companion_identity_public");
    defer id_node.deinit();
    try id_node.setContentBytes(identity_pub);
    try reg.addChild(&id_node);

    var ref_node = binary.Node.initBorrowed(allocator, "link_code_pairing_ref");
    defer ref_node.deinit();
    try ref_node.setContentBytes(pairing_ref);
    try reg.addChild(&ref_node);

    try iq.addChild(&reg);
    return iq;
}

pub const PrimaryHelloData = struct {
    wrapped_ephemeral_pub: []const u8,
    primary_identity_pub: [32]u8,
    pairing_ref: []const u8,
};

pub fn parsePrimaryHelloNotification(node: *const binary.Node) ?PrimaryHelloData {
    const children = node.getContentNodes() orelse return null;
    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "link_code_companion_reg")) {
            const stage = child.getAttribute("stage") orelse continue;
            if (!std.mem.eql(u8, stage, "primary_hello")) continue;

            var wrapped_eph: ?[]const u8 = null;
            var primary_id: ?[32]u8 = null;
            var pref: ?[]const u8 = null;

            const reg_children = child.getContentNodes() orelse continue;
            for (reg_children) |*rc| {
                if (std.mem.eql(u8, rc.tag, "link_code_pairing_wrapped_primary_ephemeral_pub")) {
                    if (rc.getContentBytes()) |bytes| {
                        if (bytes.len == 80) wrapped_eph = bytes;
                    }
                } else if (std.mem.eql(u8, rc.tag, "primary_identity_pub")) {
                    if (rc.getContentBytes()) |bytes| {
                        if (bytes.len == 32) primary_id = bytes[0..32].*;
                    }
                } else if (std.mem.eql(u8, rc.tag, "link_code_pairing_ref")) {
                    pref = rc.getContentBytes();
                }
            }

            if (wrapped_eph != null and primary_id != null and pref != null) {
                return .{
                    .wrapped_ephemeral_pub = wrapped_eph.?,
                    .primary_identity_pub = primary_id.?,
                    .pairing_ref = pref.?,
                };
            }
        }
    }
    return null;
}

// --- Unit Tests ---

test "crockford base32 encoding and validation" {
    const bytes = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A };
    const code = PairCodeUtils.encodeCrockford(bytes);
    try std.testing.expectEqual(@as(usize, 8), code.len);
    try std.testing.expect(PairCodeUtils.validateCode(&code));

    var buf: [9]u8 = undefined;
    const formatted = PairCodeUtils.formatCode(&code, &buf);
    try std.testing.expectEqual(@as(usize, 9), formatted.len);
    try std.testing.expectEqual(@as(u8, '-'), formatted[4]);
}

test "sanitize phone number" {
    var buf: [32]u8 = undefined;
    const clean = PairCodeUtils.sanitizePhoneNumber("+55 (15) 99195-7645", &buf);
    try std.testing.expectEqualStrings("5515991957645", clean);
}

test "ephemeral pub encryption and decryption roundtrip" {
    const io = std.testing.io;
    const code = "ABCD1234";
    var original_pub: [32]u8 = undefined;
    io.random(&original_pub);

    const wrapped = PairCodeUtils.encryptEphemeralPub(original_pub, code, io);
    try std.testing.expectEqual(@as(usize, 80), wrapped.len);

    const decrypted = try PairCodeUtils.decryptPrimaryEphemeralPub(&wrapped, code);
    try std.testing.expectEqualSlices(u8, &original_pub, &decrypted);
}

test "key bundle preparation and DH exchange" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const companion_eph = X25519.KeyPair.generate(io);
    const primary_eph = X25519.KeyPair.generate(io);
    const companion_id = X25519.KeyPair.generate(io);
    const primary_id = X25519.KeyPair.generate(io);

    const bundle_res = try PairCodeUtils.prepareKeyBundle(
        companion_eph.secret_key,
        companion_id.secret_key,
        companion_id.public_key,
        primary_eph.public_key,
        primary_id.public_key,
        io,
    );
    _ = allocator;

    try std.testing.expectEqual(@as(usize, 156), bundle_res.wrapped_bundle.len);
    try std.testing.expectEqual(@as(usize, 32), bundle_res.new_adv_secret.len);
}

test "build companion_hello and companion_finish IQs" {
    const allocator = std.testing.allocator;

    const wrapped_eph = [_]u8{0xAA} ** 80;
    const auth_pub = [_]u8{0xBB} ** 32;

    var hello_iq = try buildCompanionHelloIq(allocator, "5515991957645", &auth_pub, &wrapped_eph, "12345");
    defer hello_iq.deinit();

    try std.testing.expectEqualStrings("iq", hello_iq.tag);
    try std.testing.expectEqualStrings("set", hello_iq.getAttribute("type").?);

    var finish_iq = try buildCompanionFinishIq(allocator, "5515991957645", &[_]u8{0xCC} ** 156, &auth_pub, "ref123", "12346");
    defer finish_iq.deinit();

    try std.testing.expectEqualStrings("iq", finish_iq.tag);
    try std.testing.expectEqualStrings("12346", finish_iq.getAttribute("id").?);
}
