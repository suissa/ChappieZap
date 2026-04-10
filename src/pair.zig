const std = @import("std");
const binary = @import("binary");
const signal = @import("signal");
const whatsapp = @import("whatsapp_proto");

const ADV_PREFIX_DEVICE_SIGNATURE_GENERATE = [_]u8{ 6, 1 };
const ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION = [_]u8{ 6, 6 };

/// Build a DevicePairingRegistrationData for the initial ClientPayload.
/// This tells the server we're a new device that needs pairing.
pub fn buildPairingData(
    allocator: std.mem.Allocator,
    identity: signal.IdentityKeyPair,
    signed_prekey: signal.SignedPreKey,
    registration_id: u32,
    app_version: anytype,
) !PairingData {
    // Registration ID (4 bytes big-endian)
    var e_regid: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_regid, registration_id, .big);

    // Key type is always 0x05 for Curve25519
    const e_keytype = [_]u8{0x05};

    // Identity key (32 bytes)
    const e_ident = identity.key_pair.public;

    // Signed pre-key ID (3 bytes big-endian from u32)
    const spk_be = std.mem.toBytes(std.mem.nativeToBig(u32, signed_prekey.id));
    const e_skey_id = spk_be[1..4].*;

    // Signed pre-key value (32 bytes)
    const e_skey_val = signed_prekey.key_pair.public;

    // Signed pre-key signature (64 bytes)
    const e_skey_sig = signed_prekey.signature;

    // Build hash (MD5 of version string)
    var build_hash: [16]u8 = undefined;
    var version_buf: [64]u8 = undefined;
    const version_str = try std.fmt.bufPrint(&version_buf, "{d}.{d}.{d}", .{
        app_version.primary,
        app_version.secondary,
        app_version.tertiary,
    });
    std.crypto.hash.Md5.hash(version_str, &build_hash, .{});

    return .{
        .e_regid = e_regid,
        .e_keytype = e_keytype,
        .e_ident = e_ident,
        .e_skey_id = e_skey_id,
        .e_skey_val = e_skey_val,
        .e_skey_sig = e_skey_sig,
        .build_hash = build_hash,
        .allocator = allocator,
    };
}

pub const PairingData = struct {
    e_regid: [4]u8,
    e_keytype: [1]u8,
    e_ident: [32]u8,
    e_skey_id: [3]u8,
    e_skey_val: [32]u8,
    e_skey_sig: [64]u8,
    build_hash: [16]u8,
    allocator: std.mem.Allocator,
};

pub const PairCryptoResult = struct {
    self_signed_identity_bytes: []u8,
    key_index: u32,
};

/// Build the cryptographic payload for <pair-device-sign>.
/// This mirrors the Rust reference implementation's pair-success path.
pub fn doPairCrypto(
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: signal.IdentityKeyPair,
    adv_secret_key: [32]u8,
    device_identity_bytes: []const u8,
) !PairCryptoResult {
    _ = adv_secret_key; // HMAC verification is intentionally skipped for now, matching Rust.

    var hmac_reader: std.Io.Reader = .fixed(device_identity_bytes);
    var hmac_container = try whatsapp.ADVSignedDeviceIdentityHMAC.decode(&hmac_reader, allocator);
    defer hmac_container.deinit(allocator);

    const is_hosted = hmac_container.accountType != null and hmac_container.accountType.? == .HOSTED;
    const details_bytes = hmac_container.details orelse return error.InvalidPairSuccess;

    var signed_reader: std.Io.Reader = .fixed(details_bytes);
    var signed_identity = try whatsapp.ADVSignedDeviceIdentity.decode(&signed_reader, allocator);
    defer signed_identity.deinit(allocator);

    const account_sig_key_bytes = signed_identity.accountSignatureKey orelse return error.InvalidPairSuccess;
    const inner_details_bytes = signed_identity.details orelse return error.InvalidPairSuccess;
    const sig_prefix = if (is_hosted)
        &ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION
    else
        &ADV_PREFIX_DEVICE_SIGNATURE_GENERATE;

    const msg_to_sign = try concatBytes(allocator, &.{
        sig_prefix,
        inner_details_bytes,
        &identity.key_pair.public,
        account_sig_key_bytes,
    });
    defer allocator.free(msg_to_sign);

    const device_signature = identity.sign(msg_to_sign, io);
    if (signed_identity.deviceSignature) |old| allocator.free(old);
    signed_identity.deviceSignature = try allocator.dupe(u8, &device_signature);

    var details_reader: std.Io.Reader = .fixed(inner_details_bytes);
    var identity_details = try whatsapp.ADVDeviceIdentity.decode(&details_reader, allocator);
    defer identity_details.deinit(allocator);

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try signed_identity.encode(&writer.writer, allocator);

    return .{
        .self_signed_identity_bytes = try allocator.dupe(u8, writer.written()),
        .key_index = identity_details.keyIndex orelse 0,
    };
}

/// Build the <pair-device-sign> IQ result node to respond to pair-success.
pub fn buildPairDeviceSignResponse(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    device_identity_bytes: []const u8,
    key_index: u32,
) !binary.Node {
    var iq = try binary.Node.init(allocator, "iq");
    errdefer iq.deinit();

    try iq.addAttribute("to", "s.whatsapp.net");
    try iq.addAttribute("id", iq_id);
    try iq.addAttribute("type", "result");

    // <pair-device-sign>
    var pds = try binary.Node.init(allocator, "pair-device-sign");
    defer pds.deinit();

    // <device-identity key-index="0">[protobuf bytes]</device-identity>
    var di = try binary.Node.init(allocator, "device-identity");
    defer di.deinit();

    var ki_buf: [10]u8 = undefined;
    const ki_str = std.fmt.bufPrint(&ki_buf, "{d}", .{key_index}) catch "0";
    try di.addAttribute("key-index", ki_str);
    try di.setContentBytes(device_identity_bytes);
    try pds.addChild(&di);

    try iq.addChild(&pds);
    return iq;
}

/// Parse pair-success IQ to extract device JID and LID.
pub const PairSuccessInfo = struct {
    phone_jid: []const u8,
    lid_jid: []const u8,
    device_identity: ?[]const u8,
};

pub fn parsePairSuccess(node: *const binary.Node) ?PairSuccessInfo {
    const children = node.getContentNodes() orelse return null;

    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "pair-success")) {
            var result = PairSuccessInfo{
                .phone_jid = "",
                .lid_jid = "",
                .device_identity = null,
            };

            const ps_children = child.getContentNodes() orelse continue;
            for (ps_children) |*ps_child| {
                if (std.mem.eql(u8, ps_child.tag, "device")) {
                    result.phone_jid = ps_child.getAttribute("jid") orelse "";
                    result.lid_jid = ps_child.getAttribute("lid") orelse "";
                } else if (std.mem.eql(u8, ps_child.tag, "device-identity")) {
                    result.device_identity = ps_child.getContentBytes();
                }
            }

            return result;
        }
    }
    return null;
}

test "pair-device-sign response keeps Rust iq result attribute order" {
    const allocator = std.testing.allocator;

    var node = try buildPairDeviceSignResponse(allocator, "3610797473", &[_]u8{ 0x01, 0x02 }, 0);
    defer node.deinit();

    var buf: [128]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buf);
    _ = try binary.encodeNode(&node, &writer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xf8, 0x08, 0x19,
        0x11, 0x03, 0x08,
        0xff, 0x05, 0x36,
        0x10, 0x79, 0x74,
        0x73, 0x04, 0x14,
    }, writer.getWritten()[0..15]);
}

test "pairing payload matches rust reference bytes for fixed keys" {
    const allocator = std.testing.allocator;

    const identity_private = [_]u8{
        0x70, 0x61, 0x79, 0x72, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2d,
        0x6b, 0x65, 0x79, 0x2d, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x73, 0x21, 0x21,
        0x21, 0x21, 0x21, 0x21,
    };
    const signed_prekey_private = [_]u8{
        0x70, 0x61, 0x79, 0x72, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x2d, 0x70, 0x72,
        0x65, 0x6b, 0x65, 0x79, 0x2d, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x73, 0x21,
        0x21, 0x21, 0x21, 0x21,
    };

    const identity = signal.keys.IdentityKeyPair{
        .key_pair = makeKeyPair(identity_private),
    };
    const signed_prekey_keypair = makeKeyPair(signed_prekey_private);
    const signature = signWithRandom(
        identity.key_pair.private,
        &serializeDjbPublicKey(signed_prekey_keypair.public),
        random64(),
    );
    const signed_prekey = signal.keys.SignedPreKey{
        .id = 1,
        .key_pair = signed_prekey_keypair,
        .signature = signature,
    };

    const pd = try buildPairingData(allocator, identity, signed_prekey, 958248714, .{
        .primary = 2,
        .secondary = 3000,
        .tertiary = 1037005288,
    });

    const device_props = whatsapp.DeviceProps{
        .os = "rust",
        .version = .{ .primary = 0, .secondary = 1, .tertiary = 0 },
        .platformType = .UNKNOWN,
        .requireFullSync = true,
        .historySyncConfig = .{
            .fullSyncDaysLimit = 30,
            .inlineInitialPayloadInE2EeMsg = true,
            .storageQuotaMb = 10240,
            .supportMessageAssociation = true,
        },
    };
    var dp_writer = std.Io.Writer.Allocating.init(allocator);
    defer dp_writer.deinit();
    try device_props.encode(&dp_writer.writer, allocator);
    const dp_bytes = dp_writer.written();

    var payload = whatsapp.ClientPayload{
        .passive = false,
        .pull = false,
        .userAgent = .{
            .platform = .WEB,
            .releaseChannel = .RELEASE,
            .appVersion = .{ .primary = 2, .secondary = 3000, .tertiary = 1037005288 },
            .mcc = "000",
            .mnc = "000",
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
        .devicePairingData = .{
            .eRegid = &pd.e_regid,
            .eKeytype = &pd.e_keytype,
            .eIdent = &pd.e_ident,
            .eSkeyId = &pd.e_skey_id,
            .eSkeyVal = &pd.e_skey_val,
            .eSkeySig = &pd.e_skey_sig,
            .buildHash = &pd.build_hash,
            .deviceProps = dp_bytes,
        },
    };

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try payload.encode(&writer.writer, allocator);

    const expected = [_]u8{
        0x18, 0x00, 0x2a, 0x3c, 0x08, 0x0e, 0x12, 0x0b, 0x08, 0x02, 0x10, 0xb8, 0x17, 0x18, 0xe8, 0xe3,
        0xbd, 0xee, 0x03, 0x1a, 0x03, 0x30, 0x30, 0x30, 0x22, 0x03, 0x30, 0x30, 0x30, 0x2a, 0x05, 0x30,
        0x2e, 0x31, 0x2e, 0x30, 0x32, 0x00, 0x3a, 0x07, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x42,
        0x05, 0x30, 0x2e, 0x31, 0x2e, 0x30, 0x50, 0x00, 0x5a, 0x02, 0x65, 0x6e, 0x62, 0x02, 0x65, 0x6e,
        0x32, 0x02, 0x20, 0x00, 0x60, 0x01, 0x68, 0x01, 0x9a, 0x01, 0xc5, 0x01, 0x0a, 0x04, 0x39, 0x1d,
        0xb7, 0x0a, 0x12, 0x01, 0x05, 0x1a, 0x20, 0x6a, 0xbd, 0xdb, 0x83, 0x25, 0xed, 0xe6, 0x49, 0xa2,
        0xde, 0x13, 0xb2, 0xbb, 0x34, 0x76, 0xdd, 0x90, 0x77, 0x98, 0xeb, 0xef, 0x8a, 0x49, 0x01, 0xcd,
        0xda, 0x9e, 0x98, 0xc2, 0xe4, 0x01, 0x4d, 0x22, 0x03, 0x00, 0x00, 0x01, 0x2a, 0x20, 0x1f, 0xdb,
        0xe8, 0xc7, 0x8a, 0xed, 0xd0, 0xa5, 0xdf, 0x18, 0x21, 0xc4, 0xf2, 0xe5, 0x87, 0xf9, 0x7a, 0xfa,
        0x94, 0xd0, 0xc7, 0x6d, 0x72, 0xdd, 0x17, 0xf0, 0xa9, 0x9a, 0x29, 0xb1, 0x39, 0x14, 0x32, 0x40,
        0x6d, 0x5a, 0x23, 0x27, 0xa7, 0x3a, 0x86, 0xb0, 0x52, 0x20, 0xe6, 0xc1, 0x8c, 0xc3, 0x76, 0x59,
        0x82, 0x1d, 0x0a, 0xa1, 0x8d, 0xec, 0x5b, 0xef, 0xf7, 0x3e, 0xd6, 0x1b, 0x49, 0x7a, 0x5d, 0x92,
        0xb3, 0x28, 0xe1, 0x68, 0x75, 0xd0, 0xa3, 0xb6, 0xbe, 0xaf, 0xe2, 0xd8, 0x72, 0x3d, 0x35, 0xe0,
        0x55, 0x96, 0x6c, 0x72, 0xc0, 0x16, 0x36, 0x10, 0x62, 0xaf, 0x5a, 0xcf, 0x58, 0xda, 0xf9, 0x0b,
        0x3a, 0x10, 0x63, 0x2f, 0xf5, 0xd1, 0x18, 0x32, 0x71, 0x27, 0xf4, 0x9f, 0xbd, 0x03, 0x7c, 0x38,
        0x89, 0x81, 0x42, 0x1d, 0x0a, 0x04, 0x72, 0x75, 0x73, 0x74, 0x12, 0x06, 0x08, 0x00, 0x10, 0x01,
        0x18, 0x00, 0x18, 0x00, 0x20, 0x01, 0x2a, 0x09, 0x08, 0x1e, 0x18, 0x80, 0x50, 0x20, 0x01, 0x70,
        0x01, 0x88, 0x02, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, writer.written());
}

fn makeKeyPair(private: [32]u8) signal.keys.KeyPair {
    const public = (std.crypto.ecc.Curve25519.basePoint.clampedMul(private) catch unreachable).toBytes();
    return .{ .public = public, .private = private };
}

fn serializeDjbPublicKey(public: [32]u8) [33]u8 {
    var out: [33]u8 = undefined;
    out[0] = 0x05;
    @memcpy(out[1..], &public);
    return out;
}

fn random64() [64]u8 {
    var out: [64]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = @intCast(i);
    return out;
}

fn signWithRandom(private_key: [32]u8, msg: []const u8, random_bytes: [64]u8) [64]u8 {
    const Edwards25519 = std.crypto.ecc.Edwards25519;
    const Scalar = Edwards25519.scalar.Scalar;
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const xeddsa_prefix = [_]u8{0xFE} ++ ([_]u8{0xFF} ** 31);

    const ed_public = Edwards25519.basePoint.mul(private_key) catch unreachable;
    const ed_public_bytes = ed_public.toBytes();
    const sign_bit = ed_public_bytes[31] & 0x80;
    const scalar = Scalar.fromBytes(private_key);

    var hash1 = Sha512.init(.{});
    hash1.update(&xeddsa_prefix);
    hash1.update(&private_key);
    hash1.update(msg);
    hash1.update(&random_bytes);
    var digest1: [Sha512.digest_length]u8 = undefined;
    hash1.final(&digest1);

    const r = Scalar.fromBytes64(digest1);
    const cap_r_point = Edwards25519.basePoint.mul(r.toBytes()) catch unreachable;
    const cap_r = cap_r_point.toBytes();

    var hash2 = Sha512.init(.{});
    hash2.update(&cap_r);
    hash2.update(&ed_public_bytes);
    hash2.update(msg);
    var digest2: [Sha512.digest_length]u8 = undefined;
    hash2.final(&digest2);

    const h = Scalar.fromBytes64(digest2);
    const s = h.mul(scalar).add(r).toBytes();

    var sig: [64]u8 = undefined;
    @memcpy(sig[0..32], &cap_r);
    @memcpy(sig[32..64], &s);
    sig[63] &= 0x7F;
    sig[63] |= sign_bit;
    return sig;
}

fn concatBytes(allocator: std.mem.Allocator, slices: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (slices) |slice| total += slice.len;

    const out = try allocator.alloc(u8, total);
    var pos: usize = 0;
    for (slices) |slice| {
        @memcpy(out[pos..][0..slice.len], slice);
        pos += slice.len;
    }
    return out;
}
