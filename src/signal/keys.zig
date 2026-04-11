const std = @import("std");
const crypto = std.crypto;

const Edwards25519 = crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;
const Sha512 = crypto.hash.sha2.Sha512;

const XEDDSA_HASH_PREFIX = [_]u8{
    0xFE,
} ++ ([_]u8{0xFF} ** 31);

/// Curve25519 key pair for Signal Protocol
pub const KeyPair = struct {
    public: [32]u8,
    private: [32]u8,

    /// Generate a new random Curve25519 key pair
    pub fn generate(io: std.Io) KeyPair {
        var private: [32]u8 = undefined;
        io.random(&private);
        // Clamp for Curve25519
        private[0] &= 0xF8;
        private[31] &= 0x7F;
        private[31] |= 0x40;

        const public_point = crypto.ecc.Curve25519.basePoint.clampedMul(private) catch |err| {
            std.debug.panic("Curve25519 key generation failed unexpectedly: {}", .{err});
        };
        return .{
            .public = public_point.toBytes(),
            .private = private,
        };
    }

    /// Perform Curve25519 DH key agreement
    pub fn dh(self: KeyPair, their_public: [32]u8) ![32]u8 {
        const point = crypto.ecc.Curve25519.fromBytes(their_public);
        const shared = point.clampedMul(self.private) catch return error.InvalidPublicKey;
        return shared.toBytes();
    }
};

/// Identity key pair (long-term, used for signing)
pub const IdentityKeyPair = struct {
    key_pair: KeyPair,

    pub fn generate(io: std.Io) IdentityKeyPair {
        return .{
            .key_pair = KeyPair.generate(io),
        };
    }

    /// Sign data using XEdDSA directly from the X25519 identity private key.
    /// This matches libsignal's signed-prekey signature semantics.
    pub fn sign(self: IdentityKeyPair, msg: []const u8, io: std.Io) [64]u8 {
        var random_bytes: [64]u8 = undefined;
        io.random(&random_bytes);
        return xeddsaSignWithRandom(self.key_pair.private, msg, random_bytes);
    }
};

/// Signed pre-key: Curve25519 key pair + Ed25519 signature over the public key
pub const SignedPreKey = struct {
    id: u32,
    key_pair: KeyPair,
    signature: [64]u8,

    pub fn generate(id: u32, identity: IdentityKeyPair, io: std.Io) SignedPreKey {
        const kp = KeyPair.generate(io);
        const serialized_public = serializeDjbPublicKey(kp.public);
        const signature = identity.sign(&serialized_public, io);
        return .{
            .id = id,
            .key_pair = kp,
            .signature = signature,
        };
    }
};

/// One-time pre-key
pub const PreKey = struct {
    id: u32,
    key_pair: KeyPair,

    pub fn generate(id: u32, io: std.Io) PreKey {
        return .{
            .id = id,
            .key_pair = KeyPair.generate(io),
        };
    }
};

/// Registration ID (random 4-byte identifier)
pub fn generateRegistrationId(io: std.Io) u32 {
    var bytes: [4]u8 = undefined;
    io.random(&bytes);
    var id = std.mem.readInt(u32, &bytes, .big) & 0x7FFF_FFFF;
    if (id == 0) id = 1;
    return id;
}

fn serializeDjbPublicKey(public: [32]u8) [33]u8 {
    var out: [33]u8 = undefined;
    out[0] = 0x05;
    @memcpy(out[1..], &public);
    return out;
}

fn xeddsaSignWithRandom(private_key: [32]u8, msg: []const u8, random_bytes: [64]u8) [64]u8 {
    const scalar = Scalar.fromBytes(private_key);
    const ed_public = Edwards25519.basePoint.mulPublic(scalar.toBytes()) catch |err| {
        std.debug.panic("XEdDSA public key derivation failed unexpectedly: {}", .{err});
    };
    const ed_public_bytes = ed_public.toBytes();
    const sign_bit = ed_public_bytes[31] & 0x80;

    var hash1 = Sha512.init(.{});
    hash1.update(&XEDDSA_HASH_PREFIX);
    hash1.update(&private_key);
    hash1.update(msg);
    hash1.update(&random_bytes);
    var digest1: [Sha512.digest_length]u8 = undefined;
    hash1.final(&digest1);

    const r_bytes = Edwards25519.scalar.reduce64(digest1);
    const r = Scalar.fromBytes(r_bytes);
    const cap_r_point = Edwards25519.basePoint.mulPublic(r_bytes) catch |err| {
        std.debug.panic("XEdDSA nonce point derivation failed unexpectedly: {}", .{err});
    };
    const cap_r = cap_r_point.toBytes();

    var hash2 = Sha512.init(.{});
    hash2.update(&cap_r);
    hash2.update(&ed_public_bytes);
    hash2.update(msg);
    var digest2: [Sha512.digest_length]u8 = undefined;
    hash2.final(&digest2);

    const h = Scalar.fromBytes(Edwards25519.scalar.reduce64(digest2));
    const s = h.mul(scalar).add(r).toBytes();

    var signature: [64]u8 = undefined;
    @memcpy(signature[0..32], &cap_r);
    @memcpy(signature[32..64], &s);
    signature[63] &= 0x7F;
    signature[63] |= sign_bit;
    return signature;
}

test "signed prekey signature uses key type prefix" {
    const private = [32]u8{
        0x70, 0x61, 0x79, 0x72, 0x2d, 0x73, 0x69, 0x67,
        0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65,
        0x79, 0x2d, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74,
        0x65, 0x73, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
    };
    const public = [32]u8{
        0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x2d, 0x70,
        0x72, 0x65, 0x6b, 0x65, 0x79, 0x2d, 0x70, 0x75,
        0x62, 0x6c, 0x69, 0x63, 0x2d, 0x33, 0x32, 0x2d,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x21, 0x21, 0x21,
    };
    const random = [64]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };

    const raw_sig = xeddsaSignWithRandom(private, &public, random);
    const tagged_sig = xeddsaSignWithRandom(private, &serializeDjbPublicKey(public), random);
    try std.testing.expect(!std.mem.eql(u8, &raw_sig, &tagged_sig));
}

test "xeddsa runtime regression matches rust fixed signature" {
    const private = [32]u8{
        0x10, 0x73, 0x26, 0x87, 0xd3, 0xf2, 0x8d, 0xbd,
        0x0b, 0x7e, 0x0f, 0xd2, 0xe9, 0x04, 0x8e, 0xa2,
        0xd1, 0xab, 0x57, 0xfe, 0x95, 0xee, 0xf6, 0x53,
        0x20, 0xca, 0x47, 0x92, 0xbf, 0x2b, 0x1e, 0x7d,
    };
    const public = [32]u8{
        0x77, 0x15, 0x8a, 0x69, 0x6c, 0xb1, 0x7e, 0x63,
        0x06, 0x6d, 0x42, 0x1b, 0x4c, 0x34, 0x0c, 0x89,
        0x99, 0x79, 0xfd, 0x73, 0x77, 0xbc, 0x24, 0xc8,
        0x33, 0x25, 0xa1, 0x88, 0x73, 0xf1, 0xed, 0x5b,
    };
    const random = [64]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    const expected = [64]u8{
        0x5d, 0x33, 0xb2, 0xa7, 0x39, 0x33, 0xc9, 0x75,
        0x0e, 0xa4, 0x07, 0xd8, 0x77, 0xaa, 0x12, 0x19,
        0x0b, 0x77, 0xa4, 0xbe, 0x17, 0x31, 0x4a, 0x63,
        0x3c, 0x31, 0xdd, 0x60, 0x6d, 0xa1, 0xb3, 0xb5,
        0x5d, 0x7f, 0xd0, 0x64, 0xe6, 0xdb, 0x35, 0xae,
        0xe0, 0xee, 0xd8, 0x07, 0x5d, 0xc0, 0x15, 0x40,
        0x4a, 0x26, 0xe8, 0x73, 0xa9, 0x0b, 0x2a, 0x6c,
        0xf3, 0xe2, 0xd5, 0xba, 0xc8, 0x59, 0x1f, 0x8a,
    };

    const sig = xeddsaSignWithRandom(private, &serializeDjbPublicKey(public), random);
    try std.testing.expectEqualSlices(u8, &expected, &sig);
}
