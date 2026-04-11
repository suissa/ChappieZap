const std = @import("std");
const crypto = std.crypto;
const keys = @import("keys.zig");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

/// Chain key: produces message keys and steps forward
pub const ChainKey = struct {
    key: [32]u8,
    index: u32,

    const MESSAGE_KEY_SEED = [_]u8{0x01};
    const CHAIN_KEY_SEED = [_]u8{0x02};

    /// Step the chain key forward, producing message key material + next chain key
    pub fn step(self: ChainKey) struct { message_key_material: [32]u8, next: ChainKey } {
        var msg_key: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&msg_key, &MESSAGE_KEY_SEED, &self.key);

        var next_key: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&next_key, &CHAIN_KEY_SEED, &self.key);

        return .{
            .message_key_material = msg_key,
            .next = .{
                .key = next_key,
                .index = self.index + 1,
            },
        };
    }
};

/// Message encryption keys derived from chain key material
pub const MessageKeys = struct {
    cipher_key: [32]u8, // AES-256 key
    iv: [16]u8, // AES-CBC IV
    mac_key: [32]u8, // HMAC-SHA256 key
    index: u32,

    /// Derive message keys from chain key step output
    pub fn derive(material: [32]u8, index: u32) MessageKeys {
        // HKDF expand with "WhisperMessageKeys" info
        var okm: [80]u8 = undefined;
        const prk = HkdfSha256.extract(&[_]u8{0} ** 32, &material);
        HkdfSha256.expand(&okm, "WhisperMessageKeys", prk);

        return .{
            .cipher_key = okm[0..32].*,
            .mac_key = okm[32..64].*,
            .iv = okm[64..80].*,
            .index = index,
        };
    }
};

/// Root key: used for DH ratchet stepping
pub const RootKey = struct {
    key: [32]u8,

    /// Ratchet step: generate new root key + chain key from DH output
    pub fn ratchetStep(self: RootKey, dh_output: [32]u8) struct { root_key: RootKey, chain_key: ChainKey } {
        const prk = HkdfSha256.extract(&self.key, &dh_output);
        var okm: [64]u8 = undefined;
        HkdfSha256.expand(&okm, "WhisperRatchet", prk);

        return .{
            .root_key = .{ .key = okm[0..32].* },
            .chain_key = .{ .key = okm[32..64].*, .index = 0 },
        };
    }
};

/// Result of X3DH key agreement
pub const X3DHResult = struct {
    root_key: RootKey,
    chain_key: ChainKey,
};

/// X3DH key agreement: create initial root key + chain key
pub fn x3dh(
    our_identity: keys.IdentityKeyPair,
    our_base: keys.KeyPair,
    their_identity_public: [32]u8,
    their_signed_prekey: [32]u8,
    their_one_time_prekey: ?[32]u8,
) !X3DHResult {
    // Build the shared secret: discontinuity bytes + DH results
    var secret_buf: [32 * 5]u8 = undefined;
    var secret_len: usize = 0;

    // 32 discontinuity bytes (0xFF)
    @memset(secret_buf[0..32], 0xFF);
    secret_len += 32;

    // DH1: our_identity × their_signed_prekey
    const dh1 = try our_identity.key_pair.dh(their_signed_prekey);
    @memcpy(secret_buf[secret_len..][0..32], &dh1);
    secret_len += 32;

    // DH2: our_base × their_identity
    const dh2 = try our_base.dh(their_identity_public);
    @memcpy(secret_buf[secret_len..][0..32], &dh2);
    secret_len += 32;

    // DH3: our_base × their_signed_prekey
    const dh3 = try our_base.dh(their_signed_prekey);
    @memcpy(secret_buf[secret_len..][0..32], &dh3);
    secret_len += 32;

    // DH4: our_base × their_one_time_prekey (optional)
    if (their_one_time_prekey) |otpk| {
        const dh4 = try our_base.dh(otpk);
        @memcpy(secret_buf[secret_len..][0..32], &dh4);
        secret_len += 32;
    }

    // Derive root key + chain key via HKDF
    const prk = HkdfSha256.extract(&[_]u8{0} ** 32, secret_buf[0..secret_len]);
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, "WhisperText", prk);

    return .{
        .root_key = .{ .key = okm[0..32].* },
        .chain_key = .{ .key = okm[32..64].*, .index = 0 },
    };
}

/// X3DH key agreement as responder (Bob): create initial root key + chain key.
/// The DH computations mirror x3dh() but with swapped roles.
pub fn x3dhResponder(
    our_identity: keys.IdentityKeyPair,
    our_signed_prekey: keys.KeyPair,
    our_one_time_prekey: ?keys.KeyPair,
    their_identity_public: [32]u8,
    their_base_key: [32]u8,
) !X3DHResult {
    var secret_buf: [32 * 5]u8 = undefined;
    var secret_len: usize = 0;

    // 32 discontinuity bytes (0xFF)
    @memset(secret_buf[0..32], 0xFF);
    secret_len += 32;

    // DH1: our_signed_prekey × their_identity (matches initiator DH1)
    const dh1 = try our_signed_prekey.dh(their_identity_public);
    @memcpy(secret_buf[secret_len..][0..32], &dh1);
    secret_len += 32;

    // DH2: our_identity × their_base_key (matches initiator DH2)
    const dh2 = try our_identity.key_pair.dh(their_base_key);
    @memcpy(secret_buf[secret_len..][0..32], &dh2);
    secret_len += 32;

    // DH3: our_signed_prekey × their_base_key (matches initiator DH3)
    const dh3 = try our_signed_prekey.dh(their_base_key);
    @memcpy(secret_buf[secret_len..][0..32], &dh3);
    secret_len += 32;

    // DH4: our_one_time_prekey × their_base_key (optional)
    if (our_one_time_prekey) |otpk| {
        const dh4 = try otpk.dh(their_base_key);
        @memcpy(secret_buf[secret_len..][0..32], &dh4);
        secret_len += 32;
    }

    // Same HKDF derivation as initiator
    const prk = HkdfSha256.extract(&[_]u8{0} ** 32, secret_buf[0..secret_len]);
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, "WhisperText", prk);

    return .{
        .root_key = .{ .key = okm[0..32].* },
        .chain_key = .{ .key = okm[32..64].*, .index = 0 },
    };
}
