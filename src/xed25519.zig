const std = @import("std");
const crypto = std.crypto;

/// XEd25519 implementation combining X25519 (DH) and Ed25519 (signatures)
/// This is used by WhatsApp for cryptographic operations
pub const XEd25519 = struct {
    /// Key pair containing both X25519 and Ed25519 keys
    pub const KeyPair = struct {
        /// X25519 public key for Diffie-Hellman
        x25519_public: [32]u8,
        /// X25519 private key for Diffie-Hellman
        x25519_private: [32]u8,
        /// Ed25519 public key for signatures
        ed25519_public: [32]u8,
        /// Ed25519 private key for signatures (stored as secret key)
        ed25519_private: crypto.sign.Ed25519.SecretKey,

        /// Generate a new XEd25519 key pair
        pub fn generate(io: std.Io) KeyPair {
            // Noise only needs a plain X25519 keypair; generate it directly to
            // match WA Web. Keep an Ed25519 keypair around only
            // for the rare signing helpers and tests in this module.
            const x25519_keypair = crypto.dh.X25519.KeyPair.generate(io);
            const ed25519_keypair = crypto.sign.Ed25519.KeyPair.generate(io);

            return .{
                .x25519_public = x25519_keypair.public_key,
                .x25519_private = x25519_keypair.secret_key,
                .ed25519_public = ed25519_keypair.public_key.toBytes(),
                .ed25519_private = ed25519_keypair.secret_key,
            };
        }

        /// Sign a message using Ed25519
        pub fn sign(keypair: KeyPair, message: []const u8) [64]u8 {
            const public_key = crypto.sign.Ed25519.PublicKey.fromBytes(keypair.ed25519_public) catch unreachable;
            const ed25519_keypair = crypto.sign.Ed25519.KeyPair{
                .public_key = public_key,
                .secret_key = keypair.ed25519_private,
            };
            const signature = ed25519_keypair.sign(message, null) catch unreachable;
            return signature.toBytes();
        }

        /// Perform X25519 Diffie-Hellman key exchange
        pub fn dh(keypair: KeyPair, public_key: [32]u8) ![32]u8 {
            const public_point = crypto.ecc.Curve25519.fromBytes(public_key);

            const shared_secret = public_point.clampedMul(keypair.x25519_private) catch |err| {
                return switch (err) {
                    error.IdentityElement => error.InvalidPublicKey,
                };
            };

            return shared_secret.toBytes();
        }

        /// Verify an Ed25519 signature
        pub fn verify(public_key: [32]u8, message: []const u8, signature: [64]u8) !void {
            const sig = crypto.sign.Ed25519.Signature.fromBytes(signature);
            const pk = try crypto.sign.Ed25519.PublicKey.fromBytes(public_key);
            try sig.verify(message, pk);
        }
    };

    /// Convert Ed25519 public key to X25519 public key
    pub fn ed25519PublicToX25519(ed25519_public: [32]u8) ![32]u8 {
        const ed25519_point = crypto.ecc.Edwards25519.fromBytes(ed25519_public) catch |err| {
            return switch (err) {
                error.NonCanonical => error.InvalidPublicKey,
                error.IdentityElement => error.InvalidPublicKey,
                error.WeakPublicKey => error.WeakPublicKey,
            };
        };

        const x25519_point = crypto.ecc.Curve25519.fromEdwards25519(ed25519_point) catch |err| {
            return switch (err) {
                error.IdentityElement => error.InvalidPublicKey,
            };
        };

        return x25519_point.toBytes();
    }
};

test "XEd25519 key generation and operations" {
    const io = std.testing.io;
    // Generate a key pair
    const keypair = XEd25519.KeyPair.generate(io);

    // Test that keys are different
    try std.testing.expect(!std.mem.eql(u8, &keypair.x25519_public, &keypair.x25519_private));
    try std.testing.expect(!std.mem.eql(u8, &keypair.ed25519_public, &keypair.ed25519_private.seed()));

    // Test signing and verification
    const message = "Hello, WhatsApp!";
    const signature = keypair.sign(message);
    try XEd25519.KeyPair.verify(keypair.ed25519_public, message, signature);

    // Test that wrong message fails verification
    try std.testing.expectError(error.SignatureVerificationFailed, XEd25519.KeyPair.verify(keypair.ed25519_public, "Wrong message", signature));

    // Test DH key exchange
    const peer_keypair = XEd25519.KeyPair.generate(io);
    const shared_secret1 = try keypair.dh(peer_keypair.x25519_public);
    const shared_secret2 = try peer_keypair.dh(keypair.x25519_public);

    // Shared secrets should be the same
    try std.testing.expectEqualSlices(u8, &shared_secret1, &shared_secret2);
}

test "Ed25519 to X25519 conversion" {
    const io = std.testing.io;
    // Test the conversion functions
    const ed25519_keypair = crypto.sign.Ed25519.KeyPair.generate(io);

    // Convert public key
    const x25519_public = try XEd25519.ed25519PublicToX25519(ed25519_keypair.public_key.toBytes());

    const x25519_keypair = try crypto.dh.X25519.KeyPair.fromEd25519(ed25519_keypair);
    try std.testing.expectEqualSlices(u8, &x25519_public, &x25519_keypair.public_key);
}
