const std = @import("std");
const crypto = std.crypto;
const xed25519 = @import("xed25519");

const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Sha256 = crypto.hash.sha2.Sha256;

/// Noise protocol implementation for WhatsApp
/// Uses the XX pattern: Noise_XX_25519_AESGCM_SHA256
pub const Noise = struct {
    /// Handshake message structures (compatible with protobuf)
    pub const ServerHello = struct {
        ephemeral: ?[]const u8 = null,
        static: ?[]const u8 = null,
        payload: ?[]const u8 = null,
    };

    pub const ClientFinish = struct {
        static: ?[]const u8 = null,
        payload: ?[]const u8 = null,
    };

    /// Final keys after handshake completion
    pub const CipherPair = struct {
        write_key: [32]u8,
        read_key: [32]u8,
    };

    /// Core Noise state machine
    pub const NoiseState = struct {
        /// Handshake hash (h)
        hash: [32]u8,
        /// Chaining key / salt (ck)
        salt: [32]u8,
        /// Current encryption key
        key: [32]u8,
        /// Message counter for AES-GCM nonce
        counter: u32,
        /// Whether a cipher key has been established
        has_key: bool,

        /// Initialize with Noise protocol pattern
        pub fn init() NoiseState {
            // Pattern: "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00" (32 bytes)
            const pattern = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";
            comptime std.debug.assert(pattern.len == 32);

            return .{
                .hash = pattern[0..32].*,
                .salt = pattern[0..32].*,
                .key = [_]u8{0} ** 32,
                .counter = 0,
                .has_key = false,
            };
        }

        /// Generate 12-byte IV/nonce from counter
        /// Format: [8 zero bytes][4-byte big-endian counter]
        fn generateIv(counter: u32) [12]u8 {
            var iv = [_]u8{0} ** 12;
            std.mem.writeInt(u32, iv[8..12], counter, .big);
            return iv;
        }

        /// MixHash: h = SHA256(h || data)
        pub fn authenticate(state: *NoiseState, data: []const u8) void {
            var hasher = Sha256.init(.{});
            hasher.update(&state.hash);
            hasher.update(data);
            hasher.final(&state.hash);
        }

        /// MixKey: HKDF extract+expand, reset counter
        pub fn mixIntoKey(state: *NoiseState, ikm: []const u8) void {
            // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
            const prk = HkdfSha256.extract(&state.salt, ikm);

            // HKDF-Expand with empty info to get 64 bytes
            var okm: [64]u8 = undefined;
            HkdfSha256.expand(&okm, "", prk);

            // First 32 bytes → new salt, second 32 bytes → new key
            state.salt = okm[0..32].*;
            state.key = okm[32..64].*;
            state.counter = 0;
            state.has_key = true;
        }

        /// Encrypt plaintext with AES-256-GCM, using hash as AAD.
        /// Returns ciphertext + 16-byte tag. Authenticates ciphertext into hash.
        pub fn encryptAndAuthenticate(state: *NoiseState, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
            if (!state.has_key) return error.NoKeyEstablished;

            const iv = generateIv(state.counter);
            state.counter += 1;

            // Allocate ciphertext + tag
            const result = try allocator.alloc(u8, plaintext.len + Aes256Gcm.tag_length);
            errdefer allocator.free(result);

            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(
                result[0..plaintext.len],
                &tag,
                plaintext,
                &state.hash, // AAD = current hash
                iv,
                state.key,
            );
            @memcpy(result[plaintext.len..], &tag);

            // Authenticate the ciphertext (including tag) into hash
            state.authenticate(result);

            return result;
        }

        /// Decrypt ciphertext with AES-256-GCM, using hash as AAD.
        /// Input is ciphertext + 16-byte tag. Authenticates ciphertext into hash.
        pub fn decryptAndAuthenticate(state: *NoiseState, allocator: std.mem.Allocator, ciphertext_with_tag: []const u8) ![]u8 {
            if (!state.has_key) return error.NoKeyEstablished;
            if (ciphertext_with_tag.len < Aes256Gcm.tag_length) return error.CiphertextTooShort;

            const iv = generateIv(state.counter);
            state.counter += 1;

            const ciphertext_len = ciphertext_with_tag.len - Aes256Gcm.tag_length;
            const ciphertext = ciphertext_with_tag[0..ciphertext_len];
            const tag = ciphertext_with_tag[ciphertext_len..][0..Aes256Gcm.tag_length].*;

            const plaintext = try allocator.alloc(u8, ciphertext_len);
            errdefer allocator.free(plaintext);

            // Decrypt using current hash as AAD (BEFORE mixing ciphertext in)
            Aes256Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                &state.hash,
                iv,
                state.key,
            ) catch return error.DecryptionFailed;

            // THEN authenticate ciphertext into hash
            state.authenticate(ciphertext_with_tag);

            return plaintext;
        }

        /// Split: extract final write/read cipher keys
        pub fn split(state: *NoiseState) CipherPair {
            // HKDF with empty IKM
            const prk = HkdfSha256.extract(&state.salt, &.{});
            var okm: [64]u8 = undefined;
            HkdfSha256.expand(&okm, "", prk);

            return .{
                .write_key = okm[0..32].*,
                .read_key = okm[32..64].*,
            };
        }
    };

    /// Client-side handshake
    pub const ClientHandshake = struct {
        state: NoiseState,
        ephemeral_keypair: xed25519.XEd25519.KeyPair,
        static_keypair: xed25519.XEd25519.KeyPair,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, static_keypair: xed25519.XEd25519.KeyPair, prologue: []const u8, io: std.Io) !ClientHandshake {
            var state = NoiseState.init();
            // Authenticate prologue
            state.authenticate(prologue);

            // Generate ephemeral keypair
            const ephemeral_keypair = xed25519.XEd25519.KeyPair.generate(io);

            // Authenticate our ephemeral public key
            state.authenticate(&ephemeral_keypair.x25519_public);

            return .{
                .state = state,
                .ephemeral_keypair = ephemeral_keypair,
                .static_keypair = static_keypair,
                .allocator = allocator,
            };
        }

        /// Get the ephemeral public key for ClientHello
        pub fn createClientHello(client: *ClientHandshake) [32]u8 {
            return client.ephemeral_keypair.x25519_public;
        }

        /// Process ServerHello and create ClientFinish
        /// server_hello contains: ephemeral, encrypted static, encrypted cert chain
        /// client_payload is the encoded ClientPayload to encrypt and send
        pub fn processServerHello(client: *ClientHandshake, server_hello: ServerHello, client_payload: ?[]const u8) !ClientFinish {
            const server_ephemeral = server_hello.ephemeral orelse return error.InvalidServerHello;
            const server_static_ciphertext = server_hello.static orelse return error.InvalidServerHello;
            const server_cert_ciphertext = server_hello.payload orelse return error.InvalidServerHello;

            if (server_ephemeral.len != 32) return error.InvalidKeyLength;

            // 1. Authenticate server's ephemeral public key
            client.state.authenticate(server_ephemeral);

            // 2. DH: client_ephemeral × server_ephemeral → mix into key
            const dh1 = try client.ephemeral_keypair.dh(server_ephemeral[0..32].*);
            client.state.mixIntoKey(&dh1);

            // 3. Decrypt server's static key
            const server_static_pub = try client.state.decryptAndAuthenticate(client.allocator, server_static_ciphertext);
            defer client.allocator.free(server_static_pub);

            if (server_static_pub.len != 32) return error.InvalidKeyLength;

            // 4. DH: client_ephemeral × server_static → mix into key
            const dh2 = try client.ephemeral_keypair.dh(server_static_pub[0..32].*);
            client.state.mixIntoKey(&dh2);

            // 5. Decrypt server certificate chain (payload)
            const cert_chain = try client.state.decryptAndAuthenticate(client.allocator, server_cert_ciphertext);
            defer client.allocator.free(cert_chain);

            // TODO: Verify server certificate chain against WA root CA key
            // For now, skip verification (works against mock server)

            // 6. Encrypt our static public key
            const encrypted_static = try client.state.encryptAndAuthenticate(client.allocator, &client.static_keypair.x25519_public);

            // 7. DH: client_static × server_ephemeral → mix into key
            const dh3 = try client.static_keypair.dh(server_ephemeral[0..32].*);
            client.state.mixIntoKey(&dh3);

            // 8. Encrypt client payload
            var encrypted_payload: ?[]u8 = null;
            if (client_payload) |payload| {
                encrypted_payload = try client.state.encryptAndAuthenticate(client.allocator, payload);
            }

            return .{
                .static = encrypted_static,
                .payload = encrypted_payload,
            };
        }

        /// Extract final cipher keys after handshake completion
        pub fn finish(client: *ClientHandshake) CipherPair {
            return client.state.split();
        }
    };

    /// Server-side handshake
    pub const ServerHandshake = struct {
        state: NoiseState,
        static_keypair: xed25519.XEd25519.KeyPair,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, static_keypair: xed25519.XEd25519.KeyPair, prologue: []const u8) ServerHandshake {
            var state = NoiseState.init();
            state.authenticate(prologue);
            return .{
                .state = state,
                .static_keypair = static_keypair,
                .allocator = allocator,
            };
        }

        /// Process client hello and create server hello
        pub fn processClientHello(server: *ServerHandshake, client_ephemeral: [32]u8, io: std.Io) !ServerHello {
            // Authenticate client's ephemeral public key
            server.state.authenticate(&client_ephemeral);

            // Generate server's ephemeral key
            const ephemeral_keypair = xed25519.XEd25519.KeyPair.generate(io);

            // Authenticate server's ephemeral public key
            server.state.authenticate(&ephemeral_keypair.x25519_public);

            // DH: server_ephemeral × client_ephemeral → mix into key
            const dh1 = try ephemeral_keypair.dh(client_ephemeral);
            server.state.mixIntoKey(&dh1);

            // Encrypt server's static public key
            const encrypted_static = try server.state.encryptAndAuthenticate(server.allocator, &server.static_keypair.x25519_public);

            // DH: server_static × client_ephemeral → mix into key
            const dh2 = try server.static_keypair.dh(client_ephemeral);
            server.state.mixIntoKey(&dh2);

            // Encrypt server certificate (placeholder empty cert)
            const encrypted_cert = try server.state.encryptAndAuthenticate(server.allocator, &.{});

            return .{
                .ephemeral = server.allocator.dupe(u8, &ephemeral_keypair.x25519_public) catch null,
                .static = encrypted_static,
                .payload = encrypted_cert,
            };
        }

        /// Process client finish
        pub fn processClientFinish(server: *ServerHandshake, client_finish: ClientFinish) !void {
            const encrypted_static = client_finish.static orelse return error.InvalidClientFinish;

            // Decrypt client's static public key
            const client_static = try server.state.decryptAndAuthenticate(server.allocator, encrypted_static);
            defer server.allocator.free(client_static);

            if (client_static.len != 32) return error.InvalidKeyLength;

            // Decrypt client payload if present
            if (client_finish.payload) |payload| {
                const decrypted_payload = try server.state.decryptAndAuthenticate(server.allocator, payload);
                server.allocator.free(decrypted_payload);
            }
        }

        /// Extract final cipher keys
        pub fn finish(server: *ServerHandshake) CipherPair {
            return server.state.split();
        }
    };
};

test "Noise state - MixHash" {
    var state = Noise.NoiseState.init();
    const initial_hash = state.hash;
    state.authenticate("test data");
    // Hash should have changed
    try std.testing.expect(!std.mem.eql(u8, &initial_hash, &state.hash));
}

test "Noise state - encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;

    var state1 = Noise.NoiseState.init();
    var state2 = Noise.NoiseState.init();

    // Both states need a key - mix the same key material
    const key_material = [_]u8{0x42} ** 32;
    state1.mixIntoKey(&key_material);
    state2.mixIntoKey(&key_material);

    // Encrypt with state1
    const plaintext = "Hello, WhatsApp Noise!";
    const ciphertext = try state1.encryptAndAuthenticate(allocator, plaintext);
    defer allocator.free(ciphertext);

    // Decrypt with state2 (same initial state)
    const decrypted = try state2.decryptAndAuthenticate(allocator, ciphertext);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "Noise XX handshake" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Generate key pairs for client and server
    const client_keypair = xed25519.XEd25519.KeyPair.generate(io);
    const server_keypair = xed25519.XEd25519.KeyPair.generate(io);

    // Initialize handshakes
    const prologue = "test prologue";
    var client_handshake = try Noise.ClientHandshake.init(allocator, client_keypair, prologue, io);
    var server_handshake = Noise.ServerHandshake.init(allocator, server_keypair, prologue);

    // Client creates hello
    const client_hello = client_handshake.createClientHello();

    // Server processes hello and creates response
    const server_hello = try server_handshake.processClientHello(client_hello, io);
    defer {
        if (server_hello.ephemeral) |e| allocator.free(e);
        if (server_hello.static) |s| allocator.free(s);
        if (server_hello.payload) |p| allocator.free(p);
    }

    // Client processes server response and creates finish
    const client_finish = try client_handshake.processServerHello(server_hello, "test payload");
    defer {
        if (client_finish.static) |s| allocator.free(s);
        if (client_finish.payload) |p| allocator.free(p);
    }

    // Server processes client finish
    try server_handshake.processClientFinish(client_finish);

    // Extract final keys
    const client_keys = client_handshake.finish();
    const server_keys = server_handshake.finish();

    // Client's write key should be server's read key and vice versa
    try std.testing.expectEqualSlices(u8, &client_keys.write_key, &server_keys.read_key);
    try std.testing.expectEqualSlices(u8, &client_keys.read_key, &server_keys.write_key);
}
