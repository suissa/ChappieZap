const std = @import("std");
const crypto = std.crypto;
const keys = @import("keys.zig");
const ratchet = @import("ratchet.zig");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes256 = crypto.core.aes.Aes256;

/// Signal protocol session state
pub const Session = struct {
    allocator: std.mem.Allocator,

    // Identity keys
    local_identity_public: [32]u8,
    remote_identity_public: [32]u8,

    // Ratchet state
    root_key: ratchet.RootKey,
    sending_chain: ?ratchet.ChainKey,
    receiving_chain: ?ratchet.ChainKey,
    our_ratchet_key: ?keys.KeyPair,
    their_ratchet_key: ?[32]u8,

    // Counters
    previous_counter: u32,

    // Registration
    local_registration_id: u32,
    remote_registration_id: u32,

    pub fn deinit(self: *Session) void {
        _ = self;
    }

    /// Initialize a session as the initiator (Alice) using X3DH results
    pub fn initAsInitiator(
        allocator: std.mem.Allocator,
        x3dh_result: ratchet.X3DHResult,
        our_identity_public: [32]u8,
        their_identity_public: [32]u8,
        our_ratchet_key: keys.KeyPair,
        their_ratchet_key: [32]u8,
        local_reg_id: u32,
        remote_reg_id: u32,
    ) !Session {
        // Perform the first DH ratchet step
        const dh = try our_ratchet_key.dh(their_ratchet_key);
        const step = x3dh_result.root_key.ratchetStep(dh);

        return .{
            .allocator = allocator,
            .local_identity_public = our_identity_public,
            .remote_identity_public = their_identity_public,
            .root_key = step.root_key,
            .sending_chain = step.chain_key,
            .receiving_chain = x3dh_result.chain_key,
            .our_ratchet_key = our_ratchet_key,
            .their_ratchet_key = their_ratchet_key,
            .previous_counter = 0,
            .local_registration_id = local_reg_id,
            .remote_registration_id = remote_reg_id,
        };
    }

    /// Initialize a session as the responder (Bob) from a PreKeySignalMessage
    pub fn initAsResponder(
        allocator: std.mem.Allocator,
        x3dh_result: ratchet.X3DHResult,
        our_identity_public: [32]u8,
        their_identity_public: [32]u8,
        our_signed_prekey: keys.KeyPair,
        local_reg_id: u32,
        remote_reg_id: u32,
    ) Session {
        return .{
            .allocator = allocator,
            .local_identity_public = our_identity_public,
            .remote_identity_public = their_identity_public,
            .root_key = x3dh_result.root_key,
            .sending_chain = null, // Will be created on first send (DH ratchet)
            .receiving_chain = x3dh_result.chain_key,
            .our_ratchet_key = our_signed_prekey,
            .their_ratchet_key = null, // Set when receiving a message
            .previous_counter = 0,
            .local_registration_id = local_reg_id,
            .remote_registration_id = remote_reg_id,
        };
    }

    /// Encrypt a message using this session
    pub fn encrypt(self: *Session, allocator: std.mem.Allocator, plaintext: []const u8, io: std.Io) !EncryptedMessage {
        if (self.sending_chain == null) {
            // Need to perform DH ratchet step first
            const new_kp = keys.KeyPair.generate(io);
            if (self.their_ratchet_key) |their_key| {
                const dh = try new_kp.dh(their_key);
                const step = self.root_key.ratchetStep(dh);
                self.root_key = step.root_key;
                self.sending_chain = step.chain_key;
                self.our_ratchet_key = new_kp;
            } else return error.NoRemoteRatchetKey;
        }
        var chain = self.sending_chain.?;

        // Step the chain to get message keys
        const stepped = chain.step();
        self.sending_chain = stepped.next;

        const msg_keys = ratchet.MessageKeys.derive(stepped.message_key_material, stepped.next.index - 1);

        // Pad plaintext (PKCS7-style: pad byte = pad length, at least 1)
        var pad_len_byte: [1]u8 = undefined;
        io.random(&pad_len_byte);
        const pad_len: u8 = (pad_len_byte[0] % 15) + 1; // 1-15
        const padded = try allocator.alloc(u8, plaintext.len + pad_len);
        defer allocator.free(padded);
        @memcpy(padded[0..plaintext.len], plaintext);
        @memset(padded[plaintext.len..], pad_len);

        // AES-256-CBC encrypt
        const ciphertext = try aesCbcEncrypt(allocator, &msg_keys.cipher_key, &msg_keys.iv, padded);

        return .{
            .ratchet_key = self.our_ratchet_key.?.public,
            .counter = msg_keys.index,
            .previous_counter = self.previous_counter,
            .ciphertext = ciphertext,
            .sender_identity = self.local_identity_public,
            .receiver_identity = self.remote_identity_public,
            .mac_key = msg_keys.mac_key,
        };
    }

    /// Decrypt a message using this session
    pub fn decrypt(self: *Session, allocator: std.mem.Allocator, msg: *const EncryptedMessage, io: std.Io) ![]u8 {
        // Check if we need to DH ratchet (new ratchet key from sender)
        const need_ratchet = self.their_ratchet_key == null or
            !std.mem.eql(u8, &(self.their_ratchet_key.?), &msg.ratchet_key);

        if (need_ratchet) {
            // Save previous counter
            if (self.sending_chain) |sc| {
                self.previous_counter = sc.index;
            }

            // DH ratchet with their new key
            self.their_ratchet_key = msg.ratchet_key;

            if (self.our_ratchet_key) |our_key| {
                const dh1 = try our_key.dh(msg.ratchet_key);
                const step1 = self.root_key.ratchetStep(dh1);
                self.root_key = step1.root_key;
                self.receiving_chain = step1.chain_key;

                // Generate new sending ratchet
                const new_kp = keys.KeyPair.generate(io);
                const dh2 = try new_kp.dh(msg.ratchet_key);
                const step2 = self.root_key.ratchetStep(dh2);
                self.root_key = step2.root_key;
                self.sending_chain = step2.chain_key;
                self.our_ratchet_key = new_kp;
            }
        }

        // Step chain to the right index
        var chain = self.receiving_chain orelse return error.NoReceivingChain;
        while (chain.index < msg.counter) {
            const stepped = chain.step();
            chain = stepped.next;
            // TODO: store skipped message keys for out-of-order delivery
        }

        const stepped = chain.step();
        self.receiving_chain = stepped.next;

        const msg_keys = ratchet.MessageKeys.derive(stepped.message_key_material, msg.counter);

        // AES-256-CBC decrypt
        const padded = try aesCbcDecrypt(allocator, &msg_keys.cipher_key, &msg_keys.iv, msg.ciphertext);
        defer allocator.free(padded);

        // Remove PKCS7 padding
        if (padded.len == 0) return error.InvalidPadding;
        const pad_len = padded[padded.len - 1];
        if (pad_len == 0 or pad_len > 16 or pad_len > padded.len) return error.InvalidPadding;

        return allocator.dupe(u8, padded[0 .. padded.len - pad_len]);
    }
};

/// Encrypted message data (before serialization)
pub const EncryptedMessage = struct {
    ratchet_key: [32]u8,
    counter: u32,
    previous_counter: u32,
    ciphertext: []u8, // Owned
    sender_identity: [32]u8,
    receiver_identity: [32]u8,
    mac_key: [32]u8,

    pub fn deinit(self: *EncryptedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
    }

    /// Compute 8-byte truncated HMAC
    pub fn computeMac(self: *const EncryptedMessage, serialized_msg: []const u8) [8]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var hmac = HmacSha256.init(&self.mac_key);
        hmac.update(&self.sender_identity);
        hmac.update(&self.receiver_identity);
        hmac.update(serialized_msg);
        hmac.final(&mac);
        return mac[0..8].*;
    }
};

// --- AES-256-CBC ---

fn aesCbcEncrypt(allocator: std.mem.Allocator, key: *const [32]u8, iv: *const [16]u8, plaintext: []const u8) ![]u8 {
    const block_size = 16;
    // PKCS7 padding: always add 1-16 bytes so result is a multiple of block_size
    const pad: u8 = @intCast(block_size - (plaintext.len % block_size));
    const padded_len = plaintext.len + pad;

    const result = try allocator.alloc(u8, padded_len);
    errdefer allocator.free(result);

    @memcpy(result[0..plaintext.len], plaintext);
    @memset(result[plaintext.len..], pad);

    const cipher = Aes256.initEnc(key.*);
    var prev_block: [16]u8 = iv.*;

    var i: usize = 0;
    while (i < padded_len) : (i += block_size) {
        var block: [16]u8 = result[i..][0..16].*;
        for (0..16) |j| block[j] ^= prev_block[j];
        var encrypted: [16]u8 = undefined;
        cipher.encrypt(&encrypted, &block);
        @memcpy(result[i..][0..16], &encrypted);
        prev_block = encrypted;
    }

    return result;
}

fn aesCbcDecrypt(allocator: std.mem.Allocator, key: *const [32]u8, iv: *const [16]u8, ciphertext: []const u8) ![]u8 {
    const block_size = 16;
    if (ciphertext.len == 0 or ciphertext.len % block_size != 0) return error.InvalidCiphertext;

    const buf = try allocator.alloc(u8, ciphertext.len);

    const cipher = Aes256.initDec(key.*);
    var prev_block: [16]u8 = iv.*;

    var i: usize = 0;
    while (i < ciphertext.len) : (i += block_size) {
        const ct_block: [16]u8 = ciphertext[i..][0..16].*;
        var decrypted: [16]u8 = undefined;
        cipher.decrypt(&decrypted, &ct_block);
        var plain_block: [16]u8 = decrypted;
        for (0..16) |j| plain_block[j] ^= prev_block[j];
        @memcpy(buf[i..][0..16], &plain_block);
        prev_block = ct_block;
    }

    // Remove PKCS7 padding
    const pad = buf[ciphertext.len - 1];
    if (pad == 0 or pad > block_size) {
        allocator.free(buf);
        return error.InvalidPadding;
    }
    for (buf[ciphertext.len - pad ..]) |b| {
        if (b != pad) {
            allocator.free(buf);
            return error.InvalidPadding;
        }
    }
    const unpadded_len = ciphertext.len - pad;
    const result = allocator.dupe(u8, buf[0..unpadded_len]) catch |e| {
        allocator.free(buf);
        return e;
    };
    allocator.free(buf);
    return result;
}
