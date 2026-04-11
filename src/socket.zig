const std = @import("std");
const ws = @import("websocket_client");
const framing = @import("framing");
const log = @import("log");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const initial_ws_read_capacity = 8 * 1024;
const retained_scratch_capacity = 64 * 1024;

/// Post-handshake AES-256-GCM cipher with counter-based nonce.
/// Uses empty AAD (unlike the handshake which uses the hash as AAD).
pub const NoiseCipher = struct {
    key: [32]u8,
    counter: u32,

    pub fn init(key: [32]u8) NoiseCipher {
        return .{ .key = key, .counter = 0 };
    }

    /// Generate 12-byte IV: [8 zero bytes][4-byte BE counter]
    fn generateIv(counter: u32) [12]u8 {
        var iv = [_]u8{0} ** 12;
        std.mem.writeInt(u32, iv[8..12], counter, .big);
        return iv;
    }

    /// Encrypt plaintext, returns ciphertext + 16-byte tag. Increments counter.
    pub fn encrypt(self: *NoiseCipher, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        const iv = generateIv(self.counter);
        const result = try allocator.alloc(u8, plaintext.len + Aes256Gcm.tag_length);
        errdefer allocator.free(result);

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(result[0..plaintext.len], &tag, plaintext, &.{}, iv, self.key);
        @memcpy(result[plaintext.len..], &tag);

        self.counter +%= 1;
        return result;
    }

    /// Encrypt plaintext into a reusable buffer. Output is ciphertext followed by tag.
    pub fn encryptInto(self: *NoiseCipher, out: *std.ArrayList(u8), allocator: std.mem.Allocator, plaintext: []const u8) !void {
        const iv = generateIv(self.counter);
        resetReusableBuffer(out, allocator, plaintext.len + Aes256Gcm.tag_length, retained_scratch_capacity);
        const ciphertext = try out.addManyAsSlice(allocator, plaintext.len);

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        Aes256Gcm.encrypt(ciphertext, &tag, plaintext, &.{}, iv, self.key);
        try out.appendSlice(allocator, &tag);

        self.counter +%= 1;
    }

    /// Decrypt ciphertext + tag, returns plaintext. Increments counter.
    pub fn decrypt(self: *NoiseCipher, allocator: std.mem.Allocator, ciphertext_with_tag: []const u8) ![]u8 {
        if (ciphertext_with_tag.len < Aes256Gcm.tag_length) return error.CiphertextTooShort;

        const iv = generateIv(self.counter);
        const ct_len = ciphertext_with_tag.len - Aes256Gcm.tag_length;
        const tag = ciphertext_with_tag[ct_len..][0..Aes256Gcm.tag_length].*;

        const plaintext = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(plaintext);

        Aes256Gcm.decrypt(plaintext, ciphertext_with_tag[0..ct_len], tag, &.{}, iv, self.key) catch
            return error.DecryptionFailed;

        self.counter +%= 1;
        return plaintext;
    }

    /// Decrypt ciphertext + tag into reusable storage. Increments counter on success.
    pub fn decryptInto(
        self: *NoiseCipher,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        ciphertext_with_tag: []const u8,
    ) !void {
        if (ciphertext_with_tag.len < Aes256Gcm.tag_length) return error.CiphertextTooShort;

        const iv = generateIv(self.counter);
        const ct_len = ciphertext_with_tag.len - Aes256Gcm.tag_length;
        const tag = ciphertext_with_tag[ct_len..][0..Aes256Gcm.tag_length].*;

        resetReusableBuffer(out, allocator, ct_len, retained_scratch_capacity);
        const plaintext = try out.addManyAsSlice(allocator, ct_len);
        Aes256Gcm.decrypt(plaintext, ciphertext_with_tag[0..ct_len], tag, &.{}, iv, self.key) catch {
            out.clearRetainingCapacity();
            return error.DecryptionFailed;
        };

        self.counter +%= 1;
    }
};

/// Encrypted WebSocket transport using Noise cipher pair.
/// Handles framing (3-byte length prefix) and AES-256-GCM encryption/decryption.
/// Does NOT own the WebSocketClient — caller passes it to send/receive.
pub const NoiseSocket = struct {
    write_cipher: NoiseCipher,
    read_cipher: NoiseCipher,
    frame_decoder: framing.FrameDecoder,
    allocator: std.mem.Allocator,
    ws_read_buf: std.ArrayList(u8),
    recv_plain_buf: std.ArrayList(u8),
    send_cipher_buf: std.ArrayList(u8),
    send_frame_buf: std.ArrayList(u8),

    pub fn init(
        allocator: std.mem.Allocator,
        write_key: [32]u8,
        read_key: [32]u8,
    ) !NoiseSocket {
        const ws_read_buf = try std.ArrayList(u8).initCapacity(allocator, initial_ws_read_capacity);
        return .{
            .write_cipher = NoiseCipher.init(write_key),
            .read_cipher = NoiseCipher.init(read_key),
            .frame_decoder = framing.FrameDecoder.init(allocator),
            .allocator = allocator,
            .ws_read_buf = ws_read_buf,
            .recv_plain_buf = .empty,
            .send_cipher_buf = .empty,
            .send_frame_buf = .empty,
        };
    }

    pub fn deinit(self: *NoiseSocket) void {
        self.frame_decoder.deinit();
        self.ws_read_buf.deinit(self.allocator);
        self.recv_plain_buf.deinit(self.allocator);
        self.send_cipher_buf.deinit(self.allocator);
        self.send_frame_buf.deinit(self.allocator);
    }

    /// Send an encrypted frame over the WebSocket.
    pub fn send(self: *NoiseSocket, ws_client: *ws.WebSocketClient, plaintext: []const u8) !void {
        try self.write_cipher.encryptInto(&self.send_cipher_buf, self.allocator, plaintext);
        try framing.encodeFrameInto(&self.send_frame_buf, self.allocator, self.send_cipher_buf.items, null);

        if (log.enabled(.debug)) {
            const hex = try allocHexPreview(self.allocator, plaintext, 128);
            defer self.allocator.free(hex);
            log.debug("Transport", "--> Sending {d} bytes (plaintext {d} bytes): {s}", .{
                self.send_frame_buf.items.len,
                plaintext.len,
                hex,
            });
        }
        try ws_client.writeBinary(self.send_frame_buf.items);
        releaseLargeScratchBuffer(&self.send_cipher_buf, self.allocator, retained_scratch_capacity);
        releaseLargeScratchBuffer(&self.send_frame_buf, self.allocator, retained_scratch_capacity);
    }

    /// Receive and decrypt the next frame with optional timeout (milliseconds).
    /// Returns owned plaintext that must be freed by the caller.
    /// Returns error.Timeout if no data arrives within the timeout.
    pub fn receive(self: *NoiseSocket, ws_client: *ws.WebSocketClient) ![]u8 {
        return self.receiveWithTimeout(ws_client, null);
    }

    /// Receive and decrypt into internal reusable storage.
    /// The returned slice is invalidated by the next receive call.
    pub fn receiveBorrowed(self: *NoiseSocket, ws_client: *ws.WebSocketClient) ![]const u8 {
        return self.receiveWithTimeoutBorrowed(ws_client, null);
    }

    /// Receive with explicit timeout in milliseconds. null = no timeout.
    pub fn receiveWithTimeout(self: *NoiseSocket, ws_client: *ws.WebSocketClient, timeout_ms: ?u32) ![]u8 {
        const plaintext = try self.receiveWithTimeoutBorrowed(ws_client, timeout_ms);
        return self.allocator.dupe(u8, plaintext);
    }

    /// Receive with explicit timeout into internal reusable storage. null = no timeout.
    pub fn receiveWithTimeoutBorrowed(self: *NoiseSocket, ws_client: *ws.WebSocketClient, timeout_ms: ?u32) ![]const u8 {
        while (true) {
            if (self.frame_decoder.decodeFrame()) |frame_data| {
                const frame_len = frame_data.len;
                self.read_cipher.decryptInto(&self.recv_plain_buf, self.allocator, frame_data) catch |err| {
                    self.frame_decoder.consume(frame_len);
                    return err;
                };
                self.frame_decoder.consume(frame_len);
                return self.recv_plain_buf.items;
            }

            if (timeout_ms) |ms| {
                const ready = try ws_client.waitReadable(ms);
                if (!ready) return error.Timeout;
            }

            const msg = try ws_client.readMessageInto(&self.ws_read_buf, self.allocator) orelse
                return error.ConnectionClosed;

            if (msg.opcode != .binary) continue;

            log.debug("Transport", "<-- Received {d} bytes", .{msg.data.len});
            try self.frame_decoder.feed(msg.data);
        }
    }
};

fn resetReusableBuffer(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    needed: usize,
    max_retained: usize,
) void {
    if (out.capacity > max_retained and needed <= max_retained) {
        out.clearAndFree(allocator);
    } else {
        out.clearRetainingCapacity();
    }
}

fn releaseLargeScratchBuffer(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    max_retained: usize,
) void {
    if (out.capacity > max_retained) {
        out.clearAndFree(allocator);
    } else {
        out.clearRetainingCapacity();
    }
}

fn allocHexPreview(allocator: std.mem.Allocator, bytes: []const u8, max_bytes: usize) ![]u8 {
    const preview_len = @min(bytes.len, max_bytes);
    const suffix = if (preview_len < bytes.len) "..." else "";
    const out = try allocator.alloc(u8, preview_len * 2 + suffix.len);

    for (bytes[0..preview_len], 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch {
            @panic("allocHexPreview buffer too small");
        };
    }
    if (suffix.len != 0) @memcpy(out[preview_len * 2 ..], suffix);
    return out;
}
