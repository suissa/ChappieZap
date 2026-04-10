const std = @import("std");
const ws = @import("websocket_client");
const framing = @import("framing");
const log = @import("log");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

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
};

/// Encrypted WebSocket transport using Noise cipher pair.
/// Handles framing (3-byte length prefix) and AES-256-GCM encryption/decryption.
/// Does NOT own the WebSocketClient — caller passes it to send/receive.
pub const NoiseSocket = struct {
    write_cipher: NoiseCipher,
    read_cipher: NoiseCipher,
    frame_decoder: framing.FrameDecoder,
    allocator: std.mem.Allocator,
    ws_read_buf: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        write_key: [32]u8,
        read_key: [32]u8,
    ) !NoiseSocket {
        const ws_read_buf = try allocator.alloc(u8, 256 * 1024);
        return .{
            .write_cipher = NoiseCipher.init(write_key),
            .read_cipher = NoiseCipher.init(read_key),
            .frame_decoder = framing.FrameDecoder.init(allocator),
            .allocator = allocator,
            .ws_read_buf = ws_read_buf,
        };
    }

    pub fn deinit(self: *NoiseSocket) void {
        self.frame_decoder.deinit();
        self.allocator.free(self.ws_read_buf);
    }

    /// Send an encrypted frame over the WebSocket.
    pub fn send(self: *NoiseSocket, ws_client: *ws.WebSocketClient, plaintext: []const u8) !void {
        const ciphertext = try self.write_cipher.encrypt(self.allocator, plaintext);
        defer self.allocator.free(ciphertext);

        const frame = try framing.encodeFrame(self.allocator, ciphertext, null);
        defer self.allocator.free(frame);

        if (log.enabled(.debug)) {
            const hex = try allocHexPreview(self.allocator, plaintext, 128);
            defer self.allocator.free(hex);
            log.debug("Transport", "--> Sending {d} bytes (plaintext {d} bytes): {s}", .{
                frame.len,
                plaintext.len,
                hex,
            });
        }
        try ws_client.writeBinary(frame);
    }

    /// Receive and decrypt the next frame with optional timeout (milliseconds).
    /// Returns owned plaintext that must be freed by the caller.
    /// Returns error.Timeout if no data arrives within the timeout.
    pub fn receive(self: *NoiseSocket, ws_client: *ws.WebSocketClient) ![]u8 {
        return self.receiveWithTimeout(ws_client, null);
    }

    /// Receive with explicit timeout in milliseconds. null = no timeout.
    pub fn receiveWithTimeout(self: *NoiseSocket, ws_client: *ws.WebSocketClient, timeout_ms: ?u32) ![]u8 {
        // Set socket timeout before reading
        ws_client.setReadTimeout(timeout_ms);
        defer ws_client.setReadTimeout(null); // Clear timeout after read
        while (true) {
            if (self.frame_decoder.decodeFrame()) |frame_data| {
                const frame_copy = try self.allocator.dupe(u8, frame_data);
                self.frame_decoder.consume(frame_data.len);

                const plaintext = self.read_cipher.decrypt(self.allocator, frame_copy) catch |err| {
                    self.allocator.free(frame_copy);
                    return err;
                };
                self.allocator.free(frame_copy);
                return plaintext;
            }

            const msg = try ws_client.readMessage(self.ws_read_buf) orelse
                return error.ConnectionClosed;

            if (msg.opcode != .binary) continue;

            log.debug("Transport", "<-- Received {d} bytes", .{msg.data.len});
            try self.frame_decoder.feed(msg.data);
        }
    }
};

fn allocHexPreview(allocator: std.mem.Allocator, bytes: []const u8, max_bytes: usize) ![]u8 {
    const preview_len = @min(bytes.len, max_bytes);
    const suffix = if (preview_len < bytes.len) "..." else "";
    const out = try allocator.alloc(u8, preview_len * 2 + suffix.len);

    for (bytes[0..preview_len], 0..) |b, i| {
        _ = std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    }
    if (suffix.len != 0) @memcpy(out[preview_len * 2 ..], suffix);
    return out;
}
