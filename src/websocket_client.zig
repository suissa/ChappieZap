const std = @import("std");
const Io = std.Io;
const http = std.http;
const crypto = std.crypto;

/// Minimal WebSocket client built on std.http.Client for TLS + HTTP upgrade.
/// Implements RFC 6455 framing with client-side masking.
pub const WebSocketClient = struct {
    allocator: std.mem.Allocator,
    io: Io,
    http_client: *http.Client,
    connection: ?*http.Client.Connection = null,
    custom_ca_loaded: bool = false,

    const Opcode = enum(u4) {
        continuation = 0,
        text = 1,
        binary = 2,
        connection_close = 8,
        ping = 9,
        pong = 10,
        _,
    };

    pub const Message = struct {
        opcode: Opcode,
        data: []const u8,
    };

    const Header0 = packed struct(u8) {
        opcode: Opcode,
        rsv3: u1 = 0,
        rsv2: u1 = 0,
        rsv1: u1 = 0,
        fin: bool,
    };

    const Header1 = packed struct(u8) {
        payload_len: PayloadLen,
        mask: bool,
    };

    const PayloadLen = enum(u7) {
        len16 = 126,
        len64 = 127,
        _,
    };

    pub fn init(allocator: std.mem.Allocator, io: Io) !WebSocketClient {
        const client = try allocator.create(http.Client);
        client.* = .{ .allocator = allocator, .io = io };
        return .{
            .allocator = allocator,
            .io = io,
            .http_client = client,
            .custom_ca_loaded = false,
        };
    }

    pub fn deinit(self: *WebSocketClient) void {
        if (self.connection) |conn| {
            // Remove from pool used list so client.deinit() doesn't assert
            self.http_client.connection_pool.used.remove(&conn.pool_node);
            conn.destroy(self.io);
            self.connection = null;
        }
        self.http_client.deinit();
        self.allocator.destroy(self.http_client);
    }

    /// Perform WebSocket handshake via HTTP upgrade
    pub fn connect(
        self: *WebSocketClient,
        host: []const u8,
        port: u16,
        path: []const u8,
        extra_headers: []const http.Header,
    ) !void {
        return self.connectOptions(host, port, path, extra_headers, true);
    }

    pub fn addCaCertFileAbsolute(self: *WebSocketClient, abs_cert_path: []const u8) !void {
        if (self.custom_ca_loaded) return;
        try self.http_client.ca_bundle.addCertsFromFilePathAbsolute(
            self.allocator,
            self.io,
            std.Io.Clock.real.now(self.io),
            abs_cert_path,
        );
        self.custom_ca_loaded = true;
    }

    /// Perform WebSocket handshake with configurable TLS
    pub fn connectOptions(
        self: *WebSocketClient,
        host: []const u8,
        port: u16,
        path: []const u8,
        extra_headers: []const http.Header,
        tls: bool,
    ) !void {
        // Generate WebSocket key
        var key_bytes: [16]u8 = undefined;
        self.io.random(&key_bytes);
        var ws_key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&ws_key, &key_bytes);

        // Build URI
        var uri_buf: [512]u8 = undefined;
        const scheme = if (tls) "wss" else "ws";
        const uri_str = std.fmt.bufPrint(&uri_buf, "{s}://{s}:{d}{s}", .{ scheme, host, port, path }) catch return error.UriTooLong;
        const uri = std.Uri.parse(uri_str) catch return error.InvalidUri;

        // Prepare headers for WebSocket upgrade
        var all_headers: [16]http.Header = undefined;
        var header_count: usize = 0;

        all_headers[header_count] = .{ .name = "Upgrade", .value = "websocket" };
        header_count += 1;
        all_headers[header_count] = .{ .name = "Sec-WebSocket-Version", .value = "13" };
        header_count += 1;
        all_headers[header_count] = .{ .name = "Sec-WebSocket-Key", .value = &ws_key };
        header_count += 1;

        for (extra_headers) |h| {
            if (header_count >= all_headers.len) break;
            all_headers[header_count] = h;
            header_count += 1;
        }

        var req = try self.http_client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = true,
            .headers = .{
                .connection = .{ .override = "Upgrade" },
            },
            .extra_headers = all_headers[0..header_count],
        });
        errdefer req.deinit();

        try req.sendBodiless();

        var redirect_buf: [0]u8 = .{};
        const response = try req.receiveHead(&redirect_buf);

        if (response.head.status != .switching_protocols) {
            return error.WebSocketUpgradeFailed;
        }

        // Steal the connection from the request
        const conn = req.connection.?;
        req.connection = null;

        // Add to pool used list was done by the HTTP client during request.
        // We already removed req.connection, so req.deinit won't touch it.
        // But it's still in the pool's used list from connectTcp.
        // We'll track it ourselves.
        req.deinit();
        errdefer {
            self.http_client.connection_pool.used.remove(&conn.pool_node);
            conn.destroy(self.io);
        }

        self.connection = conn;
    }

    /// Send a binary WebSocket frame (client-masked per RFC 6455)
    pub fn writeBinary(self: *WebSocketClient, data: []const u8) !void {
        try self.writeFrame(data, .binary);
    }

    /// Send a text WebSocket frame
    pub fn writeText(self: *WebSocketClient, data: []const u8) !void {
        try self.writeFrame(data, .text);
    }

    /// Send a pong frame
    pub fn writePong(self: *WebSocketClient, data: []const u8) !void {
        try self.writeFrame(data, .pong);
    }

    /// Send a close frame
    pub fn writeClose(self: *WebSocketClient) !void {
        try self.writeFrame(&.{}, .connection_close);
    }

    fn writeFrame(self: *WebSocketClient, data: []const u8, opcode: Opcode) !void {
        const conn = self.connection orelse return error.NotConnected;
        const w = conn.writer();

        // Header byte 0: FIN + opcode
        try w.writeByte(@bitCast(Header0{ .opcode = opcode, .fin = true }));

        // Header byte 1: MASK=1 + payload length
        if (data.len < 126) {
            try w.writeByte(@bitCast(Header1{
                .payload_len = @enumFromInt(@as(u7, @intCast(data.len))),
                .mask = true,
            }));
        } else if (data.len <= 65535) {
            try w.writeByte(@bitCast(Header1{ .payload_len = .len16, .mask = true }));
            try w.writeInt(u16, @intCast(data.len), .big);
        } else {
            try w.writeByte(@bitCast(Header1{ .payload_len = .len64, .mask = true }));
            try w.writeInt(u64, @intCast(data.len), .big);
        }

        // Generate and write 4-byte mask key
        var mask_key: [4]u8 = undefined;
        self.io.random(&mask_key);
        try w.writeAll(&mask_key);

        // Write masked payload
        // Process in chunks that fit the writer buffer
        var offset: usize = 0;
        while (offset < data.len) {
            const remaining = data.len - offset;
            const chunk_size = @min(remaining, 4096);
            var chunk_buf: [4096]u8 = undefined;
            const chunk = chunk_buf[0..chunk_size];

            for (0..chunk_size) |i| {
                chunk[i] = data[offset + i] ^ mask_key[(offset + i) % 4];
            }

            try w.writeAll(chunk);
            offset += chunk_size;
        }

        try conn.flush();
    }

    /// Set a read timeout on the underlying socket (SO_RCVTIMEO).
    /// Pass null to clear the timeout.
    pub fn setReadTimeout(self: *WebSocketClient, timeout_ms: ?u32) void {
        const conn = self.connection orelse return;
        const fd = conn.stream_reader.stream.socket.handle;
        if (timeout_ms) |ms| {
            const tv = std.posix.timeval{
                .sec = @intCast(ms / 1000),
                .usec = @intCast((ms % 1000) * 1000),
            };
            std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        } else {
            const tv = std.posix.timeval{ .sec = 0, .usec = 0 };
            std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        }
    }

    /// Read the next WebSocket message from the server.
    /// Server frames are unmasked per RFC 6455.
    /// Returns null on connection close.
    pub fn readMessage(self: *WebSocketClient, buf: []u8) !?Message {
        const conn = self.connection orelse return error.NotConnected;
        const r = conn.reader();

        while (true) {
            // Read 2-byte header
            const header = try r.takeArray(2);
            const h0: Header0 = @bitCast(header[0]);
            const h1: Header1 = @bitCast(header[1]);

            // Determine payload length
            const payload_len: u64 = switch (h1.payload_len) {
                .len16 => try r.takeInt(u16, .big),
                .len64 => try r.takeInt(u64, .big),
                else => @intFromEnum(h1.payload_len),
            };

            if (payload_len > buf.len) return error.MessageTooLarge;
            const len: usize = @intCast(payload_len);

            // Read mask key if present (server frames should NOT be masked, but handle it)
            var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
            if (h1.mask) {
                const mk = try r.takeArray(4);
                mask_key = mk.*;
            }

            // Read payload. Using readSliceAll avoids large peek() calls that can
            // violate the TLS reader's internal buffer assumptions on big frames.
            r.readSliceAll(buf[0..len]) catch |err| switch (err) {
                error.EndOfStream => return error.ConnectionClosed,
                else => return err,
            };

            // Unmask if needed
            if (h1.mask) {
                for (0..len) |i| {
                    buf[i] ^= mask_key[i % 4];
                }
            }

            // Handle control frames
            switch (h0.opcode) {
                .ping => {
                    try self.writePong(buf[0..len]);
                    continue; // Read next frame
                },
                .pong => continue, // Ignore pongs
                .connection_close => return null,
                else => return .{
                    .opcode = h0.opcode,
                    .data = buf[0..len],
                },
            }
        }
    }
};
