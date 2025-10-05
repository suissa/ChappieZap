const std = @import("std");
const ws = @import("websocket");
const binary = @import("binary");

/// WhatsApp WebSocket client
pub const WhatsAppWebSocket = struct {
    client: ws.Client,
    allocator: std.mem.Allocator,

    /// Initialize a new WhatsApp WebSocket client
    pub fn init(allocator: std.mem.Allocator) !WhatsAppWebSocket {
        var client = try ws.Client.init(allocator, .{
            .port = 443,
            .host = "web.whatsapp.com",
            .tls = true,
        });
        errdefer client.deinit();

        return .{
            .client = client,
            .allocator = allocator,
        };
    }

    /// Deinitialize the client
    pub fn deinit(self: *WhatsAppWebSocket) void {
        self.client.deinit();
    }

    /// Connect to WhatsApp WebSocket with authentication
    pub fn connect(self: *WhatsAppWebSocket, auth_token: ?[]const u8) !void {
        // Build WebSocket URL
        var ws_url: []const u8 = undefined;
        if (auth_token) |token| {
            ws_url = try std.fmt.allocPrint(self.allocator, "/ws?token={s}", .{token});
        } else {
            ws_url = try self.allocator.dupe(u8, "/ws");
        }
        defer self.allocator.free(ws_url);

        // WhatsApp-specific headers
        const headers = try std.fmt.allocPrint(self.allocator,
            \\Host: web.whatsapp.com
            \\User-Agent: WhatsApp/2.23.20.15 W
            \\Sec-WebSocket-Version: 13
            \\Sec-WebSocket-Key: {s}
            \\Upgrade: websocket
            \\Connection: Upgrade
            \\
        , .{try self.generateWebSocketKey(self.allocator)});
        defer self.allocator.free(headers);

        // Perform WebSocket handshake
        try self.client.handshake(ws_url, .{
            .timeout_ms = 10000,
            .headers = headers,
        });

        std.debug.print("WebSocket demo: Connected to WhatsApp WebSocket\n", .{});
    }

    /// Generate a random WebSocket key for handshake
    fn generateWebSocketKey(self: *WhatsAppWebSocket, allocator: std.mem.Allocator) ![]const u8 {
        _ = self; // Not used in this implementation
        var key: [16]u8 = undefined;
        std.crypto.random.bytes(&key);

        var buffer: [28]u8 = undefined;
        const encoded_len = std.base64.standard.Encoder.encode(&buffer, &key);
        return allocator.dupe(u8, buffer[0..encoded_len]);
    }

    /// Send a binary protocol message
    pub fn sendMessage(self: *WhatsAppWebSocket, node: *const binary.Node) !void {
        // Encode the node to binary
        var buffer: [4096]u8 = undefined;
        var writer = binary.BinaryWriter.init(&buffer);
        _ = try binary.encodeNode(node, &writer);
        const encoded = writer.getWritten();

        // Send as binary WebSocket message
        try self.client.writeBin(encoded);
    }

    /// Receive a message (blocking)
    pub fn receiveMessage(self: *WhatsAppWebSocket) !?binary.Node {
        const message = (try self.client.read()) orelse return null;

        switch (message.type) {
            .binary => {
                // Decode binary protocol message
                var reader = binary.BinaryReader.init(message.data);
                const node = try binary.decodeNode(&reader, self.allocator);
                return node;
            },
            .text => {
                // Handle text messages (usually for debugging or control)
                std.debug.print("Received text message: {s}\n", .{message.data});
                return null;
            },
            .close => {
                std.debug.print("WebSocket connection closed\n", .{});
                return null;
            },
            .ping => {
                // Auto-reply to pings
                try self.client.writePong(message.data);
                return null;
            },
            .pong => {
                // Handle pong responses
                return null;
            },
        }
    }

    /// Start a background read loop
    pub fn startReadLoop(self: *WhatsAppWebSocket, handler: anytype) !std.Thread {
        return try self.client.readLoopInNewThread(handler);
    }

    /// Send authentication message
    pub fn sendAuth(self: *WhatsAppWebSocket, client_id: []const u8, client_token: []const u8, server_token: []const u8) !void {
        var auth_node = try binary.Node.init(self.allocator, "auth");
        defer auth_node.deinit();

        try auth_node.addAttribute("mechanism", "WA6B");
        try auth_node.addAttribute("user", client_id);

        // Create auth content with client token and server token
        var auth_content = std.ArrayList(u8).init(self.allocator);
        defer auth_content.deinit();

        // Add client token
        try auth_content.appendSlice(client_token);
        try auth_content.append(',');
        // Add server token
        try auth_content.appendSlice(server_token);

        try auth_node.setContentBytes(auth_content.items);

        try self.sendMessage(&auth_node);
    }

    /// Send presence update
    pub fn sendPresence(self: *WhatsAppWebSocket, presence_type: []const u8) !void {
        var presence_node = try binary.Node.init(self.allocator, "presence");
        defer presence_node.deinit();

        try presence_node.addAttribute("type", presence_type);

        try self.sendMessage(&presence_node);
    }

    /// Send IQ query
    pub fn sendIQ(self: *WhatsAppWebSocket, iq_type: []const u8, xmlns: []const u8, to: ?[]const u8) !void {
        var iq_node = try binary.Node.init(self.allocator, "iq");
        defer iq_node.deinit();

        try iq_node.addAttribute("type", iq_type);
        try iq_node.addAttribute("xmlns", xmlns);
        if (to) |to_addr| {
            try iq_node.addAttribute("to", to_addr);
        }

        try self.sendMessage(&iq_node);
    }

    /// Send a chat message
    pub fn sendChatMessage(self: *WhatsAppWebSocket, to: []const u8, message: []const u8) !void {
        var message_node = try binary.Node.init(self.allocator, "message");
        defer message_node.deinit();

        try message_node.addAttribute("to", to);
        try message_node.addAttribute("type", "chat");
        try message_node.setContentBytes(message);

        try self.sendMessage(&message_node);
    }
};

/// Example handler for processing WhatsApp messages
pub const MessageHandler = struct {
    ws_client: *WhatsAppWebSocket,

    pub fn serverMessage(self: *MessageHandler, data: []u8) !void {
        std.debug.print("Received WhatsApp message: {x}\n", .{std.fmt.fmtSliceHexLower(data)});

        // Try to decode as binary protocol message
        var reader = binary.BinaryReader.init(data);
        var decoded_node = try binary.decodeNode(&reader, self.ws_client.allocator);
        defer decoded_node.deinit();

        std.debug.print("Decoded node: tag='{s}', attributes: {}\n", .{
            decoded_node.tag,
            decoded_node.attributes.items.len,
        });

        // Handle different message types
        if (std.mem.eql(u8, decoded_node.tag, "iq")) {
            try self.handleIQ(&decoded_node);
        } else if (std.mem.eql(u8, decoded_node.tag, "message")) {
            try self.handleMessage(&decoded_node);
        } else if (std.mem.eql(u8, decoded_node.tag, "presence")) {
            try self.handlePresence(&decoded_node);
        }
    }

    fn handleIQ(self: *MessageHandler, node: *const binary.Node) !void {
        std.debug.print("Handling IQ message: {s}\n", .{node.tag});
        // Handle IQ (Info/Query) messages
        _ = self;
    }

    fn handleMessage(self: *MessageHandler, node: *const binary.Node) !void {
        std.debug.print("Handling chat message: {s}\n", .{node.tag});
        // Handle chat messages
        _ = self;
    }

    fn handlePresence(self: *MessageHandler, node: *const binary.Node) !void {
        std.debug.print("Handling presence update: {s}\n", .{node.tag});
        // Handle presence updates
        _ = self;
    }
};

/// Demo function for WebSocket functionality
pub fn demonstrateWebSocket(allocator: std.mem.Allocator) !void {
    std.debug.print("WebSocket demo: Initializing WhatsApp WebSocket client\n", .{});

    var ws_client = try WhatsAppWebSocket.init(allocator);
    defer ws_client.deinit();

    std.debug.print("WebSocket demo: Client initialized\n", .{});

    // Demonstrate creating and encoding some WhatsApp protocol messages
    std.debug.print("WebSocket demo: Demonstrating WhatsApp protocol message creation\n", .{});

    // Create a presence message
    var presence_node = try binary.Node.init(allocator, "presence");
    defer presence_node.deinit();

    try presence_node.addAttribute("type", "available");
    try presence_node.addAttribute("name", "WhatsApp Zig Client");

    var buffer: [1024]u8 = undefined;
    var writer = binary.BinaryWriter.init(&buffer);
    _ = try binary.encodeNode(&presence_node, &writer);
    const encoded = writer.getWritten();

    std.debug.print("WebSocket demo: Presence message encoded ({} bytes): ", .{encoded.len});
    for (encoded) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Create a chat message
    var chat_node = try binary.Node.init(allocator, "message");
    defer chat_node.deinit();

    try chat_node.addAttribute("to", "1234567890@s.whatsapp.net");
    try chat_node.addAttribute("type", "chat");
    try chat_node.setContentBytes("Hello from Zig WhatsApp client! 🚀");

    var chat_buffer: [1024]u8 = undefined;
    var chat_writer = binary.BinaryWriter.init(&chat_buffer);
    _ = try binary.encodeNode(&chat_node, &chat_writer);
    const chat_encoded = chat_writer.getWritten();

    std.debug.print("WebSocket demo: Chat message encoded ({} bytes): ", .{chat_encoded.len});
    for (chat_encoded) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    std.debug.print("WebSocket demo: WhatsApp WebSocket client ready for connection\n", .{});
}
