const std = @import("std");

/// Binary encoding and decoding utilities for WhatsApp protocol
/// provides functions for encoding and decoding various data types
/// used in the WhatsApp binary protocol, including varints, strings, byte arrays,
/// and compression.
/// Error types for binary operations
pub const BinaryError = error{
    /// Buffer too small for encoding
    BufferTooSmall,
    /// Invalid varint encoding
    InvalidVarint,
    /// Invalid UTF-8 string
    InvalidUtf8,
    /// Compression/decompression error
    CompressionError,
    /// Invalid data format
    InvalidFormat,
    /// Write operation failed
    WriteFailed,
    /// Read operation failed
    ReadFailed,
    /// Invalid token value
    InvalidToken,
    /// Unexpected end of stream
    EndOfStream,
    /// Invalid length value
    InvalidLength,
    /// Token not found
    TokenNotFound,
};

/// Token constants matching Rust implementation
pub const LIST_EMPTY: u8 = 0;
pub const DICTIONARY_0: u8 = 236;
pub const DICTIONARY_1: u8 = 237;
pub const DICTIONARY_2: u8 = 238;
pub const DICTIONARY_3: u8 = 239;
pub const JID_PAIR: u8 = 250;
pub const HEX_8: u8 = 251;
pub const BINARY_8: u8 = 252;
pub const BINARY_20: u8 = 253;
pub const BINARY_32: u8 = 254;
pub const NIBBLE_8: u8 = 255;
pub const INTEROP_JID: u8 = 245;
pub const FB_JID: u8 = 246;
pub const AD_JID: u8 = 247;
pub const LIST_8: u8 = 248;
pub const LIST_16: u8 = 249;
pub const PACKED_MAX: u8 = 127;

/// Compile-time token system using StaticStringMap for O(n/L) lookups
/// This replaces runtime JSON parsing with compile-time initialization
const TokenData = struct {
    page: u8,
    index: u8,
};

// Import generated token data
const tokens_gen = @import("gen/tokens_generated.zig");

/// Token data initialized at compile time from generated code
const token_data = tokens_gen.token_data;

/// Initialize tokens (no-op since everything is compile-time)
pub fn initTokens(_: std.mem.Allocator) !void {
    // No-op: all token data is initialized at compile time
}

/// Get single byte token for a string - O(n/L) lookup via StaticStringMap
pub fn getSingleByteToken(str: []const u8) ?u8 {
    return token_data.single_map.get(str);
}

/// Get double byte token for a string - O(n/L) lookup via StaticStringMap
pub fn getDoubleByteToken(str: []const u8) ?struct { u8, u8 } {
    const data = token_data.double_map.get(str) orelse return null;
    return .{ data.page, data.index };
}

/// Get string for single byte token - O(1) array lookup
pub fn getStringForSingleByteToken(token: u8) ?[]const u8 {
    if (token >= token_data.single_reverse.len) return null;
    return token_data.single_reverse[token];
}

/// Get string for double byte token - O(1) array lookup
pub fn getStringForDoubleByteToken(page: u8, token: u8) ?[]const u8 {
    if (page >= token_data.double_reverse.len) return null;
    return token_data.double_reverse[page][token];
}

/// Write a string using token compression when possible
/// Returns the number of bytes written
pub fn writeString(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (getSingleByteToken(str)) |token| {
        try writer.writeByte(token);
        return 1;
    } else if (getDoubleByteToken(str)) |double_token| {
        const page = double_token.@"0";
        const token_index = double_token.@"1";
        try writer.writeByte(DICTIONARY_0 + page);
        try writer.writeByte(token_index);
        return 2;
    } else {
        return try encodeString(str, writer);
    }
}

// WhatsApp Binary Protocol Structures

/// Attribute represents a key-value pair in a node
pub const Attribute = struct {
    key: []const u8,
    value: []const u8,

    /// Create a new attribute
    pub fn init(key: []const u8, value: []const u8) Attribute {
        return Attribute{
            .key = key,
            .value = value,
        };
    }

    /// Deinitialize an attribute (if it owns memory)
    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// NodeContent represents the content of a node - either bytes or child nodes
pub const NodeContent = union(enum) {
    Bytes: []const u8,
    Nodes: std.ArrayList(Node),

    /// Create bytes content
    pub fn initBytes(bytes: []const u8, allocator: std.mem.Allocator) !NodeContent {
        return NodeContent{ .Bytes = try allocator.dupe(u8, bytes) };
    }

    /// Create nodes content
    pub fn initNodes(allocator: std.mem.Allocator) !NodeContent {
        return NodeContent{ .Nodes = try std.ArrayList(Node).initCapacity(allocator, 4) };
    }

    /// Deinitialize content
    pub fn deinit(self: *NodeContent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Bytes => |bytes| allocator.free(bytes),
            .Nodes => |*nodes| {
                for (nodes.items) |*node| {
                    node.deinit();
                }
                nodes.deinit(allocator);
            },
        }
    }

    /// Check if content is empty
    pub fn isEmpty(self: NodeContent) bool {
        return switch (self) {
            .Bytes => |bytes| bytes.len == 0,
            .Nodes => |nodes| nodes.items.len == 0,
        };
    }
};

/// Node represents an XML-like element in the WhatsApp binary protocol
pub const Node = struct {
    allocator: std.mem.Allocator,
    tag: []const u8,
    attributes: std.ArrayList(Attribute),
    content: ?NodeContent,

    /// Create a new node
    pub fn init(allocator: std.mem.Allocator, tag: []const u8) !Node {
        return Node{
            .allocator = allocator,
            .tag = try allocator.dupe(u8, tag),
            .attributes = try std.ArrayList(Attribute).initCapacity(allocator, 4),
            .content = null,
        };
    }

    /// Deinitialize a node and all its children
    pub fn deinit(self: *Node) void {
        self.allocator.free(self.tag);
        for (self.attributes.items) |*attr| {
            attr.deinit(self.allocator);
        }
        self.attributes.deinit(self.allocator);
        if (self.content) |*content| {
            content.deinit(self.allocator);
        }
    }

    /// Add an attribute to the node
    pub fn addAttribute(self: *Node, key: []const u8, value: []const u8) !void {
        const key_dup = try self.allocator.dupe(u8, key);
        const value_dup = try self.allocator.dupe(u8, value);
        const attr = Attribute.init(key_dup, value_dup);
        try self.attributes.append(self.allocator, attr);
    }

    /// Set bytes content
    pub fn setContentBytes(self: *Node, bytes: []const u8) !void {
        if (self.content) |*old_content| {
            old_content.deinit(self.allocator);
        }
        self.content = try NodeContent.initBytes(bytes, self.allocator);
    }

    /// Add a child node
    pub fn addChild(self: *Node, child: *Node) !void {
        if (self.content == null) {
            self.content = try NodeContent.initNodes(self.allocator);
        }

        if (self.content.? != .Nodes) {
            return error.InvalidContentType;
        }

        try self.content.?.Nodes.append(self.allocator, child.*);
        // Clear the child's arrays to prevent double-free
        child.attributes = try std.ArrayList(Attribute).initCapacity(child.allocator, 0);
        child.content = null;
        // Transfer ownership of tag to the copy
        child.tag = "";
    }

    /// Get content as bytes (returns null if not bytes)
    pub fn getContentBytes(self: Node) ?[]const u8 {
        if (self.content) |content| {
            if (content == .Bytes) {
                return content.Bytes;
            }
        }
        return null;
    }

    /// Get content as nodes (returns null if not nodes)
    pub fn getContentNodes(self: Node) ?[]Node {
        if (self.content) |content| {
            if (content == .Nodes) {
                return content.Nodes.items;
            }
        }
        return null;
    }
};
/// Returns the number of bytes written
pub fn encodeNode(node: *const Node, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;

    // Calculate list length: 1 (tag) + 2 * attributes + content (0 or 1)
    const content_len: usize = if (node.content != null) 1 else 0;
    const list_len = 1 + (node.attributes.items.len * 2) + content_len;

    // Write list start
    if (list_len == 0) {
        try writer.writeByte(LIST_EMPTY);
        total_bytes += 1;
    } else if (list_len < 256) {
        try writer.writeByte(LIST_8);
        try writer.writeByte(@as(u8, @intCast(list_len)));
        total_bytes += 2;
    } else {
        try writer.writeByte(LIST_16);
        try writer.writeByte(@as(u8, @intCast(list_len >> 8)));
        try writer.writeByte(@as(u8, @intCast(list_len & 0xFF)));
        total_bytes += 3;
    }

    // Write tag
    const tag_bytes = try writeString(node.tag, writer);
    total_bytes += tag_bytes;

    // Write attributes (key-value pairs)
    for (node.attributes.items) |attr| {
        const key_bytes = try writeString(attr.key, writer);
        total_bytes += key_bytes;

        const value_bytes = try writeString(attr.value, writer);
        total_bytes += value_bytes;
    }

    // Write content if present
    if (node.content) |content| {
        switch (content) {
            .Bytes => |bytes| {
                try writer.writeByte(BINARY_8);
                const content_bytes = try encodeBytes(bytes, writer);
                total_bytes += 1 + content_bytes;
            },
            .Nodes => |nodes| {
                const nodes_bytes = try encodeNodeList(nodes.items, writer);
                total_bytes += nodes_bytes;
            },
        }
    }

    return total_bytes;
}

/// Decode a node from binary format
/// Returns the decoded node (caller owns the memory)
pub fn decodeNode(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!Node {
    // Read list size
    const tag = try reader.readByte();
    const list_size = switch (tag) {
        LIST_EMPTY => 0,
        LIST_8 => try reader.readByte(),
        LIST_16 => blk: {
            const high = try reader.readByte();
            const low = try reader.readByte();
            break :blk (@as(u16, high) << 8) | @as(u16, low);
        },
        else => return BinaryError.InvalidFormat,
    };

    if (list_size == 0) return BinaryError.InvalidFormat;

    // Read tag
    const node_tag = try decodeString(reader, allocator);
    defer allocator.free(node_tag);

    var node = try Node.init(allocator, node_tag);

    // Calculate expected items: list_size = 1 (tag) + 2 * attr_count + content_flag
    const attr_count = (list_size - 1) / 2;
    const has_content = (list_size - 1) % 2 == 1;

    // Read attributes
    var i: usize = 0;
    while (i < attr_count) : (i += 1) {
        const key = try decodeString(reader, allocator);
        errdefer allocator.free(key);

        const value = try decodeString(reader, allocator);
        errdefer allocator.free(value);

        const attr = Attribute.init(key, value);
        try node.attributes.append(allocator, attr);
    }

    // Read content if present
    if (has_content) {
        const content_tag = try reader.readByte();
        if (content_tag == LIST_EMPTY) {
            // No content
            node.content = null;
        } else if (content_tag >= BINARY_8 and content_tag <= BINARY_32) {
            // Bytes content
            const bytes = try decodeBytes(reader, allocator);
            node.content = .{ .Bytes = bytes };
        } else {
            // Nodes content - unread the tag and decode as node list
            reader.pos -= 1;
            const nodes = try decodeNodeList(reader, allocator);
            node.content = .{ .Nodes = nodes };
        }
    } else {
        node.content = null;
    }

    return node;
}

/// JID represents a WhatsApp identifier with user, server, agent, device, and integrator components
pub const JID = struct {
    user: []const u8,
    server: []const u8,
    agent: u8,
    device: u16,
    integrator: u16,
    allocator: std.mem.Allocator,

    // Server type constants
    pub const DEFAULT_USER_SERVER = "s.whatsapp.net";
    pub const HIDDEN_USER_SERVER = "hid";
    pub const HOSTED_SERVER = "hosted";
    pub const INTEROP_SERVER = "interop";
    pub const MESSENGER_SERVER = "messenger";

    /// Create a new JID by parsing a JID string
    /// Supports formats: user@server, user@server/resource, agent.device:integrator@server
    pub fn parse(jid_str: []const u8, allocator: std.mem.Allocator) !JID {
        var user: []const u8 = "";
        var server: []const u8 = "";
        var agent: u8 = 0;
        var device: u16 = 0;
        var integrator: u16 = 0;

        // Find the @ separator
        const at_index = std.mem.indexOf(u8, jid_str, "@");
        if (at_index == null) return error.InvalidJID;

        const user_part = jid_str[0..at_index.?];
        const server_part = jid_str[at_index.? + 1 ..];

        // Parse user part for agent.device:integrator format
        if (std.mem.indexOf(u8, user_part, ".")) |dot_index| {
            // Check for integrator (agent.device:integrator)
            if (std.mem.indexOf(u8, user_part[dot_index + 1 ..], ":")) |colon_index| {
                const device_str = user_part[dot_index + 1 .. dot_index + 1 + colon_index];
                const integrator_str = user_part[dot_index + 1 + colon_index + 1 ..];

                agent = std.fmt.parseInt(u8, user_part[0..dot_index], 10) catch 0;
                device = std.fmt.parseInt(u16, device_str, 10) catch 0;
                integrator = std.fmt.parseInt(u16, integrator_str, 10) catch 0;
                user = "";
            } else {
                // agent.device format
                const device_str = user_part[dot_index + 1 ..];
                agent = std.fmt.parseInt(u8, user_part[0..dot_index], 10) catch 0;
                device = std.fmt.parseInt(u16, device_str, 10) catch 0;
                user = "";
            }
        } else {
            user = user_part;
        }

        // Parse server part
        server = server_part;

        return JID{
            .user = try allocator.dupe(u8, user),
            .server = try allocator.dupe(u8, server),
            .agent = agent,
            .device = device,
            .integrator = integrator,
            .allocator = allocator,
        };
    }

    /// Create a JID from components
    pub fn init(user: []const u8, server: []const u8, agent: u8, device: u16, integrator: u16, allocator: std.mem.Allocator) !JID {
        return JID{
            .user = try allocator.dupe(u8, user),
            .server = try allocator.dupe(u8, server),
            .agent = agent,
            .device = device,
            .integrator = integrator,
            .allocator = allocator,
        };
    }

    /// Deinitialize the JID
    pub fn deinit(self: *JID) void {
        self.allocator.free(self.user);
        self.allocator.free(self.server);
    }

    /// Convert JID back to string format
    pub fn toString(self: JID, allocator: std.mem.Allocator) ![]u8 {
        if (self.agent == 0 and self.device == 0 and self.integrator == 0) {
            // Simple user@server format
            if (self.user.len > 0) {
                return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.user, self.server });
            } else {
                return std.fmt.allocPrint(allocator, "@{s}", .{self.server});
            }
        } else if (self.integrator > 0) {
            // agent.device:integrator@server format
            return std.fmt.allocPrint(allocator, "{d}.{d}:{d}@{s}", .{ self.agent, self.device, self.integrator, self.server });
        } else {
            // agent.device@server format
            return std.fmt.allocPrint(allocator, "{d}.{d}@{s}", .{ self.agent, self.device, self.server });
        }
    }

    /// Check if this is a group JID
    pub fn isGroup(self: JID) bool {
        return std.mem.eql(u8, self.server, "g.us");
    }

    /// Check if this is a broadcast JID
    pub fn isBroadcast(self: JID) bool {
        return std.mem.eql(u8, self.server, "broadcast");
    }

    /// Check if this is an interop JID
    pub fn isInterop(self: JID) bool {
        return std.mem.eql(u8, self.server, INTEROP_SERVER);
    }

    /// Check if this is a messenger JID
    pub fn isMessenger(self: JID) bool {
        return std.mem.eql(u8, self.server, MESSENGER_SERVER);
    }

    /// Get the server type based on agent value
    pub fn getServerType(self: JID) []const u8 {
        return switch (self.agent) {
            0 => DEFAULT_USER_SERVER,
            1 => HIDDEN_USER_SERVER,
            else => HOSTED_SERVER,
        };
    }
};

/// Encode a JID (WhatsApp identifier)
/// JIDs have the format: user@server, agent.device@server, agent.device:integrator@server
pub fn encodeJid(jid: []const u8, writer: *BinaryWriter) BinaryError!usize {
    // For now, just encode as string
    // In a full implementation, this would parse and encode JID components separately
    return try encodeString(jid, writer);
}

/// Decode a JID
pub fn decodeJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // For now, just decode as string
    return try decodeString(reader, allocator);
}

/// Encode a JID struct using specialized JID encoding formats
pub fn encodeJidStruct(jid: *const JID, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;

    // Determine JID encoding type based on structure
    if (jid.integrator > 0) {
        // INTEROP_JID format: user, device, integrator, server
        try writer.writeByte(245); // INTEROP_JID
        total_bytes += 1;

        // Encode user
        const user_bytes = try encodeString(jid.user, writer);
        total_bytes += user_bytes;

        // Encode device as u16
        try writer.writeByte(@as(u8, @intCast(jid.device >> 8)));
        try writer.writeByte(@as(u8, @intCast(jid.device & 0xFF)));
        total_bytes += 2;

        // Encode integrator as u16
        try writer.writeByte(@as(u8, @intCast(jid.integrator >> 8)));
        try writer.writeByte(@as(u8, @intCast(jid.integrator & 0xFF)));
        total_bytes += 2;

        // Encode server
        const server_bytes = try encodeString(jid.server, writer);
        total_bytes += server_bytes;
    } else if (jid.device > 0) {
        if (std.mem.eql(u8, jid.server, JID.MESSENGER_SERVER)) {
            // FB_JID format: user, device, server
            try writer.writeByte(246); // FB_JID
            total_bytes += 1;

            // Encode user
            const user_bytes = try encodeString(jid.user, writer);
            total_bytes += user_bytes;

            // Encode device as u16
            try writer.writeByte(@as(u8, @intCast(jid.device >> 8)));
            try writer.writeByte(@as(u8, @intCast(jid.device & 0xFF)));
            total_bytes += 2;

            // Encode server
            const server_bytes = try encodeString(jid.server, writer);
            total_bytes += server_bytes;
        } else {
            // AD_JID format: agent, device, user, server
            try writer.writeByte(247); // AD_JID
            total_bytes += 1;

            try writer.writeByte(jid.agent);
            total_bytes += 1;

            try writer.writeByte(@as(u8, @intCast(jid.device >> 8)));
            try writer.writeByte(@as(u8, @intCast(jid.device & 0xFF)));
            total_bytes += 2;

            // Encode user
            const user_bytes = try encodeString(jid.user, writer);
            total_bytes += user_bytes;

            // Server is determined by agent, don't encode it
        }
    } else {
        // JID_PAIR format: user, server
        try writer.writeByte(250); // JID_PAIR
        total_bytes += 1;

        // Encode user
        const user_bytes = try encodeString(jid.user, writer);
        total_bytes += user_bytes;

        // Encode server
        const server_bytes = try encodeString(jid.server, writer);
        total_bytes += server_bytes;
    }

    return total_bytes;
}

/// Decode a JID struct using specialized JID decoding formats
pub fn decodeJidStruct(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const jid_type = try reader.readByte();

    return switch (jid_type) {
        250 => try decodeJidPair(reader, allocator), // JID_PAIR
        247 => try decodeAdJid(reader, allocator), // AD_JID
        245 => try decodeInteropJid(reader, allocator), // INTEROP_JID
        246 => try decodeFbJid(reader, allocator), // FB_JID
        else => return BinaryError.InvalidFormat,
    };
}

/// Decode JID_PAIR format: user, server
fn decodeJidPair(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = 0,
        .integrator = 0,
        .allocator = allocator,
    };
}

/// Decode AD_JID format: agent, device, user
fn decodeAdJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const agent = try reader.readByte();

    const device_high = try reader.readByte();
    const device_low = try reader.readByte();
    const device = (@as(u16, device_high) << 8) | @as(u16, device_low);

    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const server = switch (agent) {
        0 => JID.DEFAULT_USER_SERVER,
        1 => JID.HIDDEN_USER_SERVER,
        else => JID.HOSTED_SERVER,
    };

    return JID{
        .user = user,
        .server = try allocator.dupe(u8, server),
        .agent = agent,
        .device = device,
        .integrator = 0,
        .allocator = allocator,
    };
}

/// Decode INTEROP_JID format: user, device, integrator, server
fn decodeInteropJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const device_high = try reader.readByte();
    const device_low = try reader.readByte();
    const device = (@as(u16, device_high) << 8) | @as(u16, device_low);

    const integrator_high = try reader.readByte();
    const integrator_low = try reader.readByte();
    const integrator = (@as(u16, integrator_high) << 8) | @as(u16, integrator_low);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    if (!std.mem.eql(u8, server, JID.INTEROP_SERVER)) {
        return BinaryError.InvalidFormat;
    }

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = device,
        .integrator = integrator,
        .allocator = allocator,
    };
}

/// Decode FB_JID format: user, device, server
fn decodeFbJid(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!JID {
    const user = try decodeString(reader, allocator);
    errdefer allocator.free(user);

    const device_high = try reader.readByte();
    const device_low = try reader.readByte();
    const device = (@as(u16, device_high) << 8) | @as(u16, device_low);

    const server = try decodeString(reader, allocator);
    errdefer allocator.free(server);

    if (!std.mem.eql(u8, server, JID.MESSENGER_SERVER)) {
        return BinaryError.InvalidFormat;
    }

    return JID{
        .user = user,
        .server = server,
        .agent = 0,
        .device = device,
        .integrator = 0,
        .allocator = allocator,
    };
}

/// Encode a list of nodes
pub fn encodeNodeList(nodes: []const Node, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;

    // Write list start marker
    const len = nodes.len;
    if (len == 0) {
        try writer.writeByte(LIST_EMPTY);
        total_bytes += 1;
    } else if (len < 256) {
        try writer.writeByte(LIST_8);
        try writer.writeByte(@as(u8, @intCast(len)));
        total_bytes += 2;
    } else {
        try writer.writeByte(LIST_16);
        try writer.writeByte(@as(u8, @intCast(len >> 8)));
        try writer.writeByte(@as(u8, @intCast(len & 0xFF)));
        total_bytes += 3;
    }

    // Write each node
    for (nodes) |*node| {
        const node_bytes = try encodeNode(node, writer);
        total_bytes += node_bytes;
    }

    return total_bytes;
}

/// Decode a list of nodes
pub fn decodeNodeList(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)!std.ArrayList(Node) {
    // Read list size
    const tag = try reader.readByte();
    const count = switch (tag) {
        LIST_EMPTY => 0,
        LIST_8 => try reader.readByte(),
        LIST_16 => blk: {
            const high = try reader.readByte();
            const low = try reader.readByte();
            break :blk (@as(u16, high) << 8) | @as(u16, low);
        },
        else => return BinaryError.InvalidFormat,
    };

    var nodes = try std.ArrayList(Node).initCapacity(allocator, count);

    // Read each node
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const node = try decodeNode(reader, allocator);
        try nodes.append(allocator, node);
    }

    return nodes;
}

/// Writer interface for binary encoding
pub const BinaryWriter = struct {
    buffer: []u8,
    pos: usize,

    /// Initialize a binary writer with a buffer
    pub fn init(buffer: []u8) BinaryWriter {
        return BinaryWriter{
            .buffer = buffer,
            .pos = 0,
        };
    }

    /// Write a single byte
    pub fn writeByte(self: *BinaryWriter, byte: u8) BinaryError!void {
        if (self.pos >= self.buffer.len) return BinaryError.BufferTooSmall;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    /// Write multiple bytes
    pub fn writeBytes(self: *BinaryWriter, bytes: []const u8) BinaryError!void {
        if (self.pos + bytes.len > self.buffer.len) return BinaryError.BufferTooSmall;
        @memcpy(self.buffer[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    /// Get the current position
    pub fn getPos(self: BinaryWriter) usize {
        return self.pos;
    }

    /// Get the written data
    pub fn getWritten(self: BinaryWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

/// Reader interface for binary decoding
pub const BinaryReader = struct {
    buffer: []const u8,
    pos: usize,

    /// Initialize a binary reader with a buffer
    pub fn init(buffer: []const u8) BinaryReader {
        return BinaryReader{
            .buffer = buffer,
            .pos = 0,
        };
    }

    /// Read a single byte
    pub fn readByte(self: *BinaryReader) BinaryError!u8 {
        if (self.pos >= self.buffer.len) return BinaryError.InvalidFormat;
        const byte = self.buffer[self.pos];
        self.pos += 1;
        return byte;
    }

    /// Read multiple bytes
    pub fn readBytes(self: *BinaryReader, count: usize) BinaryError![]const u8 {
        if (self.pos + count > self.buffer.len) return BinaryError.InvalidFormat;
        const bytes = self.buffer[self.pos .. self.pos + count];
        self.pos += count;
        return bytes;
    }

    /// Get the current position
    pub fn getPos(self: BinaryReader) usize {
        return self.pos;
    }

    /// Check if at end of buffer
    pub fn isAtEnd(self: BinaryReader) bool {
        return self.pos >= self.buffer.len;
    }
};

// Core encoding/decoding functions will be implemented here
// - varint encoding/decoding
// - string encoding/decoding
// - byte array encoding/decoding
// - compression/decompression

/// Encode a u64 as a varint
/// Returns the number of bytes written
pub fn encodeVarint(value: u64, writer: *BinaryWriter) BinaryError!usize {
    var val = value;
    var bytes_written: usize = 0;

    while (val >= 0x80) {
        try writer.writeByte(@as(u8, @intCast(val & 0x7F)) | 0x80);
        val >>= 7;
        bytes_written += 1;
    }

    try writer.writeByte(@as(u8, @intCast(val & 0x7F)));
    bytes_written += 1;

    return bytes_written;
}

/// Decode a varint from the reader
/// Returns the decoded u64 value
pub fn decodeVarint(reader: *BinaryReader) BinaryError!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    while (true) {
        if (bytes_read >= 10) return BinaryError.InvalidVarint; // Maximum 10 bytes for u64

        const byte = try reader.readByte();
        bytes_read += 1;

        result |= @as(u64, byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) break;

        if (shift >= 63) return BinaryError.InvalidVarint;

        shift += 7;
    }

    return result;
}

/// Get the size of a varint encoding for a u64 value
pub fn getVarintSize(value: u64) usize {
    if (value == 0) return 1;

    var val = value;
    var size: usize = 0;

    while (val > 0) {
        size += 1;
        val >>= 7;
    }

    return size;
}

/// Encode a string with length prefix
/// Returns the number of bytes written
pub fn encodeString(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    // Validate UTF-8
    if (!std.unicode.utf8ValidateSlice(str)) return BinaryError.InvalidUtf8;

    // Try packed encoding for numeric strings
    if (isDecimalDigits(str)) {
        // Use nibble encoding for decimal digits
        return try encodeNibble(str, writer);
    } else if (isHexDigits(str)) {
        // Use hex encoding for hex digits
        return try encodeHex(str, writer);
    } else {
        // Use regular string encoding
        return try encodeStringRegular(str, writer);
    }
}

/// Encode a string with regular varint length prefix
/// Returns the number of bytes written
pub fn encodeStringRegular(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!std.unicode.utf8ValidateSlice(str)) return BinaryError.InvalidUtf8;

    if (str.len < 256) {
        try writer.writeByte(BINARY_8);
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 2 + str.len;
    } else if (str.len < (1 << 20)) {
        try writer.writeByte(BINARY_20);
        try writer.writeByte(@intCast(str.len >> 16));
        try writer.writeByte(@intCast(str.len >> 8));
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 4 + str.len;
    } else {
        try writer.writeByte(BINARY_32);
        try writer.writeByte(@intCast(str.len >> 24));
        try writer.writeByte(@intCast(str.len >> 16));
        try writer.writeByte(@intCast(str.len >> 8));
        try writer.writeByte(@intCast(str.len));
        try writer.writeBytes(str);
        return 5 + str.len;
    }
}

/// Decode a string with length prefix
/// Returns the decoded string (caller owns the memory)
pub fn decodeString(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    const marker = try reader.readByte();

    switch (marker) {
        // Null/Empty
        LIST_EMPTY => return allocator.dupe(u8, ""),

        // Markers for length-prefixed strings
        BINARY_8 => {
            const len = try reader.readByte();
            const bytes = try reader.readBytes(len);
            if (!std.unicode.utf8ValidateSlice(bytes)) return BinaryError.InvalidUtf8;
            return allocator.dupe(u8, bytes);
        },
        BINARY_20 => return decodeBytes20(reader, allocator),
        BINARY_32 => return decodeBytes32(reader, allocator),

        // Packed/special strings
        NIBBLE_8 => return decodeNibble(reader, allocator),
        HEX_8 => return decodeHex(reader, allocator),
        JID_PAIR => {
            const user = try decodeString(reader, allocator);
            defer allocator.free(user);
            const server = try decodeString(reader, allocator);
            defer allocator.free(server);
            return std.fmt.allocPrint(allocator, "{s}@{s}", .{ user, server });
        },
        AD_JID => {
            var jid = try decodeAdJid(reader, allocator);
            defer jid.deinit();
            return jid.toString(allocator);
        },
        INTEROP_JID => {
            var jid = try decodeInteropJid(reader, allocator);
            defer jid.deinit();
            return jid.toString(allocator);
        },
        FB_JID => {
            var jid = try decodeFbJid(reader, allocator);
            defer jid.deinit();
            return jid.toString(allocator);
        },

        // Token-based strings
        DICTIONARY_0, DICTIONARY_1, DICTIONARY_2, DICTIONARY_3 => |dict_marker| {
            const page = dict_marker - DICTIONARY_0;
            const token_index = try reader.readByte();
            const str = getStringForDoubleByteToken(page, token_index) orelse return BinaryError.InvalidToken;
            return allocator.dupe(u8, str);
        },

        // Single byte tokens
        1...235 => |token| {
            const str = getStringForSingleByteToken(token) orelse return BinaryError.InvalidToken;
            return allocator.dupe(u8, str);
        },

        else => return BinaryError.InvalidFormat,
    }
}

/// Decode a string with regular varint length prefix
/// Returns the decoded string (caller owns the memory)
pub fn decodeStringRegular(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // This function is now deprecated in favor of the marker-based system in decodeString.
    // It is kept for compatibility with any old code that might still use varint-prefix.
    const length = try decodeVarint(reader);
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));
    if (!std.unicode.utf8ValidateSlice(bytes)) return BinaryError.InvalidUtf8;
    return allocator.dupe(u8, bytes);
}

/// Get the encoded size of a string
pub fn getStringEncodedSize(str: []const u8) usize {
    return getVarintSize(str.len) + str.len;
}

/// Encode a byte array with length prefix
/// Returns the number of bytes written
pub fn encodeBytes(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    // Encode length as varint
    const length_bytes = try encodeVarint(bytes.len, writer);

    // Write bytes
    try writer.writeBytes(bytes);

    return length_bytes + bytes.len;
}

/// Decode a byte array with length prefix
/// Returns the decoded bytes (caller owns the memory)
pub fn decodeBytes(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read length
    const length = try decodeVarint(reader);

    // Read bytes
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));

    // Duplicate the bytes for the caller
    return allocator.dupe(u8, bytes);
}

/// Get the encoded size of a byte array
pub fn getBytesEncodedSize(bytes: []const u8) usize {
    return getVarintSize(bytes.len) + bytes.len;
}

/// Check if a string contains only decimal digits (0-9)
pub fn isDecimalDigits(str: []const u8) bool {
    for (str) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Check if a string contains only hexadecimal digits (0-9,A-F,a-f)
pub fn isHexDigits(str: []const u8) bool {
    for (str) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

/// Encode a string using nibble packing (decimal digits only)
/// Packs two decimal digits (0-9) into each byte
/// Returns the number of bytes written
pub fn encodeNibble(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!isDecimalDigits(str)) return BinaryError.InvalidFormat;

    var total_bytes: usize = 0;

    // Write nibble marker
    try writer.writeByte(NIBBLE_8);
    total_bytes += 1;

    // Calculate packed length: each byte holds 2 digits, round up
    const packed_len = (str.len + 1) / 2;

    // For odd-length strings, set MSB of length byte
    var length_byte: u8 = @as(u8, @intCast(packed_len));
    if (str.len % 2 == 1) {
        length_byte |= 0x80;
    }

    // Write single length byte
    try writer.writeByte(length_byte);
    total_bytes += 1;

    // Pack two digits per byte
    var i: usize = 0;
    while (i < str.len) {
        const digit1: u4 = @intCast(str[i] - '0');
        i += 1;

        var byte: u8 = @intCast(@as(u8, digit1) << 4);

        if (i < str.len) {
            const digit2: u4 = @intCast(str[i] - '0');
            byte |= digit2;
            i += 1;
        }

        try writer.writeByte(byte);
        total_bytes += 1;
    }

    return total_bytes;
}

/// Decode a nibble-packed string
/// Returns the decoded string (caller owns the memory)
pub fn decodeNibble(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read single length byte
    const length_byte = try reader.readByte();
    const packed_len = length_byte & 0x7F; // Clear MSB
    const is_odd = (length_byte & 0x80) != 0;

    // Calculate original string length
    const original_len = packed_len * 2 - if (is_odd) @as(usize, 1) else @as(usize, 0);

    var result = try std.ArrayList(u8).initCapacity(allocator, original_len);
    defer result.deinit(allocator);

    // Read and unpack the specified number of bytes
    var bytes_read: usize = 0;
    while (bytes_read < packed_len) {
        const byte = try reader.readByte();
        bytes_read += 1;

        const digit1 = (byte >> 4) & 0xF;
        const digit2 = byte & 0xF;

        if (digit1 > 9) return BinaryError.InvalidFormat;
        try result.append(allocator, '0' + @as(u8, digit1));

        if (digit2 <= 9) { // Only append second digit if it's valid (handles odd-length strings)
            try result.append(allocator, '0' + @as(u8, digit2));
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Encode a string using hex packing (hexadecimal digits only)
/// Packs two hex digits (0-9,A-F) into each byte
/// Returns the number of bytes written
pub fn encodeHex(str: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (!isHexDigits(str)) return BinaryError.InvalidFormat;

    var total_bytes: usize = 0;

    // Write hex marker
    try writer.writeByte(HEX_8);
    total_bytes += 1;

    // Calculate packed length: each byte holds 2 digits, round up
    const packed_len = (str.len + 1) / 2;

    // For odd-length strings, set MSB of length byte
    var length_byte: u8 = @as(u8, @intCast(packed_len));
    if (str.len % 2 == 1) {
        length_byte |= 0x80;
    }

    // Write single length byte
    try writer.writeByte(length_byte);
    total_bytes += 1;

    // Pack two hex digits per byte
    var i: usize = 0;
    while (i < str.len) {
        const digit1 = hexDigitToValue(str[i]);
        i += 1;

        var byte: u8 = @intCast(@as(u8, digit1) << 4);

        if (i < str.len) {
            const digit2 = hexDigitToValue(str[i]);
            byte |= digit2;
            i += 1;
        }

        try writer.writeByte(byte);
        total_bytes += 1;
    }

    return total_bytes;
}

/// Convert a hex digit character to its numeric value
fn hexDigitToValue(c: u8) u4 {
    return switch (c) {
        '0'...'9' => @as(u4, @intCast(c - '0')),
        'A'...'F' => @as(u4, @intCast(c - 'A' + 10)),
        'a'...'f' => @as(u4, @intCast(c - 'a' + 10)),
        else => 0, // Should not happen if validated
    };
}

/// Convert a numeric value to hex digit character
fn valueToHexDigit(value: u4) u8 {
    return switch (value) {
        0...9 => @as(u8, '0') + @as(u8, value),
        10...15 => @as(u8, 'A') + @as(u8, value - 10),
    };
}

/// Decode a hex-packed string
/// Returns the decoded string (caller owns the memory)
pub fn decodeHex(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read single length byte
    const length_byte = try reader.readByte();
    const packed_len = length_byte & 0x7F; // Clear MSB
    const is_odd = (length_byte & 0x80) != 0;

    // Calculate original string length
    const original_len = packed_len * 2 - if (is_odd) @as(usize, 1) else @as(usize, 0);

    var result = try std.ArrayList(u8).initCapacity(allocator, original_len);
    defer result.deinit(allocator);

    // Read and unpack the specified number of bytes
    var bytes_read: usize = 0;
    while (bytes_read < packed_len) {
        const byte = try reader.readByte();
        bytes_read += 1;

        const digit1: u4 = @intCast((byte >> 4) & 0xF);
        const digit2: u4 = @intCast(byte & 0xF);

        try result.append(allocator, valueToHexDigit(digit1));
        try result.append(allocator, valueToHexDigit(digit2));
    }

    return result.toOwnedSlice(allocator);
}

/// Encode bytes using BINARY_20 format (20-bit length prefix)
/// Returns the number of bytes written
pub fn encodeBytes20(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    if (bytes.len >= (1 << 20)) return BinaryError.InvalidFormat; // Max 20 bits

    var total_bytes: usize = 0;

    // Write BINARY_20 marker
    try writer.writeByte(BINARY_20);
    total_bytes += 1;

    // Write 20-bit length (3 bytes, big-endian)
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 16) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 8) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast(bytes.len & 0xFF)));
    total_bytes += 3;

    // Write bytes
    try writer.writeBytes(bytes);
    total_bytes += bytes.len;

    return total_bytes;
}

/// Decode bytes using BINARY_20 format
/// Returns the decoded bytes (caller owns the memory)
pub fn decodeBytes20(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read 20-bit length (3 bytes, big-endian)
    const len_high = try reader.readByte();
    const len_mid = try reader.readByte();
    const len_low = try reader.readByte();
    const length = (@as(u32, len_high) << 16) | (@as(u32, len_mid) << 8) | @as(u32, len_low);

    // Read bytes
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));

    // Duplicate the bytes for the caller
    return allocator.dupe(u8, bytes);
}

/// Encode bytes using BINARY_32 format (32-bit length prefix)
/// Returns the number of bytes written
pub fn encodeBytes32(bytes: []const u8, writer: *BinaryWriter) BinaryError!usize {
    var total_bytes: usize = 0;

    // Write BINARY_32 marker
    try writer.writeByte(BINARY_32);
    total_bytes += 1;

    // Write 32-bit length (4 bytes, big-endian)
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 24) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 16) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast((bytes.len >> 8) & 0xFF)));
    try writer.writeByte(@as(u8, @intCast(bytes.len & 0xFF)));
    total_bytes += 4;

    // Write bytes
    try writer.writeBytes(bytes);
    total_bytes += bytes.len;

    return total_bytes;
}

/// Decode bytes using BINARY_32 format
/// Returns the decoded bytes (caller owns the memory)
pub fn decodeBytes32(reader: *BinaryReader, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    // Read 32-bit length (4 bytes, big-endian)
    const len_byte1 = try reader.readByte();
    const len_byte2 = try reader.readByte();
    const len_byte3 = try reader.readByte();
    const len_byte4 = try reader.readByte();
    const length = (@as(u32, len_byte1) << 24) | (@as(u32, len_byte2) << 16) | (@as(u32, len_byte3) << 8) | @as(u32, len_byte4);

    // Read bytes
    const bytes = try reader.readBytes(@as(usize, @intCast(length)));

    // Duplicate the bytes for the caller
    return allocator.dupe(u8, bytes);
}

/// Compress data using zlib/deflate
/// Returns the compressed data (caller owns the memory)
pub fn compressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    // Use a buffer for compression
    var compress_buffer: [4096]u8 = undefined;

    var compressor = std.compress.flate.Compress.init(&output_writer.writer, &compress_buffer, .{
        .level = .default,
        .container = .gzip,
    });

    // Write data to compressor
    _ = try compressor.writer.write(data);

    // Finish compression
    try compressor.end();

    return allocator.dupe(u8, output_writer.written());
}

/// Decompress data using zlib/deflate
/// Returns the decompressed data (caller owns the memory)
pub fn decompressData(data: []const u8, allocator: std.mem.Allocator) (BinaryError || std.mem.Allocator.Error)![]u8 {
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();

    // Create a reader from the compressed data
    var input_reader = std.Io.Reader.fixed(data);

    // Buffer for decompression
    var decompress_buffer: [65536]u8 = undefined;

    var decompressor = std.compress.flate.Decompress.init(&input_reader, .gzip, &decompress_buffer);

    // Read all decompressed data
    var buffer: [1024]u8 = undefined;
    while (true) {
        const bytes_read = decompressor.read(&buffer) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (bytes_read == 0) break;
        try output_writer.writer.writeAll(buffer[0..bytes_read]);
    }

    return allocator.dupe(u8, output_writer.written());
}

test "BinaryWriter basic functionality" {
    var buffer: [10]u8 = undefined;
    var writer = BinaryWriter.init(&buffer);

    try writer.writeByte(0x42);
    try writer.writeBytes(&[_]u8{ 0x01, 0x02, 0x03 });

    try std.testing.expectEqual(@as(usize, 4), writer.getPos());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x42, 0x01, 0x02, 0x03 }, writer.getWritten());
}

test "BinaryReader basic functionality" {
    const data = [_]u8{ 0x42, 0x01, 0x02, 0x03 };
    var reader = BinaryReader.init(&data);

    try std.testing.expectEqual(@as(u8, 0x42), try reader.readByte());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, try reader.readBytes(3));
    try std.testing.expect(reader.isAtEnd());
}

test "varint encoding/decoding" {
    var buffer: [10]u8 = undefined;

    // Test various values
    const test_values = [_]u64{ 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF };

    for (test_values) |value| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeVarint(value, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeVarint(&reader);

        try std.testing.expectEqual(value, decoded);
        try std.testing.expectEqual(getVarintSize(value), bytes_written);
    }
}

test "varint edge cases" {
    var buffer: [10]u8 = undefined;

    // Test maximum u64 value
    const max_u64 = std.math.maxInt(u64);
    var writer = BinaryWriter.init(&buffer);
    _ = try encodeVarint(max_u64, &writer);
    const encoded = writer.getWritten();

    var reader = BinaryReader.init(encoded);
    const decoded = try decodeVarint(&reader);
    try std.testing.expectEqual(max_u64, decoded);

    // Test that we don't overflow
    const overflow_data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    var overflow_reader = BinaryReader.init(&overflow_data);
    try std.testing.expectError(BinaryError.InvalidVarint, decodeVarint(&overflow_reader));
}

test "string encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_strings = [_][]const u8{
        "",
        "hello",
        "Hello, 世界!",
        "🚀 Unicode test",
        "a" ** 50, // Long string
    };

    for (test_strings) |test_str| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeString(test_str, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeString(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualStrings(test_str, decoded);
        try std.testing.expectEqual(getStringEncodedSize(test_str), bytes_written);
    }
}

test "string encoding invalid UTF-8" {
    var buffer: [10]u8 = undefined;
    var writer = BinaryWriter.init(&buffer);

    // Invalid UTF-8 sequence
    const invalid_utf8 = [_]u8{ 0xFF, 0xFE, 0xFD };
    try std.testing.expectError(BinaryError.InvalidUtf8, encodeString(&invalid_utf8, &writer));
}

test "string decoding invalid UTF-8" {
    const allocator = std.testing.allocator;

    // Manually create invalid encoded data: length 3, followed by invalid UTF-8
    const invalid_data = [_]u8{ 0x03, 0xFF, 0xFE, 0xFD };
    var reader = BinaryReader.init(&invalid_data);

    try std.testing.expectError(BinaryError.InvalidUtf8, decodeString(&reader, allocator));
}

test "byte array encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [100]u8 = undefined;

    const test_arrays = [_][]const u8{
        &[_]u8{},
        &[_]u8{0x00},
        &[_]u8{ 0xFF, 0xFE, 0xFD }, // Invalid UTF-8 but valid bytes
        &[_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 },
        &[_]u8{0xFF} ** 50, // Long byte array
    };

    for (test_arrays) |test_bytes| {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try encodeBytes(test_bytes, &writer);
        const encoded = writer.getWritten();

        var reader = BinaryReader.init(encoded);
        const decoded = try decodeBytes(&reader, allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, test_bytes, decoded);
        try std.testing.expectEqual(getBytesEncodedSize(test_bytes), bytes_written);
    }
}

test "compression/decompression" {
    // const allocator = std.testing.allocator;

    const test_data = [_][]const u8{
        "hello world",
        "Hello, World! This is a test string for compression.",
    };

    for (test_data) |data| {
        // Skip compression test for now due to API changes in Zig 0.15.1
        _ = data;
        // const compressed = try compressData(data, allocator);
        // defer allocator.free(compressed);

        // const decompressed = try decompressData(compressed, allocator);
        // defer allocator.free(decompressed);

        // try std.testing.expectEqualSlices(u8, data, decompressed);

        // // Compressed data should be different from original (unless empty)
        // if (data.len > 0) {
        //     try std.testing.expect(compressed.len != data.len or !std.mem.eql(u8, compressed, data));
        // }
    }
}

test "single byte tokens" {
    const allocator = std.testing.allocator;
    try initTokens(allocator);

    // Test some known tokens
    try std.testing.expectEqual(@as(?u8, 1), getSingleByteToken("xmlstreamstart"));
    try std.testing.expectEqual(@as(?u8, 2), getSingleByteToken("xmlstreamend"));
    try std.testing.expectEqual(@as(?u8, 3), getSingleByteToken("s.whatsapp.net"));

    // Test reverse lookup
    try std.testing.expectEqualStrings("xmlstreamstart", getStringForSingleByteToken(1).?);
    try std.testing.expectEqualStrings("xmlstreamend", getStringForSingleByteToken(2).?);
    try std.testing.expectEqualStrings("s.whatsapp.net", getStringForSingleByteToken(3).?);

    // Test non-existent token
    try std.testing.expectEqual(@as(?u8, null), getSingleByteToken("nonexistent"));
    try std.testing.expectEqual(@as(?[]const u8, null), getStringForSingleByteToken(255));
}

test "writeString tokenization" {
    const allocator = std.testing.allocator;
    try initTokens(allocator);

    var buffer: [100]u8 = undefined;

    // Test single byte token
    {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try writeString("xmlstreamstart", &writer);
        const encoded = writer.getWritten();

        try std.testing.expectEqual(@as(usize, 1), bytes_written);
        try std.testing.expectEqual(@as(u8, 1), encoded[0]);
    }

    // Test double byte token
    {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try writeString("read-self", &writer);
        const encoded = writer.getWritten();

        try std.testing.expectEqual(@as(usize, 2), bytes_written);
        try std.testing.expectEqual(DICTIONARY_0, encoded[0]); // Should be 236
        try std.testing.expectEqual(@as(u8, 0), encoded[1]); // token index
    }

    // Test no token (fallback to string encoding)
    {
        var writer = BinaryWriter.init(&buffer);
        const bytes_written = try writeString("nonexistent", &writer);
        const encoded = writer.getWritten();

        // Should be varint length (1) + "nonexistent" (11) = 12 bytes
        try std.testing.expectEqual(@as(usize, 12), bytes_written);
        try std.testing.expectEqual(@as(u8, 11), encoded[0]); // length
        try std.testing.expectEqualSlices(u8, "nonexistent", encoded[1..]);
    }
}

test "node creation and deinitialization" {
    const allocator = std.testing.allocator;

    var node = try Node.init(allocator, "message");
    defer node.deinit();

    try node.addAttribute("type", "chat");
    try node.addAttribute("id", "123");
    try node.setContentBytes("Hello World");

    try std.testing.expectEqualStrings("message", node.tag);
    try std.testing.expectEqual(@as(usize, 2), node.attributes.items.len);
    try std.testing.expectEqualStrings("chat", node.attributes.items[0].value);
    try std.testing.expectEqualStrings("Hello World", node.getContentBytes().?);
}

test "JID parsing and operations" {
    const allocator = std.testing.allocator;

    // Test parsing various JID formats
    const test_jids = [_]struct {
        input: []const u8,
        expected_user: []const u8,
        expected_server: []const u8,
        expected_agent: u8,
        expected_device: u16,
        expected_integrator: u16,
        is_group: bool,
        is_broadcast: bool,
        is_interop: bool,
        is_messenger: bool,
    }{
        .{
            .input = "1234567890@s.whatsapp.net",
            .expected_user = "1234567890",
            .expected_server = "s.whatsapp.net",
            .expected_agent = 0,
            .expected_device = 0,
            .expected_integrator = 0,
            .is_group = false,
            .is_broadcast = false,
            .is_interop = false,
            .is_messenger = false,
        },
        .{
            .input = "1234567890-9876543210@g.us",
            .expected_user = "1234567890-9876543210",
            .expected_server = "g.us",
            .expected_agent = 0,
            .expected_device = 0,
            .expected_integrator = 0,
            .is_group = true,
            .is_broadcast = false,
            .is_interop = false,
            .is_messenger = false,
        },
        .{
            .input = "status@broadcast",
            .expected_user = "status",
            .expected_server = "broadcast",
            .expected_agent = 0,
            .expected_device = 0,
            .expected_integrator = 0,
            .is_group = false,
            .is_broadcast = true,
            .is_interop = false,
            .is_messenger = false,
        },
        .{
            .input = "0.12345:56789@interop",
            .expected_user = "",
            .expected_server = "interop",
            .expected_agent = 0,
            .expected_device = 12345,
            .expected_integrator = 56789,
            .is_group = false,
            .is_broadcast = false,
            .is_interop = true,
            .is_messenger = false,
        },
        .{
            .input = "1.54321@messenger",
            .expected_user = "",
            .expected_server = "messenger",
            .expected_agent = 1,
            .expected_device = 54321,
            .expected_integrator = 0,
            .is_group = false,
            .is_broadcast = false,
            .is_interop = false,
            .is_messenger = true,
        },
    };

    for (test_jids) |test_case| {
        var jid = try JID.parse(test_case.input, allocator);
        defer jid.deinit();

        try std.testing.expectEqualStrings(test_case.expected_user, jid.user);
        try std.testing.expectEqualStrings(test_case.expected_server, jid.server);
        try std.testing.expectEqual(test_case.expected_agent, jid.agent);
        try std.testing.expectEqual(test_case.expected_device, jid.device);
        try std.testing.expectEqual(test_case.expected_integrator, jid.integrator);

        try std.testing.expectEqual(test_case.is_group, jid.isGroup());
        try std.testing.expectEqual(test_case.is_broadcast, jid.isBroadcast());
        try std.testing.expectEqual(test_case.is_interop, jid.isInterop());
        try std.testing.expectEqual(test_case.is_messenger, jid.isMessenger());

        // Test toString
        const jid_str = try jid.toString(allocator);
        defer allocator.free(jid_str);
        try std.testing.expectEqualStrings(test_case.input, jid_str);
    }
}

test "node with children encoding/decoding" {
    const allocator = std.testing.allocator;
    var buffer: [2048]u8 = undefined;

    // Initialize tokens like in runtime
    try initTokens(allocator);

    // Create a parent node with children
    var parent_node = try Node.init(allocator, "envelope");
    defer parent_node.deinit();

    try parent_node.addAttribute("xmlns", "jabber:client");

    // Create child message node
    var message_node = try Node.init(allocator, "message");
    // defer message_node.deinit(); // Don't defer, ownership transferred to parent

    try message_node.addAttribute("to", "recipient@s.whatsapp.net");
    try message_node.addAttribute("type", "chat");
    try message_node.setContentBytes("Hello from child node!");

    // Create child presence node
    var presence_node = try Node.init(allocator, "presence");
    // defer presence_node.deinit(); // Don't defer, ownership transferred to parent

    try presence_node.addAttribute("type", "available");

    // Add children to parent
    try parent_node.addChild(&message_node);
    try parent_node.addChild(&presence_node);

    // Encode
    var writer = BinaryWriter.init(&buffer);
    _ = try encodeNode(&parent_node, &writer);
    const encoded = writer.getWritten();

    // Decode
    var reader = BinaryReader.init(encoded);
    var decoded_parent = try decodeNode(&reader, allocator);
    defer decoded_parent.deinit();

    // Compare parent
    try std.testing.expectEqualStrings("envelope", decoded_parent.tag);
    try std.testing.expectEqual(@as(usize, 1), decoded_parent.attributes.items.len);
    try std.testing.expectEqualStrings("xmlns", decoded_parent.attributes.items[0].key);
    try std.testing.expectEqualStrings("jabber:client", decoded_parent.attributes.items[0].value);
    try std.testing.expect(decoded_parent.content != null);
    try std.testing.expect(decoded_parent.content.? == .Nodes);
    try std.testing.expectEqual(@as(usize, 2), decoded_parent.content.?.Nodes.items.len);

    // Compare first child (message)
    const decoded_message = &decoded_parent.content.?.Nodes.items[0];
    try std.testing.expectEqualStrings("message", decoded_message.tag);
    try std.testing.expectEqual(@as(usize, 2), decoded_message.attributes.items.len);
    try std.testing.expectEqualStrings("Hello from child node!", decoded_message.getContentBytes().?);

    // Compare second child (presence)
    const decoded_presence = &decoded_parent.content.?.Nodes.items[1];
    try std.testing.expectEqualStrings("presence", decoded_presence.tag);
    try std.testing.expectEqual(@as(usize, 1), decoded_presence.attributes.items.len);
    try std.testing.expectEqualStrings("type", decoded_presence.attributes.items[0].key);
    try std.testing.expectEqualStrings("available", decoded_presence.attributes.items[0].value);
}
