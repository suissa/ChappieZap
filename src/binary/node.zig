const std = @import("std");

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
    key_owned: bool,
    value_owned: bool,

    pub fn init(key: []const u8, value: []const u8) Attribute {
        return .{
            .key = key,
            .value = value,
            .key_owned = true,
            .value_owned = true,
        };
    }

    pub fn initBorrowed(key: []const u8, value: []const u8) Attribute {
        return .{
            .key = key,
            .value = value,
            .key_owned = false,
            .value_owned = false,
        };
    }

    pub fn initMixed(key: []const u8, key_owned: bool, value: []const u8, value_owned: bool) Attribute {
        return .{
            .key = key,
            .value = value,
            .key_owned = key_owned,
            .value_owned = value_owned,
        };
    }

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        if (self.key_owned) allocator.free(self.key);
        if (self.value_owned) allocator.free(self.value);
    }
};

pub const ByteContent = struct {
    bytes: []const u8,
    owned: bool,
};

pub const NodeContent = union(enum) {
    Bytes: ByteContent,
    Nodes: std.ArrayList(Node),

    pub fn initBytes(bytes: []const u8, allocator: std.mem.Allocator) !NodeContent {
        return .{ .Bytes = .{
            .bytes = try allocator.dupe(u8, bytes),
            .owned = true,
        } };
    }

    pub fn initBytesOwned(bytes: []const u8) NodeContent {
        return .{ .Bytes = .{
            .bytes = bytes,
            .owned = true,
        } };
    }

    pub fn initBytesBorrowed(bytes: []const u8) NodeContent {
        return .{ .Bytes = .{
            .bytes = bytes,
            .owned = false,
        } };
    }

    pub fn initNodes(allocator: std.mem.Allocator) !NodeContent {
        _ = allocator;
        return .{ .Nodes = .empty };
    }

    pub fn deinit(self: *NodeContent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Bytes => |bytes| if (bytes.owned) allocator.free(bytes.bytes),
            .Nodes => |*nodes| {
                for (nodes.items) |*node| node.deinit();
                nodes.deinit(allocator);
            },
        }
    }

    pub fn isEmpty(self: NodeContent) bool {
        return switch (self) {
            .Bytes => |bytes| bytes.bytes.len == 0,
            .Nodes => |nodes| nodes.items.len == 0,
        };
    }
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    tag: []const u8,
    tag_owned: bool,
    attributes: std.ArrayList(Attribute),
    content: ?NodeContent,

    pub fn init(allocator: std.mem.Allocator, tag: []const u8) !Node {
        return .{
            .allocator = allocator,
            .tag = try allocator.dupe(u8, tag),
            .tag_owned = true,
            .attributes = .empty,
            .content = null,
        };
    }

    pub fn initOwned(allocator: std.mem.Allocator, tag: []const u8) Node {
        return .{
            .allocator = allocator,
            .tag = tag,
            .tag_owned = true,
            .attributes = .empty,
            .content = null,
        };
    }

    pub fn initBorrowed(allocator: std.mem.Allocator, tag: []const u8) Node {
        return .{
            .allocator = allocator,
            .tag = tag,
            .tag_owned = false,
            .attributes = .empty,
            .content = null,
        };
    }

    pub fn deinit(self: *Node) void {
        if (self.tag_owned) self.allocator.free(self.tag);
        for (self.attributes.items) |*attr| attr.deinit(self.allocator);
        self.attributes.deinit(self.allocator);
        if (self.content) |*content| content.deinit(self.allocator);
    }

    pub fn addAttribute(self: *Node, key: []const u8, value: []const u8) !void {
        const key_dup = try self.allocator.dupe(u8, key);
        const value_dup = try self.allocator.dupe(u8, value);
        try self.attributes.append(self.allocator, Attribute.init(key_dup, value_dup));
    }

    pub fn addAttributeBorrowed(self: *Node, key: []const u8, value: []const u8) !void {
        try self.attributes.append(self.allocator, Attribute.initBorrowed(key, value));
    }

    pub fn addAttributeOwned(self: *Node, key: []const u8, value: []const u8) !void {
        try self.attributes.append(self.allocator, Attribute.init(key, value));
    }

    pub fn addAttributeMixed(
        self: *Node,
        key: []const u8,
        key_owned: bool,
        value: []const u8,
        value_owned: bool,
    ) !void {
        try self.attributes.append(
            self.allocator,
            Attribute.initMixed(key, key_owned, value, value_owned),
        );
    }

    pub fn setContentBytes(self: *Node, bytes: []const u8) !void {
        if (self.content) |*old_content| old_content.deinit(self.allocator);
        self.content = try NodeContent.initBytes(bytes, self.allocator);
    }

    pub fn setContentBytesBorrowed(self: *Node, bytes: []const u8) !void {
        if (self.content) |*old_content| old_content.deinit(self.allocator);
        self.content = NodeContent.initBytesBorrowed(bytes);
    }

    pub fn setContentBytesOwned(self: *Node, bytes: []const u8) !void {
        if (self.content) |*old_content| old_content.deinit(self.allocator);
        self.content = NodeContent.initBytesOwned(bytes);
    }

    pub fn ensureAttributeCapacity(self: *Node, total_count: usize) !void {
        try self.attributes.ensureTotalCapacity(self.allocator, total_count);
    }

    pub fn ensureChildCapacity(self: *Node, total_count: usize) !void {
        if (self.content == null) {
            self.content = .{ .Nodes = try std.ArrayList(Node).initCapacity(self.allocator, total_count) };
            return;
        }

        if (self.content.? != .Nodes) {
            return error.InvalidContentType;
        }

        try self.content.?.Nodes.ensureTotalCapacity(self.allocator, total_count);
    }

    pub fn addChild(self: *Node, child: *Node) !void {
        if (self.content == null) {
            self.content = try NodeContent.initNodes(self.allocator);
        }

        if (self.content.? != .Nodes) {
            return error.InvalidContentType;
        }

        try self.content.?.Nodes.append(self.allocator, child.*);
        child.attributes = .empty;
        child.content = null;
        child.tag = "";
        child.tag_owned = false;
    }

    pub fn getContentBytes(self: Node) ?[]const u8 {
        if (self.content) |content| {
            if (content == .Bytes) return content.Bytes.bytes;
        }
        return null;
    }

    pub fn getContentNodes(self: Node) ?[]Node {
        if (self.content) |content| {
            if (content == .Nodes) return content.Nodes.items;
        }
        return null;
    }

    pub fn getAttribute(self: Node, key: []const u8) ?[]const u8 {
        for (self.attributes.items) |attr| {
            if (std.mem.eql(u8, attr.key, key)) return attr.value;
        }
        return null;
    }
};
