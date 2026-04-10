const std = @import("std");
const jid_common = @import("jid_common");

pub const JID = struct {
    user: []const u8,
    server: []const u8,
    agent: u8,
    device: u16,
    integrator: u16,
    allocator: std.mem.Allocator,

    pub const DEFAULT_USER_SERVER = "s.whatsapp.net";
    pub const HIDDEN_USER_SERVER = "lid";
    pub const HOSTED_SERVER = "hosted";
    pub const INTEROP_SERVER = "interop";
    pub const MESSENGER_SERVER = "messenger";

    pub fn parse(jid_str: []const u8, allocator: std.mem.Allocator) !JID {
        const parts = jid_common.parse(jid_str) catch return error.InvalidJID;

        return JID{
            .user = try allocator.dupe(u8, parts.bare_user),
            .server = try allocator.dupe(u8, parts.server),
            .agent = parts.agent,
            .device = parts.device,
            .integrator = parts.integrator,
            .allocator = allocator,
        };
    }

    pub fn init(
        user: []const u8,
        server: []const u8,
        agent: u8,
        device: u16,
        integrator: u16,
        allocator: std.mem.Allocator,
    ) !JID {
        return JID{
            .user = try allocator.dupe(u8, user),
            .server = try allocator.dupe(u8, server),
            .agent = agent,
            .device = device,
            .integrator = integrator,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *JID) void {
        self.allocator.free(self.user);
        self.allocator.free(self.server);
    }

    pub fn toString(self: JID, allocator: std.mem.Allocator) ![]u8 {
        if (self.device == 0 and self.integrator == 0) {
            if (self.user.len > 0) {
                return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.user, self.server });
            }
            return allocator.dupe(u8, self.server);
        }

        if (self.user.len > 0 and self.integrator > 0) {
            return std.fmt.allocPrint(allocator, "{s}:{d}:{d}@{s}", .{
                self.user,
                self.device,
                self.integrator,
                self.server,
            });
        }

        if (self.user.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}:{d}@{s}", .{
                self.user,
                self.device,
                self.server,
            });
        }

        if (self.integrator > 0) {
            return std.fmt.allocPrint(allocator, "{d}.{d}:{d}@{s}", .{
                self.agent,
                self.device,
                self.integrator,
                self.server,
            });
        }

        if (self.agent != 0 or std.mem.eql(u8, self.server, MESSENGER_SERVER)) {
            return std.fmt.allocPrint(allocator, "{d}.{d}@{s}", .{
                self.agent,
                self.device,
                self.server,
            });
        }
        return allocator.dupe(u8, self.server);
    }

    pub fn isGroup(self: JID) bool {
        return std.mem.eql(u8, self.server, "g.us");
    }

    pub fn isBroadcast(self: JID) bool {
        return std.mem.eql(u8, self.server, "broadcast");
    }

    pub fn isInterop(self: JID) bool {
        return std.mem.eql(u8, self.server, INTEROP_SERVER);
    }

    pub fn isMessenger(self: JID) bool {
        return std.mem.eql(u8, self.server, MESSENGER_SERVER);
    }

    pub fn getServerType(self: JID) []const u8 {
        return switch (self.agent) {
            0 => DEFAULT_USER_SERVER,
            1 => HIDDEN_USER_SERVER,
            else => HOSTED_SERVER,
        };
    }
};
