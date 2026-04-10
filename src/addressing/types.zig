const std = @import("std");

pub const ResolvedJid = struct {
    value: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: ResolvedJid, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

pub const LearnedMapping = struct {
    lid_jid: []const u8,
    pn_jid: []const u8,
};
