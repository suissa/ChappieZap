const std = @import("std");
const binary = @import("binary");
const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

pub const ReportingContext = struct {
    message_secret: [32]u8,
    reporting_token: [16]u8,
    version: i32 = 2,
};

pub fn generateReportingContextForText(
    encode_text_fn: anytype,
    allocator: std.mem.Allocator,
    io: std.Io,
    text: []const u8,
    stanza_id: []const u8,
    sender_jid: []const u8,
    remote_jid: []const u8,
) !ReportingContext {
    var message_secret: [32]u8 = undefined;
    io.random(&message_secret);

    const content = try encode_text_fn(allocator, text);
    defer allocator.free(content);

    var info = std.ArrayList(u8).empty;
    defer info.deinit(allocator);
    try info.appendSlice(allocator, stanza_id);
    try info.appendSlice(allocator, sender_jid);
    try info.appendSlice(allocator, remote_jid);
    try info.appendSlice(allocator, "Report Token");

    const prk = HkdfSha256.extract("", &message_secret);
    var key: [32]u8 = undefined;
    HkdfSha256.expand(&key, info.items, prk);

    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, content, &key);

    var token: [16]u8 = undefined;
    @memcpy(&token, mac[0..16]);

    return .{
        .message_secret = message_secret,
        .reporting_token = token,
    };
}

pub fn buildReportingNode(
    allocator: std.mem.Allocator,
    reporting: *const ReportingContext,
) !binary.Node {
    var reporting_node = binary.Node.initBorrowed(allocator, "reporting");
    errdefer reporting_node.deinit();

    var token_node = binary.Node.initBorrowed(allocator, "reporting_token");
    errdefer token_node.deinit();
    try token_node.addAttributeBorrowed("v", "2");
    try token_node.setContentBytesBorrowed(&reporting.reporting_token);
    try reporting_node.addChild(&token_node);
    return reporting_node;
}
