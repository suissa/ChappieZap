const std = @import("std");
const binary = @import("binary");
const addressing = @import("addressing");
const signal = @import("signal");
const messaging = @import("messaging");
const session_store = @import("session_store.zig");
const pump = @import("pump.zig");
const prekey_mod = @import("prekey");
const transport = @import("transport.zig");
const stanza_log = @import("stanza_log.zig");

pub const FetchPreKeysResult = struct {
    bundle: prekey_mod.PreKeyBundle,
    route_jid: []const u8,
    route_jid_owned: ?[]u8 = null,

    pub fn deinit(self: *FetchPreKeysResult, allocator: std.mem.Allocator) void {
        if (self.route_jid_owned) |owned| allocator.free(owned);
        self.route_jid_owned = null;
    }
};

pub fn fetchPrekeys(self: anytype, jid: []const u8, PumpResult: type) !prekey_mod.PreKeyBundle {
    var result = try fetchPrekeysWithRoute(self, jid, PumpResult);
    defer result.deinit(self.allocator);
    return result.bundle;
}

pub fn fetchPrekeysWithRoute(self: anytype, jid: []const u8, PumpResult: type) !FetchPreKeysResult {
    const bundle = fetchPrekeysForJid(self, jid, PumpResult) catch |err| switch (err) {
        error.NoPreKeyBundle => {
            if (!addressing.AddressBook.isLidJid(jid)) return err;
            const fallback = try self.address_book.resolvePhoneJid(jid);
            if (std.mem.eql(u8, fallback.value, jid)) {
                fallback.deinit(self.allocator);
                return err;
            }
            return .{
                .bundle = try fetchPrekeysForJid(self, fallback.value, PumpResult),
                .route_jid = fallback.value,
                .route_jid_owned = fallback.owned,
            };
        },
        else => return err,
    };

    return .{
        .bundle = bundle,
        .route_jid = jid,
    };
}

fn fetchPrekeysForJid(self: anytype, jid: []const u8, PumpResult: type) !prekey_mod.PreKeyBundle {
    var iq_id_buf: [transport.iq_id_buffer_len]u8 = undefined;
    const iq_id = try transport.nextIqIdInto(self, &iq_id_buf);

    var fetch_iq = try messaging.buildFetchPrekeysIq(self.allocator, iq_id, &.{jid});
    defer fetch_iq.deinit();
    try transport.sendNode(self, &fetch_iq);

    var result: ?prekey_mod.PreKeyBundle = null;
    const WaitCtx = struct {
        iq_id: []const u8,
        result: *?prekey_mod.PreKeyBundle,
    };
    var wait_ctx = WaitCtx{
        .iq_id = iq_id,
        .result = &result,
    };

    try pump.pumpUntil(self, 100_000, struct {
        fn onNode(client: @TypeOf(self), ctx: *WaitCtx, node: *binary.Node) !PumpResult {
            if (std.mem.eql(u8, node.tag, "iq")) {
                const node_id = node.getAttribute("id") orelse "";
                if (stanza_log.iqIdsMatch(node_id, ctx.iq_id)) {
                    ctx.result.* = try parsePreKeyResponse(node);
                    return .done;
                }
            }
            client.processNode(node);
            return .keep_going;
        }
    }.onNode, &wait_ctx, error.PreKeyFetchTimeout);

    return result orelse error.PreKeyFetchTimeout;
}

pub fn createSession(self: anytype, jid: []const u8, bundle: prekey_mod.PreKeyBundle, PreKeyMsgParams: type) !PreKeyMsgParams {
    const created = try buildInitiatorSession(self, bundle);
    try session_store.storeSession(self, jid, created.session);
    return .{
        .registration_id = created.registration_id,
        .prekey_id = created.prekey_id,
        .signed_prekey_id = created.signed_prekey_id,
        .base_key = created.base_key,
    };
}

pub const CreatedInitiatorSession = struct {
    session: signal.Session,
    registration_id: u32,
    prekey_id: ?u32,
    signed_prekey_id: u32,
    base_key: [32]u8,
};

pub fn buildInitiatorSession(self: anytype, bundle: prekey_mod.PreKeyBundle) !CreatedInitiatorSession {
    const base_key = signal.KeyPair.generate(self.io);
    const sending_ratchet_key = signal.KeyPair.generate(self.io);
    const x3dh_result = try signal.ratchet.x3dh(
        self.identity,
        base_key,
        bundle.identity_key,
        bundle.signed_prekey_public,
        bundle.prekey_public,
    );
    const session = try signal.Session.initAsInitiator(
        self.allocator,
        x3dh_result,
        self.identity.key_pair.public,
        bundle.identity_key,
        sending_ratchet_key,
        bundle.signed_prekey_public,
        self.registration_id,
        bundle.registration_id,
    );
    return .{
        .session = session,
        .registration_id = self.registration_id,
        .prekey_id = bundle.prekey_id,
        .signed_prekey_id = bundle.signed_prekey_id,
        .base_key = base_key.public,
    };
}

pub fn parsePreKeyResponse(node: *const binary.Node) !prekey_mod.PreKeyBundle {
    const children = node.getContentNodes() orelse return error.EmptyPreKeyResponse;
    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "list")) {
            if (child.getContentNodes()) |list_children| {
                for (list_children) |*user_child| {
                    if (std.mem.eql(u8, user_child.tag, "user"))
                        return prekey_mod.parsePreKeyBundle(user_child);
                }
            }
        } else if (std.mem.eql(u8, child.tag, "user")) {
            return prekey_mod.parsePreKeyBundle(child);
        }
    }
    return error.NoPreKeyBundle;
}
