const std = @import("std");
const pair_mod = @import("pair");
const whatsapp = @import("whatsapp_proto");
const stanza_log = @import("stanza_log.zig");
const log = @import("log");

const base_user_agent = whatsapp.ClientPayload.UserAgent{
    .platform = .WEB,
    .releaseChannel = .RELEASE,
    .appVersion = .{},
    .mcc = "000",
    .mnc = "000",
    .osVersion = "0.1.0",
    .manufacturer = "",
    .device = "Desktop",
    .osBuildNumber = "0.1.0",
    .localeLanguageIso6391 = "en",
    .localeCountryIso31661Alpha2 = "en",
};

pub fn buildPairingPayload(self: anytype) ![]u8 {
    const pd = try pair_mod.buildPairingData(
        self.identity,
        self.signed_prekey,
        self.registration_id,
        self.app_version,
    );

    const ident_hex = stanza_log.shortHex(pd.e_ident[0..8]);
    const skey_pub_hex = stanza_log.shortHex(pd.e_skey_val[0..8]);
    const skey_sig_hex = stanza_log.shortHex(pd.e_skey_sig[0..8]);
    const build_hash_hex = stanza_log.shortHex(pd.build_hash[0..8]);
    const noise_pub_hex = stanza_log.shortHex(self.static_keypair.x25519_public[0..8]);

    log.debug("PairPayload", "version={d}.{d}.{d} regid={d} ident={s} skey_id={d} skey_pub={s} skey_sig={s} build_hash={s} noise_pub={s}", .{
        self.app_version.primary,
        self.app_version.secondary,
        self.app_version.tertiary,
        self.registration_id,
        &ident_hex,
        self.signed_prekey.id,
        &skey_pub_hex,
        &skey_sig_hex,
        &build_hash_hex,
        &noise_pub_hex,
    });
    if (log.enabled(.debug)) {
        const ident_full = try stanza_log.allocHex(self.allocator, &pd.e_ident);
        defer self.allocator.free(ident_full);
        const skey_pub_full = try stanza_log.allocHex(self.allocator, &pd.e_skey_val);
        defer self.allocator.free(skey_pub_full);
        const skey_sig_full = try stanza_log.allocHex(self.allocator, &pd.e_skey_sig);
        defer self.allocator.free(skey_sig_full);
        log.debug("PairPayloadFull", "e_ident={s} e_skey_val={s} e_skey_sig={s}", .{
            ident_full, skey_pub_full, skey_sig_full,
        });
    }

    const device_props = pair_mod.makePairingDeviceProps();
    var dp_writer = try std.Io.Writer.Allocating.initCapacity(self.allocator, 64);
    defer dp_writer.deinit();
    try device_props.encode(&dp_writer.writer, self.allocator);
    const dp_owned = try dp_writer.toOwnedSlice();
    defer self.allocator.free(dp_owned);

    var payload = makeBasePayload(self);
    payload.passive = false;
    payload.pull = false;
    payload.devicePairingData = .{
        .eRegid = &pd.e_regid,
        .eKeytype = &pd.e_keytype,
        .eIdent = &pd.e_ident,
        .eSkeyId = &pd.e_skey_id,
        .eSkeyVal = &pd.e_skey_val,
        .eSkeySig = &pd.e_skey_sig,
        .buildHash = &pd.build_hash,
        .deviceProps = dp_owned,
    };
    _ = &payload;

    var writer = try std.Io.Writer.Allocating.initCapacity(self.allocator, 384);
    defer writer.deinit();
    try payload.encode(&writer.writer, self.allocator);
    return writer.toOwnedSlice();
}

pub fn buildLoginPayload(self: anytype) ![]u8 {
    var username: ?u64 = null;
    if (self.phone_jid) |pj| {
        const at = std.mem.indexOfScalar(u8, pj, '@') orelse pj.len;
        const user_part = pj[0..at];
        const colon = std.mem.indexOfScalar(u8, user_part, ':') orelse user_part.len;
        const bare_user = user_part[0..colon];
        username = std.fmt.parseInt(u64, bare_user, 10) catch null;
    }

    log.debug("Client", "Building login payload: username={?}, device={d}", .{ username, self.device_id });

    var payload = makeBasePayload(self);
    payload.passive = true;
    payload.username = username;
    payload.device = self.device_id;
    _ = &payload;

    var writer = try std.Io.Writer.Allocating.initCapacity(self.allocator, 128);
    defer writer.deinit();
    try payload.encode(&writer.writer, self.allocator);
    return writer.toOwnedSlice();
}

pub fn makeBasePayload(self: anytype) whatsapp.ClientPayload {
    return .{
        .userAgent = makeUserAgent(self),
        .webInfo = .{ .webSubPlatform = .WEB_BROWSER },
        .connectType = .WIFI_UNKNOWN,
        .connectReason = .USER_ACTIVATED,
    };
}

pub fn makeUserAgent(self: anytype) whatsapp.ClientPayload.UserAgent {
    var user_agent = base_user_agent;
    user_agent.appVersion = .{
        .primary = self.app_version.primary,
        .secondary = self.app_version.secondary,
        .tertiary = self.app_version.tertiary,
    };
    return user_agent;
}
