const std = @import("std");
const sqlite = @import("sqlite.zig");

pub const DeviceRecord = struct {
    jid: []const u8,
    lid: ?[]const u8 = null,
    registration_id: u32,
    noise_key: [32]u8,
    identity_key: [32]u8,
    signed_pre_key: [32]u8,
    signed_pre_key_id: u32,
    signed_pre_key_sig: [64]u8,
    adv_key: [32]u8,
    adv_details: []const u8,
    adv_account_sig: [64]u8,
    adv_account_sig_key: [32]u8,
    adv_device_sig: [64]u8,
    platform: []const u8 = "whatszig",
    push_name: []const u8 = "whatszig",

    pub fn deinit(self: *DeviceRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.jid);
        if (self.lid) |l| allocator.free(l);
        allocator.free(self.adv_details);
    }
};

pub const WhatsStore = struct {
    db: sqlite.Db,

    pub fn init(path: [:0]const u8) !WhatsStore {
        const db = try sqlite.Db.open(path);
        const store = WhatsStore{ .db = db };
        try store.createTables();
        return store;
    }

    pub fn deinit(self: *WhatsStore) void {
        self.db.close();
    }

    pub fn createTables(self: WhatsStore) !void {
        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS whatsmeow_device (
            \\  jid TEXT PRIMARY KEY,
            \\  lid TEXT,
            \\  facebook_uuid TEXT,
            \\  registration_id BIGINT NOT NULL,
            \\  noise_key BLOB NOT NULL,
            \\  identity_key BLOB NOT NULL,
            \\  signed_pre_key BLOB NOT NULL,
            \\  signed_pre_key_id INTEGER NOT NULL,
            \\  signed_pre_key_sig BLOB NOT NULL,
            \\  adv_key BLOB NOT NULL,
            \\  adv_details BLOB NOT NULL,
            \\  adv_account_sig BLOB NOT NULL,
            \\  adv_account_sig_key BLOB NOT NULL,
            \\  adv_device_sig BLOB NOT NULL,
            \\  platform TEXT NOT NULL DEFAULT 'whatszig',
            \\  business_name TEXT NOT NULL DEFAULT '',
            \\  push_name TEXT NOT NULL DEFAULT 'whatszig',
            \\  lid_migration_ts BIGINT NOT NULL DEFAULT 0,
            \\  companion_meta_nonce TEXT NOT NULL DEFAULT ''
            \\);
            \\CREATE TABLE IF NOT EXISTS whatsmeow_identity_keys (
            \\  our_jid TEXT,
            \\  their_id TEXT,
            \\  identity BLOB NOT NULL,
            \\  PRIMARY KEY (our_jid, their_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS whatsmeow_sessions (
            \\  our_jid TEXT,
            \\  their_id TEXT,
            \\  session BLOB,
            \\  PRIMARY KEY (our_jid, their_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS whatsmeow_pre_keys (
            \\  jid TEXT,
            \\  key_id INTEGER,
            \\  key BLOB NOT NULL,
            \\  uploaded BOOLEAN NOT NULL,
            \\  PRIMARY KEY (jid, key_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS whatsmeow_lid_map (
            \\  lid TEXT PRIMARY KEY,
            \\  pn TEXT UNIQUE NOT NULL
            \\);
        );
    }

    pub fn saveDevice(self: WhatsStore, record: DeviceRecord) !void {
        var stmt = try self.db.prepare(
            \\INSERT INTO whatsmeow_device (
            \\  jid, lid, registration_id,
            \\  noise_key, identity_key,
            \\  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
            \\  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
            \\  platform, push_name
            \\) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(jid) DO UPDATE SET
            \\  lid=excluded.lid,
            \\  registration_id=excluded.registration_id,
            \\  noise_key=excluded.noise_key,
            \\  identity_key=excluded.identity_key,
            \\  signed_pre_key=excluded.signed_pre_key,
            \\  signed_pre_key_id=excluded.signed_pre_key_id,
            \\  signed_pre_key_sig=excluded.signed_pre_key_sig,
            \\  adv_key=excluded.adv_key,
            \\  adv_details=excluded.adv_details,
            \\  adv_account_sig=excluded.adv_account_sig,
            \\  adv_account_sig_key=excluded.adv_account_sig_key,
            \\  adv_device_sig=excluded.adv_device_sig,
            \\  platform=excluded.platform,
            \\  push_name=excluded.push_name;
        );
        defer stmt.finalize();

        try stmt.bindText(1, record.jid);
        if (record.lid) |l| {
            try stmt.bindText(2, l);
        } else {
            try stmt.bindNull(2);
        }
        try stmt.bindInt64(3, record.registration_id);
        try stmt.bindBlob(4, &record.noise_key);
        try stmt.bindBlob(5, &record.identity_key);
        try stmt.bindBlob(6, &record.signed_pre_key);
        try stmt.bindInt64(7, record.signed_pre_key_id);
        try stmt.bindBlob(8, &record.signed_pre_key_sig);
        try stmt.bindBlob(9, &record.adv_key);
        try stmt.bindBlob(10, record.adv_details);
        try stmt.bindBlob(11, &record.adv_account_sig);
        try stmt.bindBlob(12, &record.adv_account_sig_key);
        try stmt.bindBlob(13, &record.adv_device_sig);
        try stmt.bindText(14, record.platform);
        try stmt.bindText(15, record.push_name);

        _ = try stmt.step();
    }

    pub fn getDevice(self: WhatsStore, allocator: std.mem.Allocator, phone: []const u8) !?DeviceRecord {
        var clean_phone_buf: [64]u8 = undefined;
        var clean_len: usize = 0;
        for (phone) |c| {
            if (c >= '0' and c <= '9') {
                if (clean_len < clean_phone_buf.len) {
                    clean_phone_buf[clean_len] = c;
                    clean_len += 1;
                }
            }
        }
        const clean_phone = clean_phone_buf[0..clean_len];

        var stmt = try self.db.prepare(
            \\SELECT jid, lid, registration_id,
            \\  noise_key, identity_key,
            \\  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
            \\  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
            \\  platform, push_name
            \\FROM whatsmeow_device
            \\WHERE jid LIKE ? || ':%' OR jid = ? || '@s.whatsapp.net' OR jid = ?
            \\LIMIT 1;
        );
        defer stmt.finalize();

        try stmt.bindText(1, clean_phone);
        try stmt.bindText(2, clean_phone);
        try stmt.bindText(3, phone);

        if (!try stmt.step()) return null;

        const jid_raw = stmt.columnText(0) orelse return null;
        const lid_raw = stmt.columnText(1);
        const reg_id = @as(u32, @intCast(stmt.columnInt64(2)));

        const noise_key_blob = stmt.columnBlob(3) orelse return null;
        const identity_key_blob = stmt.columnBlob(4) orelse return null;
        const signed_pre_key_blob = stmt.columnBlob(5) orelse return null;
        const signed_pre_key_id = @as(u32, @intCast(stmt.columnInt64(6)));
        const signed_pre_key_sig_blob = stmt.columnBlob(7) orelse return null;
        const adv_key_blob = stmt.columnBlob(8) orelse return null;
        const adv_details_blob = stmt.columnBlob(9) orelse return null;
        const adv_account_sig_blob = stmt.columnBlob(10) orelse return null;
        const adv_account_sig_key_blob = stmt.columnBlob(11) orelse return null;
        const adv_device_sig_blob = stmt.columnBlob(12) orelse return null;

        if (noise_key_blob.len != 32 or identity_key_blob.len != 32 or
            signed_pre_key_blob.len != 32 or signed_pre_key_sig_blob.len != 64 or
            adv_key_blob.len != 32 or adv_account_sig_blob.len != 64 or
            adv_account_sig_key_blob.len != 32 or adv_device_sig_blob.len != 64)
        {
            return null;
        }

        var noise_key: [32]u8 = undefined;
        @memcpy(&noise_key, noise_key_blob[0..32]);
        var identity_key: [32]u8 = undefined;
        @memcpy(&identity_key, identity_key_blob[0..32]);
        var signed_pre_key: [32]u8 = undefined;
        @memcpy(&signed_pre_key, signed_pre_key_blob[0..32]);
        var signed_pre_key_sig: [64]u8 = undefined;
        @memcpy(&signed_pre_key_sig, signed_pre_key_sig_blob[0..64]);
        var adv_key: [32]u8 = undefined;
        @memcpy(&adv_key, adv_key_blob[0..32]);
        var adv_account_sig: [64]u8 = undefined;
        @memcpy(&adv_account_sig, adv_account_sig_blob[0..64]);
        var adv_account_sig_key: [32]u8 = undefined;
        @memcpy(&adv_account_sig_key, adv_account_sig_key_blob[0..32]);
        var adv_device_sig: [64]u8 = undefined;
        @memcpy(&adv_device_sig, adv_device_sig_blob[0..64]);

        return DeviceRecord{
            .jid = try allocator.dupe(u8, jid_raw),
            .lid = if (lid_raw) |l| try allocator.dupe(u8, l) else null,
            .registration_id = reg_id,
            .noise_key = noise_key,
            .identity_key = identity_key,
            .signed_pre_key = signed_pre_key,
            .signed_pre_key_id = signed_pre_key_id,
            .signed_pre_key_sig = signed_pre_key_sig,
            .adv_key = adv_key,
            .adv_details = try allocator.dupe(u8, adv_details_blob),
            .adv_account_sig = adv_account_sig,
            .adv_account_sig_key = adv_account_sig_key,
            .adv_device_sig = adv_device_sig,
            .platform = "whatszig",
            .push_name = "whatszig",
        };
    }

    pub fn saveLidMapping(self: WhatsStore, lid: []const u8, pn: []const u8) !void {
        var stmt = try self.db.prepare(
            \\INSERT INTO whatsmeow_lid_map (lid, pn) VALUES (?, ?)
            \\ON CONFLICT(lid) DO UPDATE SET pn=excluded.pn;
        );
        defer stmt.finalize();
        try stmt.bindText(1, lid);
        try stmt.bindText(2, pn);
        _ = try stmt.step();
    }

    pub fn getLidMapping(self: WhatsStore, allocator: std.mem.Allocator, lid: []const u8) !?[]u8 {
        var stmt = try self.db.prepare("SELECT pn FROM whatsmeow_lid_map WHERE lid = ?;");
        defer stmt.finalize();
        try stmt.bindText(1, lid);
        if (!try stmt.step()) return null;
        const pn = stmt.columnText(0) orelse return null;
        return try allocator.dupe(u8, pn);
    }
};

test "WhatsStore: create tables and roundtrip DeviceRecord" {
    const allocator = std.testing.allocator;

    var store = try WhatsStore.init(":memory:");
    defer store.deinit();

    const record = DeviceRecord{
        .jid = "5515991957645:56@s.whatsapp.net",
        .lid = "124953718435910:56@lid",
        .registration_id = 987654,
        .noise_key = [_]u8{1} ** 32,
        .identity_key = [_]u8{2} ** 32,
        .signed_pre_key = [_]u8{3} ** 32,
        .signed_pre_key_id = 1,
        .signed_pre_key_sig = [_]u8{4} ** 64,
        .adv_key = [_]u8{5} ** 32,
        .adv_details = "test_adv_details_bytes",
        .adv_account_sig = [_]u8{6} ** 64,
        .adv_account_sig_key = [_]u8{7} ** 32,
        .adv_device_sig = [_]u8{8} ** 64,
        .platform = "whatszig",
        .push_name = "whatszig",
    };

    try store.saveDevice(record);

    var loaded = (try store.getDevice(allocator, "5515991957645")) orelse return error.TestExpectedEqual;
    defer loaded.deinit(allocator);

    try std.testing.expectEqualStrings("5515991957645:56@s.whatsapp.net", loaded.jid);
    try std.testing.expectEqualStrings("124953718435910:56@lid", loaded.lid.?);
    try std.testing.expectEqual(@as(u32, 987654), loaded.registration_id);
    try std.testing.expectEqualSlices(u8, &record.noise_key, &loaded.noise_key);
    try std.testing.expectEqualSlices(u8, &record.identity_key, &loaded.identity_key);
    try std.testing.expectEqualSlices(u8, &record.signed_pre_key, &loaded.signed_pre_key);
    try std.testing.expectEqual(@as(u32, 1), loaded.signed_pre_key_id);
    try std.testing.expectEqualSlices(u8, &record.signed_pre_key_sig, &loaded.signed_pre_key_sig);
    try std.testing.expectEqualSlices(u8, &record.adv_key, &loaded.adv_key);
    try std.testing.expectEqualStrings("test_adv_details_bytes", loaded.adv_details);
    try std.testing.expectEqualSlices(u8, &record.adv_account_sig, &loaded.adv_account_sig);
    try std.testing.expectEqualSlices(u8, &record.adv_account_sig_key, &loaded.adv_account_sig_key);
    try std.testing.expectEqualSlices(u8, &record.adv_device_sig, &loaded.adv_device_sig);
}

test "WhatsStore: lid mapping roundtrip" {
    const allocator = std.testing.allocator;

    var store = try WhatsStore.init(":memory:");
    defer store.deinit();

    try store.saveLidMapping("124953718435910@lid", "5515991957645@s.whatsapp.net");

    const loaded_pn = (try store.getLidMapping(allocator, "124953718435910@lid")) orelse return error.TestExpectedEqual;
    defer allocator.free(loaded_pn);

    try std.testing.expectEqualStrings("5515991957645@s.whatsapp.net", loaded_pn);
}
