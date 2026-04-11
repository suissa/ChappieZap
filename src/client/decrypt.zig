const std = @import("std");
const binary = @import("binary");
const session_store = @import("session_store.zig");
const signal = @import("signal");
const log = @import("log");

pub fn decryptMessageNode(self: anytype, node: *const binary.Node) ?[]u8 {
    const children = node.getContentNodes() orelse return null;
    const from_jid = node.getAttribute("from") orelse return null;
    var encryption_jid = from_jid;
    var encryption_jid_owned: ?[]u8 = null;
    defer if (encryption_jid_owned) |owned| self.allocator.free(owned);
    if (self.options.tls) {
        const resolved = self.address_book.resolveIncomingEncryptionJid(from_jid) catch return null;
        encryption_jid = resolved.value;
        encryption_jid_owned = resolved.owned;
    }

    for (children) |*child| {
        if (!std.mem.eql(u8, child.tag, "enc")) continue;
        const enc_type = child.getAttribute("type") orelse continue;
        const ciphertext = child.getContentBytes() orelse {
            log.debug("Client/Decrypt", "enc type={s}: no content bytes", .{enc_type});
            continue;
        };

        if (std.mem.eql(u8, enc_type, "pkmsg")) {
            return decryptPreKeyMessage(self, encryption_jid, ciphertext) catch |err| {
                log.warn("Client/Decrypt", "pkmsg decrypt failed: {}", .{err});
                return null;
            };
        } else if (std.mem.eql(u8, enc_type, "msg")) {
            return decryptSessionMessage(self, encryption_jid, ciphertext) catch |err| {
                log.warn("Client/Decrypt", "msg decrypt failed: {}", .{err});
                return null;
            };
        }
    }
    return null;
}

pub fn decryptPreKeyMessage(self: anytype, from_jid: []const u8, ciphertext: []const u8) ![]u8 {
    var locked = try session_store.lockSession(self, from_jid);
    defer locked.unlock();
    const pkmsg = try signal.message.parsePreKeySignalMessage(ciphertext);

    var our_otpk: ?signal.KeyPair = null;
    if (pkmsg.prekey_id) |pk_id| {
        for (&self.prekeys) |*pk| {
            if (pk.id == pk_id) {
                our_otpk = pk.key_pair;
                break;
            }
        }
    }

    if (pkmsg.signed_prekey_id != self.signed_prekey.id) return error.SignedPreKeyMismatch;

    const x3dh_result = try signal.ratchet.x3dhResponder(
        self.identity,
        self.signed_prekey.key_pair,
        our_otpk,
        pkmsg.identity_key,
        pkmsg.base_key,
    );

    var session = signal.Session.initAsResponder(
        self.allocator,
        x3dh_result,
        self.identity.key_pair.public,
        pkmsg.identity_key,
        self.signed_prekey.key_pair,
        self.registration_id,
        pkmsg.registration_id,
    );

    const plaintext = try decryptSignalMessage(self, &session, pkmsg.signal_message, pkmsg.identity_key);
    locked.put(session) catch |err| {
        log.warn("Client/Decrypt", "Failed to persist responder session for {s}: {}", .{
            from_jid,
            err,
        });
    };
    return plaintext;
}

pub fn decryptSessionMessage(self: anytype, from_jid: []const u8, ciphertext: []const u8) ![]u8 {
    var locked = try session_store.lockSession(self, from_jid);
    defer locked.unlock();
    const session = locked.get() orelse return error.NoSession;
    return decryptSignalMessage(self, session, ciphertext, session.remote_identity_public);
}

pub fn decryptSignalMessage(self: anytype, session: *signal.Session, data: []const u8, sender_identity: [32]u8) ![]u8 {
    const parsed = try signal.message.parseSignalMessage(data);

    var enc_msg = signal.session.EncryptedMessage{
        .ratchet_key = parsed.ratchet_key,
        .counter = parsed.counter,
        .previous_counter = parsed.previous_counter,
        .ciphertext = @constCast(parsed.ciphertext),
        .sender_identity = sender_identity,
        .receiver_identity = self.identity.key_pair.public,
        .mac_key = [_]u8{0} ** 32,
    };

    return session.decryptWire(
        self.allocator,
        &enc_msg,
        data[0 .. data.len - 8],
        parsed.mac,
        self.io,
    );
}
