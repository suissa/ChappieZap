const std = @import("std");
const binary = @import("binary");
const signal = @import("signal");
const addressing = @import("addressing");
const usync = @import("usync");
const messaging = @import("messaging");
const client_pump = @import("pump.zig");
const jid_helpers = @import("jid_helpers.zig");
const prekey_flow = @import("prekeys.zig");
const session_store = @import("session_store.zig");
const stanza_log = @import("stanza_log.zig");
const transport = @import("transport.zig");

const EncryptedPayload = struct {
    route_jid: []const u8,
    route_jid_owned: ?[]u8 = null,
    ciphertext: []u8,
    is_prekey: bool,
};

pub fn sendSelfChatFanout(self: anytype, chat_jid: []const u8, text: []const u8) !void {
    const plaintext = try messaging.encodeDeviceSentTextMessageInto(&self.send_text_buf, self.allocator, chat_jid, text);

    var fanout_targets = std.ArrayList([]const u8).empty;
    defer fanout_targets.deinit(self.allocator);

    try fanout_targets.append(self.allocator, chat_jid);
    var own_devices_it = self.address_book.ownDeviceIterator();
    while (own_devices_it.next()) |jid_ptr| {
        if (std.mem.eql(u8, jid_ptr.*, chat_jid)) continue;
        try fanout_targets.append(self.allocator, jid_ptr.*);
    }

    var participants = std.ArrayList(messaging.DirectParticipant).empty;
    defer {
        for (participants.items) |p| {
            self.allocator.free(p.ciphertext);
            if (p.jid_owned) |owned| self.allocator.free(owned);
        }
        participants.deinit(self.allocator);
    }

    var any_prekey = false;
    for (fanout_targets.items) |participant_jid| {
        if (self.address_book.isCurrentDeviceJid(participant_jid)) continue;

        const resolved = try self.address_book.resolveOwnDeviceEncryptionJid(participant_jid);
        defer resolved.deinit(self.allocator);
        const encryption_jid = resolved.value;

        const payload = try encryptPayloadForFanoutTarget(
            self,
            participant_jid,
            encryption_jid,
            plaintext,
        );
        errdefer self.allocator.free(payload.ciphertext);
        any_prekey = any_prekey or payload.is_prekey;
        try participants.append(self.allocator, .{
            .jid = payload.route_jid,
            .jid_owned = payload.route_jid_owned,
            .ciphertext = payload.ciphertext,
            .is_prekey = payload.is_prekey,
        });
    }

    if (participants.items.len == 0) {
        // No other devices to send to - send directly to self using LID
        const resolved = try self.address_book.resolveEncryptionJid(chat_jid);
        defer resolved.deinit(self.allocator);
        // Use sendDirectMessageSingle for direct delivery when no fanout targets
        const msg_id_arr = messaging.generateMessageId(self.io);
        const route_jid = try bareJid(self, resolved.value);
        defer self.allocator.free(route_jid);
        
        const payload = try encryptPayloadForFanoutTarget(
            self,
            route_jid,
            resolved.value,
            plaintext,
        );
        defer {
            self.allocator.free(payload.ciphertext);
            if (payload.route_jid_owned) |owned| self.allocator.free(owned);
        }
        
        try transport.sendDirectMessageFast(
            self,
            chat_jid,
            payload.route_jid,
            &msg_id_arr,
            payload.ciphertext,
            payload.is_prekey,
            if (payload.is_prekey) self.account_device_identity else null,
        );
        return;
    }

    const msg_id_arr = messaging.generateMessageId(self.io);
    var msg_node = try messaging.buildFanoutMessageNode(
        self.allocator,
        chat_jid,
        &msg_id_arr,
        participants.items,
        if (any_prekey) self.account_device_identity else null,
    );
    defer msg_node.deinit();
    try transport.sendNode(self, &msg_node);
}

pub fn sendDirectMessageFanout(self: anytype, chat_jid: []const u8, text: []const u8) !void {
    const msg_id_arr = messaging.generateMessageId(self.io);
    const reporting = try messaging.generateReportingContextForText(
        self.allocator,
        self.io,
        text,
        &msg_id_arr,
        chat_jid,
        chat_jid,
    );

    const recipient_plaintext = try messaging.encodeTextMessageWithContextInto(
        &self.send_text_buf,
        self.allocator,
        text,
        &reporting,
    );

    const own_plaintext = try messaging.encodeDeviceSentTextMessageWithContextInto(
        &self.send_text_aux_buf,
        self.allocator,
        chat_jid,
        text,
        &reporting,
    );

    var recipient_targets = std.ArrayList([]const u8).empty;
    defer recipient_targets.deinit(self.allocator);
    var own_targets = std.ArrayList([]const u8).empty;
    defer own_targets.deinit(self.allocator);

    var recipient_target = chat_jid;
    var recipient_target_owned: ?[]u8 = null;
    defer if (recipient_target_owned) |owned| self.allocator.free(owned);

    if (self.options.tls) {
        try ensureRecipientLidMapping(self, chat_jid);
        const resolved_recipient = try self.address_book.resolveEncryptionJid(chat_jid);
        recipient_target = resolved_recipient.value;
        recipient_target_owned = resolved_recipient.owned;
    }

    const recipient_bare = try bareJid(self, recipient_target);
    defer self.allocator.free(recipient_bare);
    try recipient_targets.append(self.allocator, recipient_bare);

    if (self.address_book.phoneJid()) |own_phone| {
        try own_targets.append(self.allocator, own_phone);
    }
    var own_it = self.address_book.ownDeviceIterator();
    while (own_it.next()) |jid_ptr| {
        if (std.mem.eql(u8, jid_ptr.*, chat_jid)) continue;
        if (self.address_book.isCurrentDeviceJid(jid_ptr.*)) continue;
        if (jid_helpers.containsJid(own_targets.items, jid_ptr.*)) continue;
        try own_targets.append(self.allocator, jid_ptr.*);
    }

    var participants = std.ArrayList(messaging.DirectParticipant).empty;
    defer {
        for (participants.items) |participant| {
            self.allocator.free(participant.ciphertext);
            if (participant.jid_owned) |owned| self.allocator.free(owned);
        }
        participants.deinit(self.allocator);
    }

    var any_prekey = false;

    for (recipient_targets.items) |participant_jid| {
        var encryption_jid = participant_jid;
        var encryption_jid_owned: ?[]u8 = null;
        defer if (encryption_jid_owned) |owned| self.allocator.free(owned);
        if (self.options.tls) {
            const resolved = try self.address_book.resolveEncryptionJid(participant_jid);
            encryption_jid = resolved.value;
            encryption_jid_owned = resolved.owned;
        }
        const payload = try encryptPayloadForFanoutTarget(
            self,
            participant_jid,
            encryption_jid,
            recipient_plaintext,
        );
        errdefer self.allocator.free(payload.ciphertext);
        any_prekey = any_prekey or payload.is_prekey;
        try participants.append(self.allocator, .{
            .jid = payload.route_jid,
            .jid_owned = payload.route_jid_owned,
            .ciphertext = payload.ciphertext,
            .is_prekey = payload.is_prekey,
        });
    }

    for (own_targets.items) |participant_jid| {
        if (self.address_book.isCurrentDeviceJid(participant_jid)) continue;
        var encryption_jid = participant_jid;
        var encryption_jid_owned: ?[]u8 = null;
        defer if (encryption_jid_owned) |owned| self.allocator.free(owned);
        if (self.options.tls) {
            const resolved = try self.address_book.resolveOwnDeviceEncryptionJid(participant_jid);
            encryption_jid = resolved.value;
            encryption_jid_owned = resolved.owned;
        }
        const payload = try encryptPayloadForFanoutTarget(
            self,
            participant_jid,
            encryption_jid,
            own_plaintext,
        );
        errdefer self.allocator.free(payload.ciphertext);
        any_prekey = any_prekey or payload.is_prekey;
        try participants.append(self.allocator, .{
            .jid = payload.route_jid,
            .jid_owned = payload.route_jid_owned,
            .ciphertext = payload.ciphertext,
            .is_prekey = payload.is_prekey,
        });
    }

    if (participants.items.len == 0) {
        // No participants for fanout - send directly using single-recipient path
        try sendDirectMessageSingle(self, chat_jid, text);
        return;
    }

    var msg_node = try messaging.buildFanoutMessageNode(
        self.allocator,
        chat_jid,
        &msg_id_arr,
        participants.items,
        if (any_prekey) self.account_device_identity else null,
    );
    defer msg_node.deinit();

    var reporting_node = try messaging.buildReportingNode(self.allocator, &reporting);
    try msg_node.addChild(&reporting_node);

    try transport.sendNode(self, &msg_node);
}

pub fn sendDirectMessageSingle(self: anytype, chat_jid: []const u8, text: []const u8) !void {
    var target_jid = chat_jid;
    var target_jid_owned: ?[]u8 = null;
    defer if (target_jid_owned) |owned| self.allocator.free(owned);

    if (self.options.tls) {
        try ensureRecipientLidMapping(self, chat_jid);
        const resolved = try self.address_book.resolveEncryptionJid(chat_jid);
        target_jid = resolved.value;
        target_jid_owned = resolved.owned;
    }

    const route_jid = try bareJid(self, target_jid);
    defer self.allocator.free(route_jid);

    const plaintext = try messaging.encodeTextMessageInto(&self.send_text_buf, self.allocator, text);
    const payload = try encryptPayloadForFanoutTarget(self, route_jid, target_jid, plaintext);
    defer {
        self.allocator.free(payload.ciphertext);
        if (payload.route_jid_owned) |owned| self.allocator.free(owned);
    }

    const msg_id_arr = messaging.generateMessageId(self.io);
    try transport.sendDirectMessageFast(
        self,
        chat_jid,
        payload.route_jid,
        &msg_id_arr,
        payload.ciphertext,
        payload.is_prekey,
        if (payload.is_prekey) self.account_device_identity else null,
    );
}

pub fn encryptPayloadForFanoutTarget(
    self: anytype,
    participant_jid: []const u8,
    encryption_jid: []const u8,
    plaintext: []const u8,
) !EncryptedPayload {
    {
        var locked = try session_store.lockSession(self, encryption_jid);
        defer locked.unlock();
        if (locked.get()) |session| {
            var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
            defer encrypted_msg.deinit(self.allocator);
            return EncryptedPayload{
                .route_jid = participant_jid,
                .ciphertext = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg),
                .is_prekey = false,
            };
        }
    }

    var fetch = try prekey_flow.fetchPrekeysWithRoute(self, participant_jid, client_pump.PumpResult);
    errdefer fetch.deinit(self.allocator);

    var locked = try session_store.lockSession(self, encryption_jid);
    defer locked.unlock();
    if (locked.get()) |session| {
        var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
        defer encrypted_msg.deinit(self.allocator);
        return EncryptedPayload{
            .route_jid = participant_jid,
            .ciphertext = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg),
            .is_prekey = false,
        };
    }

    const created = try prekey_flow.buildInitiatorSession(self, fetch.bundle);
    try locked.put(created.session);
    const session = locked.get() orelse return error.NoSession;
    var encrypted_msg = try session.encrypt(self.allocator, plaintext, self.io);
    defer encrypted_msg.deinit(self.allocator);
    const signal_msg_bytes = try signal.message.serializeSignalMessage(self.allocator, &encrypted_msg);
    defer self.allocator.free(signal_msg_bytes);
    const route_jid = fetch.route_jid;
    const route_jid_owned = fetch.route_jid_owned;
    fetch.route_jid_owned = null;
    errdefer if (route_jid_owned) |owned| self.allocator.free(owned);
    return EncryptedPayload{
        .route_jid = route_jid,
        .route_jid_owned = route_jid_owned,
        .ciphertext = try signal.message.serializePreKeySignalMessage(
            self.allocator,
            created.registration_id,
            created.prekey_id,
            created.signed_prekey_id,
            created.base_key,
            self.identity.key_pair.public,
            signal_msg_bytes,
        ),
        .is_prekey = true,
    };
}

pub fn ensureRecipientLidMapping(self: anytype, chat_jid: []const u8) !void {
    if (!jid_helpers.isPnJid(chat_jid)) return;

    const resolved = try self.address_book.resolveEncryptionJid(chat_jid);
    defer resolved.deinit(self.allocator);
    if (!std.mem.eql(u8, resolved.value, chat_jid)) return;

    const bare = try bareJid(self, chat_jid);
    defer self.allocator.free(bare);
    try queryLidMappings(self, &.{bare});
}

pub fn queryLidMappings(self: anytype, jids: []const []const u8) !void {
    var iq_id_buf: [transport.iq_id_buffer_len]u8 = undefined;
    const iq_id = try transport.nextIqIdInto(self, &iq_id_buf);
    var wait_iq_id = iq_id;

    var iq = try usync.buildLidQueryIq(self.allocator, iq_id, iq_id, jids);
    defer iq.deinit();
    try transport.sendNode(self, &iq);
    return client_pump.pumpUntil(self, 100_000, struct {
        fn onNode(client: @TypeOf(self), ctx: *[]const u8, node: *binary.Node) !client_pump.PumpResult {
            if (std.mem.eql(u8, node.tag, "iq")) {
                const node_id = node.getAttribute("id") orelse "";
                if (stanza_log.iqIdsMatch(node_id, ctx.*)) {
                    const mappings = try usync.parseLidMappings(client.allocator, node);
                    defer {
                        for (mappings) |mapping| {
                            client.allocator.free(mapping.pn_jid);
                            client.allocator.free(mapping.lid_jid);
                        }
                        client.allocator.free(mappings);
                    }
                    for (mappings) |mapping| {
                        if (try client.address_book.rememberMappingJids(mapping.pn_jid, mapping.lid_jid)) |learned| {
                            session_store.migrateSessionsOnLidDiscovery(client, learned.pn_jid, learned.lid_jid);
                        }
                    }
                    return .done;
                }
            }
            client.processNode(node);
            return .keep_going;
        }
    }.onNode, &wait_iq_id, error.PreKeyFetchTimeout);
}

fn bareJid(self: anytype, jid: []const u8) ![]u8 {
    return addressing.AddressBook.stripDeviceFromJid(self.allocator, jid);
}
