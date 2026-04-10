const std = @import("std");
const addressing = @import("addressing");
const usync = @import("usync");
const client_pump = @import("pump.zig");
const client_transport = @import("transport.zig");
const session_store = @import("session_store.zig");
const stanza_log = @import("stanza_log.zig");
const log = @import("log");

pub fn syncOwnDeviceList(self: anytype) !void {
    const own_phone = self.address_book.phoneJid() orelse {
        log.debug("Client/Bootstrap", "Skipping own device sync: no phone jid", .{});
        return;
    };

    const bare = try addressing.AddressBook.stripDeviceFromJid(self.allocator, own_phone);
    defer self.allocator.free(bare);

    var iq_id_buf: [client_transport.iq_id_buffer_len]u8 = undefined;
    const iq_id = try client_transport.nextIqIdInto(self, &iq_id_buf);
    var wait_iq_id = iq_id;

    var iq = try usync.buildDeviceListIq(self.allocator, iq_id, iq_id, &.{bare});
    defer iq.deinit();
    try client_transport.sendNode(self, &iq);

    return client_pump.pumpUntil(self, 30_000, struct {
        fn onNode(client: @TypeOf(self), ctx: *[]const u8, node: *binary.Node) !client_pump.PumpResult {
            if (std.mem.eql(u8, node.tag, "iq")) {
                const node_id = node.getAttribute("id") orelse "";
                if (stanza_log.iqIdsMatch(node_id, ctx.*)) {
                    const devices = try usync.parseDeviceJids(client.allocator, node);
                    defer {
                        for (devices) |jid| client.allocator.free(jid);
                        client.allocator.free(devices);
                    }
                    try client.address_book.replaceOwnDevices(devices);

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

                    log.debug("Client/Bootstrap", "Synced own device list: {d} devices", .{
                        client.address_book.ownDeviceCount(),
                    });
                    return .done;
                }
            }
            client.processNode(node);
            return .keep_going;
        }

        const binary = @import("binary");
    }.onNode, &wait_iq_id, error.DeviceSyncTimeout);
}
