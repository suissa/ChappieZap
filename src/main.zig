const std = @import("std");
const zigwhats = @import("zigwhats");
const log = zigwhats.log;

var qr_count: usize = 0;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var client = try zigwhats.Client.init(allocator, io, .{
        .on_event = handleEvent,
    });
    defer client.deinit();

    client.connectAndRun() catch |err| {
        log.err("Main", "{}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace);
        }
    };
}

fn handleEvent(event: zigwhats.Event, ctx: *anyopaque) void {
    const client: *zigwhats.Client = @ptrCast(@alignCast(ctx));

    switch (event) {
        .qr_code => |qr| {
            qr_count += 1;
            if (qr_count == 1) {
                // Show only the first QR code (valid for ~60 seconds)
                log.info("Main", "", .{});
                log.info("Main", "Scan this QR code with WhatsApp on your phone:", .{});
                log.info("Main", "WhatsApp > Linked Devices > Link a Device", .{});
                log.info("Main", "{s}", .{qr.code});
                log.info("Main", "", .{});
            }
        },
        .pair_success => |ps| {
            log.info("Main", "Paired! phone={s} lid={s}", .{ ps.phone_jid, ps.lid });
        },
        .connected => |c| {
            log.info("Main", "Connected! phone={s} lid={s}", .{ c.phone_jid, c.lid });
            log.info("Main", "Listening for messages... Send 🦎ping to get pong", .{});
        },
        .message => |msg| {
            log.info("Main", "Message from {s}", .{msg.from});

            var has_enc = false;
            if (msg.node.getContentNodes()) |children| {
                for (children) |*child| {
                    if (std.mem.eql(u8, child.tag, "enc")) {
                        has_enc = true;
                        log.debug("Main", "  encrypted stanza type={s}", .{child.getAttribute("type") orelse "?"});
                    }
                }
            }

            // Reply to 🦎ping with pong
            if (msg.getBody()) |body| {
                if (std.mem.indexOf(u8, body, "\xf0\x9f\xa6\x8eping")) |_| {
                    log.info("Main", "Got 🦎ping! Sending pong...", .{});
                    client.sendText(msg.from, "pong") catch |err| {
                        log.err("Main", "Reply failed: {}", .{err});
                    };
                }
            } else if (has_enc) {
                log.info("Main", "Message body unavailable: incoming Signal payload is not decrypted yet", .{});
            }
        },
        .disconnected => log.warn("Main", "Disconnected", .{}),
        .login_failed => log.err("Main", "Login failed", .{}),
    }
}
