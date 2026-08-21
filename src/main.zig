const std = @import("std");
const builtin = @import("builtin");
const whatszig = @import("whatszig");
const log = whatszig.log;

pub const std_options: std.Options = switch (builtin.mode) {
    .ReleaseSmall => .{
        .signal_stack_size = null,
        .allow_stack_tracing = false,
    },
    else => .{},
};

var qr_count: usize = 0;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_it.deinit();
    _ = args_it.skip(); // skip executable name

    var pairing_phone: ?[]const u8 = null;
    if (args_it.next()) |arg| {
        pairing_phone = arg;
        log.info("Main", "Pairing phone number specified: {s}", .{arg});
    }

    var client = try whatszig.Client.init(allocator, io, .{
        .pairing_phone_number = pairing_phone,
        .on_event = handleEvent,
    });
    defer client.deinit();

    client.connectAndRun() catch |err| {
        log.err("Main", "{}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpErrorReturnTrace(trace);
        }
    };
}

fn handleEvent(event: whatszig.Event, ctx: *anyopaque) void {
    const client: *whatszig.Client = @ptrCast(@alignCast(ctx));

    switch (event) {
        .qr_code => |qr| {
            qr_count += 1;
            if (qr_count == 1) {
                // Show only the first QR code (valid for ~60 seconds)
                log.info("Main", "", .{});
                log.info("Main", "Scan this QR code with WhatsApp on your phone:", .{});
                log.info("Main", "WhatsApp > Linked Devices > Link a Device", .{});

                if (whatszig.qr.QrCode.encodeText(client.allocator, qr.code, .L)) |qr_matrix| {
                    var mut_qr = qr_matrix;
                    defer mut_qr.deinit();
                    if (mut_qr.renderTerminal(client.allocator)) |rendered| {
                        defer client.allocator.free(rendered);
                        std.debug.print("{s}", .{rendered});
                    } else |_| {
                        log.info("Main", "{s}", .{qr.code});
                    }
                } else |_| {
                    log.info("Main", "{s}", .{qr.code});
                }
                log.info("Main", "", .{});
            }
        },
        .pairing_code => |pc| {
            log.info("Main", "", .{});
            log.info("Main", "====================================================", .{});
            log.info("Main", "Pairing code for +{s}:", .{pc.phone});
            log.info("Main", "  >>> {s} <<<", .{pc.formatted_code});
            log.info("Main", "Enter this code in WhatsApp on your phone:", .{});
            log.info("Main", "  WhatsApp > Linked Devices > Link a Device > Link with phone number instead", .{});
            log.info("Main", "====================================================", .{});
            log.info("Main", "", .{});
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

            if (msg.getBody()) |body| {
                log.info("Main", "  body: {s}", .{body});
                // Reply to 🦎ping with pong
                if (std.mem.indexOf(u8, body, "\xf0\x9f\xa6\x8eping")) |_| {
                    log.info("Main", "Got 🦎ping! Sending pong to {s}...", .{msg.chat});
                    client.sendMessage(msg.chat, "pong") catch |err| {
                        log.err("Main", "Reply failed: {}", .{err});
                    };
                }
            } else {
                // Check for undecrypted enc nodes
                if (msg.node.getContentNodes()) |children| {
                    for (children) |*child| {
                        if (std.mem.eql(u8, child.tag, "enc")) {
                            log.debug("Main", "  encrypted (undecrypted) type={s}", .{
                                child.getAttribute("type") orelse "?",
                            });
                        }
                    }
                }
            }
        },
        .disconnected => log.warn("Main", "Disconnected", .{}),
        .login_failed => log.err("Main", "Login failed", .{}),
    }
}
