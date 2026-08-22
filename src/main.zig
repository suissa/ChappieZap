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

    // Usage:
    //   whatszig                           -> QR code mode (no phone)
    //   whatszig <phone>                   -> paircode mode (default when phone given)
    //   whatszig <phone> qrcode            -> QR code mode
    //   whatszig <phone> paircode          -> Phone pairing code mode
    var pairing_phone: ?[]const u8 = null;
    var pairing_mode: whatszig.PairingMode = .qrcode;

    if (args_it.next()) |phone_arg| {
        pairing_phone = phone_arg;
        pairing_mode = .paircode; // Default to paircode when phone is provided
        log.info("Main", "Phone number: {s}", .{phone_arg});

        if (args_it.next()) |mode_arg| {
            if (std.mem.eql(u8, mode_arg, "paircode")) {
                pairing_mode = .paircode;
            } else if (std.mem.eql(u8, mode_arg, "qrcode")) {
                pairing_mode = .qrcode;
            } else {
                log.warn("Main", "Unknown mode '{s}', defaulting to paircode. Use 'qrcode' or 'paircode'.", .{mode_arg});
            }
        }
    }

    log.info("Main", "Pairing mode: {s}", .{@tagName(pairing_mode)});

    var client = try whatszig.Client.init(allocator, io, .{
        .pairing_phone_number = pairing_phone,
        .pairing_mode = pairing_mode,
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
                log.info("Main", "", .{});
                log.info("Main", "Scan this QR code with WhatsApp on your phone:", .{});
                log.info("Main", "WhatsApp > Linked Devices > Link a Device", .{});

                if (whatszig.qr.QrCode.encodeText(client.allocator, qr.code, .L)) |qr_matrix| {
                    var mut_qr = qr_matrix;
                    defer mut_qr.deinit();

                    // 1. Render in terminal
                    if (mut_qr.renderTerminal(client.allocator)) |rendered| {
                        defer client.allocator.free(rendered);
                        std.debug.print("{s}", .{rendered});
                    } else |_| {
                        log.info("Main", "{s}", .{qr.code});
                    }

                    // 2. Save qrcode.html
                    saveQrCodeHtml(client.allocator, client.io, mut_qr, qr.code);
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
            log.info("Main", "", .{});
            log.info("Main", "====================================================", .{});
            log.info("Main", "✅ CONECTADO AO WHATSAPP!", .{});
            log.info("Main", "  Número: {s}", .{c.phone_jid});
            log.info("Main", "  LID:    {s}", .{c.lid});
            log.info("Main", "====================================================", .{});
            log.info("Main", "", .{});

            // Envio automático de validação para o próprio número (self-chat)
            if (c.phone_jid.len > 0) {
                sendValidationMessage(client, c.phone_jid, "⚡ [WhatsZig] Sessão conectada com sucesso! Envie 'ping' ou qualquer mensagem para testar o recebimento.");
            }
        },
        .message => |msg| {
            if (msg.getBody()) |body| {
                const is_self = client.address_book.isSelfChatJid(msg.chat) or client.address_book.isSelfChatJid(msg.from);
                log.info("Main", "", .{});
                log.info("Main", "┌──────────────────────────────────────────────────────────", .{});
                if (is_self) {
                    log.info("Main", "│ 📩 MENSAGEM RECEBIDA (AUTO-ENVIO / SELF-CHAT CONFIRMADO)", .{});
                } else {
                    log.info("Main", "│ 📩 MENSAGEM RECEBIDA", .{});
                }
                log.info("Main", "│ De:    {s}", .{msg.from});
                log.info("Main", "│ Chat:  {s}", .{msg.chat});
                log.info("Main", "│ ID:    {s}", .{msg.id});
                log.info("Main", "│ Texto: \"{s}\"", .{body});
                if (is_self) {
                    log.info("Main", "│ ✅ RECEBIMENTO CONFIRMADO VIA CLIENT WHATSZIG!", .{});
                }
                log.info("Main", "└──────────────────────────────────────────────────────────", .{});
                log.info("Main", "", .{});

                // Resposta automática se receber ping
                if (std.mem.indexOf(u8, body, "ping") != null or std.mem.indexOf(u8, body, "Ping") != null) {
                    // Resolve LID chat JID para phone JID antes de enviar
                    const reply_jid = resolveReplyJid(client, msg.chat) orelse msg.chat;
                    sendValidationMessage(client, reply_jid, "🦎 pong! Resposta automática do WhatsZig.");
                }
            } else {
                log.info("Main", "📩 [SISTEMA/SYNC] Mensagem de protocolo recebida de: {s}", .{msg.from});
            }
        },
        .disconnected => {
            log.warn("Main", "⚠️ Desconectado do WhatsApp", .{});
        },
        .login_failed => log.err("Main", "❌ Falha no login", .{}),
    }
}

/// Resolve um LID (ex: 124953718435910:50@lid) para o phone JID correspondente.
/// Se for o próprio número (self-chat), usa phone_jid direto.
/// Retorna null se não conseguir resolver (usa o JID original como fallback).
fn resolveReplyJid(client: *whatszig.Client, chat_jid: []const u8) ?[]const u8 {
    // Se for self-chat (próprio número), use sempre phone_jid
    if (client.address_book.isSelfChatJid(chat_jid)) {
        return client.phone_jid;
    }
    // Tenta resolver LID -> phone JID via address_book
    const resolved = client.address_book.resolvePhoneJid(chat_jid) catch return null;
    // Se resolveu para um phone JID diferente, retorna ele
    if (!std.mem.eql(u8, resolved.value, chat_jid)) {
        return resolved.value;
    }
    return null;
}

fn sendValidationMessage(client: *whatszig.Client, to_jid: []const u8, text: []const u8) void {
    log.info("Main", "┌──────────────────────────────────────────────────────────", .{});
    log.info("Main", "│ 📤 ENVIANDO MENSAGEM", .{});
    log.info("Main", "│ Para:  {s}", .{to_jid});
    log.info("Main", "│ Texto: \"{s}\"", .{text});
    log.info("Main", "└──────────────────────────────────────────────────────────", .{});

    client.sendMessage(to_jid, text) catch |err| {
        log.err("Main", "❌ Falha ao enviar mensagem para {s}: {}", .{ to_jid, err });
        return;
    };
    log.info("Main", "✅ Mensagem enviada com sucesso para {s}", .{to_jid});
}

fn saveQrCodeHtml(allocator: std.mem.Allocator, io: std.Io, qr: whatszig.qr.QrCode, raw_code: []const u8) void {
    if (qr.renderHtml(allocator, raw_code)) |html| {
        defer allocator.free(html);

        if (std.Io.Dir.cwd().createFile(io, "qrcode.html", .{})) |file| {
            defer file.close(io);
            file.writePositionalAll(io, html, 0) catch {};
            log.info("Main", "QR Code HTML salvo em: qrcode.html (abra no navegador para escanear)", .{});
        } else |_| {}
    } else |_| {}
}
