const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const log_level = b.option([]const u8, "log_level", "Log level: debug, info, warn, err (default: info)") orelse "info";

    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    const protobuf_mod = protobuf_dep.module("protobuf");

    // --- Modules ---

    const binary_mod = b.addModule("binary", .{
        .root_source_file = b.path("src/binary.zig"),
        .target = target,
    });

    const xed25519_mod = b.addModule("xed25519", .{
        .root_source_file = b.path("src/xed25519.zig"),
        .target = target,
    });

    const noise_mod = b.addModule("noise", .{
        .root_source_file = b.path("src/noise.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "xed25519", .module = xed25519_mod },
        },
    });

    const websocket_client_mod = b.addModule("websocket_client", .{
        .root_source_file = b.path("src/websocket_client.zig"),
        .target = target,
    });

    const framing_mod = b.addModule("framing", .{
        .root_source_file = b.path("src/framing.zig"),
        .target = target,
    });

    const wa_proto_mod = b.addModule("whatsapp_proto", .{
        .root_source_file = b.path("src/gen/whatsapp.pb.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "protobuf", .module = protobuf_mod },
        },
    });

    const log_options = b.addOptions();
    log_options.addOption([]const u8, "default_level", log_level);

    const log_mod = b.addModule("log", .{
        .root_source_file = b.path("src/log.zig"),
        .target = target,
    });
    log_mod.addOptions("build_options", log_options);

    const socket_mod = b.addModule("socket", .{
        .root_source_file = b.path("src/socket.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "websocket_client", .module = websocket_client_mod },
            .{ .name = "framing", .module = framing_mod },
            .{ .name = "log", .module = log_mod },
        },
    });

    const signal_mod = b.addModule("signal", .{
        .root_source_file = b.path("src/signal/root.zig"),
        .target = target,
    });

    const node_handler_mod = b.addModule("node_handler", .{
        .root_source_file = b.path("src/node_handler.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "binary", .module = binary_mod },
        },
    });

    const handshake_orch_mod = b.addModule("handshake", .{
        .root_source_file = b.path("src/handshake.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "websocket_client", .module = websocket_client_mod },
            .{ .name = "noise", .module = noise_mod },
            .{ .name = "xed25519", .module = xed25519_mod },
            .{ .name = "framing", .module = framing_mod },
            .{ .name = "whatsapp_proto", .module = wa_proto_mod },
            .{ .name = "log", .module = log_mod },
        },
    });

    const prekey_mod = b.addModule("prekey", .{
        .root_source_file = b.path("src/prekey.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "signal", .module = signal_mod },
        },
    });

    const pair_mod = b.addModule("pair", .{
        .root_source_file = b.path("src/pair.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "signal", .module = signal_mod },
            .{ .name = "whatsapp_proto", .module = wa_proto_mod },
        },
    });

    const messaging_mod = b.addModule("messaging", .{
        .root_source_file = b.path("src/messaging.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "signal", .module = signal_mod },
            .{ .name = "prekey", .module = prekey_mod },
            .{ .name = "protobuf", .module = protobuf_mod },
            .{ .name = "whatsapp_proto", .module = wa_proto_mod },
        },
    });

    const events_mod = b.addModule("events", .{
        .root_source_file = b.path("src/events.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "binary", .module = binary_mod },
        },
    });

    const client_mod = b.addModule("client", .{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "websocket_client", .module = websocket_client_mod },
            .{ .name = "xed25519", .module = xed25519_mod },
            .{ .name = "socket", .module = socket_mod },
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "signal", .module = signal_mod },
            .{ .name = "handshake", .module = handshake_orch_mod },
            .{ .name = "node_handler", .module = node_handler_mod },
            .{ .name = "prekey", .module = prekey_mod },
            .{ .name = "messaging", .module = messaging_mod },
            .{ .name = "pair", .module = pair_mod },
            .{ .name = "whatsapp_proto", .module = wa_proto_mod },
            .{ .name = "events", .module = events_mod },
            .{ .name = "log", .module = log_mod },
        },
    });

    // --- Library root module ---

    const mod = b.addModule("zigwhats", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "client", .module = client_mod },
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "noise", .module = noise_mod },
            .{ .name = "xed25519", .module = xed25519_mod },
            .{ .name = "framing", .module = framing_mod },
            .{ .name = "socket", .module = socket_mod },
            .{ .name = "websocket_client", .module = websocket_client_mod },
            .{ .name = "whatsapp_proto", .module = wa_proto_mod },
            .{ .name = "protobuf", .module = protobuf_mod },
            .{ .name = "signal", .module = signal_mod },
            .{ .name = "events", .module = events_mod },
            .{ .name = "log", .module = log_mod },
        },
    });

    // --- Executable ---

    const exe = b.addExecutable(.{
        .name = "zigwhats",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigwhats", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const gen_proto = b.step("gen-proto", "generates zig files from protocol buffer definitions");
    const protoc_step = protobuf.RunProtocStep.create(protobuf_dep.builder, target, .{
        .destination_directory = b.path("src/gen"),
        .source_files = &.{
            b.path("proto/whatsapp.proto"),
        },
        .include_directories = &.{
            b.path("proto"),
        },
    });
    gen_proto.dependOn(&protoc_step.step);

    // --- Run ---

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // --- Unit tests ---

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // --- E2E tests (require mock server) ---

    const e2e_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/e2e.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "client", .module = client_mod },
            },
        }),
    });

    const run_e2e_tests = b.addRunArtifact(e2e_tests);
    const e2e_step = b.step("e2e", "Run e2e tests (requires mock server)");
    e2e_step.dependOn(&run_e2e_tests.step);
}
