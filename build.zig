const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    const websocket_dep = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });

    const binary_mod = b.addModule("binary", .{
        .root_source_file = b.path("src/binary.zig"),
        .target = target,
    });

    const websocket_mod = b.addModule("websocket", .{
        .root_source_file = websocket_dep.path("src/websocket.zig"),
        .target = target,
    });

    const whatsapp_ws_mod = b.addModule("whatsapp_websocket", .{
        .root_source_file = b.path("src/whatsapp_websocket.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "websocket", .module = websocket_mod },
            .{ .name = "binary", .module = binary_mod },
        },
    });

    const mod = b.addModule("zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "protobuf", .module = protobuf_dep.module("protobuf") },
            .{ .name = "binary", .module = binary_mod },
            .{ .name = "websocket", .module = websocket_mod },
            .{ .name = "whatsapp_websocket", .module = whatsapp_ws_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    // and lastly use the dependency as a module
    exe.root_module.addImport("protobuf", protobuf_dep.module("protobuf"));

    const gen_proto = b.step("gen-proto", "generates zig files from protocol buffer definitions");

    const protoc_step = protobuf.RunProtocStep.create(b, protobuf_dep.builder, target, .{
        // out directory for the generated zig files
        .destination_directory = b.path("src/gen"),
        .source_files = &.{
            "proto/whatsapp.proto",
        },
        .include_directories = &.{},
    });

    gen_proto.dependOn(&protoc_step.step);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
