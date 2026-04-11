const std = @import("std");
const build_options = @import("build_options");

pub const Level = enum {
    debug,
    info,
    warn,
    err,
};

fn parseLevel(s: []const u8) Level {
    if (std.mem.eql(u8, s, "debug")) return .debug;
    if (std.mem.eql(u8, s, "warn")) return .warn;
    if (std.mem.eql(u8, s, "err") or std.mem.eql(u8, s, "error")) return .err;
    return .info;
}

pub var min_level: Level = parseLevel(build_options.default_level);

pub fn setLevel(level: Level) void {
    min_level = level;
}

pub fn enabled(level: Level) bool {
    return shouldLog(level);
}

fn shouldLog(level: Level) bool {
    return @intFromEnum(level) >= @intFromEnum(min_level);
}

pub fn debug(comptime scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (shouldLog(.debug)) print(.debug, scope, fmt, args);
}

pub fn info(comptime scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (shouldLog(.info)) print(.info, scope, fmt, args);
}

pub fn warn(comptime scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (shouldLog(.warn)) print(.warn, scope, fmt, args);
}

pub fn err(comptime scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (shouldLog(.err)) print(.err, scope, fmt, args);
}

fn print(level: Level, comptime scope: []const u8, comptime fmt: []const u8, args: anytype) void {
    const timestamp = currentTimestamp();
    const level_str = switch (level) {
        .debug => "DEBUG",
        .info => "INFO ",
        .warn => "WARN ",
        .err => "ERROR",
    };
    std.debug.print("{s} [{s}] [{s}] - " ++ fmt ++ "\n", .{ timestamp, level_str, scope } ++ args);
}

fn currentTimestamp() [12]u8 {
    var tv = std.mem.zeroes(std.posix.timeval);
    if (std.posix.system.gettimeofday(&tv, null) != 0) {
        return "00:00:00.000".*;
    }

    const epoch_seconds = std.time.epoch.EpochSeconds{
        .secs = @intCast(@max(tv.sec, 0)),
    };
    const day_seconds = epoch_seconds.getDaySeconds();
    const millis: u16 = @intCast(@divTrunc(tv.usec, 1000));

    var buf: [12]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        millis,
    }) catch {
        @panic("timestamp buffer too small");
    };
    return buf;
}
