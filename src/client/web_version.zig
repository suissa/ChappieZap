const std = @import("std");
const log = @import("log");
const http = std.http;

pub fn refreshAppVersion(self: anytype, comptime AppVersion: type) void {
    const latest = fetchLatestAppVersion(AppVersion, self.allocator, self.io) catch |err| {
        log.warn("Client", "Failed to fetch latest WA version: {}. Using {d}.{d}.{d}", .{
            err,
            self.app_version.primary,
            self.app_version.secondary,
            self.app_version.tertiary,
        });
        return;
    };

    if (latest.tertiary != self.app_version.tertiary) {
        log.info("Client", "Using WA version {d}.{d}.{d}", .{
            latest.primary, latest.secondary, latest.tertiary,
        });
    } else {
        log.debug("Client", "Using WA version {d}.{d}.{d}", .{
            latest.primary, latest.secondary, latest.tertiary,
        });
    }
    self.app_version = latest;
}

pub fn fetchLatestAppVersion(comptime AppVersion: type, allocator: std.mem.Allocator, io: std.Io) !AppVersion {
    var http_client = http.Client{
        .allocator = allocator,
        .io = io,
    };
    defer http_client.deinit();

    const uri = try std.Uri.parse("https://web.whatsapp.com/sw.js");
    var req = try http_client.request(.GET, uri, .{
        .headers = .{},
        .extra_headers = &.{
            .{ .name = "sec-fetch-site", .value = "none" },
            .{ .name = "user-agent", .value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [0]u8 = .{};
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status != .ok) return error.VersionFetchFailed;

    var body_writer = std.Io.Writer.Allocating.init(allocator);
    defer body_writer.deinit();
    var transfer_buf: [4096]u8 = undefined;
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    // SAFETY: `readerDecompressing` initializes and manages this scratch state before it is read.
    var decompress: http.Decompress = undefined;
    var body_reader = response.readerDecompressing(&transfer_buf, &decompress, &decompress_buf);
    _ = try body_reader.streamRemaining(&body_writer.writer);

    return parseSwJs(AppVersion, body_writer.written()) orelse error.VersionParseFailed;
}

fn parseSwJs(comptime AppVersion: type, body: []const u8) ?AppVersion {
    const key = "client_revision";
    const assets_key = "assets-manifest-";

    if (std.mem.indexOf(u8, body, key)) |start_index| {
        const suffix = body[start_index + key.len ..];
        var first_digit_index: ?usize = null;
        for (suffix, 0..) |c, i| {
            if (c >= '0' and c <= '9') {
                first_digit_index = i;
                break;
            }
        }
        if (first_digit_index) |digit_idx| {
            const number_slice = suffix[digit_idx..];
            var end_idx: usize = number_slice.len;
            for (number_slice, 0..) |c, i| {
                if (c < '0' or c > '9') {
                    end_idx = i;
                    break;
                }
            }
            const version_str = number_slice[0..end_idx];
            const revision = std.fmt.parseInt(u32, version_str, 10) catch return null;
            return .{ .tertiary = revision };
        }
    }

    if (std.mem.indexOf(u8, body, assets_key)) |_| return .{ .tertiary = 0 };

    return null;
}
