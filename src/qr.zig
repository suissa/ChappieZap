const std = @import("std");

/// Error correction level for QR code.
pub const EcLevel = enum(u2) {
    L = 1, // ~7% error correction (Low)
    M = 0, // ~15% error correction (Medium)
    Q = 3, // ~25% error correction (Quartile)
    H = 2, // ~30% error correction (High)
};

pub const QrCode = struct {
    version: u8,
    size: usize,
    modules: []bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *QrCode) void {
        self.allocator.free(self.modules);
    }

    pub fn get(self: QrCode, x: usize, y: usize) bool {
        if (x >= self.size or y >= self.size) return false;
        return self.modules[y * self.size + x];
    }

    /// Encode a text string into a QR code.
    pub fn encodeText(allocator: std.mem.Allocator, text: []const u8, min_ec: EcLevel) !QrCode {
        const version = getMinVersion(text.len, min_ec) orelse return error.DataTooLong;
        return encodeTextVersion(allocator, text, version, min_ec);
    }

    /// Render QR code into terminal string representation using half-block Unicode characters.
    /// Returns an allocated string with the rendered QR code.
    pub fn renderTerminal(self: QrCode, allocator: std.mem.Allocator) ![]u8 {
        const quiet_zone = 2;
        const total_size = self.size + quiet_zone * 2;

        var allocating_writer = try std.Io.Writer.Allocating.initCapacity(
            allocator,
            total_size * (total_size / 2 + 4) * 4,
        );
        defer allocating_writer.deinit();
        const writer = &allocating_writer.writer;

        // Top margin / quiet zone
        try writer.writeAll("\n");

        var y: usize = 0;
        while (y < total_size) : (y += 2) {
            for (0..total_size) |x| {
                const top_black = if (x >= quiet_zone and x < self.size + quiet_zone and y >= quiet_zone and y < self.size + quiet_zone)
                    self.get(x - quiet_zone, y - quiet_zone)
                else
                    false;

                const bottom_y = y + 1;
                const bottom_black = if (bottom_y < total_size and x >= quiet_zone and x < self.size + quiet_zone and bottom_y >= quiet_zone and bottom_y < self.size + quiet_zone)
                    self.get(x - quiet_zone, bottom_y - quiet_zone)
                else
                    false;

                if (top_black and bottom_black) {
                    try writer.writeAll(" ");
                } else if (top_black and !bottom_black) {
                    try writer.writeAll("▄");
                } else if (!top_black and bottom_black) {
                    try writer.writeAll("▀");
                } else {
                    try writer.writeAll("█");
                }
            }
            try writer.writeAll("\n");
        }

        try writer.writeAll("\n");
        return allocating_writer.toOwnedSlice();
    }
};

// --- Tables and Specifications for QR Code Model 2 ---

// Total data codewords available per version and EC level
const EC_CODEWORDS_TABLE = [41][4]u16{
    .{ 0, 0, 0, 0 }, // 0 (unused)
    .{ 7, 10, 13, 17 }, // 1
    .{ 10, 16, 22, 28 }, // 2
    .{ 15, 26, 36, 44 }, // 3
    .{ 20, 36, 52, 64 }, // 4
    .{ 26, 48, 72, 88 }, // 5
    .{ 36, 64, 96, 112 }, // 6
    .{ 40, 72, 108, 130 }, // 7
    .{ 48, 88, 132, 156 }, // 8
    .{ 60, 110, 160, 192 }, // 9
    .{ 72, 130, 192, 224 }, // 10
    .{ 80, 150, 224, 264 }, // 11
    .{ 96, 176, 260, 308 }, // 12
    .{ 104, 198, 288, 352 }, // 13
    .{ 120, 216, 320, 384 }, // 14
    .{ 132, 240, 360, 432 }, // 15
    .{ 144, 280, 408, 480 }, // 16
    .{ 168, 308, 448, 532 }, // 17
    .{ 180, 338, 504, 588 }, // 18
    .{ 196, 364, 546, 650 }, // 19
    .{ 224, 416, 600, 700 }, // 20
    .{ 224, 442, 644, 750 }, // 21
    .{ 252, 476, 690, 816 }, // 22
    .{ 270, 504, 750, 900 }, // 23
    .{ 300, 560, 810, 960 }, // 24
    .{ 312, 588, 870, 1050 }, // 25
    .{ 336, 644, 952, 1110 }, // 26
    .{ 360, 700, 1020, 1200 }, // 27
    .{ 390, 728, 1050, 1260 }, // 28
    .{ 420, 784, 1140, 1350 }, // 29
    .{ 450, 812, 1200, 1440 }, // 30
    .{ 480, 868, 1290, 1530 }, // 31
    .{ 510, 924, 1350, 1620 }, // 32
    .{ 540, 980, 1440, 1710 }, // 33
    .{ 570, 1036, 1530, 1800 }, // 34
    .{ 600, 1064, 1590, 1890 }, // 35
    .{ 630, 1120, 1680, 1980 }, // 36
    .{ 660, 1204, 1770, 2100 }, // 37
    .{ 720, 1260, 1860, 2220 }, // 38
    .{ 750, 1316, 1950, 2310 }, // 39
    .{ 780, 1372, 2040, 2430 }, // 40
};

// Total capacity in bytes for each version
const TOTAL_CODEWORDS_TABLE = [41]u16{
    0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
    404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
    1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
    2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706,
};

// Number of error correction blocks for each version and EC level
const EC_BLOCKS_TABLE = [41][4]u8{
    .{ 0, 0, 0, 0 },
    .{ 1, 1, 1, 1 }, // 1
    .{ 1, 1, 1, 1 }, // 2
    .{ 1, 1, 2, 2 }, // 3
    .{ 1, 2, 2, 4 }, // 4
    .{ 1, 2, 4, 4 }, // 5
    .{ 2, 4, 4, 4 }, // 6
    .{ 2, 4, 6, 5 }, // 7
    .{ 2, 4, 6, 6 }, // 8
    .{ 2, 5, 8, 8 }, // 9
    .{ 4, 5, 8, 8 }, // 10
    .{ 4, 5, 8, 11 }, // 11
    .{ 4, 8, 10, 11 }, // 12
    .{ 4, 9, 12, 16 }, // 13
    .{ 4, 9, 16, 16 }, // 14
    .{ 6, 10, 12, 18 }, // 15
    .{ 6, 10, 17, 16 }, // 16
    .{ 6, 11, 16, 19 }, // 17
    .{ 6, 13, 18, 21 }, // 18
    .{ 7, 14, 21, 25 }, // 19
    .{ 8, 16, 20, 25 }, // 20
    .{ 8, 17, 23, 25 }, // 21
    .{ 9, 17, 23, 34 }, // 22
    .{ 9, 18, 25, 30 }, // 23
    .{ 10, 20, 27, 32 }, // 24
    .{ 12, 21, 29, 35 }, // 25
    .{ 12, 23, 34, 37 }, // 26
    .{ 12, 25, 34, 40 }, // 27
    .{ 13, 26, 35, 42 }, // 28
    .{ 14, 28, 38, 45 }, // 29
    .{ 15, 29, 40, 48 }, // 30
    .{ 16, 31, 43, 51 }, // 31
    .{ 17, 33, 45, 54 }, // 32
    .{ 18, 35, 48, 57 }, // 33
    .{ 19, 37, 51, 60 }, // 34
    .{ 19, 38, 53, 63 }, // 35
    .{ 20, 40, 56, 66 }, // 36
    .{ 21, 43, 59, 70 }, // 37
    .{ 22, 45, 62, 74 }, // 38
    .{ 24, 47, 65, 77 }, // 39
    .{ 25, 49, 68, 81 }, // 40
};

// Alignment pattern positions per version (max 7 positions)
const ALIGNMENT_PATTERN_POS = [41][]const u8{
    &.{}, // 0
    &.{}, // 1
    &.{ 6, 18 }, // 2
    &.{ 6, 22 }, // 3
    &.{ 6, 26 }, // 4
    &.{ 6, 30 }, // 5
    &.{ 6, 34 }, // 6
    &.{ 6, 22, 38 }, // 7
    &.{ 6, 24, 42 }, // 8
    &.{ 6, 26, 46 }, // 9
    &.{ 6, 28, 50 }, // 10
    &.{ 6, 30, 54 }, // 11
    &.{ 6, 32, 58 }, // 12
    &.{ 6, 34, 62 }, // 13
    &.{ 6, 26, 46, 66 }, // 14
    &.{ 6, 26, 48, 70 }, // 15
    &.{ 6, 26, 50, 74 }, // 16
    &.{ 6, 30, 54, 78 }, // 17
    &.{ 6, 30, 56, 82 }, // 18
    &.{ 6, 30, 58, 86 }, // 19
    &.{ 6, 34, 62, 90 }, // 20
    &.{ 6, 28, 50, 72, 94 }, // 21
    &.{ 6, 26, 50, 74, 98 }, // 22
    &.{ 6, 30, 54, 78, 102 }, // 23
    &.{ 6, 28, 54, 80, 106 }, // 24
    &.{ 6, 32, 58, 84, 110 }, // 25
    &.{ 6, 30, 58, 86, 114 }, // 26
    &.{ 6, 34, 62, 90, 118 }, // 27
    &.{ 6, 26, 50, 74, 98, 122 }, // 28
    &.{ 6, 30, 54, 78, 102, 126 }, // 29
    &.{ 6, 26, 52, 78, 104, 130 }, // 30
    &.{ 6, 30, 56, 82, 108, 134 }, // 31
    &.{ 6, 34, 60, 86, 112, 138 }, // 32
    &.{ 6, 30, 58, 86, 114, 142 }, // 33
    &.{ 6, 34, 62, 90, 118, 146 }, // 34
    &.{ 6, 30, 54, 78, 102, 126, 150 }, // 35
    &.{ 6, 24, 50, 76, 102, 128, 154 }, // 36
    &.{ 6, 28, 54, 80, 106, 132, 158 }, // 37
    &.{ 6, 32, 58, 84, 110, 136, 162 }, // 38
    &.{ 6, 26, 54, 82, 110, 138, 166 }, // 39
    &.{ 6, 30, 58, 86, 114, 142, 170 }, // 40
};

fn ecIndex(ec: EcLevel) usize {
    return switch (ec) {
        .L => 0,
        .M => 1,
        .Q => 2,
        .H => 3,
    };
}

fn getDataCodewords(version: u8, ec: EcLevel) u16 {
    return TOTAL_CODEWORDS_TABLE[version] - EC_CODEWORDS_TABLE[version][ecIndex(ec)];
}

pub fn getMinVersion(data_len: usize, ec: EcLevel) ?u8 {
    for (1..41) |v| {
        const ver: u8 = @intCast(v);
        const data_capacity = getDataCodewords(ver, ec);
        const header_bits: usize = 4 + (if (ver < 10) @as(usize, 8) else 16);
        const total_data_bits = header_bits + data_len * 8;
        const required_bytes = (total_data_bits + 7) / 8;
        if (required_bytes <= data_capacity) {
            return ver;
        }
    }
    return null;
}

// --- Galois Field GF(256) Math for Reed-Solomon ---

const GF_EXP: [512]u8 = blk: {
    @setEvalBranchQuota(10000);
    var exp: [512]u8 = undefined;
    var x: u16 = 1;
    for (0..255) |i| {
        exp[i] = @intCast(x);
        exp[i + 255] = @intCast(x);
        x <<= 1;
        if ((x & 0x100) != 0) {
            x ^= 0x11D; // Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
        }
    }
    exp[510] = exp[0];
    exp[511] = exp[1];
    break :blk exp;
};

const GF_LOG: [256]u8 = blk: {
    @setEvalBranchQuota(10000);
    var log: [256]u8 = undefined;
    log[0] = 0;
    for (0..255) |i| {
        log[GF_EXP[i]] = @intCast(i);
    }
    break :blk log;
};

fn gfMul(x: u8, y: u8) u8 {
    if (x == 0 or y == 0) return 0;
    const log_sum = @as(usize, GF_LOG[x]) + @as(usize, GF_LOG[y]);
    return GF_EXP[log_sum];
}

fn rsGeneratorPoly(degree: usize, out: []u8) void {
    @memset(out[0 .. degree + 1], 0);
    out[0] = 1;
    for (0..degree) |i| {
        const factor = GF_EXP[i];
        var j = i + 1;
        while (j > 0) : (j -= 1) {
            out[j] = out[j] ^ gfMul(out[j - 1], factor);
        }
        out[0] = gfMul(out[0], factor);
    }
}

fn rsCalculateEc(data: []const u8, ec_count: usize, ec_out: []u8) void {
    var gen: [64]u8 = undefined;
    rsGeneratorPoly(ec_count, gen[0 .. ec_count + 1]);

    @memset(ec_out[0..ec_count], 0);
    for (data) |byte| {
        const factor = byte ^ ec_out[0];
        for (0..ec_count - 1) |j| {
            ec_out[j] = ec_out[j + 1] ^ gfMul(gen[ec_count - 1 - j], factor);
        }
        ec_out[ec_count - 1] = gfMul(gen[0], factor);
    }
}

// --- Encoding Data ---

fn encodeDataCodewords(allocator: std.mem.Allocator, text: []const u8, version: u8, ec: EcLevel) ![]u8 {
    const total_data_codewords = getDataCodewords(version, ec);
    var bit_buf: std.ArrayList(u1) = .empty;
    defer bit_buf.deinit(allocator);

    // Mode indicator: 0100 (Byte mode)
    try appendBits(&bit_buf, allocator, 0b0100, 4);

    // Character count indicator
    const count_bits: u6 = if (version < 10) 8 else 16;
    try appendBits(&bit_buf, allocator, @intCast(text.len), count_bits);

    // Data bytes
    for (text) |byte| {
        try appendBits(&bit_buf, allocator, byte, 8);
    }

    // Terminator (up to 4 zero bits)
    const max_bits = @as(usize, total_data_codewords) * 8;
    const term_bits = @min(4, max_bits - bit_buf.items.len);
    try appendBits(&bit_buf, allocator, 0, @intCast(term_bits));

    // Pad to 8 bits
    while (bit_buf.items.len % 8 != 0) {
        try bit_buf.append(allocator, 0);
    }

    // Pad bytes: alternating 0xEC (236) and 0x11 (17)
    var result = try allocator.alloc(u8, total_data_codewords);
    const written_bytes = bit_buf.items.len / 8;
    for (0..written_bytes) |i| {
        var byte: u8 = 0;
        for (0..8) |bit| {
            byte = (byte << 1) | bit_buf.items[i * 8 + bit];
        }
        result[i] = byte;
    }

    var pad: u8 = 0xEC;
    for (written_bytes..total_data_codewords) |i| {
        result[i] = pad;
        pad = if (pad == 0xEC) 0x11 else 0xEC;
    }

    return result;
}

fn appendBits(buf: *std.ArrayList(u1), allocator: std.mem.Allocator, value: u32, count: u6) !void {
    var i: usize = count;
    while (i > 0) : (i -= 1) {
        const bit: u1 = @intCast((value >> @intCast(i - 1)) & 1);
        try buf.append(allocator, bit);
    }
}

// --- Matrix Construction ---

const Matrix = struct {
    size: usize,
    modules: []u8, // 0 = empty/unassigned, 1 = white/light, 2 = black/dark, | 0x80 = function module (reserved)
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, size: usize) !Matrix {
        const modules = try allocator.alloc(u8, size * size);
        @memset(modules, 0);
        return .{
            .size = size,
            .modules = modules,
            .allocator = allocator,
        };
    }

    fn deinit(self: *Matrix) void {
        self.allocator.free(self.modules);
    }

    fn setFunction(self: *Matrix, x: usize, y: usize, is_dark: bool) void {
        self.modules[y * self.size + x] = (if (is_dark) @as(u8, 2) else 1) | 0x80;
    }

    fn isFunction(self: Matrix, x: usize, y: usize) bool {
        return (self.modules[y * self.size + x] & 0x80) != 0;
    }

    fn set(self: *Matrix, x: usize, y: usize, is_dark: bool) void {
        self.modules[y * self.size + x] = if (is_dark) 2 else 1;
    }

    fn isDark(self: Matrix, x: usize, y: usize) bool {
        return (self.modules[y * self.size + x] & 0x7F) == 2;
    }
};

fn placeFinderPattern(matrix: *Matrix, center_x: usize, center_y: usize) void {
    var dy: i32 = -4;
    while (dy <= 4) : (dy += 1) {
        var dx: i32 = -4;
        while (dx <= 4) : (dx += 1) {
            const x_i = @as(i32, @intCast(center_x)) + dx;
            const y_i = @as(i32, @intCast(center_y)) + dy;
            if (x_i >= 0 and x_i < matrix.size and y_i >= 0 and y_i < matrix.size) {
                const x: usize = @intCast(x_i);
                const y: usize = @intCast(y_i);
                const dist = @max(@abs(dx), @abs(dy));
                const is_dark = (dist != 2 and dist != 4);
                matrix.setFunction(x, y, is_dark);
            }
        }
    }
}

fn placeAlignmentPattern(matrix: *Matrix, center_x: usize, center_y: usize) void {
    var dy: i32 = -2;
    while (dy <= 2) : (dy += 1) {
        var dx: i32 = -2;
        while (dx <= 2) : (dx += 1) {
            const x: usize = @intCast(@as(i32, @intCast(center_x)) + dx);
            const y: usize = @intCast(@as(i32, @intCast(center_y)) + dy);
            if (!matrix.isFunction(x, y)) {
                const dist = @max(@abs(dx), @abs(dy));
                const is_dark = (dist != 1);
                matrix.setFunction(x, y, is_dark);
            }
        }
    }
}

fn setupFunctionModules(matrix: *Matrix, version: u8) void {
    const size = matrix.size;

    // Finder patterns & separators
    placeFinderPattern(matrix, 3, 3);
    placeFinderPattern(matrix, size - 4, 3);
    placeFinderPattern(matrix, 3, size - 4);

    // Timing patterns
    for (8..size - 8) |i| {
        const is_dark = (i % 2 == 0);
        if (!matrix.isFunction(i, 6)) matrix.setFunction(i, 6, is_dark);
        if (!matrix.isFunction(6, i)) matrix.setFunction(6, i, is_dark);
    }

    // Alignment patterns for versions >= 2
    if (version >= 2) {
        const positions = ALIGNMENT_PATTERN_POS[version];
        for (positions) |y| {
            for (positions) |x| {
                if (!matrix.isFunction(x, y)) {
                    placeAlignmentPattern(matrix, x, y);
                }
            }
        }
    }

    // Dark module
    matrix.setFunction(8, 4 * @as(usize, version) + 9, true);

    // Format information dummy reserve
    for (0..9) |i| {
        if (!matrix.isFunction(i, 8)) matrix.setFunction(i, 8, false);
        if (!matrix.isFunction(8, i)) matrix.setFunction(8, i, false);
    }
    for (0..8) |i| {
        if (!matrix.isFunction(size - 1 - i, 8)) matrix.setFunction(size - 1 - i, 8, false);
        if (!matrix.isFunction(8, size - 1 - i)) matrix.setFunction(8, size - 1 - i, false);
    }

    // Version info dummy reserve for version >= 7
    if (version >= 7) {
        for (0..6) |i| {
            for (0..3) |j| {
                matrix.setFunction(i, size - 11 + j, false);
                matrix.setFunction(size - 11 + j, i, false);
            }
        }
    }
}

// --- Format and Version Information ---

const FORMAT_MASK_TABLE = [32]u15{
    0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
    0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976,
    0x1689, 0x13BE, 0x1CE7, 0x19D0, 0x0762, 0x0255, 0x0D0C, 0x083B,
    0x355F, 0x3068, 0x3F31, 0x3A06, 0x24B4, 0x2183, 0x2EDA, 0x2BED,
};

const VERSION_INFO_TABLE = [34]u18{
    0x07C94, 0x085BC, 0x09A99, 0x0A4D3, 0x0BBF6, 0x0C762, 0x0D847, 0x0E60D,
    0x0F928, 0x10B78, 0x1145D, 0x12A17, 0x13532, 0x149A6, 0x15683, 0x168C9,
    0x177EC, 0x18EC4, 0x191E1, 0x1AFAB, 0x1B08E, 0x1CC1A, 0x1D33F, 0x1ED75,
    0x1F250, 0x209D5, 0x216F0, 0x228BA, 0x2379F, 0x24B0B, 0x2542E, 0x26A64,
    0x27541, 0x28C69,
};

fn writeFormatInfo(matrix: *Matrix, ec: EcLevel, mask: u3) void {
    const ec_val = @as(u5, @intFromEnum(ec));
    const format_index = (ec_val << 3) | mask;
    const format_bits = FORMAT_MASK_TABLE[format_index];
    const size = matrix.size;

    for (0..15) |i| {
        const bit = ((format_bits >> @intCast(i)) & 1) != 0;
        if (i < 6) {
            matrix.set(i, 8, bit);
        } else if (i < 8) {
            matrix.set(i + 1, 8, bit);
        } else {
            matrix.set(8, 15 - i, bit);
        }

        if (i < 8) {
            matrix.set(8, size - 1 - i, bit);
        } else {
            matrix.set(size - 15 + i, 8, bit);
        }
    }
}

fn writeVersionInfo(matrix: *Matrix, version: u8) void {
    if (version < 7) return;
    const v_bits = VERSION_INFO_TABLE[version - 7];
    const size = matrix.size;

    for (0..18) |i| {
        const bit = ((v_bits >> @intCast(i)) & 1) != 0;
        const row = i / 3;
        const col = i % 3;
        matrix.set(col, size - 11 + row, bit);
        matrix.set(size - 11 + row, col, bit);
    }
}

// --- Masking and Penalty Scoring ---

fn isMasked(mask: u3, x: usize, y: usize) bool {
    return switch (mask) {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => ((y / 2) + (x / 3)) % 2 == 0,
        5 => ((x * y) % 2) + ((x * y) % 3) == 0,
        6 => (((x * y) % 2) + ((x * y) % 3)) % 2 == 0,
        7 => (((x + y) % 2) + ((x * y) % 3)) % 2 == 0,
    };
}

fn evaluatePenalty(matrix: Matrix) u32 {
    const size = matrix.size;
    var penalty: u32 = 0;

    // Rule 1: 5 or more consecutive same-color modules in row/column
    for (0..size) |y| {
        var run_color = matrix.isDark(0, y);
        var run_len: u32 = 1;
        for (1..size) |x| {
            const color = matrix.isDark(x, y);
            if (color == run_color) {
                run_len += 1;
            } else {
                if (run_len >= 5) penalty += 3 + (run_len - 5);
                run_color = color;
                run_len = 1;
            }
        }
        if (run_len >= 5) penalty += 3 + (run_len - 5);
    }

    for (0..size) |x| {
        var run_color = matrix.isDark(x, 0);
        var run_len: u32 = 1;
        for (1..size) |y| {
            const color = matrix.isDark(x, y);
            if (color == run_color) {
                run_len += 1;
            } else {
                if (run_len >= 5) penalty += 3 + (run_len - 5);
                run_color = color;
                run_len = 1;
            }
        }
        if (run_len >= 5) penalty += 3 + (run_len - 5);
    }

    // Rule 2: 2x2 blocks of same color
    for (0..size - 1) |y| {
        for (0..size - 1) |x| {
            const c = matrix.isDark(x, y);
            if (c == matrix.isDark(x + 1, y) and c == matrix.isDark(x, y + 1) and c == matrix.isDark(x + 1, y + 1)) {
                penalty += 3;
            }
        }
    }

    // Rule 4: Balance of dark and light modules
    var total_dark: u32 = 0;
    for (0..size) |y| {
        for (0..size) |x| {
            if (matrix.isDark(x, y)) total_dark += 1;
        }
    }
    const total_modules: u32 = @intCast(size * size);
    const dark_percent = (total_dark * 100) / total_modules;
    const diff = if (dark_percent > 50) dark_percent - 50 else 50 - dark_percent;
    penalty += (diff / 5) * 10;

    return penalty;
}

// --- Top Level Encoding Function ---

pub fn encodeTextVersion(allocator: std.mem.Allocator, text: []const u8, version: u8, ec: EcLevel) !QrCode {
    const data_codewords = try encodeDataCodewords(allocator, text, version, ec);
    defer allocator.free(data_codewords);

    const ec_idx = ecIndex(ec);
    const total_ec_codewords = EC_CODEWORDS_TABLE[version][ec_idx];
    const num_blocks = EC_BLOCKS_TABLE[version][ec_idx];
    const total_data_codewords = getDataCodewords(version, ec);

    const ec_per_block = total_ec_codewords / num_blocks;
    const short_data_len = total_data_codewords / num_blocks;
    const num_long_blocks = total_data_codewords % num_blocks;
    const num_short_blocks = num_blocks - num_long_blocks;

    // Allocate interleaved codewords buffer
    const total_codewords = TOTAL_CODEWORDS_TABLE[version];
    const all_codewords = try allocator.alloc(u8, total_codewords);
    defer allocator.free(all_codewords);

    // Compute EC for each block
    var data_offset: usize = 0;
    var ec_buf = try allocator.alloc(u8, total_ec_codewords);
    defer allocator.free(ec_buf);

    for (0..num_blocks) |b| {
        const block_data_len = if (b < num_short_blocks) short_data_len else short_data_len + 1;
        const block_data = data_codewords[data_offset .. data_offset + block_data_len];
        const block_ec = ec_buf[b * ec_per_block .. (b + 1) * ec_per_block];
        rsCalculateEc(block_data, ec_per_block, block_ec);
        data_offset += block_data_len;
    }

    // Interleave data codewords
    var out_idx: usize = 0;
    const max_data_len = short_data_len + (if (num_long_blocks > 0) @as(usize, 1) else 0);
    for (0..max_data_len) |i| {
        var blk_start: usize = 0;
        for (0..num_blocks) |b| {
            const blk_len = if (b < num_short_blocks) short_data_len else short_data_len + 1;
            if (i < blk_len) {
                all_codewords[out_idx] = data_codewords[blk_start + i];
                out_idx += 1;
            }
            blk_start += blk_len;
        }
    }

    // Interleave error correction codewords
    for (0..ec_per_block) |i| {
        for (0..num_blocks) |b| {
            all_codewords[out_idx] = ec_buf[b * ec_per_block + i];
            out_idx += 1;
        }
    }

    // Build best matrix by trying all 8 masks
    const size = @as(usize, version) * 4 + 17;
    var best_mask: u3 = 0;
    var lowest_penalty: u32 = std.math.maxInt(u32);

    for (0..8) |mask_i| {
        const mask: u3 = @intCast(mask_i);
        var mat = try Matrix.init(allocator, size);
        defer mat.deinit();

        setupFunctionModules(&mat, version);

        // Place data bits in zigzag
        var bit_idx: usize = 0;
        const total_bits = total_codewords * 8;

        var right: i32 = @intCast(size - 1);
        while (right > 0) {
            if (right == 6) right -= 1; // Skip vertical timing pattern
            const r_u: usize = @intCast(right);
            const col_pair_idx = (size - 1 - r_u) / 2;
            const going_up = (col_pair_idx % 2 == 0);

            var y_step: usize = 0;
            while (y_step < size) : (y_step += 1) {
                const y = if (going_up) size - 1 - y_step else y_step;
                for (0..2) |x_offset| {
                    if (r_u < x_offset) continue;
                    const x = r_u - x_offset;
                    if (!mat.isFunction(x, y)) {
                        var bit = false;
                        if (bit_idx < total_bits) {
                            const byte_idx = bit_idx / 8;
                            const bit_pos: u3 = @intCast(7 - (bit_idx % 8));
                            bit = ((all_codewords[byte_idx] >> bit_pos) & 1) != 0;
                            bit_idx += 1;
                        }
                        if (isMasked(mask, x, y)) {
                            bit = !bit;
                        }
                        mat.set(x, y, bit);
                    }
                }
            }
            right -= 2;
        }

        writeFormatInfo(&mat, ec, mask);
        writeVersionInfo(&mat, version);

        const penalty = evaluatePenalty(mat);
        if (penalty < lowest_penalty) {
            lowest_penalty = penalty;
            best_mask = mask;
        }
    }

    // Now construct final QR matrix with best mask
    var final_mat = try Matrix.init(allocator, size);
    defer final_mat.deinit();

    setupFunctionModules(&final_mat, version);

    var bit_idx: usize = 0;
    const total_bits = total_codewords * 8;

    var right: i32 = @intCast(size - 1);
    while (right > 0) {
        if (right == 6) right -= 1;
        const r_u: usize = @intCast(right);
        const col_pair_idx = (size - 1 - r_u) / 2;
        const going_up = (col_pair_idx % 2 == 0);

        var y_step: usize = 0;
        while (y_step < size) : (y_step += 1) {
            const y = if (going_up) size - 1 - y_step else y_step;
            for (0..2) |x_offset| {
                if (r_u < x_offset) continue;
                const x = r_u - x_offset;
                if (!final_mat.isFunction(x, y)) {
                    var bit = false;
                    if (bit_idx < total_bits) {
                        const byte_idx = bit_idx / 8;
                        const bit_pos: u3 = @intCast(7 - (bit_idx % 8));
                        bit = ((all_codewords[byte_idx] >> bit_pos) & 1) != 0;
                        bit_idx += 1;
                    }
                    if (isMasked(best_mask, x, y)) {
                        bit = !bit;
                    }
                    final_mat.set(x, y, bit);
                }
            }
        }
        right -= 2;
    }

    writeFormatInfo(&final_mat, ec, best_mask);
    writeVersionInfo(&final_mat, version);

    // Copy to QrCode result
    const modules = try allocator.alloc(bool, size * size);
    for (0..size) |y| {
        for (0..size) |x| {
            modules[y * size + x] = final_mat.isDark(x, y);
        }
    }

    return .{
        .version = version,
        .size = size,
        .modules = modules,
        .allocator = allocator,
    };
}

// --- Unit Tests ---

test "min version determination" {
    try std.testing.expectEqual(@as(?u8, 1), getMinVersion("HELLO".len, .L));
    try std.testing.expectEqual(@as(?u8, 1), getMinVersion("1234567890".len, .M));
    // ~165 chars fits in version 8 at level L
    const v = getMinVersion(165, .L);
    try std.testing.expect(v != null);
    try std.testing.expect(v.? <= 9);
}

test "galois field multiplication" {
    try std.testing.expectEqual(@as(u8, 0), gfMul(0, 50));
    try std.testing.expectEqual(@as(u8, 0), gfMul(50, 0));
    try std.testing.expectEqual(@as(u8, 1), gfMul(1, 1));
    try std.testing.expectEqual(@as(u8, 4), gfMul(2, 2));
}

test "QR code encode basic text" {
    const allocator = std.testing.allocator;
    var qr = try QrCode.encodeText(allocator, "HELLO WORLD", .M);
    defer qr.deinit();

    try std.testing.expect(qr.size >= 21);
    // Finder pattern top-left should have dark corner
    try std.testing.expect(qr.get(0, 0));
    try std.testing.expect(qr.get(6, 0));
    try std.testing.expect(!qr.get(7, 0));
}

test "QR code encode whatsapp pairing payload" {
    const allocator = std.testing.allocator;
    const wa_payload = "2@G3fIM2jptT5skuwmY6MrqHQzMulSG1NmZ3xnknmJfJ+ngS1E/2xyYIhhYiLzvp7mAN6svFBitlNPFVzZMVMrtKTNWfk9KFzCxJo=,HCZQrJkun5/oq1VFM3/116j5RUvcZfj4Dki58tJ4z2M=,eYiHzu9i0DiFqd5oNx4fK8smz3PG127n2oSQI0CLVl8=,p/YT+AVM7VNNrU12mAcmHNN/WgEc7MUBE725BbSuodc=";
    var qr = try QrCode.encodeText(allocator, wa_payload, .L);
    defer qr.deinit();

    try std.testing.expect(qr.version >= 8);
    const term_str = try qr.renderTerminal(allocator);
    defer allocator.free(term_str);
    try std.testing.expect(term_str.len > 0);
}
