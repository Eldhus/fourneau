//! Brotli's fixed tables (RFC 7932), shared by the encoder and the decoder:
//! the static dictionary and its word transforms, the literal context
//! lookups, and the base values and extra bits of lengths and counts.
//! Each table the RFC publishes a CRC-32 for is checked against it.

const std = @import("std");
const assert = std.debug.assert;

/// The static dictionary (Appendix A), and how its words are laid out:
/// `ndbits[length]` bits of word index for each length 4..24.
pub const dictionary = @import("brotli_dictionary").bytes;

pub const ndbits = [25]u5{
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5,
};

pub const word_length_min = 4;
pub const word_length_max = 24;

/// Where the words of each length start in `dictionary` (section 8).
pub const word_offsets: [26]u32 = offsets: {
    var offsets: [26]u32 = undefined;
    offsets[0] = 0;
    for (0..25) |length| {
        offsets[length + 1] = offsets[length] + @as(u32, @intCast(length)) * word_count(length);
    }
    break :offsets offsets;
};

comptime {
    assert(word_offsets[25] == dictionary.len);
}

pub fn word_count(length: usize) u32 {
    if (length < word_length_min) return 0;
    return @as(u32, 1) << ndbits[length];
}

pub fn word(length: usize, index: u32) []const u8 {
    assert(length >= word_length_min and length <= word_length_max);
    assert(index < word_count(length));
    const start = word_offsets[length] + index * length;
    return dictionary[start..][0..length];
}

/// An elementary transform (section 8), numbered as Appendix B numbers
/// them: 0 identity, 1 ferment first, 2 ferment all, 3..11 omit the first
/// 1..9 bytes, 12..20 omit the last 1..9.
pub const Elementary = u8;
pub const identity: Elementary = 0;
pub const ferment_first: Elementary = 1;
pub const ferment_all: Elementary = 2;

fn omit_first(count: u8) Elementary {
    assert(count >= 1 and count <= 9);
    return 2 + count;
}

fn omit_last(count: u8) Elementary {
    assert(count >= 1 and count <= 9);
    return 11 + count;
}

pub const Transform = struct {
    prefix: []const u8,
    elementary: Elementary,
    suffix: []const u8,
};

pub const transforms_count = 121;
/// The most bytes a transform adds to a word (section 8).
pub const transform_growth_max = 13;

fn t(prefix: []const u8, elementary: Elementary, suffix: []const u8) Transform {
    return .{ .prefix = prefix, .elementary = elementary, .suffix = suffix };
}

/// Appendix B, in order: the comment is its ID.
pub const transforms = [transforms_count]Transform{
    t("", identity, ""), // 0
    t("", identity, " "), // 1
    t(" ", identity, " "), // 2
    t("", omit_first(1), ""), // 3
    t("", ferment_first, " "), // 4
    t("", identity, " the "), // 5
    t(" ", identity, ""), // 6
    t("s ", identity, " "), // 7
    t("", identity, " of "), // 8
    t("", ferment_first, ""), // 9
    t("", identity, " and "), // 10
    t("", omit_first(2), ""), // 11
    t("", omit_last(1), ""), // 12
    t(", ", identity, " "), // 13
    t("", identity, ", "), // 14
    t(" ", ferment_first, " "), // 15
    t("", identity, " in "), // 16
    t("", identity, " to "), // 17
    t("e ", identity, " "), // 18
    t("", identity, "\""), // 19
    t("", identity, "."), // 20
    t("", identity, "\">"), // 21
    t("", identity, "\n"), // 22
    t("", omit_last(3), ""), // 23
    t("", identity, "]"), // 24
    t("", identity, " for "), // 25
    t("", omit_first(3), ""), // 26
    t("", omit_last(2), ""), // 27
    t("", identity, " a "), // 28
    t("", identity, " that "), // 29
    t(" ", ferment_first, ""), // 30
    t("", identity, ". "), // 31
    t(".", identity, ""), // 32
    t(" ", identity, ", "), // 33
    t("", omit_first(4), ""), // 34
    t("", identity, " with "), // 35
    t("", identity, "'"), // 36
    t("", identity, " from "), // 37
    t("", identity, " by "), // 38
    t("", omit_first(5), ""), // 39
    t("", omit_first(6), ""), // 40
    t(" the ", identity, ""), // 41
    t("", omit_last(4), ""), // 42
    t("", identity, ". The "), // 43
    t("", ferment_all, ""), // 44
    t("", identity, " on "), // 45
    t("", identity, " as "), // 46
    t("", identity, " is "), // 47
    t("", omit_last(7), ""), // 48
    t("", omit_last(1), "ing "), // 49
    t("", identity, "\n\t"), // 50
    t("", identity, ":"), // 51
    t(" ", identity, ". "), // 52
    t("", identity, "ed "), // 53
    t("", omit_first(9), ""), // 54
    t("", omit_first(7), ""), // 55
    t("", omit_last(6), ""), // 56
    t("", identity, "("), // 57
    t("", ferment_first, ", "), // 58
    t("", omit_last(8), ""), // 59
    t("", identity, " at "), // 60
    t("", identity, "ly "), // 61
    t(" the ", identity, " of "), // 62
    t("", omit_last(5), ""), // 63
    t("", omit_last(9), ""), // 64
    t(" ", ferment_first, ", "), // 65
    t("", ferment_first, "\""), // 66
    t(".", identity, "("), // 67
    t("", ferment_all, " "), // 68
    t("", ferment_first, "\">"), // 69
    t("", identity, "=\""), // 70
    t(" ", identity, "."), // 71
    t(".com/", identity, ""), // 72
    t(" the ", identity, " of the "), // 73
    t("", ferment_first, "'"), // 74
    t("", identity, ". This "), // 75
    t("", identity, ","), // 76
    t(".", identity, " "), // 77
    t("", ferment_first, "("), // 78
    t("", ferment_first, "."), // 79
    t("", identity, " not "), // 80
    t(" ", identity, "=\""), // 81
    t("", identity, "er "), // 82
    t(" ", ferment_all, " "), // 83
    t("", identity, "al "), // 84
    t(" ", ferment_all, ""), // 85
    t("", identity, "='"), // 86
    t("", ferment_all, "\""), // 87
    t("", ferment_first, ". "), // 88
    t(" ", identity, "("), // 89
    t("", identity, "ful "), // 90
    t(" ", ferment_first, ". "), // 91
    t("", identity, "ive "), // 92
    t("", identity, "less "), // 93
    t("", ferment_all, "'"), // 94
    t("", identity, "est "), // 95
    t(" ", ferment_first, "."), // 96
    t("", ferment_all, "\">"), // 97
    t(" ", identity, "='"), // 98
    t("", ferment_first, ","), // 99
    t("", identity, "ize "), // 100
    t("", ferment_all, "."), // 101
    t("\xc2\xa0", identity, ""), // 102
    t(" ", identity, ","), // 103
    t("", ferment_first, "=\""), // 104
    t("", ferment_all, "=\""), // 105
    t("", identity, "ous "), // 106
    t("", ferment_all, ", "), // 107
    t("", ferment_first, "='"), // 108
    t(" ", ferment_first, ","), // 109
    t(" ", ferment_all, "=\""), // 110
    t(" ", ferment_all, ", "), // 111
    t("", ferment_all, ","), // 112
    t("", ferment_all, "("), // 113
    t("", ferment_all, ". "), // 114
    t(" ", ferment_all, "."), // 115
    t("", ferment_all, "='"), // 116
    t(" ", ferment_all, ". "), // 117
    t(" ", ferment_first, "=\""), // 118
    t(" ", ferment_all, "='"), // 119
    t(" ", ferment_first, "='"), // 120
};

/// The bytes `word` becomes under transform `id`, written to `out`.
pub const transformed_bytes_max = word_length_max + transform_growth_max;

pub fn transform_word(word_bytes: []const u8, id: u8, out: *[transformed_bytes_max]u8) []u8 {
    assert(id < transforms_count);
    assert(word_bytes.len <= word_length_max);
    const transform = &transforms[id];
    var used: usize = 0;
    @memcpy(out[used..][0..transform.prefix.len], transform.prefix);
    used += transform.prefix.len;
    const kind = transform.elementary;
    var body = word_bytes;
    if (kind >= 3 and kind <= 11) body = body[@min(body.len, kind - 2)..];
    if (kind >= 12) body = body[0 .. body.len - @min(body.len, kind - 11)];
    const body_start = used;
    @memcpy(out[used..][0..body.len], body);
    used += body.len;
    if (kind == ferment_first and body.len > 0) _ = ferment(out[body_start..used], 0);
    if (kind == ferment_all) {
        var position: usize = 0;
        for (0..body.len) |_| {
            if (position >= body.len) break;
            position += ferment(out[body_start..used], position);
        } else assert(position >= body.len);
    }
    @memcpy(out[used..][0..transform.suffix.len], transform.suffix);
    used += transform.suffix.len;
    assert(used <= out.len);
    return out[0..used];
}

/// Section 8's Ferment: uppercase one ASCII letter, or flip a bit in a
/// UTF-8 sequence's second or third byte. The bytes it stepped over.
fn ferment(bytes: []u8, position: usize) usize {
    assert(position < bytes.len);
    const byte = bytes[position];
    if (byte < 192) {
        if (byte >= 'a' and byte <= 'z') bytes[position] ^= 32;
        return 1;
    }
    if (byte < 224) {
        if (position + 1 < bytes.len) bytes[position + 1] ^= 32;
        return 2;
    }
    if (position + 2 < bytes.len) bytes[position + 2] ^= 5;
    return 3;
}

/// Literal context lookups (section 7.1).
pub const lut0 = [256]u8{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
};

pub const lut1 = [256]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};

pub const lut2 = [256]u8{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
};

pub const ContextMode = enum(u2) { lsb6 = 0, msb6 = 1, utf8 = 2, signed = 3 };

/// The literal context ID from the last two bytes, `p1` the most recent.
pub fn literal_context(mode: ContextMode, p1: u8, p2: u8) u6 {
    return switch (mode) {
        .lsb6 => @truncate(p1),
        .msb6 => @intCast(p1 >> 2),
        .utf8 => @intCast(lut0[p1] | lut1[p2]),
        .signed => @intCast((lut2[p1] << 3) | lut2[p2]),
    };
}

/// The distance context ID from the copy length (section 7.2).
pub fn distance_context(copy_length: u32) u2 {
    assert(copy_length >= 2);
    return @intCast(@min(copy_length - 2, 3));
}

/// A code's base value and the number of extra bits that follow it.
pub const Range = struct { base: u32, extra: u5 };

/// Insert lengths (section 5).
pub const insert_ranges = [24]Range{
    .{ .base = 0, .extra = 0 },     .{ .base = 1, .extra = 0 },
    .{ .base = 2, .extra = 0 },     .{ .base = 3, .extra = 0 },
    .{ .base = 4, .extra = 0 },     .{ .base = 5, .extra = 0 },
    .{ .base = 6, .extra = 1 },     .{ .base = 8, .extra = 1 },
    .{ .base = 10, .extra = 2 },    .{ .base = 14, .extra = 2 },
    .{ .base = 18, .extra = 3 },    .{ .base = 26, .extra = 3 },
    .{ .base = 34, .extra = 4 },    .{ .base = 50, .extra = 4 },
    .{ .base = 66, .extra = 5 },    .{ .base = 98, .extra = 5 },
    .{ .base = 130, .extra = 6 },   .{ .base = 194, .extra = 7 },
    .{ .base = 322, .extra = 8 },   .{ .base = 578, .extra = 9 },
    .{ .base = 1090, .extra = 10 }, .{ .base = 2114, .extra = 12 },
    .{ .base = 6210, .extra = 14 }, .{ .base = 22594, .extra = 24 },
};

/// Copy lengths (section 5).
pub const copy_ranges = [24]Range{
    .{ .base = 2, .extra = 0 },     .{ .base = 3, .extra = 0 },
    .{ .base = 4, .extra = 0 },     .{ .base = 5, .extra = 0 },
    .{ .base = 6, .extra = 0 },     .{ .base = 7, .extra = 0 },
    .{ .base = 8, .extra = 0 },     .{ .base = 9, .extra = 0 },
    .{ .base = 10, .extra = 1 },    .{ .base = 12, .extra = 1 },
    .{ .base = 14, .extra = 2 },    .{ .base = 18, .extra = 2 },
    .{ .base = 22, .extra = 3 },    .{ .base = 30, .extra = 3 },
    .{ .base = 38, .extra = 4 },    .{ .base = 54, .extra = 4 },
    .{ .base = 70, .extra = 5 },    .{ .base = 102, .extra = 5 },
    .{ .base = 134, .extra = 6 },   .{ .base = 198, .extra = 7 },
    .{ .base = 326, .extra = 8 },   .{ .base = 582, .extra = 9 },
    .{ .base = 1094, .extra = 10 }, .{ .base = 2118, .extra = 24 },
};

/// Block counts (section 6).
pub const block_count_ranges = [26]Range{
    .{ .base = 1, .extra = 2 },     .{ .base = 5, .extra = 2 },
    .{ .base = 9, .extra = 2 },     .{ .base = 13, .extra = 2 },
    .{ .base = 17, .extra = 3 },    .{ .base = 25, .extra = 3 },
    .{ .base = 33, .extra = 3 },    .{ .base = 41, .extra = 3 },
    .{ .base = 49, .extra = 4 },    .{ .base = 65, .extra = 4 },
    .{ .base = 81, .extra = 4 },    .{ .base = 97, .extra = 4 },
    .{ .base = 113, .extra = 5 },   .{ .base = 145, .extra = 5 },
    .{ .base = 177, .extra = 5 },   .{ .base = 209, .extra = 5 },
    .{ .base = 241, .extra = 6 },   .{ .base = 305, .extra = 6 },
    .{ .base = 369, .extra = 7 },   .{ .base = 497, .extra = 8 },
    .{ .base = 753, .extra = 9 },   .{ .base = 1265, .extra = 10 },
    .{ .base = 2289, .extra = 11 }, .{ .base = 4337, .extra = 12 },
    .{ .base = 8433, .extra = 13 }, .{ .base = 16625, .extra = 24 },
};

/// The insert and copy length codes, and whether the distance is the last
/// one (implicit), of an insert-and-copy symbol (section 5's table).
pub const InsertCopy = struct { insert_code: u5, copy_code: u5, last_distance: bool };

pub fn insert_copy(symbol: u16) InsertCopy {
    assert(symbol < 704);
    // Per 64-symbol cell: the insert and copy code ranges' first codes.
    const cells = [11]struct { insert: u5, copy: u5 }{
        .{ .insert = 0, .copy = 0 },   .{ .insert = 0, .copy = 8 },
        .{ .insert = 0, .copy = 0 },   .{ .insert = 0, .copy = 8 },
        .{ .insert = 8, .copy = 0 },   .{ .insert = 8, .copy = 8 },
        .{ .insert = 0, .copy = 16 },  .{ .insert = 16, .copy = 0 },
        .{ .insert = 8, .copy = 16 },  .{ .insert = 16, .copy = 8 },
        .{ .insert = 16, .copy = 16 },
    };
    const cell = cells[symbol >> 6];
    return .{
        .insert_code = cell.insert + @as(u5, @intCast((symbol >> 3) & 7)),
        .copy_code = cell.copy + @as(u5, @intCast(symbol & 7)),
        .last_distance = symbol < 128,
    };
}

const Crc32 = std.hash.Crc32;

test "brotli_tables: the dictionary is the RFC's" {
    try std.testing.expectEqual(122_784, dictionary.len);
    try std.testing.expectEqual(0x5136cb04, Crc32.hash(dictionary));
    try std.testing.expectEqualStrings("time", word(4, 0));
    try std.testing.expectEqualStrings("down", word(4, 1));
}

test "brotli_tables: the transforms are the RFC's" {
    // Appendix B: prefix, 0, the elementary transform, suffix, 0, each.
    var crc = Crc32.init();
    var length: usize = 0;
    for (transforms) |transform| {
        crc.update(transform.prefix);
        crc.update(&.{ 0, transform.elementary });
        crc.update(transform.suffix);
        crc.update(&.{0});
        length += transform.prefix.len + transform.suffix.len + 3;
    }
    try std.testing.expectEqual(648, length);
    try std.testing.expectEqual(0x3d965f81, crc.final());
}

test "brotli_tables: the context lookups are the RFC's" {
    try std.testing.expectEqual(0x8e91efb7, Crc32.hash(&lut0));
    try std.testing.expectEqual(0xd01a32f4, Crc32.hash(&lut1));
    try std.testing.expectEqual(0x0dd7a0d6, Crc32.hash(&lut2));
}

test "brotli_tables: the transforms do what section 8 says" {
    var out: [transformed_bytes_max]u8 = undefined;
    try std.testing.expectEqualStrings("time", transform_word("time", 0, &out));
    try std.testing.expectEqualStrings(" the time of the ", transform_word("time", 73, &out));
    try std.testing.expectEqualStrings("Time ", transform_word("time", 4, &out));
    try std.testing.expectEqualStrings("TIME\">", transform_word("time", 97, &out));
    try std.testing.expectEqualStrings("me", transform_word("time", 11, &out));
    try std.testing.expectEqualStrings("tim", transform_word("time", 12, &out));
    try std.testing.expectEqualStrings("timing ", transform_word("time", 49, &out));
    try std.testing.expectEqualStrings("", transform_word("time", 54, &out));
}

test "brotli_tables: lengths, counts and the insert-and-copy table" {
    // Each range ends where the next begins.
    for (insert_ranges[0..23], insert_ranges[1..]) |range, next| {
        try std.testing.expectEqual(next.base, range.base + (@as(u32, 1) << range.extra));
    }
    for (copy_ranges[0..23], copy_ranges[1..]) |range, next| {
        try std.testing.expectEqual(next.base, range.base + (@as(u32, 1) << range.extra));
    }
    for (block_count_ranges[0..25], block_count_ranges[1..]) |range, next| {
        try std.testing.expectEqual(next.base, range.base + (@as(u32, 1) << range.extra));
    }
    const expected = [_]struct { u16, InsertCopy }{
        .{ 0, .{ .insert_code = 0, .copy_code = 0, .last_distance = true } },
        .{ 127, .{ .insert_code = 7, .copy_code = 15, .last_distance = true } },
        .{ 703, .{ .insert_code = 23, .copy_code = 23, .last_distance = false } },
        .{ 384, .{ .insert_code = 0, .copy_code = 16, .last_distance = false } },
    };
    for (expected) |case| try std.testing.expectEqual(case[1], insert_copy(case[0]));
}
