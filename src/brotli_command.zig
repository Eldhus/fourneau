//! A brotli command as the stream codes it (RFC 7932 sections 4 and 5):
//! its insert-and-copy symbol, the lengths' extra bits, and its distance,
//! by the four-distance cache when that names it. Shared by the writer
//! and the parsers, so a parse is priced exactly as it will be written.

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");
const context = @import("brotli_context.zig");

/// `insert` literals, then `copy` bytes from `distance` back; the last
/// command may copy nothing.
pub const Command = struct {
    insert: u32,
    copy: u32,
    distance: u32,
};

/// NPOSTFIX 0, NDIRECT 0: the 16 short codes and 48 general ones.
pub const distance_alphabet = 16 + 48;

pub const Coded = struct {
    insert_copy: u16,
    insert_extra: u32,
    insert_extra_bits: u5,
    copy_extra: u32,
    copy_extra_bits: u5,
    /// None: the distance is implied (the last one), or there is no copy.
    distance: ?u16,
    distance_extra: u32,
    distance_extra_bits: u5,
};

/// The last four distances, as the decoder keeps them (section 4).
pub const DistanceCache = struct {
    last: [4]u32 = initial,

    pub const initial: [4]u32 = .{ 4, 11, 15, 16 };

    /// The short code for `distance`, if one names it.
    pub fn short_code(cache: *const DistanceCache, distance: u32) ?u16 {
        for (cache.last, 0..) |value, index| if (value == distance) return @intCast(index);
        const offsets = [6]i64{ -1, 1, -2, 2, -3, 3 };
        for (offsets, 0..) |offset, index| {
            if (@as(i64, cache.last[0]) + offset == distance) return @intCast(4 + index);
            if (@as(i64, cache.last[1]) + offset == distance) return @intCast(10 + index);
        }
        return null;
    }

    pub fn push(cache: *DistanceCache, distance: u32) void {
        std.mem.copyBackwards(u32, cache.last[1..], cache.last[0..3]);
        cache.last[0] = distance;
    }
};

/// The command's symbols; the cache moves as the decoder's will.
pub fn code(command: Command, distances: *DistanceCache) Coded {
    const insert = insert_length_code(command.insert);
    // The last command copies nothing: any copy code, never read.
    const copy = if (command.copy == 0) 0 else copy_length_code(command.copy);
    const copy_range = tables.copy_ranges[copy];
    var coded: Coded = .{
        .insert_copy = undefined,
        .insert_extra = command.insert - tables.insert_ranges[insert].base,
        .insert_extra_bits = tables.insert_ranges[insert].extra,
        .copy_extra = if (command.copy == 0) 0 else command.copy - copy_range.base,
        .copy_extra_bits = if (command.copy == 0) 0 else copy_range.extra,
        .distance = null,
        .distance_extra = 0,
        .distance_extra_bits = 0,
    };
    var implied = false;
    if (command.copy > 0) {
        const short = distances.short_code(command.distance);
        if (short == 0 and insert < 8 and copy < 16) {
            implied = true; // the last distance, in the symbol itself
        } else if (short) |short_code| {
            coded.distance = short_code;
            if (short_code != 0) distances.push(command.distance);
        } else {
            code_distance(command.distance, &coded);
            distances.push(command.distance);
        }
    }
    coded.insert_copy = insert_copy_symbol(insert, copy, implied);
    return coded;
}

/// Whether a command with this distance moves the cache: every distance
/// but the last one's (short code 0) does.
pub fn pushes(distances: *const DistanceCache, distance: u32) bool {
    return distances.last[0] != distance;
}

/// The insert code for `insert` literals: by table where a table is small.
pub fn insert_length_code(insert: u32) u5 {
    if (insert < insert_codes.len) return insert_codes[insert];
    return code_for(&tables.insert_ranges, insert);
}

/// The copy code for a copy of `copy` bytes (2 or more).
pub fn copy_length_code(copy: u32) u5 {
    assert(copy >= 2);
    if (copy < copy_codes.len) return copy_codes[copy];
    return code_for(&tables.copy_ranges, copy);
}

const insert_codes = code_table(2114, &tables.insert_ranges);
const copy_codes = code_table(2118, &tables.copy_ranges);

fn code_table(comptime size: usize, ranges: []const tables.Range) [size]u5 {
    @setEvalBranchQuota(size * 32);
    var table: [size]u5 = @splat(0);
    for (&table, 0..) |*entry, value| {
        if (value >= ranges[0].base) entry.* = code_for(ranges, value);
    }
    return table;
}

/// The largest code whose range starts at or below `value`.
pub fn code_for(ranges: []const tables.Range, value: u32) u5 {
    var result: u5 = @intCast(ranges.len - 1);
    while (ranges[result].base > value) result -= 1;
    assert(value - ranges[result].base < @as(u64, 1) << ranges[result].extra);
    return result;
}

/// Section 5's table, from codes back to its symbol.
pub fn insert_copy_symbol(insert_code: u5, copy_code: u5, implied: bool) u16 {
    const insert_cell: u16 = insert_code >> 3;
    const copy_cell: u16 = copy_code >> 3;
    const cell: u16 = if (implied) blk: {
        assert(insert_cell == 0 and copy_cell <= 1);
        break :blk copy_cell;
    } else switch (insert_cell * 3 + copy_cell) {
        0 => 2,
        1 => 3,
        2 => 6,
        3 => 4,
        4 => 5,
        5 => 8,
        6 => 7,
        7 => 9,
        8 => 10,
        else => unreachable,
    };
    const symbol = cell * 64 + (@as(u16, insert_code & 7) << 3) + (copy_code & 7);
    const decoded = tables.insert_copy(symbol);
    assert(decoded.insert_code == insert_code and decoded.copy_code == copy_code);
    assert(decoded.last_distance == implied);
    return symbol;
}

/// A distance as a general code (section 4, NPOSTFIX and NDIRECT 0).
pub fn code_distance(distance: u32, coded: *Coded) void {
    assert(distance >= 1);
    const value = distance + 3;
    const top: u5 = @intCast(std.math.log2_int(u32, value));
    const extra_bits: u5 = top - 1;
    const prefix = (value >> extra_bits) & 1;
    coded.distance = @intCast(16 + 2 * (@as(u16, extra_bits) - 1) + prefix);
    coded.distance_extra = value - ((2 + prefix) << extra_bits);
    coded.distance_extra_bits = extra_bits;
}

/// How often each symbol occurs in a parse: what its codes are made from.
/// Literals by their context (`brotli_context.zig`).
pub const Histograms = struct {
    literals: [context.contexts]context.Histogram = @splat(@splat(0)),
    insert_copy: [704]u32 = @splat(0),
    distances: [distance_alphabet]u32 = @splat(0),

    pub fn count(input: []const u8, commands: []const Command) Histograms {
        var histograms: Histograms = .{};
        var distances: DistanceCache = .{};
        var position: usize = 0;
        for (commands) |command| {
            for (position..position + command.insert) |at| {
                histograms.literals[context.at(input, at)][input[at]] += 1;
            }
            const coded = code(command, &distances);
            histograms.insert_copy[coded.insert_copy] += 1;
            if (coded.distance) |symbol| histograms.distances[symbol] += 1;
            position += command.insert + command.copy;
        }
        assert(position == input.len);
        return histograms;
    }
};

test "brotli_command: distances decode as they were coded" {
    // Each general distance code read back by section 4's formula.
    for ([_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 100, 1000, 65535, 1 << 20, (1 << 24) - 16 }) |distance| {
        var coded: Coded = undefined;
        code_distance(distance, &coded);
        const rest = coded.distance.? - 16;
        const extra: u5 = @intCast(1 + (rest >> 1));
        try std.testing.expectEqual(coded.distance_extra_bits, extra);
        const offset = ((2 + (@as(u32, rest) & 1)) << extra) - 4;
        try std.testing.expectEqual(distance, offset + coded.distance_extra + 1);
    }
}
