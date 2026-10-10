//! A brotli encoder (RFC 7932), for compressing static files once, at
//! load: as small as we can make them, at whatever it costs then.
//!
//! The stream is one meta-block: the commands (literals, then a copy) the
//! matcher finds, each as an insert-and-copy symbol, its literals and a
//! distance, coded with prefix codes made for these counts. Distances use
//! the four-distance cache where they can (section 4). When compressing
//! does not pay, the bytes go out as an uncompressed meta-block.

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");
const huffman = @import("brotli_huffman.zig");
const match = @import("brotli_match.zig");

const Allocator = std.mem.Allocator;
const BitWriter = huffman.BitWriter;
const Command = match.Command;

/// The most bytes in one meta-block (section 2), and so in what we encode.
pub const input_bytes_max = 1 << 24;

/// `input`, compressed; the caller frees it.
pub fn encode(gpa: Allocator, input: []const u8) ![]u8 {
    assert(input.len <= input_bytes_max);
    var writer: BitWriter = .{};
    errdefer writer.bytes.deinit(gpa);
    const window_bits = window_bits_for(input.len);
    try write_window_bits(&writer, gpa, window_bits);
    if (input.len == 0) {
        try writer.write(gpa, 0b11, 2); // ISLAST, ISLASTEMPTY
    } else {
        const window: u32 = (@as(u32, 1) << window_bits) - 16;
        var commands: std.ArrayList(Command) = .empty;
        defer commands.deinit(gpa);
        try match.parse_lazy(gpa, input, window, &commands);
        try write_compressed(&writer, gpa, input, commands.items, window);
        if (writer.bit_count() > (input.len + 8) * 8) {
            // Worse than the bytes themselves: store them.
            writer.bytes.clearRetainingCapacity();
            writer.pending = 0;
            writer.pending_count = 0;
            try write_window_bits(&writer, gpa, window_bits);
            try write_uncompressed(&writer, gpa, input);
        }
    }
    try writer.align_zero(gpa);
    return writer.bytes.toOwnedSlice(gpa);
}

/// The smallest window holding every distance in `length` bytes: 10..24.
fn window_bits_for(length: usize) u5 {
    var bits: u5 = 10;
    while (bits < 24 and (@as(usize, 1) << bits) - 16 < length) bits += 1;
    return bits;
}

/// Section 9.1's code.
fn write_window_bits(writer: *BitWriter, gpa: Allocator, bits: u5) !void {
    assert(bits >= 10 and bits <= 24);
    if (bits == 16) return writer.write(gpa, 0, 1);
    if (bits >= 18) return writer.write(gpa, 1 | (@as(u64, bits - 17) << 1), 4);
    if (bits == 17) return writer.write(gpa, 1, 7);
    return writer.write(gpa, 1 | (@as(u64, bits - 8) << 4), 7);
}

/// MNIBBLES and MLEN - 1 (section 9.2).
fn write_length(writer: *BitWriter, gpa: Allocator, length: usize) !void {
    assert(length >= 1 and length <= input_bytes_max);
    const value = length - 1;
    var nibbles: u6 = 4;
    while (nibbles < 6 and value >> (nibbles * 4) != 0) nibbles += 1;
    try writer.write(gpa, nibbles - 4, 2);
    try writer.write(gpa, value, nibbles * 4);
}

fn write_uncompressed(writer: *BitWriter, gpa: Allocator, input: []const u8) !void {
    try writer.write(gpa, 0, 1); // ISLAST: no (an uncompressed one cannot be)
    try write_length(writer, gpa, input.len);
    try writer.write(gpa, 1, 1); // ISUNCOMPRESSED
    try writer.align_zero(gpa);
    try writer.bytes.appendSlice(gpa, input);
    try writer.write(gpa, 0b11, 2); // the last meta-block: empty
}

/// One command, as coded: its insert-and-copy symbol with the lengths'
/// extra bits, and its distance symbol with its extra bits, if any.
const Coded = struct {
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

const distance_alphabet = 16 + 48; // NPOSTFIX 0, NDIRECT 0

fn write_compressed(
    writer: *BitWriter,
    gpa: Allocator,
    input: []const u8,
    commands: []const Command,
    window: u32,
) !void {
    const coded = try gpa.alloc(Coded, commands.len);
    defer gpa.free(coded);
    var literal_counts: [256]u32 = @splat(0);
    var insert_copy_counts: [704]u32 = @splat(0);
    var distance_counts: [distance_alphabet]u32 = @splat(0);
    var position: usize = 0;
    var distances = DistanceCache{};
    for (commands, coded) |command, *entry| {
        for (input[position..][0..command.insert]) |byte| literal_counts[byte] += 1;
        entry.* = code_command(command, &distances);
        insert_copy_counts[entry.insert_copy] += 1;
        if (entry.distance) |symbol| distance_counts[symbol] += 1;
        position += command.insert + command.copy;
        assert(command.distance <= window or command.copy == 0);
    }
    assert(position == input.len);
    try writer.write(gpa, 0b01, 2); // ISLAST, not ISLASTEMPTY
    try write_length(writer, gpa, input.len);
    try writer.write(gpa, 0b000, 3); // one block type each: L, I, D
    try writer.write(gpa, 0, 6); // NPOSTFIX 0, NDIRECT 0
    try writer.write(gpa, @backingInt(tables.ContextMode.lsb6), 2);
    try writer.write(gpa, 0b00, 2); // one literal tree, one distance tree
    var literal_code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, &literal_counts, &literal_code);
    var insert_copy_code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, &insert_copy_counts, &insert_copy_code);
    var distance_code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, &distance_counts, &distance_code);
    position = 0;
    for (commands, coded) |command, entry| {
        try insert_copy_code.write(writer, gpa, entry.insert_copy);
        try writer.write(gpa, entry.insert_extra, entry.insert_extra_bits);
        try writer.write(gpa, entry.copy_extra, entry.copy_extra_bits);
        for (input[position..][0..command.insert]) |byte| try literal_code.write(writer, gpa, byte);
        position += command.insert + command.copy;
        if (command.copy == 0) continue; // the last: the decoder stops here
        if (entry.distance) |symbol| {
            try distance_code.write(writer, gpa, symbol);
            try writer.write(gpa, entry.distance_extra, entry.distance_extra_bits);
        }
    }
}

/// The last four distances, as the decoder keeps them (section 4).
const DistanceCache = struct {
    last: [4]u32 = .{ 4, 11, 15, 16 },

    /// The short code for `distance`, if one names it.
    fn short_code(cache: *const DistanceCache, distance: u32) ?u16 {
        for (cache.last, 0..) |value, index| if (value == distance) return @intCast(index);
        const offsets = [6]i64{ -1, 1, -2, 2, -3, 3 };
        for (offsets, 0..) |offset, index| {
            if (@as(i64, cache.last[0]) + offset == distance) return @intCast(4 + index);
            if (@as(i64, cache.last[1]) + offset == distance) return @intCast(10 + index);
        }
        return null;
    }

    fn push(cache: *DistanceCache, distance: u32) void {
        std.mem.copyBackwards(u32, cache.last[1..], cache.last[0..3]);
        cache.last[0] = distance;
    }
};

fn code_command(command: Command, distances: *DistanceCache) Coded {
    const insert_code = code_for(&tables.insert_ranges, command.insert);
    // The last command copies nothing: any copy code, never read.
    const copy_code = if (command.copy == 0) 0 else code_for(&tables.copy_ranges, command.copy);
    const copy_range = tables.copy_ranges[copy_code];
    var coded: Coded = .{
        .insert_copy = undefined,
        .insert_extra = command.insert - tables.insert_ranges[insert_code].base,
        .insert_extra_bits = tables.insert_ranges[insert_code].extra,
        .copy_extra = if (command.copy == 0) 0 else command.copy - copy_range.base,
        .copy_extra_bits = if (command.copy == 0) 0 else copy_range.extra,
        .distance = null,
        .distance_extra = 0,
        .distance_extra_bits = 0,
    };
    var implied = false;
    if (command.copy > 0) {
        const short = distances.short_code(command.distance);
        if (short == 0 and insert_code < 8 and copy_code < 16) {
            implied = true; // the last distance, in the symbol itself
        } else if (short) |code| {
            coded.distance = code;
            if (code != 0) distances.push(command.distance);
        } else {
            code_distance(command.distance, &coded);
            distances.push(command.distance);
        }
    }
    coded.insert_copy = insert_copy_symbol(insert_code, copy_code, implied);
    return coded;
}

/// The largest code whose range starts at or below `value`.
fn code_for(ranges: []const tables.Range, value: u32) u5 {
    var code: u5 = @intCast(ranges.len - 1);
    while (ranges[code].base > value) code -= 1;
    assert(value - ranges[code].base < @as(u64, 1) << ranges[code].extra);
    return code;
}

/// Section 5's table, from codes back to its symbol.
fn insert_copy_symbol(insert_code: u5, copy_code: u5, implied: bool) u16 {
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
fn code_distance(distance: u32, coded: *Coded) void {
    assert(distance >= 1);
    const value = distance + 3;
    const top: u5 = @intCast(std.math.log2_int(u32, value));
    const extra_bits: u5 = top - 1;
    const prefix = (value >> extra_bits) & 1;
    coded.distance = @intCast(16 + 2 * (@as(u16, extra_bits) - 1) + prefix);
    coded.distance_extra = value - ((2 + prefix) << extra_bits);
    coded.distance_extra_bits = extra_bits;
}

const decode = @import("brotli_decode.zig").decode;
const Prng = @import("prng.zig").Prng;

fn expect_round_trip(input: []const u8) !void {
    const gpa = std.testing.allocator;
    const compressed = try encode(gpa, input);
    defer gpa.free(compressed);
    const out = try gpa.alloc(u8, input.len + 1);
    defer gpa.free(out);
    try std.testing.expectEqualSlices(u8, input, try decode(gpa, compressed, out));
}

test "brotli_encode: round trips through our decoder" {
    try expect_round_trip("");
    try expect_round_trip("a");
    try expect_round_trip("ab");
    try expect_round_trip("abcabcabcabcabcabcabc");
    try expect_round_trip(@embedFile("testdata/style.css"));
    var zeros: [70_000]u8 = @splat(0);
    try expect_round_trip(&zeros);
    var prng = Prng.init(1);
    var random: [5000]u8 = undefined;
    for (&random) |*byte| byte.* = @truncate(prng.next());
    try expect_round_trip(&random);
}
