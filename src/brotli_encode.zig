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
const optimal = @import("brotli_optimal.zig");
const command_module = @import("brotli_command.zig");
const context = @import("brotli_context.zig");

const Allocator = std.mem.Allocator;
const BitWriter = huffman.BitWriter;
const Command = command_module.Command;

/// The most bytes in one meta-block (section 2), and so in what we encode.
pub const input_bytes_max = 1 << 24;
/// Optimal parsing keeps ~20 bytes a byte of input; past this, the lazy
/// parse (a static site's text files are far smaller).
const optimal_bytes_max = 4 << 20;

/// `input`, compressed; the caller frees it.
pub fn encode(gpa: Allocator, input: []const u8) ![]u8 {
    assert(input.len <= input_bytes_max);
    const window_bits = window_bits_for(input.len);
    if (input.len == 0) return write_stream(gpa, input, window_bits, .empty);
    const window: u32 = (@as(u32, 1) << window_bits) - 16;
    var commands: std.ArrayList(Command) = .empty;
    defer commands.deinit(gpa);
    if (input.len <= optimal_bytes_max) {
        try optimal.parse(gpa, input, window, &commands);
    } else {
        try match.parse_lazy(gpa, input, window, &commands);
    }
    const histograms = command_module.Histograms.count(input, commands.items);
    // The smallest of: the bytes stored, the literals' contexts clustered,
    // one literal code (a small file's contexts may not pay for codes).
    // Written, not estimated: writing is quick beside parsing.
    const choices = [_]context.Clustering{
        context.cluster(&histograms.literals),
        context.single(&histograms.literals),
    };
    var best = try write_stream(gpa, input, window_bits, .stored);
    errdefer gpa.free(best);
    for (&choices) |*clusters| {
        const candidate = try write_stream(gpa, input, window_bits, .{ .compressed = .{
            .commands = commands.items,
            .histograms = &histograms,
            .clusters = clusters,
            .window = window,
        } });
        if (candidate.len < best.len) {
            gpa.free(best);
            best = candidate;
        } else gpa.free(candidate);
    }
    return best;
}

const Body = union(enum) {
    empty,
    stored,
    compressed: Compressed,
};

const Compressed = struct {
    commands: []const Command,
    histograms: *const command_module.Histograms,
    clusters: *const context.Clustering,
    window: u32,
};

fn write_stream(gpa: Allocator, input: []const u8, window_bits: u5, body: Body) ![]u8 {
    var writer: BitWriter = .{};
    errdefer writer.bytes.deinit(gpa);
    try write_window_bits(&writer, gpa, window_bits);
    switch (body) {
        .empty => try writer.write(gpa, 0b11, 2), // ISLAST, ISLASTEMPTY
        .stored => try write_uncompressed(&writer, gpa, input),
        .compressed => |compressed| try write_compressed(&writer, gpa, input, &compressed),
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

fn write_compressed(
    writer: *BitWriter,
    gpa: Allocator,
    input: []const u8,
    compressed: *const Compressed,
) !void {
    const commands = compressed.commands;
    const histograms = compressed.histograms;
    const clusters = compressed.clusters;
    const window = compressed.window;
    try writer.write(gpa, 0b01, 2); // ISLAST, not ISLASTEMPTY
    try write_length(writer, gpa, input.len);
    try writer.write(gpa, 0b000, 3); // one block type each: L, I, D
    try writer.write(gpa, 0, 6); // NPOSTFIX 0, NDIRECT 0
    try writer.write(gpa, @backingInt(context.mode), 2);
    try write_count_256(writer, gpa, clusters.trees);
    if (clusters.trees >= 2) try write_context_map(writer, gpa, &clusters.map, clusters.trees);
    try writer.write(gpa, 0, 1); // one distance tree
    var literal_codes: [context.contexts]huffman.Code = undefined;
    const trees = clusters.trees;
    for (literal_codes[0..trees], clusters.histograms[0..trees]) |*code, *counts| {
        try huffman.write_code(writer, gpa, counts, code);
    }
    var insert_copy_code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, &histograms.insert_copy, &insert_copy_code);
    var distance_code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, &histograms.distances, &distance_code);
    var distances: command_module.DistanceCache = .{};
    var position: usize = 0;
    for (commands) |command| {
        assert(command.distance <= window or command.copy == 0);
        const entry = command_module.code(command, &distances);
        try insert_copy_code.write(writer, gpa, entry.insert_copy);
        try writer.write(gpa, entry.insert_extra, entry.insert_extra_bits);
        try writer.write(gpa, entry.copy_extra, entry.copy_extra_bits);
        for (position..position + command.insert) |at| {
            const code = &literal_codes[clusters.map[context.at(input, at)]];
            try code.write(writer, gpa, input[at]);
        }
        position += command.insert + command.copy;
        if (command.copy == 0) continue; // the last: the decoder stops here
        if (entry.distance) |symbol| {
            try distance_code.write(writer, gpa, symbol);
            try writer.write(gpa, entry.distance_extra, entry.distance_extra_bits);
        }
    }
}

/// NBLTYPES and NTREES, 1..256 (section 9.2's variable-length code).
fn write_count_256(writer: *BitWriter, gpa: Allocator, value: u16) !void {
    assert(value >= 1 and value <= 256);
    if (value == 1) return writer.write(gpa, 0, 1);
    const n: u6 = @intCast(std.math.log2_int(u16, value - 1));
    try writer.write(gpa, 1, 1);
    try writer.write(gpa, n, 3);
    try writer.write(gpa, value - 1 - (@as(u16, 1) << @intCast(n)), n);
}

/// A context map (section 7.3): its values under a prefix code, with no
/// run-length codes and no move-to-front (64 entries: little to save).
fn write_context_map(writer: *BitWriter, gpa: Allocator, map: []const u8, trees: u8) !void {
    assert(trees >= 2);
    try writer.write(gpa, 0, 1); // RLEMAX 0
    var counts: [context.contexts]u32 = @splat(0);
    for (map) |tree| {
        assert(tree < trees);
        counts[tree] += 1;
    }
    var code: huffman.Code = undefined;
    try huffman.write_code(writer, gpa, counts[0..trees], &code);
    for (map) |tree| try code.write(writer, gpa, tree);
    try writer.write(gpa, 0, 1); // no inverse move-to-front
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
