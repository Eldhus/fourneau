//! A brotli decoder (RFC 7932), strict: every rule the RFC says makes a
//! stream invalid is checked, and the stream must end exactly where the
//! input does. fourneau never decodes brotli in service (it compresses
//! static files at load); this is the encoder's oracle in tests, itself
//! checked against streams from the reference encoder.
//!
//! Plain over fast: bits are read one at a time and prefix codes decoded
//! canonically, a length at a time (RFC 1951's puff does the same).

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ Invalid, OutputTooLarge, OutOfMemory };

/// Decompress `input` into `output`; the bytes it holds.
pub fn decode(gpa: Allocator, input: []const u8, output: []u8) Error![]u8 {
    var decoder: Decoder = .{
        .bits = .{ .bytes = input },
        .out = output,
        .window_bytes = 0,
    };
    decoder.window_bytes = (@as(u32, 1) << try read_window_bits(&decoder.bits)) - 16;
    // A meta-block takes at least a bit: bounded by the input's bits.
    for (0..input.len * 8 + 1) |_| {
        if (try decoder.meta_block(gpa)) break;
    } else return error.Invalid;
    try decoder.bits.align_zero();
    if (decoder.bits.position != input.len * 8) return error.Invalid; // bytes after the end
    return output[0..decoder.used];
}

const BitReader = struct {
    bytes: []const u8,
    /// In bits.
    position: usize = 0,

    fn bit(reader: *BitReader) Error!u1 {
        if (reader.position >= reader.bytes.len * 8) return error.Invalid; // cut short
        const byte = reader.bytes[reader.position / 8];
        const value: u1 = @truncate(byte >> @intCast(reader.position % 8));
        reader.position += 1;
        return value;
    }

    /// `count` bits, the first the least significant.
    fn read(reader: *BitReader, count: u5) Error!u32 {
        assert(count <= 24);
        var value: u32 = 0;
        for (0..count) |index| value |= @as(u32, try reader.bit()) << @intCast(index);
        return value;
    }

    /// To the next byte boundary, over bits that must be zero.
    fn align_zero(reader: *BitReader) Error!void {
        for (0..8) |_| {
            if (reader.position % 8 == 0) return;
            if (try reader.bit() != 0) return error.Invalid;
        } else unreachable;
    }
};

/// Section 9.1.
fn read_window_bits(bits: *BitReader) Error!u5 {
    if (try bits.bit() == 0) return 16;
    const n = try bits.read(3);
    if (n != 0) return @intCast(17 + n);
    const m = try bits.read(3);
    if (m == 1) return error.Invalid; // 0010001, reserved
    if (m != 0) return @intCast(8 + m);
    return 17;
}

/// A canonical prefix code (section 3.2), decoded a length at a time.
const PrefixCode = struct {
    /// How many codes have each length, 1..15.
    counts: [length_max + 1]u16,
    /// The symbols with a code, by length, then by value.
    symbols: [alphabet_max]u16,
    /// The one symbol of a code with no bits (a one-symbol code).
    single: ?u16,

    const length_max = 15;
    const alphabet_max = 704;

    fn from_lengths(code: *PrefixCode, lengths: []const u4) void {
        assert(lengths.len <= alphabet_max);
        code.counts = @splat(0);
        code.single = null;
        for (lengths) |length| code.counts[length] += 1;
        code.counts[0] = 0;
        var offsets: [length_max + 2]u16 = undefined;
        offsets[1] = 0;
        for (1..length_max + 1) |length| {
            offsets[length + 1] = offsets[length] + code.counts[length];
        }
        for (lengths, 0..) |length, symbol| {
            if (length == 0) continue;
            code.symbols[offsets[length]] = @intCast(symbol);
            offsets[length] += 1;
        }
    }

    fn one(code: *PrefixCode, symbol: u16) void {
        code.counts = @splat(0);
        code.single = symbol;
    }

    fn decode(code: *const PrefixCode, bits: *BitReader) Error!u16 {
        if (code.single) |symbol| return symbol;
        var value: u32 = 0; // the code read so far
        var first: u32 = 0; // the first code of this length
        var index: u32 = 0; // where this length's symbols start
        for (1..length_max + 1) |length| {
            value |= try bits.bit();
            const count = code.counts[length];
            if (value - first < count) return code.symbols[index + value - first];
            index += count;
            first = (first + count) << 1;
            value <<= 1;
        }
        return error.Invalid; // no code this long: an incomplete code
    }
};

/// Section 3.4 and 3.5: a prefix code over `alphabet_size` symbols.
fn read_prefix_code(bits: *BitReader, alphabet_size: u16, code: *PrefixCode) Error!void {
    assert(alphabet_size >= 2 and alphabet_size <= PrefixCode.alphabet_max);
    const hskip = try bits.read(2);
    if (hskip == 1) return read_simple_code(bits, alphabet_size, code);
    var length_code: PrefixCode = undefined;
    try read_code_length_code(bits, hskip, &length_code);
    var lengths: [PrefixCode.alphabet_max]u4 = @splat(0);
    try read_symbol_lengths(bits, &length_code, lengths[0..alphabet_size]);
    code.from_lengths(lengths[0..alphabet_size]);
}

fn read_simple_code(bits: *BitReader, alphabet_size: u16, code: *PrefixCode) Error!void {
    const alphabet_bits: u5 = @intCast(std.math.log2_int(u16, alphabet_size - 1) + 1);
    const count = try bits.read(2) + 1;
    var symbols: [4]u16 = undefined;
    for (symbols[0..count], 0..) |*symbol, index| {
        symbol.* = @intCast(try bits.read(alphabet_bits));
        if (symbol.* >= alphabet_size) return error.Invalid;
        for (symbols[0..index]) |earlier| if (earlier == symbol.*) return error.Invalid;
    }
    if (count == 1) return code.one(symbols[0]);
    // Lengths by the order the symbols appear; codes by symbol order.
    const lengths: [4]u4 = switch (count) {
        2 => .{ 1, 1, 0, 0 },
        3 => .{ 1, 2, 2, 0 },
        4 => if (try bits.bit() == 0) .{ 2, 2, 2, 2 } else .{ 1, 2, 3, 3 },
        else => unreachable,
    };
    var all: [PrefixCode.alphabet_max]u4 = @splat(0);
    for (symbols[0..count], lengths[0..count]) |symbol, length| all[symbol] = length;
    code.from_lengths(all[0..alphabet_size]);
}

/// The order code length code lengths come in (section 3.5).
const code_length_order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

fn read_code_length_code(bits: *BitReader, hskip: u32, code: *PrefixCode) Error!void {
    assert(hskip != 1);
    var lengths: [18]u4 = @splat(0);
    var space: i32 = 32;
    var nonzero: u32 = 0;
    for (code_length_order[hskip..]) |symbol| {
        const length = try read_code_length_length(bits);
        lengths[symbol] = length;
        if (length == 0) continue;
        nonzero += 1;
        space -= @as(i32, 32) >> length;
        if (space <= 0) break;
    }
    if (nonzero != 1 and space != 0) return error.Invalid;
    if (nonzero == 1) {
        for (lengths, 0..) |length, symbol| if (length != 0) return code.one(@intCast(symbol));
        unreachable;
    }
    code.from_lengths(&lengths);
}

/// The fixed code for code length code lengths, 0..5 (section 3.5).
fn read_code_length_length(bits: *BitReader) Error!u4 {
    const first = try bits.bit();
    const second = try bits.bit();
    if (first == 0) return if (second == 0) 0 else 3;
    if (second == 0) return 4;
    if (try bits.bit() == 0) return 2;
    return if (try bits.bit() == 0) 1 else 5;
}

fn read_symbol_lengths(bits: *BitReader, length_code: *const PrefixCode, lengths: []u4) Error!void {
    var symbol: usize = 0;
    var previous: u4 = 8; // the last non-zero length
    var repeat: u32 = 0;
    var repeat_length: u4 = 0;
    var space: i32 = 32768;
    for (0..lengths.len + 1) |_| {
        if (symbol == lengths.len or space <= 0) break;
        const code_symbol = try length_code.decode(bits);
        if (code_symbol < 16) {
            repeat = 0;
            lengths[symbol] = @intCast(code_symbol);
            symbol += 1;
            if (code_symbol != 0) {
                previous = @intCast(code_symbol);
                space -= @as(i32, 32768) >> @intCast(code_symbol);
            }
            continue;
        }
        const extra: u5 = if (code_symbol == 16) 2 else 3;
        const length: u4 = if (code_symbol == 16) previous else 0;
        if (repeat_length != length) {
            repeat = 0;
            repeat_length = length;
        }
        const before = repeat;
        if (repeat > 0) repeat = (repeat - 2) << extra;
        repeat += try bits.read(extra) + 3;
        const delta = repeat - before;
        if (symbol + delta > lengths.len) return error.Invalid;
        @memset(lengths[symbol..][0..delta], length);
        symbol += delta;
        if (length != 0) space -= @as(i32, @intCast(delta << (15 - @as(u5, length))));
    } else unreachable;
    if (space != 0) return error.Invalid;
}

/// One category's blocks (section 6): its block type now and before, and
/// how many more elements the current block holds.
const Blocks = struct {
    types: u16,
    type_code: PrefixCode,
    count_code: PrefixCode,
    current: u8 = 0,
    previous: u8 = 1,
    remaining: u32,

    fn read(bits: *BitReader, blocks: *Blocks) Error!void {
        blocks.types = try read_count_256(bits);
        blocks.current = 0;
        blocks.previous = 1;
        if (blocks.types < 2) {
            blocks.remaining = 1 << 24;
            return;
        }
        try read_prefix_code(bits, blocks.types + 2, &blocks.type_code);
        try read_prefix_code(bits, 26, &blocks.count_code);
        blocks.remaining = try read_block_count(bits, &blocks.count_code);
    }

    /// Before each element: a block switch when this block is spent.
    fn next(blocks: *Blocks, bits: *BitReader) Error!void {
        if (blocks.remaining == 0) {
            const symbol = try blocks.type_code.decode(bits);
            const new: u16 = switch (symbol) {
                0 => blocks.previous,
                1 => (@as(u16, blocks.current) + 1) % blocks.types,
                else => symbol - 2,
            };
            if (new >= blocks.types) return error.Invalid;
            blocks.previous = blocks.current;
            blocks.current = @intCast(new);
            blocks.remaining = try read_block_count(bits, &blocks.count_code);
        }
        blocks.remaining -= 1;
    }
};

fn read_block_count(bits: *BitReader, code: *const PrefixCode) Error!u32 {
    const range = tables.block_count_ranges[try code.decode(bits)];
    return range.base + try bits.read(range.extra);
}

/// NBLTYPES and NTREES (section 9.2): 1..256.
fn read_count_256(bits: *BitReader) Error!u16 {
    if (try bits.bit() == 0) return 1;
    const n: u5 = @intCast(try bits.read(3));
    if (n == 0) return 2;
    return @intCast((@as(u32, 1) << n) + 1 + try bits.read(n));
}

/// A context map (section 7.3) of `map.len` entries over `trees` codes.
fn read_context_map(bits: *BitReader, trees: u16, map: []u8) Error!void {
    if (trees < 2) return @memset(map, 0);
    const rle_max: u5 = if (try bits.bit() == 0) 0 else @intCast(try bits.read(4) + 1);
    var code: PrefixCode = undefined;
    try read_prefix_code(bits, trees + rle_max, &code);
    var index: usize = 0;
    for (0..map.len + 1) |_| {
        if (index == map.len) break;
        const symbol = try code.decode(bits);
        if (symbol == 0) {
            map[index] = 0;
            index += 1;
        } else if (symbol <= rle_max) {
            const zeros = (@as(usize, 1) << @intCast(symbol)) + try bits.read(@intCast(symbol));
            if (index + zeros > map.len) return error.Invalid;
            @memset(map[index..][0..zeros], 0);
            index += zeros;
        } else {
            map[index] = @intCast(symbol - rle_max);
            index += 1;
        }
    } else unreachable;
    if (try bits.bit() == 1) inverse_move_to_front(map);
    for (map) |value| if (value >= trees) return error.Invalid;
}

fn inverse_move_to_front(values: []u8) void {
    var order: [256]u8 = undefined;
    for (&order, 0..) |*entry, index| entry.* = @intCast(index);
    for (values) |*value| {
        const index = value.*;
        const front = order[index];
        std.mem.copyBackwards(u8, order[1 .. @as(usize, index) + 1], order[0..index]);
        order[0] = front;
        value.* = front;
    }
}

const Decoder = struct {
    bits: BitReader,
    out: []u8,
    used: usize = 0,
    window_bytes: u32,
    /// The last four distances, the last first (section 4).
    distances: [4]u32 = .{ 4, 11, 15, 16 },

    /// One meta-block; true when it was the last.
    fn meta_block(decoder: *Decoder, gpa: Allocator) Error!bool {
        const bits = &decoder.bits;
        const last = try bits.bit() == 1;
        if (last and try bits.bit() == 1) return true; // ISLASTEMPTY
        const nibbles_code = try bits.read(2);
        if (nibbles_code == 3) {
            try decoder.skip_metadata();
            return last;
        }
        const nibbles: u5 = @intCast(nibbles_code + 4);
        const length_minus_one = try bits.read(nibbles * 4);
        if (nibbles > 4 and length_minus_one >> ((nibbles - 1) * 4) == 0) return error.Invalid;
        const length = length_minus_one + 1;
        if (decoder.used + length > decoder.out.len) return error.OutputTooLarge;
        if (!last and try bits.bit() == 1) {
            try bits.align_zero();
            const start = bits.position / 8;
            if (start + length > bits.bytes.len) return error.Invalid;
            @memcpy(decoder.out[decoder.used..][0..length], bits.bytes[start..][0..length]);
            decoder.used += length;
            bits.position += length * 8;
            return false;
        }
        try decoder.compressed(gpa, length);
        return last;
    }

    fn skip_metadata(decoder: *Decoder) Error!void {
        const bits = &decoder.bits;
        if (try bits.bit() != 0) return error.Invalid; // reserved
        const skip_bytes: u5 = @intCast(try bits.read(2));
        var skip: usize = 0;
        if (skip_bytes > 0) {
            const value = try bits.read(skip_bytes * 8);
            if (skip_bytes > 1 and value >> ((skip_bytes - 1) * 8) == 0) return error.Invalid;
            skip = value + 1;
        }
        try bits.align_zero();
        if (bits.position / 8 + skip > bits.bytes.len) return error.Invalid;
        bits.position += skip * 8;
    }

    fn compressed(decoder: *Decoder, gpa: Allocator, length: u32) Error!void {
        var block: MetaBlock = undefined;
        try block.read(gpa, &decoder.bits);
        defer block.deinit(gpa);
        const end = decoder.used + length;
        // Each command produces a byte at least, or ends the block.
        for (0..length + 1) |_| {
            if (decoder.used == end) return;
            try decoder.command(&block, end);
        } else unreachable;
    }

    fn command(decoder: *Decoder, block: *MetaBlock, end: usize) Error!void {
        const bits = &decoder.bits;
        try block.insert_copy.next(bits);
        const symbol = try block.insert_copy_codes[block.insert_copy.current].decode(bits);
        const lengths = tables.insert_copy(symbol);
        const insert_range = tables.insert_ranges[lengths.insert_code];
        const copy_range = tables.copy_ranges[lengths.copy_code];
        const insert = insert_range.base + try bits.read(insert_range.extra);
        const copy = copy_range.base + try bits.read(copy_range.extra);
        if (decoder.used + insert > end) return error.Invalid;
        for (0..insert) |_| try decoder.literal(block);
        if (decoder.used == end) return; // the copy is ignored
        const distance, const code = if (lengths.last_distance)
            .{ decoder.distances[0], 0 }
        else
            try decoder.read_distance(block, copy);
        const distance_max = @min(decoder.window_bytes, decoder.used);
        if (distance > distance_max) {
            return decoder.dictionary_word(copy, distance - distance_max - 1, end);
        }
        if (decoder.used + copy > end) return error.Invalid;
        if (code != 0) decoder.push_distance(distance);
        for (0..copy) |_| {
            decoder.out[decoder.used] = decoder.out[decoder.used - distance];
            decoder.used += 1;
        }
    }

    fn literal(decoder: *Decoder, block: *MetaBlock) Error!void {
        try block.literals.next(&decoder.bits);
        const block_type = block.literals.current;
        const p1 = if (decoder.used >= 1) decoder.out[decoder.used - 1] else 0;
        const p2 = if (decoder.used >= 2) decoder.out[decoder.used - 2] else 0;
        const context = tables.literal_context(block.modes[block_type], p1, p2);
        const tree = block.literal_map[@as(usize, block_type) * 64 + context];
        decoder.out[decoder.used] = @intCast(try block.literal_codes[tree].decode(&decoder.bits));
        decoder.used += 1;
    }

    /// A distance and its code (section 4); 0 is the last distance.
    fn read_distance(decoder: *Decoder, block: *MetaBlock, copy: u32) Error!struct { u32, u16 } {
        const bits = &decoder.bits;
        try block.distance_blocks.next(bits);
        const index = @as(usize, block.distance_blocks.current) * 4 + tables.distance_context(copy);
        const code = try block.distance_codes[block.distance_map[index]].decode(bits);
        if (code < 16) return .{ try decoder.short_distance(code), code };
        const direct = block.direct;
        if (code < 16 + direct) return .{ code - 15, code };
        const postfix = block.postfix;
        const rest = code - direct - 16;
        const extra: u5 = @intCast(1 + (rest >> (postfix + 1)));
        const high = rest >> postfix;
        const low = rest & ((@as(u32, 1) << postfix) - 1);
        const offset = ((2 + (high & 1)) << extra) - 4;
        const distance = ((offset + try bits.read(extra)) << postfix) + low + direct + 1;
        return .{ distance, code };
    }

    fn short_distance(decoder: *const Decoder, code: u16) Error!u32 {
        assert(code < 16);
        if (code < 4) return decoder.distances[code];
        const base = decoder.distances[if (code < 10) 0 else 1];
        const offsets = [6]i32{ -1, 1, -2, 2, -3, 3 };
        const distance = @as(i64, base) + offsets[(code - 4) % 6];
        if (distance <= 0) return error.Invalid;
        return @intCast(distance);
    }

    fn push_distance(decoder: *Decoder, distance: u32) void {
        std.mem.copyBackwards(u32, decoder.distances[1..], decoder.distances[0..3]);
        decoder.distances[0] = distance;
    }

    /// Section 8: a word of the static dictionary, transformed.
    fn dictionary_word(decoder: *Decoder, length: u32, word_id: u32, end: usize) Error!void {
        if (length < tables.word_length_min) return error.Invalid;
        if (length > tables.word_length_max) return error.Invalid;
        const count = tables.word_count(length);
        const transform = word_id >> tables.ndbits[length];
        if (transform >= tables.transforms_count) return error.Invalid;
        var buffer: [tables.transformed_bytes_max]u8 = undefined;
        const word = tables.word(length, word_id % count);
        const bytes = tables.transform_word(word, @intCast(transform), &buffer);
        if (decoder.used + bytes.len > end) return error.Invalid;
        @memcpy(decoder.out[decoder.used..][0..bytes.len], bytes);
        decoder.used += bytes.len;
    }
};

/// A compressed meta-block's header (section 9.2): its blocks, context
/// modes and maps, and prefix codes.
const MetaBlock = struct {
    literals: Blocks,
    insert_copy: Blocks,
    distance_blocks: Blocks,
    postfix: u5,
    direct: u32,
    modes: [256]tables.ContextMode,
    literal_map: []u8,
    distance_map: []u8,
    literal_codes: []PrefixCode,
    insert_copy_codes: []PrefixCode,
    distance_codes: []PrefixCode,

    fn read(block: *MetaBlock, gpa: Allocator, bits: *BitReader) Error!void {
        try Blocks.read(bits, &block.literals);
        try Blocks.read(bits, &block.insert_copy);
        try Blocks.read(bits, &block.distance_blocks);
        block.postfix = @intCast(try bits.read(2));
        block.direct = try bits.read(4) << block.postfix;
        for (block.modes[0..block.literals.types]) |*mode| {
            mode.* = @fromBackingInt(@as(u2, @intCast(try bits.read(2))));
        }
        const literal_trees = try read_count_256(bits);
        block.literal_map = try gpa.alloc(u8, @as(usize, block.literals.types) * 64);
        errdefer gpa.free(block.literal_map);
        try read_context_map(bits, literal_trees, block.literal_map);
        const distance_trees = try read_count_256(bits);
        block.distance_map = try gpa.alloc(u8, @as(usize, block.distance_blocks.types) * 4);
        errdefer gpa.free(block.distance_map);
        try read_context_map(bits, distance_trees, block.distance_map);
        block.literal_codes = try read_codes(gpa, bits, literal_trees, 256);
        errdefer gpa.free(block.literal_codes);
        block.insert_copy_codes = try read_codes(gpa, bits, block.insert_copy.types, 704);
        errdefer gpa.free(block.insert_copy_codes);
        const distance_alphabet: u16 =
            @intCast(16 + block.direct + (@as(u32, 48) << block.postfix));
        block.distance_codes = try read_codes(gpa, bits, distance_trees, distance_alphabet);
    }

    fn deinit(block: *MetaBlock, gpa: Allocator) void {
        gpa.free(block.literal_map);
        gpa.free(block.distance_map);
        gpa.free(block.literal_codes);
        gpa.free(block.insert_copy_codes);
        gpa.free(block.distance_codes);
        block.* = undefined;
    }
};

fn read_codes(gpa: Allocator, bits: *BitReader, count: u16, alphabet: u16) Error![]PrefixCode {
    const codes = try gpa.alloc(PrefixCode, count);
    errdefer gpa.free(codes);
    for (codes) |*code| try read_prefix_code(bits, alphabet, code);
    return codes;
}

test "brotli_decode: the RFC's trivial streams" {
    const gpa = std.testing.allocator;
    var out: [64]u8 = undefined;
    // An empty stream (section 11.1), and one uncompressed meta-block.
    try std.testing.expectEqualStrings("", try decode(gpa, &.{6}, &out));
    const hello = [_]u8{ 12, (4 & 31) << 3, 0, 8 } ++ "hello".* ++ [_]u8{3};
    try std.testing.expectEqualStrings("hello", try decode(gpa, &hello, &out));
    // Cut short anywhere: invalid, never a wrong answer.
    for (0..hello.len) |length| {
        try std.testing.expectError(error.Invalid, decode(gpa, hello[0..length], &out));
    }
    // A byte after the end.
    try std.testing.expectError(error.Invalid, decode(gpa, &(hello ++ [_]u8{0}), &out));
    try std.testing.expectError(error.OutputTooLarge, decode(gpa, &hello, out[0..4]));
}

/// The reference encoder's stream (brotli 1.2.0, `-q 11`) of 3,000 bytes
/// of the dragrace site's stylesheet: the dictionary, context maps and
/// block switches all in use.
const reference_original = @embedFile("testdata/style.css");
const reference_stream = @embedFile("testdata/style.css.br");

test "brotli_decode: the reference encoder's stream" {
    const gpa = std.testing.allocator;
    var out: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(reference_original, try decode(gpa, reference_stream, &out));
}

test "brotli_decode: a damaged stream is refused or decodes, never crashes" {
    const gpa = std.testing.allocator;
    var out: [4096]u8 = undefined;
    var stream: [reference_stream.len]u8 = reference_stream.*;
    var refused: u32 = 0;
    for (0..stream.len) |index| {
        for ([_]u8{ 0x01, 0x80, 0xff }) |flip| {
            stream[index] ^= flip;
            defer stream[index] ^= flip;
            _ = decode(gpa, &stream, &out) catch |err| switch (err) {
                error.Invalid, error.OutputTooLarge => refused += 1,
                error.OutOfMemory => return err,
            };
        }
    }
    // Most damage is caught (brotli has no checksum: not all of it).
    try std.testing.expect(refused > stream.len * 3 / 2);
}
