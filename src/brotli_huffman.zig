//! Brotli's prefix codes, the encoder's side (RFC 7932 section 3): the
//! bit writer, length-limited Huffman code lengths from symbol counts,
//! canonical codes from lengths, and a code's compact form in a stream.

const std = @import("std");
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;

pub const alphabet_max = 704;
/// The longest code a stream may use, and the longest for the code that
/// codes code lengths (section 3.5).
pub const length_max = 15;
const length_length_max = 5;

/// Bits in stream order: each value's least significant bit first.
pub const BitWriter = struct {
    bytes: std.ArrayList(u8) = .empty,
    /// Bits not yet a whole byte.
    pending: u64 = 0,
    pending_count: u6 = 0,

    pub fn write(writer: *BitWriter, gpa: Allocator, value: u64, count: u6) Allocator.Error!void {
        assert(count <= 32);
        assert(count == 64 or value >> count == 0);
        writer.pending |= value << writer.pending_count;
        writer.pending_count += count;
        for (0..5) |_| {
            if (writer.pending_count < 8) break;
            try writer.bytes.append(gpa, @truncate(writer.pending));
            writer.pending >>= 8;
            writer.pending_count -= 8;
        }
        assert(writer.pending_count < 8);
    }

    /// Zero bits to the next byte boundary.
    pub fn align_zero(writer: *BitWriter, gpa: Allocator) Allocator.Error!void {
        if (writer.pending_count == 0) return;
        try writer.write(gpa, 0, 8 - writer.pending_count);
        assert(writer.pending_count == 0);
    }
};

/// A prefix code over an alphabet: each symbol's length and its code,
/// bit-reversed, so writing it is writing an integer (section 1.5.1).
pub const Code = struct {
    lengths: [alphabet_max]u4,
    reversed: [alphabet_max]u16,
    alphabet_size: u16,
    /// The symbol of a one-symbol code, which costs no bits.
    single: ?u16,

    pub fn write(code: *const Code, writer: *BitWriter, gpa: Allocator, symbol: u16) !void {
        assert(symbol < code.alphabet_size);
        if (code.single) |only| return assert(symbol == only);
        const length = code.lengths[symbol];
        assert(length > 0); // a symbol the code was made for
        try writer.write(gpa, code.reversed[symbol], length);
    }
};

/// Code lengths from symbol counts: Huffman's, limited to `limit` bits by
/// raising the smallest counts until the tree fits (the reference
/// encoder's way). A symbol never seen gets no code; a lone symbol gets
/// length 0 (it costs no bits).
pub fn code_lengths(counts: []const u32, limit: u4, lengths: []u4) void {
    assert(counts.len == lengths.len);
    assert(counts.len <= alphabet_max);
    @memset(lengths, 0);
    var floor: u32 = 1;
    // Each round doubles the floor: within 32 rounds every count is equal.
    for (0..33) |_| {
        if (huffman(counts, floor, limit, lengths)) return;
        floor *= 2;
    } else unreachable;
}

const Node = struct { count: u64, left: i16, right: i16 };

/// One try at Huffman's code with every count at least `floor`: false
/// when the code is longer than `limit`.
fn huffman(counts: []const u32, floor: u32, limit: u4, lengths: []u4) bool {
    var leaves: [alphabet_max]u16 = undefined;
    var leaf_count: usize = 0;
    for (counts, 0..) |count, symbol| {
        if (count == 0) continue;
        leaves[leaf_count] = @intCast(symbol);
        leaf_count += 1;
    }
    if (leaf_count <= 1) return true; // none, or a lone symbol: length 0
    const Context = struct { counts: []const u32, floor: u32 };
    const less = struct {
        fn less(context: Context, a: u16, b: u16) bool {
            const count_a = @max(context.counts[a], context.floor);
            const count_b = @max(context.counts[b], context.floor);
            return count_a < count_b or (count_a == count_b and a < b);
        }
    }.less;
    std.sort.pdq(u16, leaves[0..leaf_count], Context{ .counts = counts, .floor = floor }, less);
    // Two queues: the sorted leaves, and the merged nodes, made in order.
    var nodes: [alphabet_max * 2]Node = undefined;
    for (leaves[0..leaf_count], 0..) |symbol, index| {
        // A leaf: no left child, its symbol on the right.
        const count = @max(counts[symbol], floor);
        nodes[index] = .{ .count = count, .left = -1, .right = @intCast(symbol) };
    }
    var next_leaf: usize = 0;
    var next_merged: usize = leaf_count;
    var made: usize = leaf_count;
    for (0..leaf_count - 1) |_| {
        const a = take_smallest(&nodes, &next_leaf, leaf_count, &next_merged, made);
        const b = take_smallest(&nodes, &next_leaf, leaf_count, &next_merged, made);
        const count = nodes[a].count + nodes[b].count;
        nodes[made] = .{ .count = count, .left = @intCast(a), .right = @intCast(b) };
        made += 1;
    }
    assert(made == leaf_count * 2 - 1);
    return assign_depths(&nodes, made - 1, limit, lengths);
}

fn take_smallest(
    nodes: *const [alphabet_max * 2]Node,
    next_leaf: *usize,
    leaf_count: usize,
    next_merged: *usize,
    made: usize,
) usize {
    const leaf_left = next_leaf.* < leaf_count;
    const merged_left = next_merged.* < made;
    assert(leaf_left or merged_left);
    const take_leaf = leaf_left and
        (!merged_left or nodes[next_leaf.*].count <= nodes[next_merged.*].count);
    if (take_leaf) {
        next_leaf.* += 1;
        return next_leaf.* - 1;
    }
    next_merged.* += 1;
    return next_merged.* - 1;
}

/// Each leaf's depth from the root (a walk with an explicit stack: no
/// recursion); false when one is deeper than `limit`.
fn assign_depths(nodes: *const [alphabet_max * 2]Node, root: usize, limit: u4, lengths: []u4) bool {
    var stack: [alphabet_max * 2]struct { node: u16, depth: u8 } = undefined;
    var top: usize = 1;
    stack[0] = .{ .node = @intCast(root), .depth = 0 };
    for (0..alphabet_max * 2) |_| {
        if (top == 0) return true;
        top -= 1;
        const entry = stack[top];
        const node = nodes[entry.node];
        if (node.left < 0) {
            if (entry.depth > limit) return false;
            lengths[@intCast(node.right)] = @intCast(entry.depth);
            continue;
        }
        stack[top] = .{ .node = @intCast(node.left), .depth = entry.depth + 1 };
        stack[top + 1] = .{ .node = @intCast(node.right), .depth = entry.depth + 1 };
        top += 2;
    } else unreachable;
}

/// The canonical code for these lengths (section 3.2), bit-reversed.
pub fn canonical(lengths: []const u4, code: *Code) void {
    assert(lengths.len <= alphabet_max);
    code.alphabet_size = @intCast(lengths.len);
    code.single = null;
    @memcpy(code.lengths[0..lengths.len], lengths);
    var counts: [length_max + 1]u16 = @splat(0);
    for (lengths) |length| counts[length] += 1;
    counts[0] = 0;
    var next: [length_max + 1]u16 = undefined;
    var value: u16 = 0;
    for (1..length_max + 1) |length| {
        value = (value + counts[length - 1]) << 1;
        next[length] = value;
    }
    for (lengths, 0..) |length, symbol| {
        if (length == 0) continue;
        code.reversed[symbol] = @bitReverse(next[length]) >> @intCast(16 - @as(u5, length));
        next[length] += 1;
    }
}

/// The code for `counts`, chosen and written in its compact form: a
/// simple code for up to four symbols, else a complex one (section 3).
pub fn write_code(
    writer: *BitWriter,
    gpa: Allocator,
    counts: []const u32,
    code: *Code,
) !void {
    assert(counts.len >= 2 and counts.len <= alphabet_max);
    var lengths: [alphabet_max]u4 = undefined;
    code_lengths(counts, length_max, lengths[0..counts.len]);
    var used: u32 = 0;
    for (counts) |count| used += @intFromBool(count > 0);
    if (used <= 4) return write_simple(writer, gpa, counts, code);
    canonical(lengths[0..counts.len], code);
    try write_complex(writer, gpa, lengths[0..counts.len]);
}

/// Up to four symbols (section 3.4). Their lengths are fixed by their
/// order in the code: listed by count, the most frequent first.
fn write_simple(writer: *BitWriter, gpa: Allocator, counts: []const u32, code: *Code) !void {
    var symbols: [4]u16 = undefined;
    var count: usize = 0;
    for (counts, 0..) |symbol_count, symbol| {
        if (symbol_count == 0) continue;
        symbols[count] = @intCast(symbol);
        count += 1;
    }
    if (count == 0) { // nothing to code: any one symbol
        symbols[0] = 0;
        count = 1;
    }
    const Context = []const u32;
    const by_count = struct {
        fn more(context: Context, a: u16, b: u16) bool {
            return context[a] > context[b] or (context[a] == context[b] and a < b);
        }
    }.more;
    std.sort.insertion(u16, symbols[0..count], counts, by_count);
    // Four symbols: 2,2,2,2 or 1,2,3,3, whichever costs fewer bits.
    const flat = count == 4 and 2 * (counts[symbols[0]] + counts[symbols[1]]) +
        2 * (counts[symbols[2]] + counts[symbols[3]]) <=
        counts[symbols[0]] + 2 * counts[symbols[1]] + 3 * (counts[symbols[2]] + counts[symbols[3]]);
    const order: [4]u4 = switch (count) {
        1 => .{ 0, 0, 0, 0 },
        2 => .{ 1, 1, 0, 0 },
        3 => .{ 1, 2, 2, 0 },
        4 => if (flat) .{ 2, 2, 2, 2 } else .{ 1, 2, 3, 3 },
        else => unreachable,
    };
    var lengths: [alphabet_max]u4 = @splat(0);
    for (symbols[0..count], order[0..count]) |symbol, length| lengths[symbol] = length;
    canonical(lengths[0..counts.len], code);
    if (count == 1) code.single = symbols[0];
    const alphabet_bits: u6 = @intCast(std.math.log2_int(usize, counts.len - 1) + 1);
    try writer.write(gpa, 1, 2); // simple
    try writer.write(gpa, count - 1, 2);
    for (symbols[0..count]) |symbol| try writer.write(gpa, symbol, alphabet_bits);
    if (count == 4) try writer.write(gpa, @intFromBool(!flat), 1);
}

/// The order code length code lengths are written in (section 3.5).
const code_length_order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

/// A run-length coded code length: 0..15, or 16/17 with extra bits.
const LengthSymbol = struct { symbol: u5, extra: u3 };

fn write_complex(writer: *BitWriter, gpa: Allocator, lengths: []const u4) !void {
    var symbols: [alphabet_max]LengthSymbol = undefined;
    const symbol_count = run_lengths(lengths, &symbols);
    var counts: [18]u32 = @splat(0);
    for (symbols[0..symbol_count]) |entry| counts[entry.symbol] += 1;
    var length_lengths: [18]u4 = undefined;
    code_lengths(&counts, length_length_max, &length_lengths);
    var used: u32 = 0;
    for (&length_lengths, counts) |*length, count| {
        if (count > 0 and length.* == 0) length.* = 1; // a lone symbol still needs a length
        used += @intFromBool(count > 0);
    }
    var length_code: Code = undefined;
    canonical(&length_lengths, &length_code);
    try write_length_lengths(writer, gpa, &length_lengths, used);
    if (used == 1) length_code.single = symbols[0].symbol;
    for (symbols[0..symbol_count]) |entry| {
        try length_code.write(writer, gpa, entry.symbol);
        if (entry.symbol == 16) try writer.write(gpa, entry.extra, 2);
        if (entry.symbol == 17) try writer.write(gpa, entry.extra, 3);
    }
}

/// HSKIP and the code length code lengths, in their fixed code.
fn write_length_lengths(
    writer: *BitWriter,
    gpa: Allocator,
    lengths: *const [18]u4,
    used: u32,
) !void {
    var skip: u2 = 0;
    if (lengths[code_length_order[0]] == 0 and lengths[code_length_order[1]] == 0) {
        skip = 2;
        if (lengths[code_length_order[2]] == 0) skip = 3;
    }
    // Stop after the last length that is not zero (the reader stops when
    // the code is complete); with one symbol, the reader reads them all.
    var last: usize = 17;
    if (used > 1) {
        while (lengths[code_length_order[last]] == 0) last -= 1;
    }
    try writer.write(gpa, skip, 2);
    // The fixed code: 0 "00", 1 "0111", 2 "011", 3 "10", 4 "01", 5 "1111".
    // The RFC prints it as parsed from the right, so each pattern read as
    // a number is the value, written least significant bit first.
    const bits = [6]u4{ 0b00, 0b0111, 0b011, 0b10, 0b01, 0b1111 };
    const widths = [6]u3{ 2, 4, 3, 2, 2, 4 };
    for (code_length_order[skip .. last + 1]) |symbol| {
        const length = lengths[symbol];
        assert(length <= length_length_max);
        try writer.write(gpa, bits[length], widths[length]);
    }
}

/// The code lengths as the reader expects them: runs of a non-zero length
/// as 16s, of zeros as 17s, trailing zeros left out (section 3.5); the
/// encoding of runs is the reference encoder's.
fn run_lengths(lengths: []const u4, out: *[alphabet_max]LengthSymbol) usize {
    var end = lengths.len;
    while (end > 0 and lengths[end - 1] == 0) end -= 1;
    var runs: Runs = .{ .out = out };
    var previous: u4 = 8;
    var index: usize = 0;
    for (0..end + 1) |_| {
        if (index == end) break;
        const value = lengths[index];
        var run: usize = 1;
        while (index + run < end and lengths[index + run] == value) run += 1;
        if (value == 0) {
            runs.zeros(run);
        } else {
            runs.value(value, previous, run);
            previous = value;
        }
        index += run;
    } else unreachable;
    return runs.count;
}

/// Run-length coded lengths, as they are made.
const Runs = struct {
    out: *[alphabet_max]LengthSymbol,
    count: usize = 0,

    fn add(runs: *Runs, symbol: u5, extra: u3) void {
        runs.out[runs.count] = .{ .symbol = symbol, .extra = extra };
        runs.count += 1;
    }

    fn zeros(runs: *Runs, run_whole: usize) void {
        var run = run_whole;
        if (run == 11) { // 11 as 17s alone wastes bits; a 0 first does not
            runs.add(0, 0);
            run -= 1;
        }
        if (run < 3) {
            for (0..run) |_| runs.add(0, 0);
        } else runs.repeats(17, 3, run - 3);
    }

    /// A run of a length: written once unless the reader's previous
    /// length is this one, then repeated by 16s.
    fn value(runs: *Runs, length: u4, previous: u4, run_whole: usize) void {
        var run = run_whole;
        if (length != previous) {
            runs.add(length, 0);
            run -= 1;
        }
        if (run == 7) { // as for 11 zeros
            runs.add(length, 0);
            run -= 1;
        }
        if (run < 3) {
            for (0..run) |_| runs.add(length, 0);
        } else runs.repeats(16, 2, run - 3);
    }

    /// `rest` more than three repeats as chained 16s or 17s: each chained
    /// symbol multiplies the count so far (section 3.5), so the extras are
    /// the digits of `rest`, written most significant first.
    fn repeats(runs: *Runs, symbol: u5, extra_bits: u3, rest_whole: usize) void {
        var rest = rest_whole;
        const start = runs.count;
        const mask = (@as(usize, 1) << extra_bits) - 1;
        for (0..alphabet_max) |_| {
            runs.add(symbol, @intCast(rest & mask));
            rest >>= extra_bits;
            if (rest == 0) break;
            rest -= 1;
        } else unreachable;
        std.mem.reverse(LengthSymbol, runs.out[start..runs.count]);
    }
};

test "brotli_huffman: lengths are Huffman's, complete, and limited" {
    const counts = [_]u32{ 45, 13, 12, 16, 9, 5, 0, 1 };
    var lengths: [counts.len]u4 = undefined;
    code_lengths(&counts, 15, &lengths);
    try std.testing.expectEqualSlices(u4, &.{ 1, 3, 3, 3, 4, 5, 0, 5 }, &lengths);
    // Fibonacci counts make a deep tree; a limit flattens it, completely.
    var fibonacci: [20]u32 = undefined;
    fibonacci[0] = 1;
    fibonacci[1] = 1;
    for (2..20) |index| fibonacci[index] = fibonacci[index - 1] + fibonacci[index - 2];
    var deep: [20]u4 = undefined;
    code_lengths(&fibonacci, 7, &deep);
    var kraft: u32 = 0;
    for (deep) |length| {
        try std.testing.expect(length >= 1 and length <= 7);
        kraft += @as(u32, 1) << @intCast(7 - @as(u5, length));
    }
    try std.testing.expectEqual(1 << 7, kraft);
}

test "brotli_huffman: canonical codes are the RFC's example" {
    // Section 3.2: ABCDEFGH with lengths 3,3,3,3,3,2,4,4.
    const lengths = [_]u4{ 3, 3, 3, 3, 3, 2, 4, 4 };
    var code: Code = undefined;
    canonical(&lengths, &code);
    const expected = [_]u16{ 0b010, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111 };
    for (expected, 0..) |value, symbol| {
        const length: u5 = lengths[symbol];
        const written = @bitReverse(code.reversed[symbol]) >> @intCast(16 - length);
        try std.testing.expectEqual(value, written);
    }
}

test "brotli_huffman: runs are the counts they stand for" {
    // Every run of zeros and of a value, written and read back by the
    // rules of section 3.5.
    for (1..120) |run| {
        for ([_]u4{ 0, 5 }) |value| {
            var lengths: [alphabet_max]u4 = @splat(0);
            @memset(lengths[0..run], value);
            lengths[run] = 3; // so trailing zeros are not left out
            var symbols: [alphabet_max]LengthSymbol = undefined;
            const count = run_lengths(lengths[0 .. run + 1], &symbols);
            var expanded: [alphabet_max]u4 = undefined;
            const total = expand(symbols[0..count], &expanded);
            try std.testing.expectEqualSlices(u4, lengths[0 .. run + 1], expanded[0..total]);
        }
    }
}

/// Section 3.5's reading of run-length symbols, for the test above.
fn expand(symbols: []const LengthSymbol, out: []u4) usize {
    var count: usize = 0;
    var previous: u4 = 8;
    var repeat: usize = 0;
    var repeat_length: u4 = 0;
    for (symbols) |entry| {
        if (entry.symbol < 16) {
            out[count] = @intCast(entry.symbol);
            count += 1;
            repeat = 0;
            if (entry.symbol != 0) previous = @intCast(entry.symbol);
            continue;
        }
        const length: u4 = if (entry.symbol == 16) previous else 0;
        const bits: u3 = if (entry.symbol == 16) 2 else 3;
        if (repeat_length != length) {
            repeat = 0;
            repeat_length = length;
        }
        const before = repeat;
        if (repeat > 0) repeat = (repeat - 2) << bits;
        repeat += @as(usize, entry.extra) + 3;
        @memset(out[count..][0 .. repeat - before], length);
        count += repeat - before;
    }
    return count;
}
