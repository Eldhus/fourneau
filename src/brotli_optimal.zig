//! Optimal parsing for brotli's encoder, Zopfli's method as brotli's own
//! qualities 10 and 11 use it: the input's positions are a graph, each
//! edge a literal or a copy priced in bits by the current codes, and the
//! cheapest path to the end is the parse. The codes made from that parse
//! price the next round.
//!
//! A copy's price depends on the path that reaches it: its insert length
//! (the literals since the last command) shares its symbol, and its
//! distance may be one the four-distance cache names. Each node keeps
//! both: the literals since the last command, and a shortcut to the last
//! command that moved the cache, from which the cache is rebuilt exactly
//! by walking four commands back (brotli's `ComputeDistanceCache`).

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");
const command_module = @import("brotli_command.zig");
const context = @import("brotli_context.zig");
const match = @import("brotli_match.zig");

const Allocator = std.mem.Allocator;
const Command = command_module.Command;
const DistanceCache = command_module.DistanceCache;
const Histograms = command_module.Histograms;
const Match = match.Match;

/// Lengths past this are taken whole: a match this long is good enough,
/// and pricing each shorter length costs more than it wins (brotli's
/// `max_zopfli_len`).
const long_length = 325;
/// Matches kept per position.
const candidates_max = 16;
/// Rounds of pricing and parsing. Measured on index.html: 1 round 7,159
/// bytes, 3 rounds 7,126, 6 rounds 7,125.
pub const rounds = 3;

/// Bits per symbol, from the counts of the last parse: literals by the
/// code their context's cluster uses, as they will be written.
const Model = struct {
    literal: [context.contexts][256]f32,
    map: [context.contexts]u8,
    insert_copy: [704]f32,
    distance: [command_module.distance_alphabet]f32,

    fn from(histograms: *const Histograms) Model {
        var model: Model = undefined;
        const clusters = context.cluster(&histograms.literals);
        model.map = clusters.map;
        for (clusters.histograms[0..clusters.trees], 0..) |*counts, tree| {
            bits(counts, &model.literal[tree]);
        }
        bits(&histograms.insert_copy, &model.insert_copy);
        bits(&histograms.distances, &model.distance);
        return model;
    }

    fn literal_bits(model: *const Model, input: []const u8, position: usize) f32 {
        return model.literal[model.map[context.at(input, position)]][input[position]];
    }

    /// -log2 of each symbol's share, smoothed so an unseen symbol costs
    /// more than any seen one, never infinitely much.
    fn bits(counts: []const u32, out: []f32) void {
        assert(counts.len == out.len);
        const smoothing = 0.25;
        var total: f64 = 0;
        for (counts) |count| total += @as(f64, @floatFromInt(count)) + smoothing;
        for (counts, out) |count, *cost| {
            const share = (@as(f64, @floatFromInt(count)) + smoothing) / total;
            cost.* = @floatCast(-std.math.log2(share));
        }
    }
};

const Node = struct {
    cost: f32,
    /// The copy that reached this node; 0: a literal did.
    length: u32,
    distance: u32,
    /// Reached by a literal: the literals since the last command. Reached
    /// by a copy: that command's literals.
    insert: u32,
    /// Where the last command that moved the distance cache ended; 0: none.
    shortcut: u32,

    fn run(node: *const Node) u32 {
        return if (node.length == 0) node.insert else 0;
    }
};

/// Each position's matches, nearest first, flat.
const Matches = struct {
    starts: []u32,
    items: std.ArrayList(Match),

    fn at(matches: *const Matches, position: usize) []const Match {
        return matches.items.items[matches.starts[position]..matches.starts[position + 1]];
    }

    fn deinit(matches: *Matches, gpa: Allocator) void {
        gpa.free(matches.starts);
        matches.items.deinit(gpa);
        matches.* = undefined;
    }
};

fn collect(gpa: Allocator, input: []const u8, window: u32) Allocator.Error!Matches {
    var chains = try match.Chains.init(gpa, input, window);
    defer chains.deinit(gpa);
    var matches: Matches = .{ .starts = try gpa.alloc(u32, input.len + 1), .items = .empty };
    errdefer matches.deinit(gpa);
    var buffer: [candidates_max]Match = undefined;
    // Inside a long match no search: the path takes it whole from its
    // start (`shortest_path`), as brotli's encoder skips such positions.
    var skip_until: usize = 0;
    for (0..input.len) |position| {
        matches.starts[position] = @intCast(matches.items.items.len);
        if (position < skip_until) continue;
        const count = match.candidates(&chains, position, long_length, &buffer);
        try matches.items.appendSlice(gpa, buffer[0..count]);
        if (count > 0 and buffer[count - 1].length >= long_length) {
            skip_until = position + buffer[count - 1].length;
        }
    }
    matches.starts[input.len] = @intCast(matches.items.items.len);
    return matches;
}

/// The parse: the lazy one, then `rounds` of pricing and parsing.
pub fn parse(
    gpa: Allocator,
    input: []const u8,
    window: u32,
    commands: *std.ArrayList(Command),
) Allocator.Error!void {
    assert(input.len > 0);
    try match.parse_lazy(gpa, input, window, commands);
    var matches = try collect(gpa, input, window);
    defer matches.deinit(gpa);
    const nodes = try gpa.alloc(Node, input.len + 1);
    defer gpa.free(nodes);
    for (0..rounds) |_| {
        const histograms = Histograms.count(input, commands.items);
        const model = Model.from(&histograms);
        shortest_path(input, window, &matches, &model, nodes);
        try trace(gpa, nodes, commands);
    }
}

fn shortest_path(
    input: []const u8,
    window: u32,
    matches: *const Matches,
    model: *const Model,
    nodes: []Node,
) void {
    assert(nodes.len == input.len + 1);
    const unreached: Node = .{
        .cost = std.math.inf(f32),
        .length = 0,
        .distance = 0,
        .insert = 0,
        .shortcut = 0,
    };
    @memset(nodes, unreached);
    nodes[0].cost = 0;
    var skip_until: usize = 0;
    for (0..input.len) |position| {
        const node = nodes[position];
        assert(node.cost < std.math.inf(f32)); // a literal reaches every node
        relax(nodes, position + 1, .{
            .cost = node.cost + model.literal_bits(input, position),
            .length = 0,
            .distance = 0,
            .insert = node.run() + 1,
            .shortcut = node.shortcut,
        });
        // Inside a long match: no copies from here (brotli's skip). Each
        // would price hundreds of lengths for what the long one covers.
        if (position < skip_until) continue;
        const here = matches.at(position);
        if (here.len > 0 and here[here.len - 1].length >= long_length) {
            skip_until = position + here[here.len - 1].length;
        }
        const cache = cache_at(nodes, position);
        var from: Copies = .{ .position = position, .node = node, .cache = cache, .model = model };
        // The cache's own distances first: often shorter, and cheap. Only
        // `long_length` ahead: a longer copy is among the matches anyway,
        // and looking further made a run of zeros quadratic (15 s for
        // 70 KB).
        for (cache.last) |distance| {
            if (distance > position or distance > window) continue;
            const ahead = input[position..@min(input.len, position + long_length)];
            const length = match.common_length(input[position - distance ..], ahead);
            if (length >= 2) from.lengths(nodes, distance, 2, @intCast(length));
        }
        var shortest: u32 = match.match_min;
        for (here) |candidate| {
            from.lengths(nodes, candidate.distance, shortest, candidate.length);
            shortest = candidate.length + 1;
        }
    }
}

fn relax(nodes: []Node, position: usize, candidate: Node) void {
    if (candidate.cost < nodes[position].cost) nodes[position] = candidate;
}

/// Copies from one node, priced.
const Copies = struct {
    position: usize,
    node: Node,
    cache: DistanceCache,
    model: *const Model,

    /// Copies of `shortest..longest` bytes at `distance`: each length up
    /// to `long_length`, and the longest.
    fn lengths(copies: *Copies, nodes: []Node, distance: u32, shortest: u32, longest: u32) void {
        if (shortest > longest) return;
        const model = copies.model;
        const run = copies.node.run();
        const insert_code = command_module.insert_length_code(run);
        const insert_bits: f32 = @floatFromInt(tables.insert_ranges[insert_code].extra);
        const short = copies.cache.short_code(distance);
        const distance_bits: f32 = if (short) |code|
            model.distance[code]
        else blk: {
            var coded: command_module.Coded = undefined;
            command_module.code_distance(distance, &coded);
            const extra: f32 = @floatFromInt(coded.distance_extra_bits);
            break :blk model.distance[coded.distance.?] + extra;
        };
        const moves = command_module.pushes(&copies.cache, distance);
        const top = @min(longest, long_length);
        var length = shortest;
        for (0..longest - shortest + 2) |_| {
            if (length > longest) break;
            if (length > top) length = longest;
            const copy_code = command_module.copy_length_code(length);
            const implied = short == 0 and insert_code < 8 and copy_code < 16;
            const symbol = command_module.insert_copy_symbol(insert_code, copy_code, implied);
            const copy_bits: f32 = @floatFromInt(tables.copy_ranges[copy_code].extra);
            const end = copies.position + length;
            relax(nodes, end, .{
                .cost = copies.node.cost + model.insert_copy[symbol] + insert_bits + copy_bits +
                    (if (implied) 0 else distance_bits),
                .length = length,
                .distance = distance,
                .insert = run,
                .shortcut = if (moves) @intCast(end) else copies.node.shortcut,
            });
            length += 1;
        } else unreachable;
    }
};

/// The distance cache on the cheapest path to `position`: the last four
/// distances that moved it, newest first, then the initial ones.
fn cache_at(nodes: []const Node, position: usize) DistanceCache {
    var cache: DistanceCache = .{};
    var filled: usize = 0;
    var end = nodes[position].shortcut;
    for (0..4) |_| {
        if (end == 0) break;
        const node = nodes[end];
        assert(node.length > 0);
        cache.last[filled] = node.distance;
        filled += 1;
        end = nodes[end - node.length].shortcut;
    }
    for (cache.last[filled..], 0..) |*slot, index| slot.* = DistanceCache.initial[index];
    return cache;
}

/// The commands on the cheapest path, from its end back.
fn trace(
    gpa: Allocator,
    nodes: []const Node,
    commands: *std.ArrayList(Command),
) Allocator.Error!void {
    commands.clearRetainingCapacity();
    var position = nodes.len - 1;
    const trailing = nodes[position].run();
    if (trailing > 0) try commands.append(gpa, .{ .insert = trailing, .copy = 0, .distance = 0 });
    position -= trailing;
    for (0..nodes.len) |_| {
        if (position == 0) break;
        const node = nodes[position];
        assert(node.length > 0); // literals are counted in the copy's insert
        try commands.append(gpa, .{
            .insert = node.insert,
            .copy = node.length,
            .distance = node.distance,
        });
        position -= node.length + node.insert;
    } else unreachable;
    std.mem.reverse(Command, commands.items);
}

test "brotli_optimal: the parse covers the input and copies what was there" {
    const gpa = std.testing.allocator;
    const inputs = [_][]const u8{
        "a",
        "abcabcabcabcabcabc",
        "the quick brown fox jumps over the lazy dog; the quick brown fox again",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        @embedFile("testdata/style.css"),
    };
    for (inputs) |input| {
        var commands: std.ArrayList(Command) = .empty;
        defer commands.deinit(gpa);
        try parse(gpa, input, 1 << 20, &commands);
        var out: [4096]u8 = undefined;
        var used: usize = 0;
        for (commands.items) |command| {
            @memcpy(out[used..][0..command.insert], input[used..][0..command.insert]);
            used += command.insert;
            for (0..command.copy) |_| {
                out[used] = out[used - command.distance];
                used += 1;
            }
        }
        try std.testing.expectEqualStrings(input, out[0..used]);
    }
}
