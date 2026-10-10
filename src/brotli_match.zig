//! Finding repeats for brotli's encoder: LZ77 over hash chains. A command
//! is some literals, then a copy of earlier bytes (RFC 7932 section 2).

const std = @import("std");
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;

const Command = @import("brotli_command.zig").Command;

pub const Match = struct { length: u32, distance: u32 };

/// The shortest match worth a command.
pub const match_min = 4;
const hash_bits = 17;
/// How far down a chain a search goes: more finds longer matches, slower.
const chain_steps_max = 1024;

/// Every position's earlier positions with the same next four bytes, most
/// recent first: `heads` per hash, `previous` per position (index + 1;
/// 0 ends a chain).
pub const Chains = struct {
    heads: []u32,
    previous: []u32,
    input: []const u8,
    window: u32,
    /// Positions inserted so far.
    inserted: u32 = 0,

    pub fn init(gpa: Allocator, input: []const u8, window: u32) Allocator.Error!Chains {
        const heads = try gpa.alloc(u32, 1 << hash_bits);
        @memset(heads, 0);
        return .{
            .heads = heads,
            .previous = try gpa.alloc(u32, input.len),
            .input = input,
            .window = window,
        };
    }

    pub fn deinit(chains: *Chains, gpa: Allocator) void {
        gpa.free(chains.heads);
        gpa.free(chains.previous);
        chains.* = undefined;
    }

    fn hash(chains: *const Chains, position: usize) u32 {
        const bytes = std.mem.readInt(u32, chains.input[position..][0..4], .little);
        return (bytes *% 0x1e35a7bd) >> (32 - hash_bits);
    }

    /// Every position before `end` into its chain.
    pub fn insert_until(chains: *Chains, end: usize) void {
        const last = @min(end, chains.input.len -| (match_min - 1));
        while (chains.inserted < last) {
            const position = chains.inserted;
            const slot = &chains.heads[chains.hash(position)];
            chains.previous[position] = slot.*;
            slot.* = position + 1;
            chains.inserted += 1;
        }
    }

    /// The longest earlier match for the bytes at `position`, within the
    /// window; length 0 when there is none of `match_min` bytes.
    pub fn longest(chains: *Chains, position: usize) Match {
        var best: Match = .{ .length = 0, .distance = 0 };
        if (position + match_min > chains.input.len) return best;
        chains.insert_until(position);
        const rest = chains.input[position..];
        var candidate = chains.heads[chains.hash(position)];
        for (0..chain_steps_max) |_| {
            if (candidate == 0) break;
            const earlier = candidate - 1;
            assert(earlier < position);
            const distance: u32 = @intCast(position - earlier);
            if (distance > chains.window) break;
            const length = common_length(chains.input[earlier..], rest);
            if (length > best.length) {
                best = .{ .length = @intCast(length), .distance = distance };
                if (length == rest.len) break;
            }
            candidate = chains.previous[earlier];
        }
        if (best.length < match_min) best.length = 0;
        return best;
    }
};

/// Every match worth having at `position`, nearest first: each one longer
/// than all nearer ones (so any length up to its own is had at its
/// distance, the nearest that has it). Stops at `out.len` matches, or at
/// one of `long` bytes, which no later one improves enough to matter.
pub fn candidates(chains: *Chains, position: usize, long: u32, out: []Match) usize {
    assert(out.len > 0);
    if (position + match_min > chains.input.len) return 0;
    chains.insert_until(position);
    const rest = chains.input[position..];
    var count: usize = 0;
    var best: usize = match_min - 1;
    var candidate = chains.heads[chains.hash(position)];
    for (0..chain_steps_max) |_| {
        if (candidate == 0 or count == out.len) break;
        const earlier = candidate - 1;
        const distance: u32 = @intCast(position - earlier);
        if (distance > chains.window) break;
        const length = common_length(chains.input[earlier..], rest);
        if (length > best) {
            best = length;
            out[count] = .{ .length = @intCast(length), .distance = distance };
            count += 1;
            if (length >= long or length == rest.len) break;
        }
        candidate = chains.previous[earlier];
    }
    return count;
}

pub fn common_length(a: []const u8, b: []const u8) usize {
    const limit = @min(a.len, b.len);
    return std.mem.indexOfDiff(u8, a[0..limit], b[0..limit]) orelse limit;
}

/// Commands for all of `input`: the longest match at each position, but
/// one step later when that one is longer (lazy matching, as gzip does).
pub fn parse_lazy(
    gpa: Allocator,
    input: []const u8,
    window: u32,
    commands: *std.ArrayList(Command),
) Allocator.Error!void {
    var chains = try Chains.init(gpa, input, window);
    defer chains.deinit(gpa);
    var position: usize = 0;
    var literals_start: usize = 0;
    for (0..input.len + 1) |_| {
        if (position >= input.len) break;
        const here = chains.longest(position);
        if (here.length == 0) {
            position += 1;
            continue;
        }
        if (position + 1 < input.len) {
            const next = chains.longest(position + 1);
            if (next.length > here.length + 1) {
                position += 1;
                continue;
            }
        }
        try commands.append(gpa, .{
            .insert = @intCast(position - literals_start),
            .copy = here.length,
            .distance = here.distance,
            .out = here.length,
        });
        position += here.length;
        literals_start = position;
    } else unreachable;
    if (literals_start < input.len or commands.items.len == 0) {
        try commands.append(gpa, .{
            .insert = @intCast(input.len - literals_start),
            .copy = 0,
            .distance = 0,
            .out = 0,
        });
    }
}

test "brotli_match: commands cover the input and copy what was there" {
    const gpa = std.testing.allocator;
    const inputs = [_][]const u8{
        "",
        "a",
        "abcabcabcabcabcabc",
        "the quick brown fox jumps over the lazy dog; the quick brown fox again",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    for (inputs) |input| {
        var commands: std.ArrayList(Command) = .empty;
        defer commands.deinit(gpa);
        try parse_lazy(gpa, input, 1 << 20, &commands);
        // Replay: literals from the input, copies from what was produced.
        var out: [128]u8 = undefined;
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
