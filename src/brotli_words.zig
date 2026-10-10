//! Finding the static dictionary's words in the input (RFC 7932 section
//! 8): a word of 4..24 letters, through one of 121 transforms (a prefix,
//! the word as is, capitalized, upper-cased or cut short, a suffix), is
//! one copy command. Small files, which cannot repeat themselves much,
//! gain most from it.
//!
//! Words are indexed by their first four letters, case-folded. At a
//! position, each prefix the transforms use is tried; after a matching
//! prefix, the words whose first letters match are tried under each
//! transform with that prefix. A transform that drops a word's first
//! letters is never tried: its body does not start with them.

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");

const Allocator = std.mem.Allocator;

/// A word found: it produces `out` bytes of input; `length` is the base
/// word's (the copy length coded) and `id` its transform and index,
/// `transform << ndbits[length] | index` (the distance's offset).
pub const Found = struct { out: u32, length: u5, id: u32 };

const key_bits = 15;
const words_count = count: {
    var sum: u32 = 0;
    for (tables.word_length_min..tables.word_length_max + 1) |length| {
        sum += tables.word_count(length);
    }
    break :count sum;
};

/// Each transform prefix and the transforms that use it.
const Group = struct { prefix: []const u8, transforms: []const u8 };

const groups: []const Group = make: {
    @setEvalBranchQuota(200_000);
    var prefixes: [16][]const u8 = undefined;
    var members: [16][tables.transforms_count]u8 = undefined;
    var sizes: [16]usize = @splat(0);
    var count: usize = 0;
    for (tables.transforms, 0..) |transform, id| {
        const kind = transform.elementary;
        if (kind >= 3 and kind <= 11) continue; // omits the first letters
        const group = for (prefixes[0..count], 0..) |prefix, index| {
            if (std.mem.eql(u8, prefix, transform.prefix)) break index;
        } else new: {
            prefixes[count] = transform.prefix;
            count += 1;
            break :new count - 1;
        };
        members[group][sizes[group]] = id;
        sizes[group] += 1;
    }
    var made: [count]Group = undefined;
    for (&made, 0..) |*group, index| {
        const ids = members[index][0..sizes[index]].*;
        group.* = .{ .prefix = prefixes[index], .transforms = &ids };
    }
    const final = made;
    break :make &final;
};

pub const Index = struct {
    /// Per key: the first word with it, + 1; 0: none.
    heads: []u16,
    /// Per word: the next with the same key, + 1.
    next: []u16,

    pub fn init(gpa: Allocator) Allocator.Error!Index {
        comptime assert(words_count < std.math.maxInt(u16));
        const index: Index = .{
            .heads = try gpa.alloc(u16, 1 << key_bits),
            .next = try gpa.alloc(u16, words_count),
        };
        @memset(index.heads, 0);
        // Inserted backwards, so each chain is in word order: the first
        // word of a key is the lowest index, and so the shortest distance.
        var number: u32 = words_count;
        while (number > 0) {
            number -= 1;
            const word = word_of(number);
            const slot = &index.heads[key(tables.word(word.length, word.index)[0..4])];
            index.next[number] = slot.*;
            slot.* = @intCast(number + 1);
        }
        return index;
    }

    pub fn deinit(index: *Index, gpa: Allocator) void {
        gpa.free(index.heads);
        gpa.free(index.next);
        index.* = undefined;
    }

    /// The words found at `position`, at most `out.len`, the first for
    /// each length of input it covers.
    pub fn find(index: *const Index, input: []const u8, position: usize, out: []Found) usize {
        var count: usize = 0;
        const rest = input[position..];
        for (groups) |group| {
            if (!std.mem.startsWith(u8, rest, group.prefix)) continue;
            const body = rest[group.prefix.len..];
            if (body.len < 4) continue;
            var link = index.heads[key(body[0..4])];
            for (0..words_count) |_| {
                if (link == 0) break;
                const word = word_of(link - 1);
                count = try_word(rest, group, word, out, count);
                link = index.next[link - 1];
            } else unreachable;
        }
        return count;
    }
};

const WordAt = struct { length: u5, index: u32 };

/// Words are numbered by length, then index.
fn word_of(number: u32) WordAt {
    var rest = number;
    for (tables.word_length_min..tables.word_length_max + 1) |length| {
        const count = tables.word_count(length);
        if (rest < count) return .{ .length = @intCast(length), .index = rest };
        rest -= count;
    }
    unreachable;
}

fn key(bytes: *const [4]u8) u32 {
    var folded: [4]u8 = undefined;
    for (&folded, bytes) |*into, byte| into.* = std.ascii.toLower(byte);
    return (std.mem.readInt(u32, &folded, .little) *% 0x1e35a7bd) >> (32 - key_bits);
}

/// The group's transforms of this word that the input holds here.
fn try_word(rest: []const u8, group: Group, word: WordAt, out: []Found, start: usize) usize {
    var count = start;
    const letters = tables.word(word.length, word.index);
    const body = rest[group.prefix.len..];
    const exact = common(letters, body);
    const folded = common_folded(letters, body);
    for (group.transforms) |id| {
        const kind = tables.transforms[id].elementary;
        // Cheap tests first: the body must hold the word, as transformed.
        const possible = switch (kind) {
            tables.identity => exact == letters.len,
            tables.ferment_first, tables.ferment_all => folded == letters.len,
            else => exact >= letters.len - @min(letters.len, kind - 11),
        };
        if (!possible) continue;
        var buffer: [tables.transformed_bytes_max]u8 = undefined;
        const made = tables.transform_word(letters, id, &buffer);
        if (made.len == 0 or !std.mem.startsWith(u8, rest, made)) continue;
        if (count == out.len) return count;
        if (covered(out[0..count], made.len)) continue;
        out[count] = .{
            .out = @intCast(made.len),
            .length = word.length,
            .id = (@as(u32, id) << tables.ndbits[word.length]) | word.index,
        };
        count += 1;
    }
    return count;
}

fn covered(found: []const Found, out: usize) bool {
    for (found) |entry| if (entry.out == out) return true;
    return false;
}

fn common(a: []const u8, b: []const u8) usize {
    const limit = @min(a.len, b.len);
    return std.mem.indexOfDiff(u8, a[0..limit], b[0..limit]) orelse limit;
}

fn common_folded(a: []const u8, b: []const u8) usize {
    const limit = @min(a.len, b.len);
    for (a[0..limit], b[0..limit], 0..) |x, y, index| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return index;
    }
    return limit;
}

test "brotli_words: words are found as the RFC's transforms make them" {
    const gpa = std.testing.allocator;
    var index = try Index.init(gpa);
    defer index.deinit(gpa);
    var found: [32]Found = undefined;
    // "time" is word 0 of length 4; " the time of the " is transform 73.
    const input = " the time of the year";
    const count = index.find(input, 0, &found);
    var best: usize = 0;
    for (found[0..count]) |entry| {
        var buffer: [tables.transformed_bytes_max]u8 = undefined;
        const transform: u8 = @intCast(entry.id >> tables.ndbits[entry.length]);
        const word_index = entry.id & ((@as(u32, 1) << tables.ndbits[entry.length]) - 1);
        const word = tables.word(entry.length, word_index);
        const made = tables.transform_word(word, transform, &buffer);
        try std.testing.expectEqual(entry.out, made.len);
        try std.testing.expect(std.mem.startsWith(u8, input, made));
        best = @max(best, entry.out);
    }
    try std.testing.expectEqual(" the time of the ".len, best);
    // Capitalized and upper-cased forms are found too.
    try std.testing.expect(index.find("Time", 0, &found) > 0);
    try std.testing.expect(index.find("TIME", 0, &found) > 0);
}
