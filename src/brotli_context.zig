//! Context modeling for literals (RFC 7932 section 7): each literal's
//! prefix code chosen by its context, the two bytes before it. Text's
//! letters, digits, spaces and punctuation follow each other differently,
//! so 64 contexts (UTF8 mode) with their own counts code better than one;
//! but a code costs its description, so contexts that count alike share
//! one: clusters, merged greedily while merging saves bits.

const std = @import("std");
const assert = std.debug.assert;
const tables = @import("brotli_tables.zig");

pub const contexts = 64;
pub const mode: tables.ContextMode = .utf8;
/// The most codes the literals get: more costs more in descriptions than
/// it saves on these files (measured, DIARY).
pub const trees_max = 16;

/// The literal context at `position`: from the two bytes before it, which
/// are the input's whatever the parse (0 before the start).
pub fn at(input: []const u8, position: usize) u6 {
    const p1 = if (position >= 1) input[position - 1] else 0;
    const p2 = if (position >= 2) input[position - 2] else 0;
    return tables.literal_context(mode, p1, p2);
}

pub const Histogram = [256]u32;

/// The contexts' clusters: which code each context uses, and each code's
/// counts.
pub const Clustering = struct {
    map: [contexts]u8,
    trees: u8,
    histograms: [contexts]Histogram,
};

/// Greedy agglomerative clustering, as brotli's encoder clusters: merge
/// the two clusters whose union costs least over their parts, while that
/// saves bits or there are more than `trees_max`.
pub fn cluster(by_context: *const [contexts]Histogram) Clustering {
    var result: Clustering = .{ .map = @splat(0), .trees = 0, .histograms = undefined };
    // A cluster per context that has literals; one for none at all.
    var members: [contexts]u64 = @splat(0); // bit c: context c belongs
    var costs: [contexts]f64 = undefined;
    var count: usize = 0;
    for (by_context, 0..) |histogram, context| {
        if (total(&histogram) == 0) continue;
        result.histograms[count] = histogram;
        members[count] = @as(u64, 1) << @intCast(context);
        costs[count] = population_cost(&histogram);
        count += 1;
    }
    if (count == 0) {
        result.histograms[0] = @splat(0);
        result.trees = 1;
        return result;
    }
    // What merging each pair saves, kept up to date: a merge changes only
    // the merged cluster's row (and moves the last one into the gap).
    var savings: [contexts][contexts]f64 = undefined;
    for (0..count) |a| {
        for (a + 1..count) |b| savings[a][b] = saving(&result.histograms, &costs, a, b);
    }
    for (0..contexts) |_| {
        if (count == 1) break;
        const best = cheapest_merge(&savings, count);
        if (best.saving <= 0 and count <= trees_max) break;
        // Merge b into a, then fill b's place with the last cluster.
        for (&result.histograms[best.a], result.histograms[best.b]) |*into, from| into.* += from;
        members[best.a] |= members[best.b];
        costs[best.a] = population_cost(&result.histograms[best.a]);
        count -= 1;
        result.histograms[best.b] = result.histograms[count];
        members[best.b] = members[count];
        costs[best.b] = costs[count];
        for (0..count) |other| {
            for ([_]usize{ best.a, best.b }) |changed| {
                if (changed >= count or other == changed) continue;
                const low = @min(other, changed);
                const high = @max(other, changed);
                savings[low][high] = saving(&result.histograms, &costs, low, high);
            }
        }
    } else unreachable;
    for (members[0..count], 0..) |set, tree| {
        for (0..contexts) |context| {
            if (set & (@as(u64, 1) << @intCast(context)) != 0) result.map[context] = @intCast(tree);
        }
    }
    result.trees = @intCast(count);
    return result;
}

/// Every context on one code: the encoder's alternative when a file is
/// too small for its contexts to pay for their codes.
pub fn single(by_context: *const [contexts]Histogram) Clustering {
    var result: Clustering = .{ .map = @splat(0), .trees = 1, .histograms = undefined };
    result.histograms[0] = @splat(0);
    for (by_context) |histogram| {
        for (&result.histograms[0], histogram) |*into, from| into.* += from;
    }
    return result;
}

const Merge = struct { a: usize, b: usize, saving: f64 };

fn cheapest_merge(savings: *const [contexts][contexts]f64, count: usize) Merge {
    assert(count >= 2);
    var best: Merge = .{ .a = 0, .b = 1, .saving = -std.math.inf(f64) };
    for (0..count) |a| {
        for (a + 1..count) |b| {
            if (savings[a][b] > best.saving) best = .{ .a = a, .b = b, .saving = savings[a][b] };
        }
    }
    return best;
}

/// The bits merging clusters `a` and `b` saves (negative: it costs).
fn saving(
    histograms: *const [contexts]Histogram,
    costs: *const [contexts]f64,
    a: usize,
    b: usize,
) f64 {
    assert(a < b);
    var merged: Histogram = histograms[a];
    for (&merged, histograms[b]) |*into, from| into.* += from;
    return costs[a] + costs[b] - population_cost(&merged);
}

fn total(histogram: *const Histogram) u64 {
    var sum: u64 = 0;
    for (histogram) |count| sum += count;
    return sum;
}

/// The bits a histogram's literals cost under their own code, with the
/// code's description: Shannon's bits, plus about four bits a symbol used
/// and a fixed part for the code's header (an estimate; measured against
/// written sizes in the DIARY).
pub fn population_cost(histogram: *const Histogram) f64 {
    const sum: f64 = @floatFromInt(total(histogram));
    if (sum == 0) return 0;
    var bits: f64 = 0;
    var used: f64 = 0;
    for (histogram) |count| {
        if (count == 0) continue;
        const c: f64 = @floatFromInt(count);
        bits += c * std.math.log2(sum / c);
        used += 1;
    }
    return bits + 4 * used + 20;
}

test "brotli_context: alike contexts merge, unlike ones stay apart" {
    var by_context: [contexts]Histogram = @splat(@splat(0));
    // Contexts 0..3 all count 'a' and 'b' alike; 10..13 count 'x' and 'y'.
    for (0..4) |context| {
        by_context[context]['a'] = 1000;
        by_context[context]['b'] = 1000;
        by_context[context + 10]['x'] = 900;
        by_context[context + 10]['y'] = 100;
    }
    const result = cluster(&by_context);
    try std.testing.expectEqual(2, result.trees);
    for (1..4) |context| {
        try std.testing.expectEqual(result.map[0], result.map[context]);
        try std.testing.expectEqual(result.map[10], result.map[context + 10]);
    }
    try std.testing.expect(result.map[0] != result.map[10]);
}
