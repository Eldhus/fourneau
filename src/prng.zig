//! Our own random numbers, so a seed means the same simulated run for as
//! long as this file does not change: no library update can reshuffle them
//! (TigerBeetle's stdx.PRNG, for the same reason).
//!
//! xoshiro256++ (Blackman and Vigna), seeded through SplitMix64. Integers
//! only: probabilities are ratios, ranges are exact (rejection sampling,
//! not a biased modulo), and the bell curve is Irwin-Hall (a sum of twelve
//! uniforms), so nothing depends on how a platform computes `log` or `cos`.

const std = @import("std");
const assert = std.debug.assert;

/// A probability as a ratio: `numerator` in `denominator`.
pub const Ratio = struct {
    numerator: u64,
    denominator: u64,

    pub fn of(numerator: u64, denominator: u64) Ratio {
        assert(denominator > 0);
        assert(numerator <= denominator);
        return .{ .numerator = numerator, .denominator = denominator };
    }
};

pub fn ratio(numerator: u64, denominator: u64) Ratio {
    return Ratio.of(numerator, denominator);
}

pub const Prng = struct {
    s: [4]u64,

    pub fn init(seed: u64) Prng {
        var x = seed;
        var p: Prng = .{ .s = undefined };
        for (&p.s) |*word| word.* = split_mix(&x);
        assert(!std.mem.allEqual(u64, &p.s, 0)); // the one state xoshiro cannot leave
        return p;
    }

    pub fn next(p: *Prng) u64 {
        const s = &p.s;
        const result = std.math.rotl(u64, s[0] +% s[3], 23) +% s[0];
        const t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = std.math.rotl(u64, s[3], 45);
        return result;
    }

    pub fn boolean(p: *Prng) bool {
        return p.next() >> 63 == 1;
    }

    /// Uniform in [0, bound): Lemire's multiply, rejecting the few values
    /// that would bias it. Each draw is rejected with probability below
    /// bound / 2^64, so the loop's bound is never reached in practice.
    pub fn int_less_than(p: *Prng, comptime T: type, bound: T) T {
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        comptime assert(@bitSizeOf(T) <= 64);
        assert(bound > 0);
        const n: u64 = bound;
        const threshold = (0 -% n) % n; // 2^64 mod n
        for (0..64) |_| {
            const m = @as(u128, p.next()) * n;
            if (@as(u64, @truncate(m)) >= threshold) return @intCast(m >> 64);
        }
        unreachable; // 64 rejections in a row: probability below 2^-64
    }

    /// Uniform in [min, max], inclusive.
    pub fn int_at_most(p: *Prng, comptime T: type, min: T, max: T) T {
        assert(min <= max);
        const Wide = @Int(.unsigned, @bitSizeOf(T));
        const span: u64 = @as(Wide, @bitCast(max -% min));
        if (span == std.math.maxInt(u64)) return @bitCast(@as(Wide, @truncate(p.next())));
        const offset: Wide = @intCast(p.int_less_than(u64, span + 1));
        return @bitCast(@as(Wide, @bitCast(min)) +% offset);
    }

    /// True with probability `r`.
    pub fn chance(p: *Prng, r: Ratio) bool {
        assert(r.numerator <= r.denominator);
        return p.int_less_than(u64, r.denominator) < r.numerator;
    }

    /// A bell curve centred on `mean` with standard deviation `sigma`,
    /// within six sigma: Irwin-Hall, twelve uniforms summed, in integers.
    pub fn normal(p: *Prng, mean: i64, sigma: i64) i64 {
        assert(sigma >= 0);
        const unit: i64 = 1 << 16;
        var sum: i64 = 0;
        for (0..12) |_| sum += @intCast(p.int_less_than(u64, unit));
        // twelve uniforms on [0, 1) have mean 6 and variance 1
        const z = sum - 6 * unit;
        assert(@abs(z) <= 6 * unit);
        return mean + @divFloor(z * sigma, unit);
    }
};

fn split_mix(x: *u64) u64 {
    x.* +%= 0x9e3779b97f4a7c15;
    var z = x.*;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

// The sequence is the contract: if this changes, every seed means another
// run. (These are this generator's first outputs for seed 0; they pin
// the implementation, and change only with a deliberate decision.)
test "prng: a seed's sequence never changes" {
    var p = Prng.init(0);
    var got: [4]u64 = undefined;
    for (&got) |*x| x.* = p.next();
    var again = Prng.init(0);
    for (got) |x| try testing.expectEqual(x, again.next());
    try testing.expect(got[0] != got[1]);
    try testing.expectEqual(@as(u64, 0x53175d61490b23df), got[0]);
}

test "prng: ranges are exact and inclusive; chance and normal are calibrated" {
    var p = Prng.init(42);
    var seen: [7]u32 = @splat(0);
    for (0..70_000) |_| {
        const x = p.int_at_most(i32, -3, 3);
        try testing.expect(x >= -3 and x <= 3);
        seen[@intCast(x + 3)] += 1;
    }
    for (seen) |n| try testing.expect(n > 9_000 and n < 11_000); // about 10,000 each
    try testing.expectEqual(@as(u8, 255), p.int_at_most(u8, 255, 255));
    var hits: u32 = 0;
    for (0..100_000) |_| hits += @intFromBool(p.chance(ratio(35, 100)));
    try testing.expect(hits > 34_000 and hits < 36_000);
    var sum: i64 = 0;
    var sum_sq: i64 = 0;
    const n = 20_000;
    for (0..n) |_| {
        const x = p.normal(1000, 100);
        try testing.expect(x >= 400 and x <= 1600);
        sum += x;
        sum_sq += (x - 1000) * (x - 1000);
    }
    try testing.expect(@abs(@divTrunc(sum, n) - 1000) <= 3);
    const variance = @divTrunc(sum_sq, n);
    try testing.expect(variance > 9_000 and variance < 11_000); // sigma about 100
}

test "prng: boolean is fair" {
    var p = Prng.init(7);
    var trues: u32 = 0;
    for (0..10_000) |_| trues += @intFromBool(p.boolean());
    try testing.expect(trues > 4_800 and trues < 5_200);
}
