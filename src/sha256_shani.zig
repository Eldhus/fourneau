//! Zig std's SHA-256, compiled for a CPU with the SHA extensions (and
//! AVX2): std chooses its `sha256rnds2` path at compile time, so this file
//! is an object of its own, built for x86-64-v3 with SHA (build.zig), and
//! `sha256.zig` calls it only where `cpuid` says the CPU has them. Nothing
//! here hashes: it moves the state into std's `Sha256` and back.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

comptime {
    // Else std takes its portable path and this object is for nothing.
    assert(builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }));
}

/// `sha256.zig`'s `State`, field for field (both assert the layout).
const State = extern struct {
    s: [8]u32,
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,
};

comptime {
    assert(@sizeOf(State) == 112);
    assert(@offsetOf(State, "total_len") == 104);
}

fn to_std(state: *const State) Sha256 {
    assert(state.buf_len < 64);
    return .{
        .s = state.s,
        .buf = state.buf,
        .buf_len = state.buf_len,
        .total_len = state.total_len,
    };
}

fn from_std(state: *State, hash: *const Sha256) void {
    assert(hash.buf_len < 64);
    state.* = .{
        .s = hash.s,
        .buf = hash.buf,
        .buf_len = hash.buf_len,
        .total_len = hash.total_len,
    };
}

export fn fourneau_sha256_shani_update(state: *State, bytes: [*]const u8, length: usize) void {
    var hash = to_std(state);
    hash.update(bytes[0..length]);
    from_std(state, &hash);
}

/// Not stored back: a hash after `final` is spent, as std's is.
export fn fourneau_sha256_shani_final(state: *const State, out: *[Sha256.digest_length]u8) void {
    var hash = to_std(state);
    hash.final(out);
}
