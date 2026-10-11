//! SHA-256 for the TLS handshake: Zig std's, with the CPU's SHA extensions
//! where it has them. std chooses that path at compile time, and the race's
//! CPU level (x86-64-v3) has no SHA: a build with it would stop with an
//! illegal instruction on a Broadwell or a Skylake droplet. So std's code is
//! built twice, here (the build's CPU) and in `sha256_shani.zig` (an object
//! for x86-64-v3 with SHA), and `cpuid`, asked once, picks. 38% of a
//! handshake's instructions were SHA-256's (measured).
//!
//! The same interface as `std.crypto.hash.sha2.Sha256`, so std's HMAC and
//! HKDF take it: tls.zig names it for its transcript and suites (its patch).
//! A module of its own (tls.zig imports it); its tests are their own
//! artifact (build.zig).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const StdSha256 = std.crypto.hash.sha2.Sha256;

comptime {
    assert(builtin.cpu.arch == .x86_64);
}

/// The hash's state between calls: std's `Sha256` fields, in a layout both
/// builds agree on (`sha256_shani.zig` asserts the same).
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

extern fn fourneau_sha256_shani_update(
    state: *State,
    bytes: [*]const u8,
    length: usize,
) callconv(.c) void;
extern fn fourneau_sha256_shani_final(state: *const State, out: *[32]u8) callconv(.c) void;

/// Which build of std's SHA-256 runs: `build`, std as this build compiled
/// it (the SHA extensions' path itself when the build targets them);
/// `shani`, the object built for them.
pub const Path = enum { build, shani };

/// What the CPU said, once asked: 0 not yet, else 1 + @backingInt(Path).
/// Shards may ask at once; they store the same answer.
var path_known = std.atomic.Value(u8).init(0);

/// The SHA extensions' build where the CPU has SHA and AVX2. Asked once,
/// not per call: in a virtual machine `cpuid` traps to the hypervisor.
pub fn path() Path {
    if (comptime builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 })) return .build;
    const known = path_known.load(.monotonic);
    if (known != 0) return @fromBackingInt(@intCast(known - 1));
    const answer: Path = if (cpu_has_sha_avx2()) .shani else .build;
    path_known.store(1 + @as(u8, @backingInt(answer)), .monotonic);
    return answer;
}

fn cpu_has_sha_avx2() bool {
    if (cpuid(0).eax < 7) return false;
    const features = cpuid(7).ebx;
    const avx2 = features & (1 << 5) != 0;
    const sha = features & (1 << 29) != 0;
    // AVX2 also needs the OS to save the YMM registers (OSXSAVE, XCR0). The
    // object targets x86-64-v3: every CPU with SHA and AVX2 has the rest of
    // it (Intel from Ice Lake, AMD from Zen).
    return avx2 and sha and os_saves_ymm();
}

fn os_saves_ymm() bool {
    const osxsave = cpuid(1).ecx & (1 << 27) != 0;
    if (!osxsave) return false;
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("xgetbv"
        : [_] "={eax}" (eax),
          [_] "={edx}" (edx),
        : [_] "{ecx}" (@as(u32, 0)),
    );
    return eax & 0b110 == 0b110;
}

fn cpuid(leaf: u32) struct { eax: u32, ebx: u32, ecx: u32 } {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (@as(u32, 0)),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx };
}

/// `std.crypto.hash.sha2.Sha256`'s interface, either build underneath.
pub const Sha256 = struct {
    pub const block_length = StdSha256.block_length;
    pub const digest_length = StdSha256.digest_length;
    pub const Options = StdSha256.Options;

    /// std's own state: the build's path works on it in place; the SHA
    /// extensions' path copies it out and back, which its speed pays for
    /// (copying both ways cost 1% of a handshake on a CPU without them).
    inner: StdSha256,
    /// A test's choice; else the CPU's, asked at the first `update` (not at
    /// `init`: tls.zig inits one as a field default, at compile time).
    forced: ?Path = null,

    pub fn init(options: Options) Sha256 {
        return .{ .inner = StdSha256.init(options) };
    }

    fn init_on(on: Path, options: Options) Sha256 {
        var d = Sha256.init(options);
        d.forced = on;
        return d;
    }

    pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Sha256.init(options);
        d.update(bytes);
        d.final(out);
    }

    pub fn update(d: *Sha256, bytes: []const u8) void {
        switch (d.forced orelse path()) {
            .build => d.inner.update(bytes),
            .shani => {
                var state = to_state(&d.inner);
                fourneau_sha256_shani_update(&state, bytes.ptr, bytes.len);
                d.inner = from_state(&state);
            },
        }
    }

    pub fn peek(d: Sha256) [digest_length]u8 {
        var copy = d;
        return copy.finalResult();
    }

    pub fn final(d: *Sha256, out: *[digest_length]u8) void {
        switch (d.forced orelse path()) {
            .build => d.inner.final(out),
            // Not stored back: a hash after `final` is spent, as std's is.
            .shani => fourneau_sha256_shani_final(&to_state(&d.inner), out),
        }
    }

    /// The same hash as std's own type, for code that names it (tls.zig's
    /// RSA and TLS 1.2 signers take the transcript's so).
    pub fn toStd(d: Sha256) StdSha256 {
        return d.inner;
    }

    pub fn finalResult(d: *Sha256) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        d.final(&out);
        return out;
    }
};

fn from_state(state: *const State) StdSha256 {
    assert(state.buf_len < 64);
    return .{
        .s = state.s,
        .buf = state.buf,
        .buf_len = state.buf_len,
        .total_len = state.total_len,
    };
}

fn to_state(std_hash: *const StdSha256) State {
    assert(std_hash.buf_len < 64);
    return .{
        .s = std_hash.s,
        .buf = std_hash.buf,
        .buf_len = std_hash.buf_len,
        .total_len = std_hash.total_len,
    };
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

/// The paths this CPU can run: the SHA extensions' only where it has them
/// (a CPU without them has that path tested on one with them).
fn paths() []const Path {
    return if (path() == .shani) &.{ .build, .shani } else &.{.build};
}

test "sha256: the CPU's path is asked once and kept" {
    try testing.expectEqual(path(), path());
}

test "sha256: FIPS 180's examples" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "", .out = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        .{ .in = "abc", .out = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        .{
            .in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            .out = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        },
    };
    for (paths()) |on| {
        for (cases) |case| {
            var want: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&want, case.out);
            var d = Sha256.init_on(on, .{});
            d.update(case.in);
            try testing.expectEqual(want, d.finalResult());
        }
    }
}

test "sha256: equals std's for every length and split, and peek leaves it be" {
    var bytes: [300]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index *% 151 +% 7);
    for (paths()) |on| {
        for (0..bytes.len + 1) |length| {
            const want = digest_std(bytes[0..length]);
            const split = length * 37 % (length + 1);
            var d = Sha256.init_on(on, .{});
            d.update(bytes[0..split]);
            const peeked = d.peek();
            d.update(bytes[split..length]);
            try testing.expectEqual(want, d.peek());
            try testing.expectEqual(want, d.finalResult());
            try testing.expectEqual(digest_std(bytes[0..split]), peeked);
            var as_std = Sha256.init_on(on, .{});
            as_std.update(bytes[0..length]);
            var std_hash = as_std.toStd();
            try testing.expectEqual(want, std_hash.finalResult());
        }
    }
}

test "sha256: std's HMAC and HKDF over it equal theirs over std's" {
    const Hmac = std.crypto.auth.hmac.Hmac(Sha256);
    const HmacStd = std.crypto.auth.hmac.sha2.HmacSha256;
    const key = "a key longer than one SHA-256 block (64 bytes), so HMAC hashes it first";
    var got: [32]u8 = undefined;
    var want: [32]u8 = undefined;
    Hmac.create(&got, "the message", key);
    HmacStd.create(&want, "the message", key);
    try testing.expectEqual(want, got);
    const prk = std.crypto.kdf.hkdf.Hkdf(Hmac).extract("salt", "input key material");
    const prk_std = std.crypto.kdf.hkdf.HkdfSha256.extract("salt", "input key material");
    try testing.expectEqual(prk_std, prk);
}

fn digest_std(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    StdSha256.hash(bytes, &out, .{});
    return out;
}
