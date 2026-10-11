//! The TLS handshake's elliptic curves on s2n-bignum's formally verified
//! assembly (vendor/s2n-bignum, AWS's, the code aws-lc runs): X25519's key
//! pair and shared secret, and for an ECDSA P-256 signature the multiple of
//! the base point and the inverse of the nonce. Each result equals Zig
//! std's for the same input, which the tests check; std's took ~310 µs of a
//! handshake on one machine, these ~40 (measured).
//!
//! The rest of a signature is std's code, copied because std keeps it
//! private: the nonce from the key and the message, and the scalar
//! arithmetic. So a signature is std's, byte for byte.
//!
//! s2n-bignum has each routine twice: one for CPUs with BMI2 and ADX (mulx,
//! adcx, adox) and an `_alt` one without. Which runs is the CPU's answer,
//! asked once (`form`), as aws-lc does: the race builds for a CPU level
//! without ADX, which every droplet has anyway.
//!
//! A module of its own because tls.zig imports it (vendor/tls.zig, the one
//! patch); its tests run as their own artifact (build.zig).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;

pub const X25519 = std.crypto.dh.X25519;
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

comptime {
    // The assembly is x86-64's; the table is little-endian words.
    assert(builtin.cpu.arch == .x86_64);
    assert(builtin.cpu.arch.endian() == .little);
}

const s2n = struct {
    extern fn curve25519_x25519base_byte(res: *[32]u8, scalar: *const [32]u8) callconv(.c) void;
    extern fn curve25519_x25519base_byte_alt(res: *[32]u8, scalar: *const [32]u8) callconv(.c) void;
    extern fn curve25519_x25519_byte(
        res: *[32]u8,
        scalar: *const [32]u8,
        point: *const [32]u8,
    ) callconv(.c) void;
    extern fn curve25519_x25519_byte_alt(
        res: *[32]u8,
        scalar: *const [32]u8,
        point: *const [32]u8,
    ) callconv(.c) void;
    extern fn p256_scalarmulbase(
        res: *[8]u64,
        scalar: *const [4]u64,
        blocksize: u64,
        table: *const [p256_table_words]u64,
    ) callconv(.c) void;
    extern fn p256_scalarmulbase_alt(
        res: *[8]u64,
        scalar: *const [4]u64,
        blocksize: u64,
        table: *const [p256_table_words]u64,
    ) callconv(.c) void;
    extern fn bignum_tomont_p256(z: *[4]u64, x: *const [4]u64) callconv(.c) void;
    extern fn bignum_tomont_p256_alt(z: *[4]u64, x: *const [4]u64) callconv(.c) void;
    /// Generic, in any x86-64's instructions: no `_alt`.
    extern fn bignum_modinv(
        k: u64,
        z: *[4]u64,
        a: *const [4]u64,
        b: *const [4]u64,
        t: *[12]u64,
    ) callconv(.c) void;
};

/// Which of s2n-bignum's two forms of a routine to run.
pub const Form = enum { fast, alt };

/// What the CPU said, once asked: 0 not yet, else 1 + @intFromEnum(Form).
/// Shards may ask at once; they store the same answer.
var form_known = std.atomic.Value(u8).init(0);

/// The fast form where the CPU has BMI2 and ADX. Asked once, not per call:
/// in a virtual machine `cpuid` traps to the hypervisor.
pub fn form() Form {
    if (comptime builtin.cpu.hasAll(.x86, &.{ .adx, .bmi2 })) return .fast;
    const known = form_known.load(.monotonic);
    if (known != 0) return @fromBackingInt(@intCast(known - 1));
    const answer: Form = if (cpu_has_adx_bmi2()) .fast else .alt;
    form_known.store(1 + @as(u8, @backingInt(answer)), .monotonic);
    return answer;
}

fn cpu_has_adx_bmi2() bool {
    const leaf_max = cpuid(0).eax;
    if (leaf_max < 7) return false;
    const features = cpuid(7).ebx;
    const bmi2 = features & (1 << 8) != 0;
    const adx = features & (1 << 19) != 0;
    return bmi2 and adx;
}

fn cpuid(leaf: u32) struct { eax: u32, ebx: u32 } {
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
    return .{ .eax = eax, .ebx = ebx };
}

// --- X25519 -----------------------------------------------------------------

/// std's `X25519.KeyPair.generateDeterministic`: the seed is the secret key.
pub fn x25519_key_pair(seed: [32]u8) X25519.KeyPair {
    return .{ .secret_key = seed, .public_key = x25519_public_key(form(), seed) };
}

fn x25519_public_key(f: Form, secret_key: [32]u8) [32]u8 {
    var public_key: [32]u8 = undefined;
    switch (f) {
        .fast => s2n.curve25519_x25519base_byte(&public_key, &secret_key),
        .alt => s2n.curve25519_x25519base_byte_alt(&public_key, &secret_key),
    }
    // A clamped scalar is 8m with 2^251 <= m < 2^252 < l, the base point's
    // prime order: never a multiple of l, so never the identity.
    assert(!all_zero(&public_key));
    return public_key;
}

/// std's `X25519.scalarmult`: RFC 7748's X25519, refusing the all-zero
/// result a low-order public key gives (RFC 8446, 7.4.2).
pub fn x25519_shared(
    secret_key: [32]u8,
    public_key: [32]u8,
) IdentityElementError![32]u8 {
    return x25519_shared_in(form(), secret_key, public_key);
}

fn x25519_shared_in(
    f: Form,
    secret_key: [32]u8,
    public_key: [32]u8,
) IdentityElementError![32]u8 {
    var shared: [32]u8 = undefined;
    switch (f) {
        .fast => s2n.curve25519_x25519_byte(&shared, &secret_key, &public_key),
        .alt => s2n.curve25519_x25519_byte_alt(&shared, &secret_key, &public_key),
    }
    if (all_zero(&shared)) return error.IdentityElement;
    return shared;
}

/// Every byte read whatever they hold: the time says nothing of a secret.
fn all_zero(bytes: []const u8) bool {
    var any: u8 = 0;
    for (bytes) |byte| any |= byte;
    return any == 0;
}

// --- P-256 ------------------------------------------------------------------

/// `p256_scalarmulbase`'s table: for each block i (blocksize·i <= 256) and
/// 1 <= j <= 2^(blocksize-1), the point 2^(blocksize·i)·j·G, affine, each
/// coordinate in Montgomery form. 5 bits a block: 52 KiB, k·G in 9 µs on
/// one machine; 4 was 33 KiB and slower, 6 and 7 larger for little (measured).
pub const p256_table_blocksize = 5;
const p256_table_points = 1 << (p256_table_blocksize - 1);
const p256_table_blocks = 256 / p256_table_blocksize + 1;
pub const p256_table_words = 8 * p256_table_points * p256_table_blocks;
pub const p256_table_bytes = 8 * p256_table_words;

/// Built by `zig build curves-table` (p256_table_build), checked by a test.
const p256_table: [p256_table_words]u64 = table: {
    const file = @embedFile("curves_p256_base.bin");
    assert(file.len == p256_table_bytes);
    const bytes: [p256_table_bytes]u8 = file.*;
    break :table @bitCast(bytes);
};

/// A point's affine coordinates, each big-endian, as std encodes them.
pub const Affine = struct { x: [32]u8, y: [32]u8 };

/// k·G for the scalar k (big-endian); the identity, which s2n-bignum gives
/// for k ≡ 0 (mod n) as (0, 0), is an error, as std's `mul` makes it.
pub fn p256_base_mul(f: Form, k: [32]u8) IdentityElementError!Affine {
    const scalar = limbs_from_big(k);
    var point: [8]u64 = undefined;
    switch (f) {
        .fast => s2n.p256_scalarmulbase(&point, &scalar, p256_table_blocksize, &p256_table),
        .alt => s2n.p256_scalarmulbase_alt(&point, &scalar, p256_table_blocksize, &p256_table),
    }
    const affine: Affine = .{
        .x = big_from_limbs(point[0..4].*),
        .y = big_from_limbs(point[4..8].*),
    };
    if (all_zero(&affine.x) and all_zero(&affine.y)) return error.IdentityElement;
    return affine;
}

/// The table `p256_base_mul` reads, from std's P-256: for the tool that
/// writes the file and the test that checks it.
pub fn p256_table_build(f: Form, table: *[p256_table_words]u64) void {
    var block_base = P256.basePoint;
    for (0..p256_table_blocks) |block| {
        var multiple = block_base;
        for (0..p256_table_points) |point| {
            const at = 8 * (p256_table_points * block + point);
            const affine = multiple.affineCoordinates();
            to_montgomery(f, table[at..][0..4], limbs_from_big(affine.x.toBytes(.big)));
            to_montgomery(f, table[at + 4 ..][0..4], limbs_from_big(affine.y.toBytes(.big)));
            multiple = multiple.add(block_base);
        }
        for (0..p256_table_blocksize) |_| block_base = block_base.dbl();
    }
    assert(table[0] != 0);
    assert(table[p256_table_words - 1] != 0);
}

fn to_montgomery(f: Form, out: *[4]u64, x: [4]u64) void {
    switch (f) {
        .fast => s2n.bignum_tomont_p256(out, &x),
        .alt => s2n.bignum_tomont_p256_alt(out, &x),
    }
}

/// n, the order of P-256's base point, as s2n-bignum's words.
const p256_order: [4]u64 = order: {
    const n: u256 = P256.scalar.field_order;
    break :order .{ @truncate(n), @truncate(n >> 64), @truncate(n >> 128), @truncate(n >> 192) };
};

/// k⁻¹ (mod n), in constant time; k is never zero (a nonce).
fn scalar_invert(k: Scalar) Scalar {
    assert(!k.isZero());
    var inverse: [4]u64 = undefined;
    var scratch: [12]u64 = undefined;
    s2n.bignum_modinv(4, &inverse, &limbs_from_big(k.toBytes(.big)), &p256_order, &scratch);
    const result = Scalar.fromBytes(big_from_limbs(inverse), .big) catch unreachable;
    assert(!result.isZero());
    return result;
}

/// tls.zig's ECDSA P-256 signer: std's `Ecdsa.Signer`, with k·G and k⁻¹
/// on s2n-bignum. Deterministic, as tls.zig asks of std (no noise).
pub const P256Signer = struct {
    /// Named as std's: tls.zig sets it for TLS 1.2.
    h: Sha256,
    secret_key: Ecdsa.SecretKey,

    pub fn init(key_pair: Ecdsa.KeyPair) P256Signer {
        return .{ .h = Sha256.init(.{}), .secret_key = key_pair.secret_key };
    }

    pub fn update(signer: *P256Signer, data: []const u8) void {
        signer.h.update(data);
    }

    pub fn finalize(
        signer: *P256Signer,
    ) (IdentityElementError || NonCanonicalError)!Ecdsa.Signature {
        var digest: [Sha256.digest_length]u8 = undefined;
        signer.h.final(&digest);
        return sign_digest(form(), signer.secret_key, digest);
    }
};

/// std's `Signer.finalizePrehashed` for P-256 and SHA-256, k·G and k⁻¹ ours.
fn sign_digest(
    f: Form,
    secret_key: Ecdsa.SecretKey,
    digest: [Sha256.digest_length]u8,
) (IdentityElementError || NonCanonicalError)!Ecdsa.Signature {
    const z = reduce_to_scalar(digest);
    const k = nonce(digest, secret_key.bytes);
    const point = try p256_base_mul(f, k.toBytes(.big));
    const r = reduce_to_scalar(point.x);
    if (r.isZero()) return error.IdentityElement;
    const d = try Scalar.fromBytes(secret_key.bytes, .big);
    const s = scalar_invert(k).mul(z.add(r.mul(d)));
    if (s.isZero()) return error.IdentityElement;
    return .{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
}

/// std's `reduceToScalar` for 32 bytes: a coordinate or digest, mod n.
fn reduce_to_scalar(bytes: [32]u8) Scalar {
    var wide: [48]u8 = @splat(0);
    @memcpy(wide[16..], &bytes);
    return Scalar.fromBytes48(wide, .big);
}

/// std's `deterministicScalar` with no noise: the nonce from the digest and
/// the key ("Deterministic ECDSA and EdDSA Signatures with Additional
/// Randomness", as std). Bounded where std loops: each try fails with
/// probability under 2^-32.
fn nonce(digest: [32]u8, secret_key: [32]u8) Scalar {
    const tries_max = 64;
    var key: [32]u8 = @splat(0);
    // v, i, the noise (zero), the secret key, the digest.
    var m: [32 + 1 + 32 + 32 + 32]u8 = @splat(0);
    const v = m[0..32];
    const i = &m[32];
    @memset(v, 0x01);
    @memcpy(m[65..97], &secret_key);
    @memcpy(m[97..129], &digest);
    HmacSha256.create(&key, &m, &key);
    HmacSha256.create(v, v, &key);
    i.* = 0x01;
    HmacSha256.create(&key, &m, &key);
    HmacSha256.create(v, v, &key);
    for (0..tries_max) |_| {
        HmacSha256.create(v, v, &key);
        if (Scalar.fromBytes(v.*, .big)) |k| return k else |_| {}
        i.* = 0x00;
        HmacSha256.create(&key, m[0..33], &key);
        HmacSha256.create(v, v, &key);
    }
    @panic("ECDSA nonce: 64 tries out of range");
}

/// s2n-bignum's numbers: four 64-bit words, least significant first.
fn limbs_from_big(bytes: [32]u8) [4]u64 {
    var limbs: [4]u64 = undefined;
    for (&limbs, 0..) |*limb, index| {
        limb.* = std.mem.readInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], .big);
    }
    return limbs;
}

fn big_from_limbs(limbs: [4]u64) [32]u8 {
    var bytes: [32]u8 = undefined;
    for (limbs, 0..) |limb, index| {
        std.mem.writeInt(u64, bytes[32 - 8 * (index + 1) ..][0..8], limb, .big);
    }
    return bytes;
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;
const forms = [_]Form{ .fast, .alt };

/// Test inputs: SHA-256 of a label and a counter, the same every run.
fn input(label: []const u8, index: u32) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(label);
    var counter: [4]u8 = undefined;
    std.mem.writeInt(u32, &counter, index, .little);
    hash.update(&counter);
    return hash.finalResult();
}

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var bytes: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable;
    return bytes;
}

test "curves: the CPU's form is asked once and kept" {
    const first = form();
    try testing.expectEqual(first, form());
    try testing.expect(form_known.load(.monotonic) != 0 or
        comptime builtin.cpu.hasAll(.x86, &.{ .adx, .bmi2 }));
}

test "curves: X25519, RFC 7748's vectors (5.2, 6.1), both forms" {
    const vectors = [_]struct { k: [32]u8, u: [32]u8, out: [32]u8 }{
        .{
            .k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            .u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            .out = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        },
        .{
            .k = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            .u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            .out = hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        },
    };
    const alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    for (forms) |f| {
        for (vectors) |vector| {
            try testing.expectEqual(vector.out, try x25519_shared_in(f, vector.k, vector.u));
        }
        try testing.expectEqual(alice_public, x25519_public_key(f, alice));
        try testing.expectEqual(bob_public, x25519_public_key(f, bob));
        try testing.expectEqual(shared, try x25519_shared_in(f, alice, bob_public));
        try testing.expectEqual(shared, try x25519_shared_in(f, bob, alice_public));
    }
}

test "curves: X25519 equals std's, the public key's top bit set or not" {
    for (0..16) |index| {
        const secret_key = input("x25519 secret", @intCast(index));
        var public_key = input("x25519 public", @intCast(index));
        // RFC 7748 ignores the top bit of u: half the inputs set it.
        if (index % 2 == 0) public_key[31] |= 0x80;
        const want_public = X25519.recoverPublicKey(secret_key);
        const want_shared = try X25519.scalarmult(secret_key, public_key);
        for (forms) |f| {
            try testing.expectEqual(want_public, x25519_public_key(f, secret_key));
            try testing.expectEqual(want_shared, try x25519_shared_in(f, secret_key, public_key));
        }
    }
    const pair = x25519_key_pair(input("x25519 pair", 0));
    try testing.expectEqual(X25519.KeyPair.generateDeterministic(input("x25519 pair", 0)), pair);
}

test "curves: X25519 refuses a low-order public key, as std does" {
    const secret_key = input("x25519 low order", 0);
    // 0 and 1, and a point of order 8 (RFC 7748's list, as curve25519.zig's).
    const low_order = [_][32]u8{
        @splat(0),
        hex("0100000000000000000000000000000000000000000000000000000000000000"),
        hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    };
    for (low_order) |public_key| {
        try testing.expectError(error.IdentityElement, X25519.scalarmult(secret_key, public_key));
        try testing.expectError(error.IdentityElement, x25519_shared(secret_key, public_key));
        for (forms) |f| {
            const shared = x25519_shared_in(f, secret_key, public_key);
            try testing.expectError(error.IdentityElement, shared);
        }
    }
}

test "curves: P-256 k·G equals std's; 0 and n are the identity" {
    for (0..12) |index| {
        const k = input("p256 k", @intCast(index));
        const want = (try P256.basePoint.mul(k, .big)).affineCoordinates();
        for (forms) |f| {
            const got = try p256_base_mul(f, k);
            try testing.expectEqual(want.x.toBytes(.big), got.x);
            try testing.expectEqual(want.y.toBytes(.big), got.y);
        }
    }
    const n = big_from_limbs(p256_order);
    var n_minus_1 = n;
    n_minus_1[31] -= 1;
    var one: [32]u8 = @splat(0);
    one[31] = 1;
    const g = P256.basePoint.affineCoordinates();
    const minus_g = P256.basePoint.neg().affineCoordinates();
    for (forms) |f| {
        try testing.expectError(error.IdentityElement, p256_base_mul(f, @splat(0)));
        try testing.expectError(error.IdentityElement, p256_base_mul(f, n));
        try testing.expectEqual(g.x.toBytes(.big), (try p256_base_mul(f, one)).x);
        try testing.expectEqual(minus_g.y.toBytes(.big), (try p256_base_mul(f, n_minus_1)).y);
    }
}

test "curves: the embedded P-256 table holds the points std computes" {
    // Each entry std's 2^(5i)·j·G on its own, for a sample of entries: the
    // whole table, rebuilt, takes 4 s in Debug. In full: `zig build
    // curves-table` must leave `git diff` clean (vendor/s2n-bignum).
    const n: u512 = P256.scalar.field_order;
    for (0..20) |sample| {
        const digest = input("p256 table", @intCast(sample));
        // The first block and the last always, the rest at random.
        const block: u32 = switch (sample) {
            0 => 0,
            1 => p256_table_blocks - 1,
            else => digest[0] % p256_table_blocks,
        };
        const point: u32 = digest[1] % p256_table_points;
        const shift: u9 = @intCast(p256_table_blocksize * block);
        const k: u256 = @intCast(((@as(u512, point) + 1) << shift) % n);
        var k_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &k_bytes, k, .big);
        const affine = (try P256.basePoint.mul(k_bytes, .big)).affineCoordinates();
        const at = 8 * (p256_table_points * block + point);
        var x: [4]u64 = undefined;
        var y: [4]u64 = undefined;
        to_montgomery(form(), &x, limbs_from_big(affine.x.toBytes(.big)));
        to_montgomery(form(), &y, limbs_from_big(affine.y.toBytes(.big)));
        try testing.expectEqualSlices(u64, &x, p256_table[at..][0..4]);
        try testing.expectEqualSlices(u64, &y, p256_table[at + 4 ..][0..4]);
    }
}

test "curves: k⁻¹ mod n equals std's" {
    for (0..32) |index| {
        const wide = @as([16]u8, @splat(0)) ++ input("p256 inverse", @intCast(index));
        const k = Scalar.fromBytes48(wide, .big);
        try testing.expectEqual(k.invert().toBytes(.big), scalar_invert(k).toBytes(.big));
    }
    try testing.expectEqual(Scalar.one.toBytes(.big), scalar_invert(Scalar.one).toBytes(.big));
}

test "curves: a P-256 signature is std's, byte for byte, and std verifies it" {
    for (0..4) |index| {
        const seed = input("p256 key", @intCast(index));
        const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
        const message = input("p256 message", @intCast(index));
        var want_signer = try key_pair.signer(null);
        want_signer.update(&message);
        const want = try want_signer.finalize();
        for (forms) |f| {
            var signer = P256Signer.init(key_pair);
            signer.update(message[0..10]);
            signer.update(message[10..]);
            var digest: [32]u8 = undefined;
            signer.h.final(&digest);
            const got = try sign_digest(f, key_pair.secret_key, digest);
            try testing.expectEqual(want.r, got.r);
            try testing.expectEqual(want.s, got.s);
            try got.verify(&message, key_pair.public_key);
        }
    }
    // The public path, with the CPU's form.
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(input("p256 key", 99));
    var signer = P256Signer.init(key_pair);
    signer.update("the server's CertificateVerify");
    const signature = try signer.finalize();
    try signature.verify("the server's CertificateVerify", key_pair.public_key);
}
