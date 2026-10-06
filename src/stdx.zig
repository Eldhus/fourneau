//! What `std` lacks, or what we want stricter than `std` (TigerBeetle's
//! stdx, for the same reason): one place to change when `std` moves.

const std = @import("std");
const assert = std.debug.assert;

/// The dual of `assert`: this is sometimes true and sometimes false. It
/// documents that both sides of a branch were thought about.
pub fn maybe(ok: bool) void {
    assert(ok or !ok);
}

/// Copy `source` into the start of `target`, which must not overlap it.
/// `.exact` asserts the lengths are equal; `.inexact` that the target is
/// at least as long. The call site says which.
pub fn copy_disjoint(
    comptime mode: enum { exact, inexact },
    comptime T: type,
    target: []T,
    source: []const T,
) void {
    switch (mode) {
        .exact => assert(target.len == source.len),
        .inexact => assert(target.len >= source.len),
    }
    if (source.len == 0) return;
    const target_start = @intFromPtr(target.ptr);
    const source_start = @intFromPtr(source.ptr);
    const bytes = source.len * @sizeOf(T);
    assert(target_start + bytes <= source_start or source_start + bytes <= target_start);
    @memcpy(target[0..source.len], source);
}

/// ASCII lower case of one byte (header names compare case-insensitively).
pub fn lower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte | 0x20 else byte;
}

/// Case-insensitive equality of ASCII text, as header names compare.
pub fn equal_ignoring_case(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (lower(x) != lower(y)) return false;
    }
    return true;
}

test "stdx: equal_ignoring_case" {
    try std.testing.expect(equal_ignoring_case("Content-Length", "content-length"));
    try std.testing.expect(!equal_ignoring_case("Content-Length", "content-lengt"));
    try std.testing.expect(!equal_ignoring_case("a", "b"));
    // Only ASCII letters fold: '@' (0x40) and '`' (0x60) differ by the same bit.
    try std.testing.expect(!equal_ignoring_case("@", "`"));
    maybe(equal_ignoring_case("a", "A"));
}

test "stdx: copy_disjoint" {
    var target: [4]u8 = undefined;
    copy_disjoint(.exact, u8, &target, "abcd");
    try std.testing.expectEqualStrings("abcd", &target);
    copy_disjoint(.inexact, u8, &target, "xy");
    try std.testing.expectEqualStrings("xycd", &target);
}

/// `text` repeated `count` times, at compile time (Zig 0.17 removed `**`).
pub inline fn repeat(comptime text: []const u8, comptime count: usize) *const [text.len * count]u8 {
    comptime {
        var out: [text.len * count]u8 = undefined;
        for (0..count) |index| @memcpy(out[index * text.len ..][0..text.len], text);
        const result = out;
        return &result;
    }
}

test "stdx: repeat" {
    try std.testing.expectEqualStrings("ababab", repeat("ab", 3));
    try std.testing.expectEqualStrings("", repeat("ab", 0));
}
