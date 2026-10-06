//! DER, the little of it ACME needs: a certificate signing request and a
//! SEC1 private key (acme.zig). Written into a caller's fixed buffer; a
//! value that would not fit is an error, never a reallocation.
//!
//! A constructed value (SEQUENCE, SET, context tags) is written by opening
//! it, writing its contents, and closing it: `close` moves the contents up
//! to make room for the length it now knows. Nesting is bounded.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{DerTooLarge};

pub const Tag = enum(u8) {
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    null = 0x05,
    object_identifier = 0x06,
    utf8_string = 0x0c,
    sequence = 0x30,
    set = 0x31,
    _,

    /// `[n]` constructed, as `[0] EXPLICIT` and CSR attributes use.
    pub fn context_constructed(n: u5) Tag {
        return @fromBackingInt(@as(u8, 0xa0) | n);
    }

    /// `[n]` primitive, as GeneralName's `iPAddress [7]` and `dNSName [2]`.
    pub fn context_primitive(n: u5) Tag {
        return @fromBackingInt(@as(u8, 0x80) | n);
    }
};

/// Nesting deep enough for a CSR (six levels), with room to spare.
const depth_max = 16;

pub const Writer = struct {
    buffer: []u8,
    end: u32 = 0,
    /// Where each open constructed value's contents start.
    open: [depth_max]u32 = undefined,
    depth: u32 = 0,

    pub fn init(buffer: []u8) Writer {
        assert(buffer.len > 0);
        assert(buffer.len <= std.math.maxInt(u32));
        return .{ .buffer = buffer };
    }

    /// The finished encoding: every constructed value closed.
    pub fn bytes(writer: *const Writer) []const u8 {
        assert(writer.depth == 0);
        return writer.buffer[0..writer.end];
    }

    pub fn begin(writer: *Writer, tag: Tag) Error!void {
        assert(writer.depth < depth_max);
        try writer.put(&.{@backingInt(tag)});
        writer.open[writer.depth] = writer.end;
        writer.depth += 1;
    }

    /// Inserts the length in front of the contents written since `begin`.
    pub fn end_value(writer: *Writer) Error!void {
        assert(writer.depth > 0);
        writer.depth -= 1;
        const start = writer.open[writer.depth];
        assert(start <= writer.end);
        const contents_len = writer.end - start;
        var length: [5]u8 = undefined;
        const length_bytes = encode_length(contents_len, &length);
        if (writer.end + length_bytes.len > writer.buffer.len) return error.DerTooLarge;
        const contents = writer.buffer[start..writer.end];
        const shifted = writer.buffer[start + length_bytes.len ..][0..contents.len];
        std.mem.copyBackwards(u8, shifted, contents);
        @memcpy(writer.buffer[start..][0..length_bytes.len], length_bytes);
        writer.end += @intCast(length_bytes.len);
    }

    /// A primitive value whole: tag, length, contents.
    pub fn value(writer: *Writer, tag: Tag, contents: []const u8) Error!void {
        var length: [5]u8 = undefined;
        try writer.put(&.{@backingInt(tag)});
        try writer.put(encode_length(@intCast(contents.len), &length));
        try writer.put(contents);
    }

    /// A BIT STRING of whole bytes (no unused bits).
    pub fn bit_string(writer: *Writer, contents: []const u8) Error!void {
        try writer.begin(.bit_string);
        try writer.put(&.{0});
        try writer.put(contents);
        try writer.end_value();
    }

    /// A non-negative INTEGER from a small value.
    pub fn small_integer(writer: *Writer, n: u7) Error!void {
        try writer.value(.integer, &.{n});
    }

    /// Bytes already DER (an OID's encoding, a nested structure).
    pub fn raw(writer: *Writer, encoded: []const u8) Error!void {
        try writer.put(encoded);
    }

    fn put(writer: *Writer, data: []const u8) Error!void {
        if (writer.end + data.len > writer.buffer.len) return error.DerTooLarge;
        @memcpy(writer.buffer[writer.end..][0..data.len], data);
        writer.end += @intCast(data.len);
    }
};

/// Definite-form length: short below 128, else 0x80 | the byte count.
fn encode_length(len: u32, out: *[5]u8) []const u8 {
    if (len < 0x80) {
        out[0] = @intCast(len);
        return out[0..1];
    }
    var count: u8 = 0;
    var rest = len;
    while (rest > 0) : (rest >>= 8) count += 1;
    assert(count >= 1 and count <= 4);
    out[0] = 0x80 | count;
    for (0..count) |i| {
        const shift: u5 = @intCast(8 * (count - 1 - i));
        out[1 + i] = @truncate(len >> shift);
    }
    return out[0 .. 1 + count];
}

/// Object identifiers ACME uses, already DER-encoded (tag and length).
pub const oid = struct {
    pub const ec_public_key = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    pub const prime256v1 = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    pub const ecdsa_with_sha256 = [_]u8{
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    };
    pub const extension_request = [_]u8{
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
    };
    pub const subject_alt_name = [_]u8{ 0x06, 0x03, 0x55, 0x1d, 0x11 };
};

test "der: lengths, short and long" {
    var out: [5]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{0x05}, encode_length(5, &out));
    try std.testing.expectEqualSlices(u8, &.{0x7f}, encode_length(127, &out));
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0x80 }, encode_length(128, &out));
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0x01, 0x00 }, encode_length(256, &out));
}

test "der: nested values, and a contents longer than 127 bytes" {
    var buffer: [512]u8 = undefined;
    var writer = Writer.init(&buffer);
    try writer.begin(.sequence);
    try writer.small_integer(0);
    try writer.begin(.sequence);
    const filler: [200]u8 = @splat(0xab);
    try writer.value(.octet_string, &filler);
    try writer.end_value();
    try writer.end_value();
    const encoded = writer.bytes();
    // SEQUENCE(209) { INTEGER 0, SEQUENCE(203) { OCTET STRING(200) } }
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x81, 0xd1, 0x02, 0x01, 0x00 }, encoded[0..6]);
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x81, 0xcb, 0x04, 0x81, 0xc8 }, encoded[6..12]);
    try std.testing.expectEqual(@as(usize, 3 + 0xd1), encoded.len);
}

test "der: a value that does not fit is refused" {
    var buffer: [8]u8 = undefined;
    var writer = Writer.init(&buffer);
    try std.testing.expectError(error.DerTooLarge, writer.value(.octet_string, "0123456789"));
}
