//! The chunked transfer coding of request bodies (RFC 9112 §7.1), decoded
//! as a state machine over bytes as they arrive.
//!
//! `decode` takes the bytes received and room for body bytes, and says how
//! many of each it used. Chunk data is copied in bulk; framing is read a
//! byte at a time. Everything is bounded: the body by `body_bytes_max`,
//! chunk extensions (ignored, but read) and trailer fields (read and
//! discarded) by their own byte limits.
//!
//! Strict as the head parser is: CRLF only; the chunk size is hex digits,
//! with whitespace allowed only before a `;` extension (RFC 9112's BWS),
//! never alone at the end of the line, where parsers have disagreed.

const std = @import("std");
const stdx = @import("stdx.zig");
const assert = std.debug.assert;

pub const Limits = struct {
    body_bytes_max: u64,
    /// All chunk extensions of one body, together.
    extension_bytes_max: u32,
    /// The trailer section, together.
    trailer_bytes_max: u32,
};

pub const Refusal = enum {
    bad_request,
    content_too_large,

    pub fn status(refusal: Refusal) u16 {
        return switch (refusal) {
            .bad_request => 400,
            .content_too_large => 413,
        };
    }
};

pub const Progress = struct {
    /// Input bytes used.
    consumed: u32,
    /// Body bytes written to the output.
    produced: u32,
    /// The last chunk and the trailer section have been read: the body is
    /// complete, and any input after `consumed` is the next request.
    done: bool,
};

pub const Result = union(enum) {
    progress: Progress,
    refusal: Refusal,
};

const State = enum {
    /// The first hex digit of a chunk size.
    size_first,
    /// More hex digits, or what ends them.
    size,
    /// Whitespace after the size: only a `;` may follow.
    size_whitespace,
    /// Inside a chunk extension, up to CR.
    extension,
    size_lf,
    data,
    data_cr,
    data_lf,
    /// The start of a trailer line, or the CR of the final empty line.
    trailer_start,
    trailer,
    trailer_lf,
    end_lf,
    done,
};

/// Hex digits in a chunk size, leading zeros included: more is refused.
const size_digits_max = 16;

pub const Decoder = struct {
    limits: Limits,
    state: State = .size_first,
    /// The size being read, or the bytes left in the current chunk.
    chunk_bytes: u64 = 0,
    size_digits: u8 = 0,
    body_bytes: u64 = 0,
    extension_bytes: u32 = 0,
    trailer_bytes: u32 = 0,

    pub fn init(limits: Limits) Decoder {
        assert(limits.body_bytes_max < std.math.maxInt(u64) / 16);
        return .{ .limits = limits };
    }

    pub fn decode(decoder: *Decoder, input: []const u8, output: []u8) Result {
        assert(decoder.state != .done);
        assert(decoder.body_bytes <= decoder.limits.body_bytes_max);
        var consumed: usize = 0;
        var produced: usize = 0;
        // Each pass consumes at least one byte, or stops.
        for (0..input.len + 1) |_| {
            if (consumed == input.len or decoder.state == .done) break;
            if (decoder.state == .data) {
                if (produced == output.len) break;
                const bytes = decoder.copy_data(input[consumed..], output[produced..]);
                consumed += bytes;
                produced += bytes;
                continue;
            }
            if (decoder.step(input[consumed])) |refusal| return .{ .refusal = refusal };
            consumed += 1;
        } else unreachable;
        assert(consumed <= input.len);
        assert(produced <= output.len);
        return .{ .progress = .{
            .consumed = @intCast(consumed),
            .produced = @intCast(produced),
            .done = decoder.state == .done,
        } };
    }

    fn copy_data(decoder: *Decoder, input: []const u8, output: []u8) usize {
        assert(decoder.chunk_bytes > 0);
        const bytes: usize = @intCast(@min(decoder.chunk_bytes, input.len, output.len));
        assert(bytes > 0);
        @memcpy(output[0..bytes], input[0..bytes]);
        decoder.chunk_bytes -= bytes;
        decoder.body_bytes += bytes;
        if (decoder.chunk_bytes == 0) decoder.state = .data_cr;
        return bytes;
    }

    /// One framing byte. Returns a refusal, or null to go on.
    fn step(decoder: *Decoder, byte: u8) ?Refusal {
        switch (decoder.state) {
            .size_first => {
                decoder.chunk_bytes = 0;
                decoder.size_digits = 0;
                return decoder.size_digit(byte) orelse {
                    decoder.state = .size;
                    return null;
                };
            },
            .size => return switch (byte) {
                '\r' => decoder.to(.size_lf),
                ';' => decoder.to(.extension),
                ' ', '\t' => decoder.to(.size_whitespace),
                else => decoder.size_digit(byte),
            },
            .size_whitespace => return switch (byte) {
                ' ', '\t' => null,
                ';' => decoder.to(.extension),
                else => .bad_request,
            },
            .extension => return decoder.extension_byte(byte),
            .size_lf => return if (byte == '\n') decoder.size_done() else .bad_request,
            .data => unreachable, // copied in bulk by `decode`
            .data_cr => return if (byte == '\r') decoder.to(.data_lf) else .bad_request,
            .data_lf => return if (byte == '\n') decoder.to(.size_first) else .bad_request,
            .trailer_start, .trailer, .trailer_lf, .end_lf => return decoder.trailer_byte(byte),
            .done => unreachable,
        }
    }

    fn to(decoder: *Decoder, state: State) ?Refusal {
        decoder.state = state;
        return null;
    }

    fn size_digit(decoder: *Decoder, byte: u8) ?Refusal {
        const digit = std.fmt.charToDigit(byte, 16) catch return .bad_request;
        if (decoder.size_digits == size_digits_max) return .bad_request;
        decoder.size_digits += 1;
        decoder.chunk_bytes = decoder.chunk_bytes * 16 + digit;
        // Refused as soon as it is too large: the bound also keeps the
        // multiplication above from overflowing.
        if (decoder.chunk_bytes > decoder.limits.body_bytes_max - decoder.body_bytes) {
            return .content_too_large;
        }
        return null;
    }

    fn extension_byte(decoder: *Decoder, byte: u8) ?Refusal {
        if (byte == '\r') return decoder.to(.size_lf);
        if (decoder.extension_bytes == decoder.limits.extension_bytes_max) {
            return .content_too_large;
        }
        decoder.extension_bytes += 1;
        // Extensions are ignored, but must be text: no controls but tab.
        const text = byte == '\t' or (byte >= 0x20 and byte != 0x7f);
        return if (text) null else .bad_request;
    }

    /// After a chunk size's CRLF: data, or the trailer section after the
    /// last (zero-sized) chunk.
    fn size_done(decoder: *Decoder) ?Refusal {
        decoder.state = if (decoder.chunk_bytes == 0) .trailer_start else .data;
        return null;
    }

    /// Trailer fields are read and discarded: their bytes are bounded and
    /// each line must be CRLF-terminated text.
    fn trailer_byte(decoder: *Decoder, byte: u8) ?Refusal {
        switch (decoder.state) {
            .trailer_start => switch (byte) {
                '\r' => return decoder.to(.end_lf),
                // A line starting with whitespace is obsolete folding.
                ' ', '\t' => return .bad_request,
                else => {},
            },
            .trailer => if (byte == '\r') return decoder.to(.trailer_lf),
            .trailer_lf => return if (byte == '\n') decoder.to(.trailer_start) else .bad_request,
            .end_lf => return if (byte == '\n') decoder.to(.done) else .bad_request,
            else => unreachable,
        }
        if (decoder.trailer_bytes == decoder.limits.trailer_bytes_max) {
            return .content_too_large;
        }
        decoder.trailer_bytes += 1;
        const text = byte == '\t' or (byte >= 0x20 and byte != 0x7f) or byte >= 0x80;
        if (!text) return .bad_request;
        decoder.state = .trailer;
        return null;
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;

const test_limits: Limits = .{
    .body_bytes_max = 64,
    .extension_bytes_max = 16,
    .trailer_bytes_max = 32,
};

const Decoded = union(enum) {
    /// The body, and how many input bytes the coding took.
    body: struct { bytes: []const u8, consumed: usize },
    incomplete,
    refusal: Refusal,
};

/// Decode `input` with input in `pieces`-sized reads and output room of
/// `room` bytes per call.
fn decode_in(input: []const u8, piece_bytes: usize, room: usize, body: []u8) Decoded {
    var decoder = Decoder.init(test_limits);
    var input_used: usize = 0;
    var body_used: usize = 0;
    var arrived: usize = @min(piece_bytes, input.len);
    for (0..input.len * 4 + 4) |_| {
        const output_end = @min(body.len, body_used + room);
        const result = decoder.decode(input[input_used..arrived], body[body_used..output_end]);
        const progress = switch (result) {
            .refusal => |refusal| return .{ .refusal = refusal },
            .progress => |progress| progress,
        };
        input_used += progress.consumed;
        body_used += progress.produced;
        if (progress.done) {
            return .{ .body = .{ .bytes = body[0..body_used], .consumed = input_used } };
        }
        if (input_used == arrived) {
            if (arrived == input.len) return .incomplete;
            arrived = @min(input.len, arrived + piece_bytes);
        }
    } else unreachable;
}

/// Decode every way (whole, every two-piece     for (1..(input.len, 1)) |split| {
// Two reads, a byte at a time, one
/// byte of output room at a time) and require the same answer.
fn decode_every_way(input: []const u8, body: []u8) Decoded {
    const whole = decode_in(input, input.len, body.len, body);
    var other_body: [128]u8 = undefined;
    const ways = [_][2]usize{ .{ 1, body.len }, .{ input.len, 1 }, .{ 1, 1 } };
    for (ways) |way| {
        assert(decoded_equal(whole, decode_in(input, way[0], way[1], &other_body)));
    }
    for (1..@max(input.len, 1)) |split| {
        // Two reads: the first `split` bytes, then the rest.
        assert(decoded_equal(whole, decode_two(input, split, &other_body)));
    }
    return whole;
}

fn decode_two(input: []const u8, split: usize, body: []u8) Decoded {
    var decoder = Decoder.init(test_limits);
    const first = decoder.decode(input[0..split], body);
    const progress = switch (first) {
        .refusal => |refusal| return .{ .refusal = refusal },
        .progress => |progress| progress,
    };
    if (progress.done) {
        return .{ .body = .{ .bytes = body[0..progress.produced], .consumed = progress.consumed } };
    }
    assert(progress.consumed == split); // nothing is held back
    const second = decoder.decode(input[split..], body[progress.produced..]);
    const rest = switch (second) {
        .refusal => |refusal| return .{ .refusal = refusal },
        .progress => |rest| rest,
    };
    if (!rest.done) return .incomplete;
    return .{ .body = .{
        .bytes = body[0 .. progress.produced + rest.produced],
        .consumed = split + rest.consumed,
    } };
}

fn decoded_equal(a: Decoded, b: Decoded) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .body => |body| std.mem.eql(u8, body.bytes, b.body.bytes) and
            body.consumed == b.body.consumed,
        .incomplete => true,
        .refusal => |refusal| refusal == b.refusal,
    };
}

fn expect_body(expected: []const u8, input: []const u8) !void {
    var body: [128]u8 = undefined;
    const decoded = decode_every_way(input, &body);
    if (decoded != .body) {
        std.debug.print("expected a body, got {any}\n", .{decoded});
        return error.TestUnexpectedResult;
    }
    try testing.expectEqualStrings(expected, decoded.body.bytes);
    try testing.expectEqual(input.len, decoded.body.consumed);
}

fn expect_refusal(expected: Refusal, input: []const u8) !void {
    var body: [128]u8 = undefined;
    const decoded = decode_every_way(input, &body);
    if (decoded != .refusal or decoded.refusal != expected) {
        std.debug.print("expected {s}, got {any}\n", .{ @tagName(expected), decoded });
        return error.TestUnexpectedResult;
    }
}

fn expect_incomplete(input: []const u8) !void {
    var body: [128]u8 = undefined;
    try testing.expect(decode_every_way(input, &body) == .incomplete);
}

test "http1: chunked: bodies" {
    try expect_body("", "0\r\n\r\n");
    try expect_body("", "000\r\n\r\n");
    try expect_body("hello", "5\r\nhello\r\n0\r\n\r\n");
    try expect_body("hello world", "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    try expect_body("0123456789", "A\r\n0123456789\r\n0\r\n\r\n");
    try expect_body("0123456789", "a\r\n0123456789\r\n0\r\n\r\n");
    try expect_body("0123456789", "0a\r\n0123456789\r\n0\r\n\r\n");
    try expect_body("\r\n\r\n", "4\r\n\r\n\r\n\r\n0\r\n\r\n");
}

test "http1: chunked: extensions are read and ignored" {
    try expect_body("a", "1;ext\r\na\r\n0\r\n\r\n");
    try expect_body("a", "1;n=v;x=\"q d\"\r\na\r\n0\r\n\r\n");
    try expect_body("a", "1 ;x\r\na\r\n0\r\n\r\n");
    try expect_body("a", "1\t \t;x\r\na\r\n0\r\n\r\n");
    try expect_body("", "0;last\r\n\r\n");
    try expect_refusal(.bad_request, "1;a\nb\r\na\r\n0\r\n\r\n");
    try expect_refusal(.bad_request, "1;a\x00\r\na\r\n0\r\n\r\n");
    try expect_refusal(.content_too_large, "1;" ++ stdx.repeat("x", 17) ++ "\r\na\r\n0\r\n\r\n");
    _ = try expect_body("a", "1;" ++ stdx.repeat("x", 15) ++ "\r\na\r\n0\r\n\r\n");
}

test "http1: chunked: trailers are read and discarded" {
    try expect_body("a", "1\r\na\r\n0\r\nX-Sum: 1\r\n\r\n");
    try expect_body("a", "1\r\na\r\n0\r\nA: 1\r\nB: 2\r\n\r\n");
    try expect_refusal(.bad_request, "1\r\na\r\n0\r\nA: 1\r\n b\r\n\r\n");
    try expect_refusal(.bad_request, "1\r\na\r\n0\r\nA: 1\n\r\n");
    try expect_refusal(.bad_request, "1\r\na\r\n0\r\nA: \x01\r\n\r\n");
    try expect_refusal(.content_too_large, "0\r\nX: " ++ stdx.repeat("y", 40) ++ "\r\n\r\n");
}

test "http1: chunked: size refusals" {
    // hyper's table, with whitespace alone after the size refused.
    try expect_refusal(.bad_request, "\r\n\r\n");
    try expect_refusal(.bad_request, "X\r\n");
    try expect_refusal(.bad_request, "1X\r\n");
    try expect_refusal(.bad_request, "-1\r\n");
    try expect_refusal(.bad_request, "+1\r\n");
    try expect_refusal(.bad_request, "0x1\r\n");
    try expect_refusal(.bad_request, " 1\r\n");
    try expect_refusal(.bad_request, "1 \r\n");
    try expect_refusal(.bad_request, "1 A\r\n");
    try expect_refusal(.bad_request, "1 invalid extension\r\n");
    try expect_refusal(.bad_request, "F\rF");
    try expect_refusal(.bad_request, "1\na\r\n");
    try expect_refusal(.bad_request, "00000000000000001\r\n");
    try expect_refusal(.content_too_large, "f0000000000000003\r\n");
    try expect_refusal(.content_too_large, "41\r\n");
    try expect_refusal(.content_too_large, "20\r\n" ++ stdx.repeat("x", 32) ++ "\r\n21\r\n");
    try expect_body(stdx.repeat("x", 64), "40\r\n" ++ stdx.repeat("x", 64) ++ "\r\n0\r\n\r\n");
}

test "http1: chunked: data must end in CRLF" {
    try expect_refusal(.bad_request, "1\r\nab\r\n0\r\n\r\n");
    try expect_refusal(.bad_request, "1\r\na\n0\r\n\r\n");
    try expect_refusal(.bad_request, "1\r\na\r0\r\n\r\n");
    try expect_refusal(.bad_request, "0\r\n\r\r");
}

test "http1: chunked: incomplete until the final CRLF" {
    try expect_incomplete("");
    try expect_incomplete("5");
    try expect_incomplete("5\r\nhel");
    try expect_incomplete("5\r\nhello\r\n");
    try expect_incomplete("5\r\nhello\r\n0\r\n");
    try expect_incomplete("5\r\nhello\r\n0\r\nX: 1\r\n");
    try expect_incomplete("0\r\n\r");
}

test "http1: chunked: input after the body is left for the next request" {
    var decoder = Decoder.init(test_limits);
    var body: [8]u8 = undefined;
    const input = "1\r\na\r\n0\r\n\r\nGET / HTTP/1.1\r\n";
    const progress = decoder.decode(input, &body).progress;
    try testing.expect(progress.done);
    try testing.expectEqual(@as(u32, 11), progress.consumed);
    try testing.expectEqual(@as(u32, 1), progress.produced);
    try testing.expectEqual(@as(u16, 413), Refusal.content_too_large.status());
}

test "http1: chunked: every byte value at every position: no crash, sound results" {
    const original = "3;e=1\r\nabc\r\n2\r\nde\r\n0\r\nT: 1\r\n\r\n";
    var bytes: [original.len]u8 = original.*;
    var body: [test_limits.body_bytes_max]u8 = undefined;
    for (0..bytes.len) |position| {
        for (0..256) |value| {
            bytes[position] = @intCast(value);
            var decoder = Decoder.init(test_limits);
            switch (decoder.decode(&bytes, &body)) {
                .progress => |progress| {
                    try testing.expect(progress.consumed <= bytes.len);
                    try testing.expect(progress.produced <= progress.consumed);
                    if (!progress.done) try testing.expectEqual(bytes.len, progress.consumed);
                },
                .refusal => {},
            }
        }
        bytes[position] = original[position];
    }
}

/// Coverage-guided fuzzing: any bytes, decoded whole and in two reads with
/// little output room; nothing crashes and both ways agree.
fn fuzz_chunked(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [256]u8 = undefined;
    const length = smith.slice(&bytes);
    const input = bytes[0..length];
    var body: [128]u8 = undefined;
    var other: [128]u8 = undefined;
    const whole = decode_in(input, input.len, body.len, &body);
    const split = if (length == 0) 0 else smith.value(u32) % length;
    const two = decode_two(input, split, &other);
    try testing.expect(decoded_equal(whole, two));
    switch (whole) {
        .body => |decoded| try testing.expect(decoded.consumed <= input.len),
        .incomplete, .refusal => {},
    }
}

test "http1: chunked: fuzz" {
    try testing.fuzz({}, fuzz_chunked, .{ .corpus = &.{
        "5\r\nhello\r\n0\r\n\r\n",
        "1;ext=1\r\na\r\n0\r\nT: 1\r\n\r\n",
        "0\r\n\r\n",
    } });
}
