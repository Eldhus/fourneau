//! HTTP/1.1 response heads (RFC 9112 §4, §6; RFC 9110 §15): serialised
//! into a caller's buffer.
//!
//! The server owns the framing: `Date`, `Content-Length` or
//! `Transfer-Encoding`, and `Connection`; and, on HTTPS, the transport's
//! policy: `Strict-Transport-Security`. An application header with one
//! of those names, or with a name or value that could break the framing
//! (CR, LF, NUL: header injection), is refused, never cleaned up: the
//! caller answers 500 instead, and the application's bug is visible.

const std = @import("std");
const stdx = @import("stdx.zig");
const http_date = @import("http_date.zig");
const Prng = @import("prng.zig").Prng;
const assert = std.debug.assert;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Framing = union(enum) {
    /// A body of exactly this many bytes follows (zero is a body too).
    length: u64,
    /// A body in chunks follows, its end unknown yet (a stream).
    chunked,
    /// No body, and no length: 1xx, 204 and 304 (RFC 9110 §6.4.1).
    none,
};

pub const Head = struct {
    status: u16,
    headers: []const Header,
    framing: Framing,
    /// False closes the connection after this response.
    keep_alive: bool,
    date: *const [http_date.length]u8,
    /// The connection is HTTPS: the head says to keep to it
    /// (`Strict-Transport-Security`). Never on plain HTTP, where a client
    /// must ignore it (RFC 6797 §7.2, §8.1).
    secure: bool,
};

/// HTTPS only, for a year, on every response over TLS. The server's own:
/// one policy for the whole site, whatever the application answers. No
/// `includeSubDomains`: a server speaks for its own host, not its
/// siblings (fourneau.y2kbugger.com must not bind y2kbugger.com's
/// others). Browsers ignore it for an IP address (RFC 6797 §8.1.1).
pub const strict_transport_security = "max-age=31536000";
const strict_transport_security_line =
    "Strict-Transport-Security: " ++ strict_transport_security ++ "\r\n";

pub const Refusal = enum {
    status_invalid,
    header_name_invalid,
    header_value_invalid,
    /// A header the server writes itself (framing, connection, date).
    header_reserved,
    /// A body (or a length) where the status forbids one, or none where it
    /// requires a length.
    framing_invalid,
    /// The head does not fit the buffer.
    too_large,
};

pub const Result = union(enum) {
    bytes: u32,
    refusal: Refusal,
};

pub fn write(buffer: []u8, head: Head) Result {
    if (head.status < 100 or head.status > 999) return .{ .refusal = .status_invalid };
    if (status_forbids_body(head.status) != (head.framing == .none)) {
        return .{ .refusal = .framing_invalid };
    }
    for (head.headers) |header| {
        if (header_refusal(header)) |refusal| return .{ .refusal = refusal };
    }
    var writer: Writer = .{ .buffer = buffer };
    if (status_line(head.status)) |line| {
        writer.text(line);
    } else {
        writer.text("HTTP/1.1 ");
        writer.number(head.status);
        writer.text(" \r\n");
    }
    writer.text("Date: ");
    writer.text(head.date);
    writer.text("\r\n");
    switch (head.framing) {
        .length => |length| {
            writer.text("Content-Length: ");
            writer.number(length);
            writer.text("\r\n");
        },
        .chunked => writer.text("Transfer-Encoding: chunked\r\n"),
        .none => {},
    }
    if (!head.keep_alive) writer.text("Connection: close\r\n");
    if (head.secure) writer.text(strict_transport_security_line);
    for (head.headers) |header| {
        writer.text(header.name);
        writer.text(": ");
        writer.text(header.value);
        writer.text("\r\n");
    }
    writer.text("\r\n");
    if (writer.overflow) return .{ .refusal = .too_large };
    assert(writer.used <= buffer.len);
    assert(std.mem.endsWith(u8, buffer[0..writer.used], "\r\n\r\n"));
    return .{ .bytes = @intCast(writer.used) };
}

// --- chunks (RFC 9112 §7.1): a streamed body ---------------------------------

/// The longest chunk size line: 16 hex digits (a u64) and CRLF.
pub const chunk_size_line_bytes_max = 16 + 2;
/// What follows a chunk's data.
pub const chunk_tail = "\r\n";
/// The last chunk, with no trailer section: the end of a streamed body.
pub const chunk_last = "0\r\n\r\n";

/// A chunk's size line: lowercase hex, no extensions, no leading zeros.
/// Zero is the last chunk and never a size line: a data chunk is not empty.
pub fn chunk_size_line(buffer: *[chunk_size_line_bytes_max]u8, size: u64) []const u8 {
    assert(size > 0);
    const digits = "0123456789abcdef";
    var index: usize = chunk_size_line_bytes_max - 2;
    var rest = size;
    for (0..16) |_| {
        index -= 1;
        buffer[index] = digits[@intCast(rest & 0xf)];
        rest >>= 4;
        if (rest == 0) break;
    } else unreachable; // a u64 has at most 16 hex digits
    buffer[chunk_size_line_bytes_max - 2 ..][0..2].* = "\r\n".*;
    const line = buffer[index..];
    assert(line.len >= 3);
    assert(line[0] != '0');
    return line;
}

test "http1: response: chunk size lines" {
    var buffer: [chunk_size_line_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("1\r\n", chunk_size_line(&buffer, 1));
    try testing.expectEqualStrings("3a\r\n", chunk_size_line(&buffer, 58));
    try testing.expectEqualStrings("1000\r\n", chunk_size_line(&buffer, 4096));
    try testing.expectEqualStrings(
        "ffffffffffffffff\r\n",
        chunk_size_line(&buffer, std.math.maxInt(u64)),
    );
    // Every size reads back as itself, through the strict parse a client does.
    var prng = Prng.init(1);
    for (0..1000) |_| {
        const size = prng.next() >> @intCast(prng.int_less_than(u64, 64)) | 1;
        const line = chunk_size_line(&buffer, size);
        const parsed = try std.fmt.parseInt(u64, line[0 .. line.len - 2], 16);
        try testing.expectEqual(size, parsed);
    }
}

/// 1xx, 204 No Content and 304 Not Modified carry no body (RFC 9110
/// §15.2, §15.3.5, §15.4.5).
pub fn status_forbids_body(status: u16) bool {
    return status < 200 or status == 204 or status == 304;
}

const reserved_names = [_][]const u8{
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "date",
    "strict-transport-security",
};

/// An application's header the server will not send (HTTP/2's heads too).
pub fn header_refusal(header: Header) ?Refusal {
    if (header.name.len == 0) return .header_name_invalid;
    // Tables, not comparisons: this runs for every header of every response.
    for (header.name) |byte| {
        if (!token_table[byte]) return .header_name_invalid;
    }
    for (header.value) |byte| {
        if (!value_table[byte]) return .header_value_invalid;
    }
    // Surrounding whitespace would be stripped by the client: the value
    // would not be what the application meant.
    if (header.value.len > 0) {
        const first = header.value[0];
        const last = header.value[header.value.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') {
            return .header_value_invalid;
        }
    }
    // Every reserved name starts with one of these letters: most headers
    // (Content-Type, Cache-Control, ...) skip the comparisons on the second.
    const first = stdx.lower(header.name[0]);
    if (!reserved_first_table[first]) return null;
    for (reserved_names) |name| {
        if (stdx.equal_ignoring_case(header.name, name)) return .header_reserved;
    }
    return null;
}

/// tchar (RFC 9110 §5.6.2).
const token_table = table: {
    var table: [256]bool = @splat(false);
    for ("!#$%&'*+-.^_`|~") |byte| table[byte] = true;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    break :table table;
};

/// A response field value: tab, and visible bytes; no CR, LF, NUL or DEL.
const value_table = table: {
    var table: [256]bool = @splat(false);
    table['\t'] = true;
    for (0x20..0x100) |byte| table[byte] = byte != 0x7f;
    break :table table;
};

const reserved_first_table = table: {
    var table: [256]bool = @splat(false);
    for (reserved_names) |name| table[name[0]] = true;
    break :table table;
};

/// The reason phrase: informative only (clients ignore it), so unknown
/// codes get none, which the grammar allows.
fn reason(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        else => "",
    };
}

/// Appends to a fixed buffer; past its end it only records the overflow,
/// so the caller checks once.
const Writer = struct {
    buffer: []u8,
    used: usize = 0,
    overflow: bool = false,

    fn text(writer: *Writer, bytes: []const u8) void {
        if (writer.overflow or writer.buffer.len - writer.used < bytes.len) {
            writer.overflow = true;
            return;
        }
        @memcpy(writer.buffer[writer.used..][0..bytes.len], bytes);
        writer.used += bytes.len;
    }

    /// Decimal digits, written backwards into a small buffer: no `std.fmt`
    /// on the hot path (it was 3% of a pipelined profile, 2026-10-05).
    fn number(writer: *Writer, value: u64) void {
        var digits: [20]u8 = undefined;
        var index: usize = digits.len;
        var rest = value;
        for (0..digits.len) |_| {
            index -= 1;
            digits[index] = '0' + @as(u8, @intCast(rest % 10));
            rest /= 10;
            if (rest == 0) break;
        } else unreachable; // a u64 has at most 20 digits
        writer.text(digits[index..]);
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;
const test_date = "Sun, 06 Nov 1994 08:49:37 GMT";

fn expect_written(expected: []const u8, head: Head) !void {
    var buffer: [512]u8 = undefined;
    const result = write(&buffer, head);
    if (result != .bytes) {
        std.debug.print("expected bytes, got {any}\n", .{result});
        return error.TestUnexpectedResult;
    }
    try testing.expectEqualStrings(expected, buffer[0..result.bytes]);
}

fn expect_refused(expected: Refusal, head: Head) !void {
    var buffer: [512]u8 = undefined;
    const result = write(&buffer, head);
    try testing.expect(result == .refusal);
    try testing.expectEqual(expected, result.refusal);
}

test "http1: response: a simple response" {
    try expect_written(
        "HTTP/1.1 200 OK\r\nDate: " ++ test_date ++ "\r\nContent-Length: 5\r\n" ++
            "Content-Type: text/plain\r\n\r\n",
        .{
            .status = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .framing = .{ .length = 5 },
            .keep_alive = true,
            .date = test_date,
            .secure = false,
        },
    );
}

test "http1: response: closing, chunked, no body, unknown status" {
    try expect_written(
        "HTTP/1.1 404 Not Found\r\nDate: " ++ test_date ++ "\r\nContent-Length: 0\r\n" ++
            "Connection: close\r\n\r\n",
        bare(404, .{ .length = 0 }, false),
    );
    try expect_written(
        "HTTP/1.1 200 OK\r\nDate: " ++ test_date ++ "\r\nTransfer-Encoding: chunked\r\n\r\n",
        bare(200, .chunked, true),
    );
    try expect_written(
        "HTTP/1.1 204 No Content\r\nDate: " ++ test_date ++ "\r\n\r\n",
        bare(204, .none, true),
    );
    try expect_written(
        "HTTP/1.1 299 \r\nDate: " ++ test_date ++ "\r\nContent-Length: 0\r\n\r\n",
        bare(299, .{ .length = 0 }, true),
    );
}

test "http1: response: refusals" {
    const ok: Head = .{
        .status = 200,
        .headers = &.{},
        .framing = .{ .length = 0 },
        .keep_alive = true,
        .date = test_date,
        .secure = false,
    };
    var head = ok;
    head.status = 99;
    try expect_refused(.status_invalid, head);
    head.status = 1000;
    try expect_refused(.status_invalid, head);
    head.status = 204;
    try expect_refused(.framing_invalid, head);
    head.status = 304;
    try expect_refused(.framing_invalid, head);
    head = ok;
    head.framing = .none;
    try expect_refused(.framing_invalid, head);

    const cases = [_]struct { Refusal, Header }{
        .{ .header_name_invalid, .{ .name = "", .value = "v" } },
        .{ .header_name_invalid, .{ .name = "X Y", .value = "v" } },
        .{ .header_name_invalid, .{ .name = "X:", .value = "v" } },
        .{ .header_value_invalid, .{ .name = "X", .value = "a\r\nSet-Cookie: evil" } },
        .{ .header_value_invalid, .{ .name = "X", .value = "a\nb" } },
        .{ .header_value_invalid, .{ .name = "X", .value = "a\x00b" } },
        .{ .header_value_invalid, .{ .name = "X", .value = " padded" } },
        .{ .header_reserved, .{ .name = "content-length", .value = "5" } },
        .{ .header_reserved, .{ .name = "Transfer-Encoding", .value = "chunked" } },
        .{ .header_reserved, .{ .name = "Connection", .value = "close" } },
        .{ .header_reserved, .{ .name = "DATE", .value = "x" } },
    };
    for (cases) |case| {
        head = ok;
        head.headers = &.{case[1]};
        try expect_refused(case[0], head);
    }
}

test "http1: response: HTTPS keeps to HTTPS, and only the server says so" {
    var head = bare(200, .{ .length = 0 }, true);
    head.secure = true;
    try expect_written(
        "HTTP/1.1 200 OK\r\nDate: " ++ test_date ++ "\r\nContent-Length: 0\r\n" ++
            "Strict-Transport-Security: max-age=31536000\r\n\r\n",
        head,
    );
    // Plain HTTP never carries it (RFC 6797 §7.2): see the simple response.
    // An application's own would be a second policy, or a weaker one.
    head.headers = &.{.{ .name = "strict-transport-security", .value = "max-age=0" }};
    try expect_refused(.header_reserved, head);
    head.secure = false;
    try expect_refused(.header_reserved, head);
}

test "http1: response: a head that does not fit is refused" {
    var buffer: [40]u8 = undefined;
    const result = write(&buffer, .{
        .status = 200,
        .headers = &.{},
        .framing = .{ .length = 0 },
        .keep_alive = true,
        .date = test_date,
        .secure = false,
    });
    try testing.expectEqual(Refusal.too_large, result.refusal);
}

fn bare(status: u16, framing: Framing, keep_alive: bool) Head {
    return .{
        .status = status,
        .headers = &.{},
        .framing = framing,
        .keep_alive = keep_alive,
        .date = test_date,
        .secure = false,
    };
}

/// "HTTP/1.1 200 OK\r\n" and the rest, built at compile time for every
/// status a response sends in practice; others are written piecewise.
const status_lines_first = 100;
const status_lines = table: {
    @setEvalBranchQuota(1_000_000);
    var lines: [600 - status_lines_first][]const u8 = undefined;
    for (&lines, status_lines_first..) |*line, status| {
        line.* = std.fmt.comptimePrint("HTTP/1.1 {d} {s}\r\n", .{ status, reason(status) });
    }
    break :table lines;
};

/// The whole status line, or null for 600-999 (allowed by the grammar, sent
/// by nobody), which `write` spells out piecewise.
fn status_line(status: u16) ?[]const u8 {
    assert(status >= 100 and status <= 999);
    if (status >= status_lines_first + status_lines.len) return null;
    return status_lines[status - status_lines_first];
}

test "http1: response: status lines match the piecewise form" {
    for ([_]u16{ 100, 200, 204, 404, 418, 599 }) |status| {
        var expected: [64]u8 = undefined;
        const format = "HTTP/1.1 {d} {s}\r\n";
        const want = try std.fmt.bufPrint(&expected, format, .{ status, reason(status) });
        try testing.expectEqualStrings(want, status_line(status).?);
    }
    try testing.expect(status_line(600) == null);
    try testing.expect(status_line(999) == null);
}
