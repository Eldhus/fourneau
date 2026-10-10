//! HTTP/1.1 request heads (RFC 9112 §2-§7, RFC 9110 for field semantics):
//! a state machine over the bytes received so far.
//!
//! The connection appends bytes to one buffer and calls `parse` with all
//! of them. The parser resumes after the last complete line it has seen,
//! so a client that sends a byte at a time costs O(n) in total, not O(n²).
//! It returns `incomplete`, a `complete` head (whose slices point into the
//! buffer), or a `refusal`: the status to answer with before closing.
//!
//! The parser is strict wherever leniency is how request smuggling and
//! cache poisoning happen: bare CR or LF line endings, whitespace before a
//! colon, obsolete line folding, `Content-Length` together with
//! `Transfer-Encoding`, duplicate or malformed lengths, transfer codings
//! other than chunked, a missing or duplicated `Host`. Each is refused,
//! never guessed at (RFC 9112 §11.2: "the server MUST respond with 400").

const std = @import("std");
const stdx = @import("stdx.zig");
const assert = std.debug.assert;
const maybe = stdx.maybe;

pub const Limits = struct {
    /// The whole head: request line, fields and the blank line.
    head_bytes_max: u32,
    /// The request target alone (414 beyond it).
    target_bytes_max: u32,
    /// Header fields (431 beyond it).
    headers_max: u16,
    /// A body announced by `Content-Length` beyond this is refused (413);
    /// a chunked body is held to it as it is decoded.
    body_bytes_max: u64,

    pub fn assert_valid(limits: Limits) void {
        assert(limits.target_bytes_max > 0);
        assert(limits.target_bytes_max < limits.head_bytes_max);
        assert(limits.headers_max > 0);
        // Offsets into the head are u32; a head never approaches 4 GiB.
        assert(limits.head_bytes_max <= 1 << 24);
    }
};

/// Why a request is refused: each is answered with its status, then the
/// connection is closed (the stream can no longer be trusted).
pub const Refusal = enum {
    bad_request,
    content_too_large,
    uri_too_long,
    expectation_failed,
    header_fields_too_large,
    not_implemented,
    version_not_supported,

    pub fn status(refusal: Refusal) u16 {
        return switch (refusal) {
            .bad_request => 400,
            .content_too_large => 413,
            .uri_too_long => 414,
            .expectation_failed => 417,
            .header_fields_too_large => 431,
            .not_implemented => 501,
            .version_not_supported => 505,
        };
    }
};

pub const Method = enum { get, head, post, put, delete, options, patch, trace, other };

/// HTTP/2 requests take this head's shape too (the server converts them).
pub const Version = enum { http_1_0, http_1_1, http_2 };

pub const Body = union(enum) {
    none,
    length: u64,
    chunked,
};

/// A header field as received: the name keeps its case; the value has its
/// surrounding whitespace removed.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Head = struct {
    method: Method,
    /// The method as sent (for `other`, the application's to interpret).
    method_text: []const u8,
    /// As sent: origin-form (`/path?query`), absolute-form, or `*`.
    target: []const u8,
    /// The path and query: the target itself in origin-form, its tail in
    /// absolute-form, `*` for `OPTIONS *`.
    path_and_query: []const u8,
    version: Version,
    /// The authority: from an absolute-form target if there is one (RFC
    /// 9112 §3.2.2), else the `Host` field; empty for HTTP/1.0 without one.
    host: []const u8,
    headers: []const Header,
    body: Body,
    /// The connection may serve another request after this one.
    keep_alive: bool,
    /// The client waits for `100 Continue` before sending the body.
    expect_continue: bool,
};

pub const Result = union(enum) {
    incomplete,
    complete: struct { head: Head, head_bytes: u32 },
    refusal: Refusal,
};

/// The parser's state between calls: where the next line starts, and the
/// fields found so far. `headers` is the caller's storage, sized to
/// `limits.headers_max`.
pub const Parser = struct {
    limits: Limits,
    headers: []Header,
    header_count: u16 = 0,
    /// Offset of the first byte not yet consumed as a complete line.
    line_start: u32 = 0,
    /// Set once the request line is parsed.
    request_line: ?RequestLine = null,

    const RequestLine = struct {
        method: Method,
        method_text: []const u8,
        target: []const u8,
        version: Version,
    };

    pub fn init(limits: Limits, headers: []Header) Parser {
        limits.assert_valid();
        assert(headers.len == limits.headers_max);
        return .{ .limits = limits, .headers = headers };
    }

    /// Start over for the next request on the same connection.
    pub fn reset(parser: *Parser) void {
        parser.* = init(parser.limits, parser.headers);
    }

    /// Parse what has arrived. `buffer` holds every byte received for this
    /// request so far and only grows between calls (the same bytes, more of
    /// them), up to `limits.head_bytes_max`.
    pub fn parse(parser: *Parser, buffer: []const u8) Result {
        assert(parser.line_start <= buffer.len);
        const limit = @min(buffer.len, parser.limits.head_bytes_max);
        for (0..parser.limits.head_bytes_max) |_| {
            const line = next_line(buffer[0..limit], parser.line_start) orelse break;
            const line_end = parser.line_start + @as(u32, @intCast(line.len)) + 2;
            switch (parser.take_line(line)) {
                .more => parser.line_start = line_end,
                .done => return parser.finish(buffer[0..line_end]),
                .refusal => |refusal| return .{ .refusal = refusal },
            }
        } else unreachable; // every pass consumes at least two bytes
        return parser.incomplete(buffer[0..limit]);
    }

    const Step = union(enum) { more, done, refusal: Refusal };

    /// Where no complete head fits the limits, say which limit it broke.
    fn incomplete(parser: *const Parser, buffer: []const u8) Result {
        const partial = buffer[parser.line_start..];
        if (std.mem.indexOfScalar(u8, partial, '\n')) |_| {
            return .{ .refusal = .bad_request }; // an LF without its CR
        }
        if (parser.request_line == null) {
            const target_bytes_max = parser.limits.target_bytes_max;
            // A request line longer than any method, target and version.
            if (partial.len > target_bytes_max + request_line_overhead_bytes) {
                return .{ .refusal = .uri_too_long };
            }
        }
        if (buffer.len >= parser.limits.head_bytes_max) {
            return .{ .refusal = .header_fields_too_large };
        }
        return .incomplete;
    }

    fn take_line(parser: *Parser, line: []const u8) Step {
        if (parser.request_line == null) {
            // RFC 9112 §2.2: ignore empty lines before the request line.
            if (line.len == 0) return .more;
            parser.request_line = switch (parse_request_line(line, parser.limits)) {
                .line => |request_line| request_line,
                .refusal => |refusal| return .{ .refusal = refusal },
            };
            return .more;
        }
        if (line.len == 0) return .done;
        if (parser.header_count == parser.limits.headers_max) {
            return .{ .refusal = .header_fields_too_large };
        }
        const header = parse_field(line) orelse return .{ .refusal = .bad_request };
        parser.headers[parser.header_count] = header;
        parser.header_count += 1;
        return .more;
    }

    fn finish(parser: *const Parser, head_bytes: []const u8) Result {
        const request_line = parser.request_line.?;
        const headers = parser.headers[0..parser.header_count];
        const semantics = switch (field_semantics(request_line.version, headers)) {
            .semantics => |semantics| semantics,
            .refusal => |refusal| return .{ .refusal = refusal },
        };
        const target = switch (parse_target(request_line.method, request_line.target)) {
            .target => |target| target,
            .refusal => |refusal| return .{ .refusal = refusal },
        };
        const body = switch (body_framing(request_line.version, semantics, parser.limits)) {
            .body => |body| body,
            .refusal => |refusal| return .{ .refusal = refusal },
        };
        if (request_line.version == .http_1_1 and semantics.host_count == 0) {
            return .{ .refusal = .bad_request }; // RFC 9112 §3.2: MUST be 400
        }
        maybe(semantics.expect_continue);
        return .{ .complete = .{
            .head = .{
                .method = request_line.method,
                .method_text = request_line.method_text,
                .target = request_line.target,
                .path_and_query = target.path_and_query,
                .version = request_line.version,
                .host = target.authority orelse semantics.host,
                .headers = headers,
                .body = body,
                .keep_alive = semantics.keep_alive,
                .expect_continue = semantics.expect_continue and body != .none,
            },
            .head_bytes = @intCast(head_bytes.len),
        } };
    }
};

/// The bytes of a request line besides its target: the longest method we
/// name, two spaces and `HTTP/1.1`. A longer line without an end is a
/// target too long (414), not a head too large (431).
const request_line_overhead_bytes = 32;

/// The line starting at `start`, without its CRLF, if it is complete.
/// A line ends at CRLF only; a bare LF is found by the caller's checks.
fn next_line(buffer: []const u8, start: u32) ?[]const u8 {
    const rest = buffer[start..];
    const lf = std.mem.indexOfScalar(u8, rest, '\n') orelse return null;
    if (lf == 0 or rest[lf - 1] != '\r') return null; // a bare LF: refused later
    return rest[0 .. lf - 1];
}

const RequestLineResult = union(enum) { line: Parser.RequestLine, refusal: Refusal };

/// `method SP request-target SP HTTP-version`, exactly one space apart.
fn parse_request_line(line: []const u8, limits: Limits) RequestLineResult {
    assert(line.len > 0);
    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse
        return .{ .refusal = .bad_request };
    const method_text = line[0..method_end];
    if (method_text.len == 0 or !all_in(method_text, &token_table)) {
        return .{ .refusal = .bad_request };
    }
    const rest = line[method_end + 1 ..];
    const target_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return .{ .refusal = .bad_request };
    const target = rest[0..target_end];
    if (target.len > limits.target_bytes_max) return .{ .refusal = .uri_too_long };
    if (target.len == 0 or !all_in(target, &target_table)) return .{ .refusal = .bad_request };
    const version = switch (parse_version(rest[target_end + 1 ..])) {
        .version => |version| version,
        .refusal => |refusal| return .{ .refusal = refusal },
    };
    const method = method_of(method_text);
    // CONNECT asks for a tunnel: this server is an origin, not a proxy.
    if (std.mem.eql(u8, method_text, "CONNECT")) return .{ .refusal = .not_implemented };
    return .{ .line = .{
        .method = method,
        .method_text = method_text,
        .target = target,
        .version = version,
    } };
}

const VersionResult = union(enum) { version: Version, refusal: Refusal };

fn parse_version(text: []const u8) VersionResult {
    if (std.mem.eql(u8, text, "HTTP/1.1")) return .{ .version = .http_1_1 };
    if (std.mem.eql(u8, text, "HTTP/1.0")) return .{ .version = .http_1_0 };
    // Well-formed but another version (HTTP/2.0 sent as text, HTTP/3.0,
    // HTTP/0.9 is never well-formed here): 505. Anything else is garbage.
    const well_formed = text.len == 8 and std.mem.startsWith(u8, text, "HTTP/") and
        std.ascii.isDigit(text[5]) and text[6] == '.' and std.ascii.isDigit(text[7]);
    return .{ .refusal = if (well_formed) .version_not_supported else .bad_request };
}

/// Methods are case-sensitive (RFC 9110 §9.1): `get` is not `GET`.
pub fn method_of(text: []const u8) Method {
    const known = [_]struct { []const u8, Method }{
        .{ "GET", .get },     .{ "HEAD", .head },     .{ "POST", .post },
        .{ "PUT", .put },     .{ "DELETE", .delete }, .{ "OPTIONS", .options },
        .{ "PATCH", .patch }, .{ "TRACE", .trace },
    };
    for (known) |entry| {
        if (std.mem.eql(u8, text, entry[0])) return entry[1];
    }
    return .other;
}

const TargetResult = union(enum) {
    target: struct { path_and_query: []const u8, authority: ?[]const u8 },
    refusal: Refusal,
};

/// RFC 9112 §3.2: origin-form, absolute-form (which a server MUST accept),
/// or asterisk-form for `OPTIONS` only. Authority-form is CONNECT's, which
/// is refused before this.
fn parse_target(method: Method, target: []const u8) TargetResult {
    assert(target.len > 0);
    if (target[0] == '/') return .{ .target = .{ .path_and_query = target, .authority = null } };
    if (std.mem.eql(u8, target, "*")) {
        if (method != .options) return .{ .refusal = .bad_request };
        return .{ .target = .{ .path_and_query = target, .authority = null } };
    }
    const after_scheme = scheme_end(target) orelse return .{ .refusal = .bad_request };
    const rest = target[after_scheme..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    const authority = rest[0..authority_end];
    if (authority.len == 0 or !valid_host(authority)) return .{ .refusal = .bad_request };
    // `http://host?query` has an empty path, which means `/` (RFC 9110
    // §4.2.3); the query alone cannot be a path, so it is refused rather
    // than rewritten in a buffer we do not own.
    if (authority_end == rest.len) {
        return .{ .target = .{ .path_and_query = "/", .authority = authority } };
    }
    if (rest[authority_end] != '/') return .{ .refusal = .bad_request };
    return .{ .target = .{ .path_and_query = rest[authority_end..], .authority = authority } };
}

/// The offset after `http://` or `https://` (any case), if the target
/// starts with one.
fn scheme_end(target: []const u8) ?usize {
    const schemes = [_][]const u8{ "http://", "https://" };
    for (schemes) |scheme| {
        if (target.len >= scheme.len and stdx.equal_ignoring_case(target[0..scheme.len], scheme)) {
            return scheme.len;
        }
    }
    return null;
}

/// `name ":" OWS value OWS`, with no whitespace before the colon (RFC 9112
/// §5.1: MUST reject) and no obsolete folding (the line starts with a
/// name, never whitespace).
fn parse_field(line: []const u8) ?Header {
    assert(line.len > 0);
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const name = line[0..colon];
    if (name.len == 0 or !all_in(name, &token_table)) return null;
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    if (!all_in(value, &value_table)) return null;
    return .{ .name = name, .value = value };
}

/// What the fields say about framing and the connection, before the body
/// framing is decided.
const Semantics = struct {
    host: []const u8 = "",
    host_count: u32 = 0,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool,
    expect_continue: bool = false,
};

const SemanticsResult = union(enum) { semantics: Semantics, refusal: Refusal };

fn field_semantics(version: Version, headers: []const Header) SemanticsResult {
    var semantics: Semantics = .{ .keep_alive = version == .http_1_1 };
    var transfer_encoding_seen = false;
    for (headers) |header| {
        const name = header.name;
        if (stdx.equal_ignoring_case(name, "host")) {
            if (semantics.host_count > 0) return .{ .refusal = .bad_request };
            if (!valid_host(header.value)) return .{ .refusal = .bad_request };
            semantics.host = header.value;
            semantics.host_count += 1;
        } else if (stdx.equal_ignoring_case(name, "content-length")) {
            // Duplicates, even equal ones, are refused: a list or a second
            // field is how two parsers come to disagree on a length.
            if (semantics.content_length != null) return .{ .refusal = .bad_request };
            semantics.content_length = parse_length(header.value) orelse
                return .{ .refusal = .bad_request };
        } else if (stdx.equal_ignoring_case(name, "transfer-encoding")) {
            if (transfer_encoding_seen) return .{ .refusal = .not_implemented };
            transfer_encoding_seen = true;
            // Only `chunked`, alone: any other coding is one we do not
            // implement (RFC 9112 §6.1: 501).
            if (!stdx.equal_ignoring_case(header.value, "chunked")) {
                return .{ .refusal = .not_implemented };
            }
            semantics.chunked = true;
        } else if (stdx.equal_ignoring_case(name, "connection")) {
            connection_options(&semantics, header.value);
        } else if (stdx.equal_ignoring_case(name, "expect")) {
            if (!stdx.equal_ignoring_case(header.value, "100-continue")) {
                return .{ .refusal = .expectation_failed };
            }
            semantics.expect_continue = true;
        }
    }
    return .{ .semantics = semantics };
}

/// `Connection` is a comma-separated list of options; `close` wins over
/// `keep-alive`, which only matters for HTTP/1.0.
fn connection_options(semantics: *Semantics, value: []const u8) void {
    var options = std.mem.splitScalar(u8, value, ',');
    while (options.next()) |option_raw| {
        const option = std.mem.trim(u8, option_raw, " \t");
        if (stdx.equal_ignoring_case(option, "close")) {
            semantics.keep_alive = false;
            return;
        }
        if (stdx.equal_ignoring_case(option, "keep-alive")) semantics.keep_alive = true;
    }
}

const BodyResult = union(enum) { body: Body, refusal: Refusal };

fn body_framing(version: Version, semantics: Semantics, limits: Limits) BodyResult {
    if (semantics.chunked) {
        // RFC 9112 §6.1: a server MAY reject both; doing so leaves no
        // message whose length two parsers could read differently.
        if (semantics.content_length != null) return .{ .refusal = .bad_request };
        // HTTP/1.0 has no chunked coding (§6.1: treat as faulty framing).
        if (version == .http_1_0) return .{ .refusal = .bad_request };
        return .{ .body = .chunked };
    }
    const length = semantics.content_length orelse return .{ .body = .none };
    if (length > limits.body_bytes_max) return .{ .refusal = .content_too_large };
    if (length == 0) return .{ .body = .none };
    return .{ .body = .{ .length = length } };
}

/// `1*DIGIT`, nothing else: no sign, no space, no list. Lengths beyond
/// any body this server accepts are still parsed exactly, up to 18 digits.
fn parse_length(value: []const u8) ?u64 {
    if (value.len == 0 or value.len > 18) return null;
    var length: u64 = 0;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        length = length * 10 + (byte - '0');
    }
    assert(length < 1_000_000_000_000_000_000);
    return length;
}

/// `uri-host [ ":" port ]`, conservatively: the characters of a reg-name,
/// an IPv6 literal and a port. No `/`, `@`, whitespace or controls.
fn valid_host(value: []const u8) bool {
    return all_in(value, &host_table);
}

pub fn all_in(text: []const u8, table: *const [256]bool) bool {
    for (text) |byte| {
        if (!table[byte]) return false;
    }
    return true;
}

/// tchar (RFC 9110 §5.6.2).
pub const token_table = table: {
    var table: [256]bool = @splat(false);
    for ("!#$%&'*+-.^_`|~") |byte| table[byte] = true;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    break :table table;
};

/// Request targets: visible ASCII. Clients percent-encode the rest;
/// anything outside (space, controls, DEL, non-ASCII bytes) is refused.
pub const target_table = table: {
    var table: [256]bool = @splat(false);
    for (0x21..0x7f) |byte| table[byte] = true;
    break :table table;
};

/// field-value (RFC 9110 §5.5): visible ASCII, obs-text (0x80-0xff), and
/// space or tab inside. NUL, CR, LF and other controls are refused.
pub const value_table = table: {
    var table: [256]bool = @splat(false);
    for (0x21..0x7f) |byte| table[byte] = true;
    for (0x80..0x100) |byte| table[byte] = true;
    table[' '] = true;
    table['\t'] = true;
    break :table table;
};

const host_table = table: {
    var table: [256]bool = @splat(false);
    for ("-._~!$&'()*+,;=%:[]") |byte| table[byte] = true;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    break :table table;
};

comptime {
    assert(!token_table[' ']);
    assert(!token_table[':']);
    assert(!target_table[' ']);
    assert(!target_table[0x7f]);
    assert(!value_table['\r']);
    assert(!value_table['\n']);
    assert(!value_table[0]);
    assert(!host_table['/']);
    assert(!host_table['@']);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

const test_limits: Limits = .{
    .head_bytes_max = 1024,
    .target_bytes_max = 64,
    .headers_max = 8,
    .body_bytes_max = 1000,
};

/// Parse `bytes` as it would arrive in every possible pair of reads, and
/// as one read; every way must give the same result (the parser resumes,
/// so this is the property that matters most). Returns that result.
fn parse_every_split(bytes: []const u8, headers: []Header) Result {
    var parser = Parser.init(test_limits, headers);
    const whole = parser.parse(bytes);
    for (0..bytes.len) |split| {
        var split_headers: [test_limits.headers_max]Header = undefined;
        var split_parser = Parser.init(test_limits, &split_headers);
        const first = split_parser.parse(bytes[0..split]);
        switch (first) {
            // A refusal on a prefix must be the refusal of the whole.
            .refusal => |refusal| {
                assert(whole == .refusal);
                assert(whole.refusal == refusal);
                continue;
            },
            .complete => |complete| {
                // Complete on a prefix: the whole has trailing bytes (a
                // pipelined request, or a body) after the same head.
                assert(whole == .complete);
                assert(whole.complete.head_bytes == complete.head_bytes);
                continue;
            },
            .incomplete => {},
        }
        const second = split_parser.parse(bytes);
        assert(std.meta.activeTag(second) == std.meta.activeTag(whole));
        switch (second) {
            .refusal => |refusal| assert(refusal == whole.refusal),
            .complete => |complete| {
                assert(complete.head_bytes == whole.complete.head_bytes);
                assert(complete.head.headers.len == whole.complete.head.headers.len);
            },
            .incomplete => {},
        }
    }
    return whole;
}

fn expect_head(bytes: []const u8) !Head {
    var headers: [test_limits.headers_max]Header = undefined;
    const result = parse_every_split(bytes, &headers);
    if (result != .complete) {
        std.debug.print("expected a head, got {any}\n", .{result});
        return error.TestUnexpectedResult;
    }
    try testing.expectEqual(bytes.len, result.complete.head_bytes);
    // The headers live in this frame: copy what the tests look at.
    var head = result.complete.head;
    head.headers = &.{};
    return head;
}

fn expect_refusal(expected: Refusal, bytes: []const u8) !void {
    var headers: [test_limits.headers_max]Header = undefined;
    const result = parse_every_split(bytes, &headers);
    if (result != .refusal or result.refusal != expected) {
        std.debug.print("expected {s}, got {any}\n", .{ @tagName(expected), result });
        return error.TestUnexpectedResult;
    }
}

fn expect_incomplete(bytes: []const u8) !void {
    var headers: [test_limits.headers_max]Header = undefined;
    var parser = Parser.init(test_limits, &headers);
    try testing.expect(parser.parse(bytes) == .incomplete);
}

test "http1: head: a simple GET" {
    const head = try expect_head("GET /a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try testing.expectEqual(Method.get, head.method);
    try testing.expectEqualStrings("/a?b=c", head.target);
    try testing.expectEqualStrings("/a?b=c", head.path_and_query);
    try testing.expectEqualStrings("example.com", head.host);
    try testing.expectEqual(Version.http_1_1, head.version);
    try testing.expect(head.body == .none);
    try testing.expect(head.keep_alive);
    try testing.expect(!head.expect_continue);
}

test "http1: head: fields keep their case, values lose surrounding whitespace" {
    var headers: [test_limits.headers_max]Header = undefined;
    var parser = Parser.init(test_limits, &headers);
    const result = parser.parse("GET / HTTP/1.1\r\nHost:h\r\nX-A: \t one two \t\r\nX-B:\r\n\r\n");
    const head = result.complete.head;
    try testing.expectEqual(@as(usize, 3), head.headers.len);
    try testing.expectEqualStrings("X-A", head.headers[1].name);
    try testing.expectEqualStrings("one two", head.headers[1].value);
    try testing.expectEqualStrings("", head.headers[2].value);
}

test "http1: head: incomplete until the blank line" {
    try expect_incomplete("");
    try expect_incomplete("G");
    try expect_incomplete("GET / HTTP/1.1");
    try expect_incomplete("GET / HTTP/1.1\r");
    try expect_incomplete("GET / HTTP/1.1\r\n");
    try expect_incomplete("GET / HTTP/1.1\r\nHost: h\r\n");
    try expect_incomplete("GET / HTTP/1.1\r\nHost: h\r\n\r");
}

test "http1: head: empty lines before the request line are ignored" {
    const head = try expect_head("\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expectEqualStrings("/", head.target);
}

test "http1: head: a pipelined request after the head is left alone" {
    const first = "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n";
    const bytes = first ++ "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n";
    var headers: [test_limits.headers_max]Header = undefined;
    var parser = Parser.init(test_limits, &headers);
    const result = parser.parse(bytes);
    try testing.expectEqual(@as(u32, first.len), result.complete.head_bytes);
    try testing.expectEqualStrings("/1", result.complete.head.target);
}

test "http1: head: line endings are CRLF only" {
    try expect_refusal(.bad_request, "GET / HTTP/1.1\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\n\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\rHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "\nGET / HTTP/1.1\r\nHost: h\r\n\r\n");
}

test "http1: head: request line refusals" {
    try expect_refusal(.bad_request, "GET  / HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET /  HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, " / HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET /\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1 \r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GE{T / HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET /a\tb HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET /caf\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET /\x7f HTTP/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / http/1.1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1\r\nHost: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.10\r\nHost: h\r\n\r\n");
}

test "http1: head: other versions are 505" {
    try expect_refusal(.version_not_supported, "GET / HTTP/2.0\r\nHost: h\r\n\r\n");
    try expect_refusal(.version_not_supported, "GET / HTTP/1.2\r\nHost: h\r\n\r\n");
    try expect_refusal(.version_not_supported, "GET / HTTP/0.9\r\nHost: h\r\n\r\n");
}

test "http1: head: methods are case-sensitive tokens" {
    const lower = try expect_head("get / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expectEqual(Method.other, lower.method);
    const head = try expect_head("PURGE / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expectEqual(Method.other, head.method);
    try testing.expectEqualStrings("PURGE", head.method_text);
    const head_method = try expect_head("HEAD / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expectEqual(Method.head, head_method.method);
    try expect_refusal(.not_implemented, "CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n");
}

test "http1: head: target forms" {
    const star = try expect_head("OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expectEqualStrings("*", star.path_and_query);
    try expect_refusal(.bad_request, "GET * HTTP/1.1\r\nHost: h\r\n\r\n");

    // Absolute-form: the authority in the target wins over Host.
    const absolute = try expect_head("GET http://a.example:8080/p?q HTTP/1.1\r\nHost: b\r\n\r\n");
    try testing.expectEqualStrings("a.example:8080", absolute.host);
    try testing.expectEqualStrings("/p?q", absolute.path_and_query);
    const bare = try expect_head("GET HTTPS://a.example HTTP/1.1\r\nHost: b\r\n\r\n");
    try testing.expectEqualStrings("/", bare.path_and_query);
    try expect_refusal(.bad_request, "GET http://a.example?q HTTP/1.1\r\nHost: b\r\n\r\n");
    try expect_refusal(.bad_request, "GET http:///p HTTP/1.1\r\nHost: b\r\n\r\n");
    try expect_refusal(.bad_request, "GET ftp://a/p HTTP/1.1\r\nHost: b\r\n\r\n");
    try expect_refusal(.bad_request, "GET http://u@a/p HTTP/1.1\r\nHost: b\r\n\r\n");
    try expect_refusal(.bad_request, "GET a/b HTTP/1.1\r\nHost: h\r\n\r\n");
}

test "http1: head: limits" {
    const long_target = "/" ++ stdx.repeat("a", 64);
    try expect_refusal(.uri_too_long, "GET " ++ long_target ++ " HTTP/1.1\r\nHost: h\r\n\r\n");
    // Still arriving, and already too long for any request line.
    try expect_refusal(.uri_too_long, "GET /" ++ stdx.repeat("a", 200));
    const exact_target = "/" ++ stdx.repeat("a", 63);
    _ = try expect_head("GET " ++ exact_target ++ " HTTP/1.1\r\nHost: h\r\n\r\n");

    const field = comptime "X: " ++ stdx.repeat("v", 200) ++ "\r\n";
    try expect_refusal(
        .header_fields_too_large,
        "GET / HTTP/1.1\r\nHost: h\r\n" ++ stdx.repeat(field, 5) ++ "\r\n",
    );
    try expect_refusal(
        .header_fields_too_large,
        "GET / HTTP/1.1\r\nHost: h\r\n" ++ stdx.repeat("X: y\r\n", 8) ++ "\r\n",
    );
    _ = try expect_head("GET / HTTP/1.1\r\nHost: h\r\n" ++ stdx.repeat("X: y\r\n", 7) ++ "\r\n");
}

test "http1: head: field syntax refusals" {
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost : h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost\t: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\n Host: h\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n b\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nNo colon\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\n: empty name\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nX: a\x7fb\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: h\r\nX(y): z\r\n\r\n");
    // obs-text is allowed in values.
    _ = try expect_head("GET / HTTP/1.1\r\nHost: h\r\nX: caf\xc3\xa9\r\n\r\n");
}

test "http1: head: Host" {
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: u@a\r\n\r\n");
    try expect_refusal(.bad_request, "GET / HTTP/1.1\r\nHost: a b\r\n\r\n");
    const v6 = try expect_head("GET / HTTP/1.1\r\nhost: [::1]:8080\r\n\r\n");
    try testing.expectEqualStrings("[::1]:8080", v6.host);
    const empty = try expect_head("GET / HTTP/1.1\r\nHost:\r\n\r\n");
    try testing.expectEqualStrings("", empty.host);
    const old = try expect_head("GET / HTTP/1.0\r\n\r\n");
    try testing.expectEqualStrings("", old.host);
    try testing.expect(!old.keep_alive);
}

test "http1: head: Content-Length" {
    const ten = try expect_head("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n");
    try testing.expectEqual(@as(u64, 10), ten.body.length);
    const zero = try expect_head("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n");
    try testing.expect(zero.body == .none);
    const padded = try expect_head("POST / HTTP/1.1\r\nHost: h\r\nContent-Length:  7 \r\n\r\n");
    try testing.expectEqual(@as(u64, 7), padded.body.length);
    const no_length = try expect_head("POST / HTTP/1.1\r\nHost: h\r\n\r\n");
    try testing.expect(no_length.body == .none);

    const cl = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: ";
    try expect_refusal(.bad_request, cl ++ "+10\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "-1\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "1 0\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "0x10\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "10, 10\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "1234567890123456789\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "10\r\nContent-Length: 10\r\n\r\n");
    try expect_refusal(.bad_request, cl ++ "10\r\ncontent-length: 11\r\n\r\n");
    try expect_refusal(.content_too_large, cl ++ "1001\r\n\r\n");
    try expect_refusal(.content_too_large, cl ++ "123456789012345678\r\n\r\n");
    const max = try expect_head(cl ++ "1000\r\n\r\n");
    try testing.expectEqual(@as(u64, 1000), max.body.length);
}

test "http1: head: Transfer-Encoding" {
    const te = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: ";
    try testing.expect((try expect_head(te ++ "chunked\r\n\r\n")).body == .chunked);
    try testing.expect((try expect_head(te ++ "Chunked\r\n\r\n")).body == .chunked);
    try expect_refusal(.not_implemented, te ++ "gzip\r\n\r\n");
    try expect_refusal(.not_implemented, te ++ "gzip, chunked\r\n\r\n");
    try expect_refusal(.not_implemented, te ++ "chunked, gzip\r\n\r\n");
    try expect_refusal(.not_implemented, te ++ "chunked\r\nTransfer-Encoding: chunked\r\n\r\n");
    try expect_refusal(.not_implemented, te ++ "chunked,\r\n\r\n");
    // Both lengths: refused whichever comes first.
    try expect_refusal(.bad_request, te ++ "chunked\r\nContent-Length: 10\r\n\r\n");
    try expect_refusal(
        .bad_request,
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    try expect_refusal(.bad_request, "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n");
}

test "http1: head: Connection" {
    const close = try expect_head("GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    try testing.expect(!close.keep_alive);
    const both_text = "GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, CLOSE\r\n\r\n";
    const both = try expect_head(both_text);
    try testing.expect(!both.keep_alive);
    const old = try expect_head("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n");
    try testing.expect(old.keep_alive);
    const upgrade = try expect_head("GET / HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\n\r\n");
    try testing.expect(upgrade.keep_alive);
}

test "http1: head: Expect" {
    const post = "POST / HTTP/1.1\r\nHost: h\r\n";
    const wait = try expect_head(post ++ "Content-Length: 5\r\nExpect: 100-continue\r\n\r\n");
    try testing.expect(wait.expect_continue);
    // Nothing to wait for without a body.
    const no_body = try expect_head(post ++ "Expect: 100-Continue\r\n\r\n");
    try testing.expect(!no_body.expect_continue);
    try expect_refusal(.expectation_failed, post ++ "Expect: something-else\r\n\r\n");
}

test "http1: head: the parser can be reset for the next request" {
    var headers: [test_limits.headers_max]Header = undefined;
    var parser = Parser.init(test_limits, &headers);
    _ = parser.parse("GET /1 HTTP/1.1\r\nHost: h\r\nX: 1\r\n\r\n").complete;
    parser.reset();
    const second = parser.parse("GET /2 HTTP/1.1\r\nHost: h\r\n\r\n").complete.head;
    try testing.expectEqualStrings("/2", second.target);
    try testing.expectEqual(@as(usize, 1), second.headers.len);
}

test "http1: head: every refusal has a 4xx or 5xx status" {
    for (std.enums.values(Refusal)) |refusal| {
        const status = refusal.status();
        try testing.expect(status >= 400 and status < 600);
    }
    try testing.expectEqual(@as(u16, 431), Refusal.header_fields_too_large.status());
}

test "http1: head: every byte value at every position: no crash, sound results" {
    const original = "POST /a?b HTTP/1.1\r\nHost: h:1\r\nContent-Length: 3\r\nX: y\r\n\r\n";
    var bytes: [original.len]u8 = original.*;
    var headers: [test_limits.headers_max]Header = undefined;
    var complete_count: u32 = 0;
    for (0..bytes.len) |position| {
        for (0..256) |value| {
            bytes[position] = @intCast(value);
            var parser = Parser.init(test_limits, &headers);
            switch (parser.parse(&bytes)) {
                .complete => |complete| {
                    complete_count += 1;
                    try expect_sound(&bytes, complete.head, complete.head_bytes);
                },
                .incomplete, .refusal => {},
            }
        }
        bytes[position] = original[position];
    }
    // Most single-byte changes inside a value or a name still parse.
    try testing.expect(complete_count > bytes.len);
}

/// What any accepted head must satisfy, whatever the input was.
fn expect_sound(bytes: []const u8, head: Head, head_bytes: u32) !void {
    try testing.expect(head_bytes <= bytes.len);
    try testing.expect(std.mem.endsWith(u8, bytes[0..head_bytes], "\r\n\r\n"));
    try testing.expect(head.method_text.len > 0);
    try testing.expect(all_in(head.method_text, &token_table));
    try testing.expect(all_in(head.target, &target_table));
    try testing.expect(valid_host(head.host));
    for (head.headers) |header| {
        try testing.expect(header.name.len > 0);
        try testing.expect(all_in(header.name, &token_table));
        try testing.expect(all_in(header.value, &value_table));
    }
    switch (head.body) {
        .length => |length| try testing.expect(length > 0 and length <= test_limits.body_bytes_max),
        .none, .chunked => {},
    }
}

/// Coverage-guided fuzzing (`zig build test --fuzz`): any bytes, split at
/// any point. Nothing crashes, every accepted head is sound, and the split
/// changes nothing (the parser resumes).
fn fuzz_head(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [512]u8 = undefined;
    const length = smith.slice(&bytes);
    const input = bytes[0..length];
    var headers: [test_limits.headers_max]Header = undefined;
    var parser = Parser.init(test_limits, &headers);
    const whole = parser.parse(input);
    if (whole == .complete) try expect_sound(input, whole.complete.head, whole.complete.head_bytes);

    const split = if (length == 0) 0 else smith.value(u32) % length;
    var split_headers: [test_limits.headers_max]Header = undefined;
    var split_parser = Parser.init(test_limits, &split_headers);
    const first = split_parser.parse(input[0..split]);
    if (first != .incomplete) return; // a prefix decided: checked by the unit tests
    const second = split_parser.parse(input);
    try testing.expectEqual(std.meta.activeTag(whole), std.meta.activeTag(second));
    switch (whole) {
        .complete => |complete| {
            try testing.expectEqual(complete.head_bytes, second.complete.head_bytes);
        },
        .refusal => |refusal| try testing.expectEqual(refusal, second.refusal),
        .incomplete => {},
    }
}

test "http1: head: fuzz" {
    try testing.fuzz({}, fuzz_head, .{ .corpus = &.{
        "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
        "POST /a?b HTTP/1.1\r\nHost: h:1\r\nContent-Length: 3\r\n\r\nabc",
        "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET http://a.example/p HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n",
        "OPTIONS * HTTP/1.0\r\nExpect: 100-continue\r\n\r\n",
    } });
}
