//! Simulated HTTP/1.1 clients and the model of what the server must answer.
//!
//! A client's whole script (its requests and how it behaves) is generated
//! from its seed before it runs: the workload is data. Each request has an
//! expectation, computed from what the client meant to send, never from
//! what the server saw, so a server that mangles a request is caught by the
//! application's echo of it.
//!
//! The rules for what may happen besides the expected response are few and
//! written down in `on_end`: a request with a body may be refused 503 when
//! the server's body buffers are all taken; a slow client may be timed out;
//! a keep-alive connection that is idle may be closed, and its next request
//! is then retried on a new connection (as real clients do).

const std = @import("std");
const assert = std.debug.assert;
const prng_module = @import("prng.zig");

const Prng = prng_module.Prng;
const ratio = prng_module.ratio;

/// What a client may generate, from the server's configuration: valid
/// requests must fit its limits, invalid ones must break exactly one.
pub const Limits = struct {
    head_bytes_max: u32,
    target_bytes_max: u32,
    headers_max: u16,
    body_bytes_max: u32,
    /// The largest response body a request may ask for (`/big/N`).
    big_bytes_max: u32,
    /// Ticks a fast client may stay idle between requests, and a slow one
    /// may pause between pieces: chosen to cross the server's timeouts.
    idle_ticks_max: u32,
    pause_ticks_max: u32,
};

pub const requests_max = 16;
/// The bytes of one request (head and body) as the client writes it.
pub const request_bytes_max = 16 * 1024;
pub const response_bytes_max = 64 * 1024;

/// What is wrong with a request, if anything, and so what it must get.
pub const Kind = enum(u8) {
    valid,
    bad_version,
    space_before_colon,
    both_lengths,
    transfer_coding_gzip,
    length_too_large,
    target_too_long,
    too_many_headers,
    connect,
    bare_lf,
    expect_other,
    bad_chunk_size,

    fn status(kind: Kind) u16 {
        return switch (kind) {
            .valid => unreachable,
            .bad_version => 505,
            .space_before_colon, .both_lengths, .bare_lf, .bad_chunk_size => 400,
            .transfer_coding_gzip, .connect => 501,
            .length_too_large => 413,
            .target_too_long => 414,
            .too_many_headers => 431,
            .expect_other => 417,
        };
    }
};

pub const Method = enum { GET, HEAD, POST, PUT, DELETE, OPTIONS };

pub const Target = union(enum) {
    root,
    /// `/echo/<n>`: the application echoes the request.
    echo: u32,
    /// `/s/<code>`: answered with that status.
    status: u16,
    /// `/big/<n>`: answered with n bytes.
    big: u32,
};

pub const Spec = struct {
    kind: Kind,
    method: Method,
    target: Target,
    extra_headers: u8,
    body_bytes: u32,
    chunked: bool,
    expect_continue: bool,
    close: bool,
    /// Seeds the body's bytes and the header names' case.
    seed: u64,

    pub fn has_body(spec: *const Spec) bool {
        return spec.body_bytes > 0 or spec.chunked;
    }
};

pub const Behavior = struct {
    /// Pauses between pieces, long enough to be timed out.
    slow: bool,
    /// Send the next request before the response to this one.
    pipeline: bool,
    /// The most bytes written at once.
    piece_bytes_max: u32,
    /// Stay idle after a response, sometimes past the server's patience.
    idle: bool,
    /// Give up partway through the script: close (or reset) mid-request.
    abandon_at: ?u32,
    abandon_reset: bool,
};

pub const Failure = enum {
    none,
    response_wrong,
    response_malformed,
    response_unsolicited,
    response_truncated,
    closed_without_response,
};

// --- generation ----------------------------------------------------------------

pub fn generate_spec(prng: *Prng, limits: Limits) Spec {
    const kind: Kind = if (prng.chance(ratio(1, 6)))
        @fromBackingInt(prng.int_at_most(u8, 1, @backingInt(Kind.bad_chunk_size)))
    else
        .valid;
    const method = generate_method(prng);
    var spec: Spec = .{
        .kind = kind,
        .method = method,
        .target = generate_target(prng, limits),
        .extra_headers = prng.int_at_most(u8, 0, @intCast(@min(limits.headers_max - 4, 8))),
        .body_bytes = 0,
        .chunked = false,
        .expect_continue = false,
        .close = prng.chance(ratio(1, 8)),
        .seed = prng.next(),
    };
    if (method == .POST or method == .PUT) {
        const large = prng.chance(ratio(1, 4));
        spec.body_bytes = prng.int_at_most(u32, 0, if (large) limits.body_bytes_max else 64);
        spec.chunked = prng.chance(ratio(1, 3));
        spec.expect_continue = spec.has_body() and prng.chance(ratio(1, 5));
    }
    // A kind about bodies needs a body; others need the plain shape.
    switch (kind) {
        .both_lengths, .bad_chunk_size => spec.chunked = true,
        .transfer_coding_gzip, .length_too_large => spec.chunked = false,
        .expect_other => spec.expect_continue = false,
        else => {},
    }
    return spec;
}

fn generate_method(prng: *Prng) Method {
    const roll = prng.int_less_than(u32, 100);
    if (roll < 45) return .GET;
    if (roll < 55) return .HEAD;
    if (roll < 80) return .POST;
    if (roll < 88) return .PUT;
    if (roll < 95) return .DELETE;
    return .OPTIONS;
}

fn generate_target(prng: *Prng, limits: Limits) Target {
    const statuses = [_]u16{ 200, 201, 204, 304, 404, 418, 500 };
    return switch (prng.int_less_than(u32, 8)) {
        0 => .root,
        1, 2 => .{ .status = statuses[prng.int_less_than(usize, statuses.len)] },
        3 => .{ .big = prng.int_at_most(u32, 0, limits.big_bytes_max) },
        else => .{ .echo = prng.int_less_than(u32, 1_000_000) },
    };
}

pub fn generate_behavior(prng: *Prng, requests: u32) Behavior {
    assert(requests > 0);
    return .{
        .slow = prng.chance(ratio(1, 10)),
        .pipeline = prng.chance(ratio(1, 3)),
        .piece_bytes_max = if (prng.boolean()) request_bytes_max else prng.int_at_most(u32, 1, 64),
        .idle = prng.chance(ratio(1, 4)),
        .abandon_at = if (prng.chance(ratio(1, 10))) prng.int_less_than(u32, requests) else null,
        .abandon_reset = prng.boolean(),
    };
}

// --- requests as bytes -----------------------------------------------------------

fn target_text(spec: *const Spec, out: []u8) []const u8 {
    return switch (spec.target) {
        .root => "/",
        .echo => |n| std.fmt.bufPrint(out, "/echo/{d}?q={d}", .{ n, n % 7 }) catch unreachable,
        .status => |code| std.fmt.bufPrint(out, "/s/{d}", .{code}) catch unreachable,
        .big => |n| std.fmt.bufPrint(out, "/big/{d}", .{n}) catch unreachable,
    };
}

/// A byte of a body: deterministic from the spec's seed and the offset.
pub fn body_byte(seed: u64, offset: u64) u8 {
    const mixed = (seed +% offset *% 0x9e3779b97f4a7c15) *% 0xbf58476d1ce4e5b9;
    return 'a' + @as(u8, @intCast((mixed >> 59) % 26));
}

/// The request as the client writes it.
pub fn write_request(spec: *const Spec, limits: Limits, out: []u8) []const u8 {
    var writer: Writer = .{ .buffer = out };
    var target_buffer: [64]u8 = undefined;
    const method = if (spec.kind == .connect) "CONNECT" else @tagName(spec.method);
    writer.text(method);
    writer.text(" ");
    if (spec.kind == .target_too_long) {
        writer.text("/");
        for (0..limits.target_bytes_max) |_| writer.text("t");
    } else {
        writer.text(target_text(spec, &target_buffer));
    }
    writer.text(if (spec.kind == .bad_version) " HTTP/1.2\r\n" else " HTTP/1.1\r\n");
    writer.text("Host: sim.example\r\n");
    write_headers(spec, limits, &writer);
    writer.text(if (spec.kind == .bare_lf) "\n" else "\r\n");
    if (spec.kind == .valid or spec.kind == .bad_chunk_size) write_body(spec, &writer);
    assert(!writer.overflow);
    return out[0..writer.used];
}

fn write_headers(spec: *const Spec, limits: Limits, writer: *Writer) void {
    var prng = Prng.init(spec.seed);
    for (0..spec.extra_headers) |index| {
        // Field names in any case: the server must not care.
        writer.text(if (prng.boolean()) "X-Sim-" else "x-sim-");
        writer.number(index);
        writer.text(": value ");
        writer.number(prng.int_less_than(u32, 1000));
        writer.text("\r\n");
    }
    if (spec.kind == .too_many_headers) {
        for (0..limits.headers_max) |_| writer.text("X-Many: 1\r\n");
    }
    if (spec.kind == .space_before_colon) writer.text("X-Bad : 1\r\n");
    if (spec.kind == .expect_other) writer.text("Expect: lunch\r\n");
    if (spec.close) writer.text("Connection: close\r\n");
    switch (spec.kind) {
        .transfer_coding_gzip => writer.text("Transfer-Encoding: gzip\r\n"),
        .length_too_large => {
            writer.text("Content-Length: ");
            writer.number(@as(u64, limits.body_bytes_max) + 1);
            writer.text("\r\n");
        },
        .both_lengths => writer.text("Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"),
        else => if (spec.chunked) {
            writer.text("Transfer-Encoding: chunked\r\n");
        } else if (spec.has_body()) {
            writer.text("Content-Length: ");
            writer.number(spec.body_bytes);
            writer.text("\r\n");
        },
    }
    if (spec.expect_continue) writer.text("Expect: 100-continue\r\n");
}

/// Where the head ends in a written request (the body starts there).
pub fn head_length(request: []const u8) usize {
    const end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse unreachable;
    return end + 4;
}

fn write_body(spec: *const Spec, writer: *Writer) void {
    if (!spec.chunked) {
        for (0..spec.body_bytes) |offset| writer.byte(body_byte(spec.seed, offset));
        return;
    }
    if (spec.kind == .bad_chunk_size) {
        writer.text("1 \r\nx\r\n0\r\n\r\n"); // whitespace alone after a size
        return;
    }
    var prng = Prng.init(spec.seed ^ 0x55);
    var offset: u32 = 0;
    for (0..spec.body_bytes + 1) |_| {
        if (offset == spec.body_bytes) break;
        const size = prng.int_at_most(u32, 1, spec.body_bytes - offset);
        writer.hex(size);
        if (prng.chance(ratio(1, 4))) writer.text(";ext=1");
        writer.text("\r\n");
        for (offset..offset + size) |at| writer.byte(body_byte(spec.seed, at));
        writer.text("\r\n");
        offset += size;
    }
    writer.text("0\r\n");
    if (prng.chance(ratio(1, 4))) writer.text("X-Trailer: done\r\n");
    writer.text("\r\n");
}

// --- the application's answers, and so the model ---------------------------------

/// FNV-1a: the application's checksum of a body, and the model's; the
/// application adds the body a read at a time.
pub const checksum_start: u64 = 0xcbf29ce484222325;

pub fn checksum_add(hash: u64, bytes: []const u8) u64 {
    var result = hash;
    for (bytes) |byte| result = (result ^ byte) *% 0x100000001b3;
    return result;
}

/// The checksum of the body the client means to send, byte by byte.
fn spec_checksum(spec: *const Spec) u64 {
    var hash = checksum_start;
    for (0..spec.body_bytes) |offset| hash = checksum_add(hash, &.{body_byte(spec.seed, offset)});
    return hash;
}

/// The application's answer to a request: the simulator's App calls this
/// with what the server delivered; the model with what the client sent.
pub fn answer(
    method: []const u8,
    path: []const u8,
    body_bytes: u64,
    body_checksum: u64,
    out: []u8,
) struct { status: u16, body: []const u8 } {
    if (std.mem.startsWith(u8, path, "/s/")) {
        const status = std.fmt.parseInt(u16, path[3..], 10) catch 400;
        const no_body = status == 204 or status == 304;
        return .{ .status = status, .body = if (no_body) "" else "status\n" };
    }
    if (std.mem.startsWith(u8, path, "/big/")) {
        const length = std.fmt.parseInt(u32, path[5..], 10) catch 0;
        assert(length <= out.len);
        for (out[0..length], 0..) |*byte, offset| byte.* = body_byte(length, offset);
        return .{ .status = 200, .body = out[0..length] };
    }
    const text = std.fmt.bufPrint(out, "{s} {s} {d} {x}\n", .{
        method, path, body_bytes, body_checksum,
    }) catch unreachable;
    return .{ .status = 200, .body = text };
}

pub const Expectation = struct {
    status: u16,
    body: []const u8,
    /// HEAD: a Content-Length but no body.
    head: bool,
    /// The server closes after it.
    closes: bool,
    /// A 503 (and close) is also correct: the body buffers were all taken.
    may_be_unavailable: bool,
};

pub fn expect(spec: *const Spec, out: []u8) Expectation {
    if (spec.kind != .valid) {
        return .{
            .status = spec.kind.status(),
            .body = "",
            .head = false,
            .closes = true,
            // A bad chunk is found only while reading the body, which needs
            // a body buffer first: without one, 503 comes before the 400.
            .may_be_unavailable = spec.kind == .bad_chunk_size,
        };
    }
    var target_buffer: [64]u8 = undefined;
    const path = target_text(spec, &target_buffer);
    const result = answer(@tagName(spec.method), path, spec.body_bytes, spec_checksum(spec), out);
    return .{
        .status = result.status,
        .body = result.body,
        .head = spec.method == .HEAD,
        .closes = spec.close,
        .may_be_unavailable = spec.has_body(),
    };
}

/// Appends to a fixed buffer, recording overflow.
const Writer = struct {
    buffer: []u8,
    used: usize = 0,
    overflow: bool = false,

    fn text(writer: *Writer, bytes: []const u8) void {
        if (writer.buffer.len - writer.used < bytes.len) {
            writer.overflow = true;
            return;
        }
        @memcpy(writer.buffer[writer.used..][0..bytes.len], bytes);
        writer.used += bytes.len;
    }

    fn byte(writer: *Writer, value: u8) void {
        writer.text(&.{value});
    }

    fn number(writer: *Writer, value: u64) void {
        var digits: [20]u8 = undefined;
        writer.text(std.fmt.bufPrint(&digits, "{d}", .{value}) catch unreachable);
    }

    fn hex(writer: *Writer, value: u64) void {
        var digits: [16]u8 = undefined;
        writer.text(std.fmt.bufPrint(&digits, "{x}", .{value}) catch unreachable);
    }
};

// --- responses -------------------------------------------------------------------

pub const Response = struct {
    status: u16,
    content_length: u64,
    closes: bool,
    has_date: bool,
    body: []const u8,
    /// Bytes of the response, head and body.
    bytes: usize,
};

pub const ParseResult = union(enum) {
    incomplete,
    malformed,
    response: Response,
};

/// One response from the start of `bytes`: strict, because the server's
/// output must be exactly well-formed. `head` says the request was HEAD.
pub fn parse_response(bytes: []const u8, head: bool) ParseResult {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return .incomplete;
    var lines = std.mem.splitSequence(u8, bytes[0..head_end], "\r\n");
    const status_line = lines.next().?;
    if (status_line.len < 13) return .malformed;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 ")) return .malformed;
    if (status_line[12] != ' ') return .malformed;
    const status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return .malformed;
    var response: Response = .{
        .status = status,
        .content_length = 0,
        .closes = false,
        .has_date = false,
        .body = "",
        .bytes = 0,
    };
    var length_seen = false;
    for (0..256) |_| {
        const line = lines.next() orelse break;
        const colon = std.mem.indexOf(u8, line, ": ") orelse return .malformed;
        const name = line[0..colon];
        const value = line[colon + 2 ..];
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (length_seen) return .malformed;
            length_seen = true;
            response.content_length = std.fmt.parseInt(u64, value, 10) catch return .malformed;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            response.closes = std.mem.eql(u8, value, "close");
        } else if (std.ascii.eqlIgnoreCase(name, "date")) {
            response.has_date = value.len == 29 and std.mem.endsWith(u8, value, " GMT");
        }
    } else return .malformed;
    const no_body = status < 200 or status == 204 or status == 304;
    if (no_body and length_seen) return .malformed;
    if (!no_body and !length_seen) return .malformed;
    const body_bytes: usize = if (head or no_body) 0 else @intCast(response.content_length);
    const total = head_end + 4 + body_bytes;
    if (bytes.len < total) return .incomplete;
    response.body = bytes[head_end + 4 .. total];
    response.bytes = total;
    return .{ .response = response };
}

test "sim_client: requests are well-formed and answers agree with the model" {
    const limits: Limits = .{
        .head_bytes_max = 2048,
        .target_bytes_max = 64,
        .headers_max = 16,
        .body_bytes_max = 512,
        .big_bytes_max = 1000,
        .idle_ticks_max = 10,
        .pause_ticks_max = 10,
    };
    var prng = Prng.init(1);
    var request_buffer: [request_bytes_max]u8 = undefined;
    var expected_buffer: [response_bytes_max]u8 = undefined;
    for (0..500) |_| {
        const spec = generate_spec(&prng, limits);
        const request = write_request(&spec, limits, &request_buffer);
        try std.testing.expect(
            std.mem.indexOf(u8, request, "\r\n\r\n") != null or spec.kind == .bare_lf,
        );
        const expectation = expect(&spec, &expected_buffer);
        if (spec.kind != .valid) try std.testing.expect(expectation.closes);
    }
    _ = generate_behavior(&prng, 3);
}

test "sim_client: responses parse strictly" {
    const ok = "HTTP/1.1 200 OK\r\n" ++
        "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 2\r\n\r\nhi";
    const parsed = parse_response(ok, false).response;
    try std.testing.expectEqual(@as(u16, 200), parsed.status);
    try std.testing.expectEqualStrings("hi", parsed.body);
    try std.testing.expect(parsed.has_date);
    try std.testing.expect(parse_response(ok[0 .. ok.len - 1], false) == .incomplete);
    try std.testing.expectEqual(
        @as(usize, ok.len - 2),
        parse_response(ok[0 .. ok.len - 2], true).response.bytes,
    );
    try std.testing.expect(parse_response("HTTP/1.1 200 OK\r\n\r\n", false) == .malformed);
    try std.testing.expect(
        parse_response("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", false) == .malformed,
    );
}

// --- a client running its script ----------------------------------------------

pub const Client = struct {
    limits: Limits,
    prng: Prng,
    specs: [requests_max]Spec,
    specs_count: u32,
    behavior: Behavior,
    start_tick: u64,
    state: enum { waiting, running, done } = .waiting,
    connection: ?u32 = null,
    /// The request being sent, and how far.
    send_index: u32 = 0,
    send_offset: u32 = 0,
    request: [request_bytes_max]u8 = undefined,
    request_bytes: u32 = 0,
    request_head_bytes: u32 = 0,
    /// The head is sent; the body waits for 100 Continue.
    awaiting_continue: bool = false,
    /// The request whose response comes next.
    receive_index: u32 = 0,
    /// Responses received on the current connection.
    connection_responses: u32 = 0,
    /// A response said the server closes: send nothing more here.
    end_announced: bool = false,
    response: [response_bytes_max]u8 = undefined,
    response_bytes: u32 = 0,
    expected: [response_bytes_max]u8 = undefined,
    wake_tick: u64 = 0,
    idle_drawn: bool = false,
    failure: Failure = .none,
    failure_index: u32 = 0,
    /// Print what a failed check saw. Off for the canary, whose failure
    /// is expected: its report would bury a real one.
    report_failures: bool = true,
    stats: Stats = .{},

    pub const Stats = struct {
        responses: u32 = 0,
        unavailable: u32 = 0,
        retries: u32 = 0,
        timed_out: u32 = 0,
        reconnects: u32 = 0,
    };

    pub fn init(client: *Client, seed: u64, limits: Limits, start_tick: u64) void {
        var prng = Prng.init(seed);
        const count = prng.int_at_most(u32, 1, requests_max);
        client.* = .{
            .limits = limits,
            .prng = prng,
            .specs = undefined,
            .specs_count = count,
            .behavior = generate_behavior(&prng, count),
            .start_tick = start_tick,
        };
        for (client.specs[0..count]) |*spec| spec.* = generate_spec(&client.prng, limits);
    }

    pub fn step(client: *Client, io: anytype, tick: u64) void {
        if (client.state == .done or client.failure != .none) return;
        if (tick < client.start_tick) return;
        client.state = .running;
        // A pause holds back writing only: a client always reads what
        // arrives, so a pause never stalls the server's sends.
        if (client.connection) |connection| {
            client.receive(io);
            if (client.failure != .none) return;
            if (io.client_sees_end(connection)) return client.on_end(io);
        }
        if (tick < client.wake_tick) return;
        if (client.connection == null) {
            if (!client.connect(io)) return;
            client.receive(io);
        }
        client.send(io, tick);
    }

    fn connect(client: *Client, io: anytype) bool {
        assert(client.connection == null);
        if (client.receive_index == client.specs_count) {
            client.state = .done;
            return false;
        }
        client.connection = io.client_connect() orelse return false;
        client.stats.reconnects += 1;
        client.send_index = client.receive_index;
        client.send_offset = 0;
        client.awaiting_continue = false;
        client.connection_responses = 0;
        client.end_announced = false;
        client.response_bytes = 0;
        return true;
    }

    fn disconnect(client: *Client, io: anytype) void {
        io.client_close(client.connection.?);
        client.connection = null;
        client.send_offset = 0;
    }

    fn fail(client: *Client, failure: Failure) void {
        assert(failure != .none);
        if (client.failure != .none) return;
        client.failure = failure;
        client.failure_index = client.receive_index;
    }

    fn receive(client: *Client, io: anytype) void {
        const connection = client.connection.?;
        for (0..response_bytes_max) |_| {
            const room = client.response[client.response_bytes..];
            if (room.len == 0) break;
            const got = io.client_receive(connection, room);
            if (got == 0) break;
            client.response_bytes += got;
        }
        for (0..requests_max * 2 + 1) |_| {
            if (client.response_bytes == 0 or client.failure != .none) return;
            if (!client.take_response()) return;
        }
    }

    /// Parse and check one response; false when it is not all here yet.
    fn take_response(client: *Client) bool {
        const sent_any = client.receive_index < client.send_index or
            (client.receive_index == client.send_index and client.send_offset > 0);
        if (client.receive_index == client.specs_count or !sent_any) {
            client.fail(.response_unsolicited);
            return false;
        }
        const spec = &client.specs[client.receive_index];
        const bytes = client.response[0..client.response_bytes];
        const response = switch (parse_response(bytes, spec.method == .HEAD)) {
            .incomplete => return false,
            .malformed => {
                client.fail(.response_malformed);
                return false;
            },
            .response => |response| response,
        };
        // An interim or final answer to the request being sent ends its
        // wait for 100; one to an earlier, pipelined request does not.
        const current = client.receive_index == client.send_index;
        if (response.status == 100) {
            if (!client.awaiting_continue or !current) client.fail(.response_wrong);
            client.awaiting_continue = false;
        } else {
            if (current) client.awaiting_continue = false;
            client.check(spec, response);
            client.receive_index += 1;
            client.connection_responses += 1;
            client.stats.responses += 1;
            if (response.closes) client.end_announced = true;
        }
        const rest = client.response_bytes - @as(u32, @intCast(response.bytes));
        std.mem.copyForwards(
            u8,
            client.response[0..rest],
            client.response[response.bytes..][0..rest],
        );
        client.response_bytes = rest;
        return true;
    }

    fn check(client: *Client, spec: *const Spec, response: Response) void {
        const expected = expect(spec, &client.expected);
        client.check_against(response, expected);
        if (client.failure != .none and client.report_failures) report(spec, response, expected);
    }

    fn check_against(client: *Client, response: Response, expected: Expectation) void {
        if (!response.has_date) return client.fail(.response_malformed);
        if (response.status == 503 and expected.may_be_unavailable) {
            // The body buffers were all taken: allowed, and it must close.
            if (!response.closes) return client.fail(.response_wrong);
            client.stats.unavailable += 1;
            return;
        }
        if (response.status != expected.status) return client.fail(.response_wrong);
        if (response.closes != expected.closes) return client.fail(.response_wrong);
        if (expected.head) {
            if (response.body.len != 0) return client.fail(.response_wrong);
            if (response.content_length != expected.body.len) return client.fail(.response_wrong);
            return;
        }
        if (!std.mem.eql(u8, response.body, expected.body)) return client.fail(.response_wrong);
    }

    /// The server closed the connection and everything it sent is read.
    fn on_end(client: *Client, io: anytype) void {
        if (client.response_bytes > 0) return client.fail(.response_truncated);
        const outstanding = client.receive_index < client.send_index or
            (client.receive_index == client.send_index and client.send_offset > 0);
        if (outstanding) {
            if (client.end_announced) {
                // Pipelined after a response that announced the close:
                // sent into a closing connection, so sent again.
                client.stats.retries += 1;
            } else if (client.behavior.slow) {
                // Timed out for being slow: give up, as a real one would.
                client.stats.timed_out += 1;
                client.disconnect(io);
                client.state = .done;
                return;
            } else if (client.connection_responses > 0) {
                // The server closed an idle keep-alive connection as the
                // request was on its way: the race every client retries.
                client.stats.retries += 1;
            } else {
                return client.fail(.closed_without_response);
            }
        }
        client.disconnect(io);
    }

    fn send(client: *Client, io: anytype, tick: u64) void {
        // A fast client writes until the window is full or it must wait:
        // its piece size tests fragmentation, never the server's patience.
        const pieces_max: u32 = if (client.behavior.slow) 1 else request_bytes_max * requests_max;
        for (0..pieces_max) |_| {
            const before = client.send_offset + client.send_index * request_bytes_max;
            if (!client.may_send()) return;
            if (client.send_offset == 0 and !client.begin_request(io, tick)) return;
            if (client.connection == null) return; // abandoned
            client.send_piece(io);
            const after = client.send_offset + client.send_index * request_bytes_max;
            if (after == before) return; // the window is full
            if (client.behavior.slow) {
                client.wake_tick = tick + client.prng.int_at_most(
                    u64,
                    1,
                    client.limits.pause_ticks_max,
                );
                return;
            }
        }
    }

    fn may_send(client: *const Client) bool {
        if (client.end_announced or client.awaiting_continue) return false;
        if (client.send_index == client.specs_count) return false;
        if (client.send_index == client.receive_index) return true;
        if (client.send_offset > 0) return true; // finish what was begun
        // Pipeline only after a request that leaves the connection open
        // and needs no interim answer.
        const previous = &client.specs[client.send_index - 1];
        const keeps_open = previous.kind == .valid and !previous.close and
            !previous.expect_continue;
        return client.behavior.pipeline and keeps_open;
    }

    /// Write the next request's bytes; perhaps idle first, perhaps abandon.
    fn begin_request(client: *Client, io: anytype, tick: u64) bool {
        const spec = &client.specs[client.send_index];
        if (client.behavior.idle and !client.idle_drawn and client.connection_responses > 0) {
            client.idle_drawn = true;
            client.wake_tick = tick + client.prng.int_at_most(u64, 0, client.limits.idle_ticks_max);
            return false;
        }
        client.idle_drawn = false;
        const request = write_request(spec, client.limits, &client.request);
        client.request_bytes = @intCast(request.len);
        const head_bytes = if (spec.kind == .bare_lf) request.len else head_length(request);
        client.request_head_bytes = @intCast(head_bytes);
        if (client.behavior.abandon_at == client.send_index) {
            const part = client.prng.int_at_most(u32, 0, client.request_bytes - 1);
            _ = io.client_send(client.connection.?, client.request[0..part]);
            if (client.behavior.abandon_reset) {
                io.client_reset(client.connection.?);
            } else {
                io.client_close(client.connection.?);
            }
            client.connection = null;
            client.state = .done;
        }
        return true;
    }

    fn send_piece(client: *Client, io: anytype) void {
        const spec = &client.specs[client.send_index];
        var end = client.request_bytes;
        // With Expect: 100-continue, the body waits for the server's word.
        const waits = spec.expect_continue and client.send_offset < client.request_head_bytes;
        if (waits) end = client.request_head_bytes;
        const left = end - client.send_offset;
        assert(left > 0);
        const piece = client.prng.int_at_most(u32, 1, @min(left, client.behavior.piece_bytes_max));
        const bytes = client.request[client.send_offset..][0..piece];
        client.send_offset += io.client_send(client.connection.?, bytes);
        if (waits and client.send_offset == client.request_head_bytes and
            end < client.request_bytes)
        {
            client.awaiting_continue = true;
        }
        if (client.send_offset == client.request_bytes) {
            client.send_index += 1;
            client.send_offset = 0;
        }
    }
};

/// What a failed check saw, for the person replaying the seed.
fn report(spec: *const Spec, response: Response, expected: Expectation) void {
    std.debug.print("  request: {s} {s} {any} body={d} chunked={} expect={} close={}\n", .{
        @tagName(spec.kind), @tagName(spec.method), spec.target,
        spec.body_bytes,     spec.chunked,          spec.expect_continue,
        spec.close,
    });
    const expected_body = expected.body[0..@min(expected.body.len, 80)];
    std.debug.print("  expected: status={d} closes={} head={} body({d})={s}\n", .{
        expected.status, expected.closes, expected.head, expected.body.len, expected_body,
    });
    const body = response.body[0..@min(response.body.len, 80)];
    std.debug.print("  got:      status={d} closes={} length={d} body({d})={s}\n", .{
        response.status, response.closes, response.content_length, response.body.len, body,
    });
}
