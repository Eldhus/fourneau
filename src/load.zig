//! fourneau-load: an HTTP/1.1 load generator light enough to saturate a
//! server from fewer cores than the server has.
//!
//!   fourneau-load --port P [--path /] [--connections N] [--threads T]
//!                 [--seconds S] [--pipeline K] [--format text|json]
//!                 [--mode requests|events]
//!
//! Built as fourneau-floor is: each thread owns an io_uring and a fixed array
//! of connections, each a small state machine (send K requests, read K
//! responses); nothing is allocated while it runs. Responses are parsed
//! only as far as framing needs (the head's end and Content-Length).
//! Latency goes into a log-linear histogram of fixed buckets, so the
//! percentiles cost no memory per request.
//!
//! `--mode events` measures a server-sent event stream instead: each
//! connection asks for the path once and reads the stream, counting
//! events, and asks again when it ends. The body is decoded by the
//! server's own chunked decoder and the events by the format's rules (a
//! blank line after a `data` field), never by searching the bytes.
//!
//! Why our own: on one 8-core machine, oha on two cores saturated at
//! ~160k requests/s while a six-core server sat at 134% CPU, so it
//! measured oha, not servers.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const http1_chunked = @import("http1_chunked.zig");

const Options = struct {
    port: u16 = 8080,
    path: []const u8 = "/",
    connections: u32 = 128,
    threads: u32 = 2,
    seconds: u32 = 10,
    pipeline: u32 = 1,
    /// `text`, for people (stderr); `json`, one object on stdout, for a
    /// program that shows the result (roux's dev server).
    format: enum { text, json } = .text,
    /// `requests`: answers a second; `events`: server-sent events a
    /// second, each connection holding one stream at a time.
    mode: enum { requests, events } = .requests,
};

/// A stream's body: as long as it lasts, within reason.
const stream_limits: http1_chunked.Limits = .{
    .body_bytes_max = 1 << 50,
    .extension_bytes_max = 4096,
    .trailer_bytes_max = 4096,
};

/// Server-sent events counted as they arrive, by the format's rules
/// (WHATWG HTML, "Parsing an event stream"): lines end in CRLF, LF or CR;
/// a blank line dispatches an event if a `data` field came since the last
/// one; comments (`:`) and other fields alone dispatch nothing.
const EventCounter = struct {
    /// No byte of the current line yet.
    line_empty: bool = true,
    /// Still in the line's field name (no `:` yet).
    in_name: bool = false,
    /// How much of "data" the name has matched; more than 4: not "data".
    name_matched: u8 = 0,
    /// The last line ended in CR: an LF next is part of that end.
    after_cr: bool = false,
    /// A `data` field since the last event.
    has_data: bool = false,

    const field = "data";

    fn feed(counter: *EventCounter, bytes: []const u8) u64 {
        var events: u64 = 0;
        var index: usize = 0;
        // Each pass takes at least one byte.
        for (0..bytes.len + 1) |_| {
            if (index == bytes.len) break;
            const byte = bytes[index];
            if (counter.after_cr) {
                counter.after_cr = false;
                if (byte == '\n') {
                    index += 1;
                    continue;
                }
            }
            if (byte == '\r' or byte == '\n') {
                events += counter.line_end();
                counter.after_cr = byte == '\r';
                index += 1;
            } else if (counter.line_empty or counter.in_name) {
                counter.name_byte(byte);
                index += 1;
            } else {
                // A field's value: nothing in it matters until its end.
                const end = std.mem.indexOfAnyPos(u8, bytes, index, "\r\n") orelse bytes.len;
                assert(end > index);
                index = end;
            }
        } else unreachable;
        assert(index == bytes.len);
        return events;
    }

    fn name_byte(counter: *EventCounter, byte: u8) void {
        assert(byte != '\r' and byte != '\n');
        if (counter.line_empty) {
            counter.line_empty = false;
            counter.in_name = true;
            counter.name_matched = 0;
        }
        assert(counter.in_name);
        if (byte == ':') {
            counter.in_name = false;
            if (counter.name_matched == field.len) counter.has_data = true;
        } else if (counter.name_matched < field.len and byte == field[counter.name_matched]) {
            counter.name_matched += 1;
        } else {
            counter.name_matched = field.len + 1;
        }
    }

    /// One line ended: a blank one dispatches; "data" alone is a field.
    fn line_end(counter: *EventCounter) u64 {
        var dispatched = false;
        if (counter.line_empty) {
            dispatched = counter.has_data;
            counter.has_data = false;
        } else if (counter.in_name and counter.name_matched == field.len) {
            counter.has_data = true;
        }
        counter.line_empty = true;
        counter.in_name = false;
        return @intFromBool(dispatched);
    }
};

const response_buffer_bytes = 64 * 1024;
const request_bytes_max = 4096;
const cqes_max = 256;

/// Log-linear buckets: 64 per power of two of microseconds, up to ~1 s.
const Histogram = struct {
    counts: [buckets]u64 = @splat(0),

    // Exact below 64 µs, then 32 buckets per power of two (about 3% wide),
    // up to 2^25 µs (33 s); anything longer lands in the last bucket.
    const linear = 64;
    const per_octave = 32;
    const octaves = 20;
    const buckets = linear + octaves * per_octave;

    fn record(histogram: *Histogram, latency_ns: u64) void {
        histogram.counts[bucket_of(latency_ns / 1000)] += 1;
    }

    fn bucket_of(us: u64) usize {
        if (us < linear) return @intCast(us);
        const octave: u64 = std.math.log2_int(u64, us) - 5; // 1 for [64, 128)
        if (octave > octaves) return buckets - 1;
        const mantissa = us >> @intCast(octave); // in [32, 64)
        assert(mantissa >= per_octave and mantissa < 2 * per_octave);
        return @intCast(linear + (octave - 1) * per_octave + (mantissa - per_octave));
    }

    /// The smallest latency (µs) of bucket `index`: the inverse of `bucket_of`.
    fn floor_us(index: usize) u64 {
        if (index < linear) return index;
        const octave = (index - linear) / per_octave + 1;
        const mantissa = (index - linear) % per_octave + per_octave;
        return @as(u64, mantissa) << @intCast(octave);
    }

    fn merge(histogram: *Histogram, other: *const Histogram) void {
        for (&histogram.counts, other.counts) |*count, add| count.* += add;
    }

    fn percentile_us(histogram: *const Histogram, permille: u64) u64 {
        var total: u64 = 0;
        for (histogram.counts) |count| total += count;
        if (total == 0) return 0;
        const rank = (total * permille + 999) / 1000;
        var seen: u64 = 0;
        for (histogram.counts, 0..) |count, index| {
            seen += count;
            if (seen >= rank) return floor_us(index);
        }
        unreachable;
    }
};

const Connection = struct {
    fd: i32,
    state: enum { connecting, sending, receiving, failed },
    response: []u8,
    response_used: u32,
    responses_due: u32,
    sent_ns: u64,
    /// `--mode events`: past the stream's head, into its chunked body.
    in_body: bool = false,
    decoder: http1_chunked.Decoder = .init(stream_limits),
    counter: EventCounter = .{},
};

const Worker = struct {
    options: *const Options,
    ring: linux.IoUring,
    connections: []Connection,
    request: []const u8,
    histogram: Histogram = .{},
    responses: u64 = 0,
    errors: u64 = 0,
    /// `--mode events`: events read, and room to decode a body into.
    events: u64 = 0,
    decoded: []u8,
    address: linux.sockaddr.in,

    fn run(worker: *Worker, deadline_ns: u64) void {
        for (worker.connections, 0..) |*connection, index| {
            worker.connect(connection, @intCast(index));
        }
        var cqes: [cqes_max]linux.io_uring_cqe = undefined;
        // A timeout always in the ring, so the loop wakes to check the
        // deadline even if every connection has failed: every wait has an
        // exit (a dead server once hung this loop forever).
        const wake: linux.kernel_timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        worker.arm_wake(&wake);
        for (0..std.math.maxInt(u64)) |_| {
            _ = worker.ring.submit_and_wait(1) catch |err| std.debug.panic("submit: {t}", .{err});
            const count = worker.ring.copy_cqes(&cqes, 0) catch |err|
                std.debug.panic("cqes: {t}", .{err});
            const now = now_ns();
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == wake_user_data) {
                    worker.arm_wake(&wake);
                } else {
                    worker.complete(cqe, now);
                }
            }
            if (now >= deadline_ns or worker.all_failed()) return;
        } else unreachable;
    }

    const wake_user_data = std.math.maxInt(u64);

    fn arm_wake(worker: *Worker, wake: *const linux.kernel_timespec) void {
        _ = worker.ring.timeout(wake_user_data, wake, 0, 0) catch unreachable; // room for it
    }

    fn all_failed(worker: *const Worker) bool {
        for (worker.connections) |*connection| {
            if (connection.state != .failed) return false;
        }
        return true;
    }

    fn connect(worker: *Worker, connection: *Connection, index: u32) void {
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        assert(linux.errno(fd) == .SUCCESS);
        const on: u32 = 1;
        _ = linux.setsockopt(
            @intCast(fd),
            linux.IPPROTO.TCP,
            linux.TCP.NODELAY,
            std.mem.asBytes(&on),
            4,
        );
        connection.fd = @intCast(fd);
        connection.state = .connecting;
        connection.response_used = 0;
        const address: *const linux.sockaddr = @ptrCast(&worker.address);
        _ = worker.ring.connect(index, connection.fd, address, @sizeOf(linux.sockaddr.in)) catch
            unreachable; // the ring is sized for every connection's one operation
    }

    fn complete(worker: *Worker, cqe: linux.io_uring_cqe, now: u64) void {
        const connection = &worker.connections[@intCast(cqe.user_data)];
        if (cqe.res < 0) {
            worker.errors += 1;
            connection.state = .failed;
            return;
        }
        switch (connection.state) {
            .connecting => worker.send(connection, cqe.user_data, now),
            .sending => {
                const expected = worker.request.len * worker.options.pipeline;
                if (@as(usize, @intCast(cqe.res)) != expected) {
                    // A short send of a few hundred bytes: count it as failed.
                    worker.errors += 1;
                    connection.state = .failed;
                    return;
                }
                connection.state = .receiving;
                worker.receive(connection, cqe.user_data);
            },
            .receiving => switch (worker.options.mode) {
                .requests => worker.on_receive(connection, cqe, now),
                .events => worker.on_receive_events(connection, cqe, now),
            },
            .failed => {},
        }
    }

    fn send(worker: *Worker, connection: *Connection, user_data: u64, now: u64) void {
        connection.state = .sending;
        connection.sent_ns = now;
        connection.responses_due = worker.options.pipeline;
        const bytes = worker.request.len * worker.options.pipeline;
        const bytes_out = pipelined_requests[0..bytes];
        _ = worker.ring.send(user_data, connection.fd, bytes_out, 0) catch unreachable;
    }

    fn receive(worker: *Worker, connection: *Connection, user_data: u64) void {
        const room = connection.response[connection.response_used..];
        assert(room.len > 0);
        _ = worker.ring.recv(user_data, connection.fd, .{ .buffer = room }, 0) catch unreachable;
    }

    fn on_receive(
        worker: *Worker,
        connection: *Connection,
        cqe: linux.io_uring_cqe,
        now: u64,
    ) void {
        if (cqe.res == 0) {
            worker.errors += 1;
            connection.state = .failed;
            return;
        }
        connection.response_used += @intCast(cqe.res);
        // Take every complete response; at most the pipeline's count.
        for (0..worker.options.pipeline) |_| {
            const received = connection.response[0..connection.response_used];
            const length = response_length(received) orelse break;
            const rest = connection.response[length..connection.response_used];
            std.mem.copyForwards(u8, connection.response[0..rest.len], rest);
            connection.response_used = @intCast(rest.len);
            connection.responses_due -= 1;
            worker.responses += 1;
            worker.histogram.record(now - connection.sent_ns);
            if (connection.responses_due == 0) break;
        }
        if (connection.responses_due == 0) return worker.send(connection, cqe.user_data, now);
        worker.receive(connection, cqe.user_data);
    }

    /// A stream's bytes: its head, then its body, decoded and its events
    /// counted as they come; at its end, the next stream is asked for.
    fn on_receive_events(
        worker: *Worker,
        connection: *Connection,
        cqe: linux.io_uring_cqe,
        now: u64,
    ) void {
        assert(worker.options.pipeline == 1);
        if (cqe.res == 0) return worker.fail(connection);
        connection.response_used += @intCast(cqe.res);
        var input: []const u8 = connection.response[0..connection.response_used];
        if (!connection.in_body) {
            const head_end = std.mem.indexOf(u8, input, "\r\n\r\n") orelse {
                if (input.len == connection.response.len) return worker.fail(connection);
                return worker.receive(connection, cqe.user_data);
            };
            if (!is_event_stream_head(input[0..head_end])) return worker.fail(connection);
            connection.in_body = true;
            connection.decoder = .init(stream_limits);
            connection.counter = .{};
            worker.histogram.record(now - connection.sent_ns);
            input = input[head_end + 4 ..];
        }
        // Each pass consumes input, or fills the decoded bytes' room.
        for (0..input.len + 1) |_| {
            if (input.len == 0) break;
            const progress = switch (connection.decoder.decode(input, worker.decoded)) {
                .progress => |progress| progress,
                .refusal => return worker.fail(connection),
            };
            assert(progress.consumed > 0 or progress.produced > 0);
            worker.events += connection.counter.feed(worker.decoded[0..progress.produced]);
            input = input[progress.consumed..];
            if (progress.done) {
                // Nothing was asked for after the stream.
                if (input.len > 0) return worker.fail(connection);
                connection.in_body = false;
                connection.response_used = 0;
                worker.responses += 1;
                return worker.send(connection, cqe.user_data, now);
            }
        } else unreachable;
        connection.response_used = 0;
        worker.receive(connection, cqe.user_data);
    }

    fn fail(worker: *Worker, connection: *Connection) void {
        worker.errors += 1;
        connection.state = .failed;
    }
};

/// A 200 whose body is chunked: what a stream of events is sent as.
fn is_event_stream_head(head: []const u8) bool {
    if (!std.mem.startsWith(u8, head, "HTTP/1.1 200 ")) return false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // The status line.
    var chunked = false;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) {
            chunked = std.ascii.eqlIgnoreCase(value, "chunked");
        }
    }
    return chunked;
}

/// The bytes of one response at the start of `bytes`, if it is all here.
fn response_length(bytes: []const u8) ?usize {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return null;
    const head = bytes[0..head_end];
    const body = content_length(head) orelse 0;
    const total = head_end + 4 + body;
    return if (bytes.len >= total) total else null;
}

fn content_length(head: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        const name = "content-length:";
        if (line.len <= name.len or !std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
        const value = std.mem.trim(u8, line[name.len..], " ");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

var pipelined_requests: [request_bytes_max * 64]u8 = undefined;

fn now_ns() u64 {
    var spec: linux.timespec = undefined;
    assert(linux.errno(linux.clock_gettime(.MONOTONIC, &spec)) == .SUCCESS);
    return @as(u64, @intCast(spec.sec)) * std.time.ns_per_s + @as(u64, @intCast(spec.nsec));
}

fn parse_options(init: std.process.Init.Minimal) !Options {
    var options: Options = .{};
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |arg| {
        const value = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--path")) {
            options.path = value;
        } else if (std.mem.eql(u8, arg, "--connections")) {
            options.connections = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--threads")) {
            options.threads = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            options.seconds = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--pipeline")) {
            options.pipeline = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--format")) {
            options.format = std.meta.stringToEnum(@TypeOf(options.format), value) orelse
                return error.Usage;
        } else if (std.mem.eql(u8, arg, "--mode")) {
            options.mode = std.meta.stringToEnum(@TypeOf(options.mode), value) orelse
                return error.Usage;
        } else return error.Usage;
    }
    if (options.pipeline == 0 or options.pipeline > 64) return error.Usage;
    // A stream holds its connection until it ends: one at a time.
    if (options.mode == .events and options.pipeline != 1) return error.Usage;
    if (options.threads == 0 or options.connections < options.threads) return error.Usage;
    return options;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const options = try parse_options(init);
    const gpa = std.heap.page_allocator;
    var request_buffer: [request_bytes_max]u8 = undefined;
    const request_format = "GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    const request = try std.fmt.bufPrint(&request_buffer, request_format, .{options.path});
    for (0..options.pipeline) |index| {
        @memcpy(pipelined_requests[index * request.len ..][0..request.len], request);
    }

    const workers = try gpa.alloc(Worker, options.threads);
    const per_thread = options.connections / options.threads;
    for (workers) |*worker| {
        const connections = try gpa.alloc(Connection, per_thread);
        for (connections) |*connection| {
            connection.* = .{
                .fd = -1,
                .state = .failed,
                .response = try gpa.alloc(u8, response_buffer_bytes),
                .response_used = 0,
                .responses_due = 0,
                .sent_ns = 0,
            };
        }
        const entries = try std.math.ceilPowerOfTwo(u32, @max(per_thread * 2, 64));
        worker.* = .{
            .options = &options,
            .ring = try linux.IoUring.init(@intCast(@min(entries, 32768)), 0),
            .connections = connections,
            .request = request,
            .decoded = try gpa.alloc(u8, response_buffer_bytes),
            .address = .{
                .port = std.mem.nativeToBig(u16, options.port),
                .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
            },
        };
    }
    const start = now_ns();
    const deadline = start + @as(u64, options.seconds) * std.time.ns_per_s;
    const threads = try gpa.alloc(std.Thread, options.threads);
    for (threads, workers) |*thread, *worker| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ worker, deadline });
    }
    for (threads) |thread| thread.join();
    const elapsed_ns = now_ns() - start;
    switch (options.mode) {
        .requests => report(workers, elapsed_ns, options.format),
        .events => report_events(workers, elapsed_ns, options.format),
    }
}

/// Events a second; streams are the ones that ended (and were asked
/// again); the percentiles are of the time to a stream's head.
fn report_events(workers: []Worker, elapsed_ns: u64, format: @FieldType(Options, "format")) void {
    var histogram: Histogram = .{};
    var events: u64 = 0;
    var streams: u64 = 0;
    var errors: u64 = 0;
    for (workers) |*worker| {
        histogram.merge(&worker.histogram);
        events += worker.events;
        streams += worker.responses;
        errors += worker.errors;
    }
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const rate = @as(f64, @floatFromInt(events)) / seconds;
    if (format == .json) {
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{{\"events_per_second\":{d:.0}," ++
            "\"events\":{d},\"streams\":{d},\"errors\":{d},\"head_p50_us\":{d}," ++
            "\"head_p99_us\":{d}}}\n", .{
            rate,
            events,
            streams,
            errors,
            histogram.percentile_us(500),
            histogram.percentile_us(990),
        }) catch unreachable; // six numbers fit
        _ = linux.write(1, line.ptr, line.len);
        return;
    }
    std.debug.print("events/s={d:.0} events={d} streams={d} errors={d} ", .{
        rate,
        events,
        streams,
        errors,
    });
    std.debug.print("head p50={d}us p99={d}us\n", .{
        histogram.percentile_us(500),
        histogram.percentile_us(990),
    });
}

fn report(workers: []Worker, elapsed_ns: u64, format: @FieldType(Options, "format")) void {
    var histogram: Histogram = .{};
    var responses: u64 = 0;
    var errors: u64 = 0;
    for (workers) |*worker| {
        histogram.merge(&worker.histogram);
        responses += worker.responses;
        errors += worker.errors;
    }
    const seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const rate = @as(f64, @floatFromInt(responses)) / seconds;
    if (format == .json) {
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{{\"requests_per_second\":{d:.0}," ++
            "\"responses\":{d},\"errors\":{d},\"p50_us\":{d},\"p99_us\":{d},\"p999_us\":{d}}}\n", .{
            rate,
            responses,
            errors,
            histogram.percentile_us(500),
            histogram.percentile_us(990),
            histogram.percentile_us(999),
        }) catch unreachable; // six numbers fit
        _ = linux.write(1, line.ptr, line.len);
        return;
    }
    std.debug.print("requests/s={d:.0} responses={d} errors={d} ", .{ rate, responses, errors });
    std.debug.print("p50={d}us p99={d}us p99.9={d}us max_bucket={d}us\n", .{
        histogram.percentile_us(500),
        histogram.percentile_us(990),
        histogram.percentile_us(999),
        histogram.percentile_us(1000),
    });
}

test "load: histogram buckets invert and order" {
    var previous: usize = 0;
    for ([_]u64{ 0, 1, 63, 64, 65, 127, 128, 1000, 123_456, 1_000_000 }) |us| {
        const bucket = Histogram.bucket_of(us);
        try std.testing.expect(bucket >= previous);
        previous = bucket;
        const floor = Histogram.floor_us(bucket);
        try std.testing.expect(floor <= us);
        // Within one bucket's width: about 3% above 64 µs.
        try std.testing.expect(us - floor <= @max(1, us / 32));
    }
    var histogram: Histogram = .{};
    for (1..1001) |ms| histogram.record(ms * std.time.ns_per_ms);
    // The median of 1..1000 ms is 500 ms, to within a bucket.
    const median = histogram.percentile_us(500);
    try std.testing.expect(median <= 500_000 and median >= 500_000 - 500_000 / 32);
}

test "load: response framing" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\nHTTP/1.1";
    try std.testing.expectEqual(@as(?usize, 44), response_length(response));
    try std.testing.expectEqual(@as(?usize, null), response_length(response[0..40]));
}

fn count_events(stream: []const u8) u64 {
    var counter: EventCounter = .{};
    return counter.feed(stream);
}

test "load: events end at a blank line, after a data field" {
    // Datastar's shape: an event line, data lines, a blank line.
    const patch = "event: datastar-patch-elements\ndata: elements <b id=\"n\">7</b>\n\n";
    try std.testing.expectEqual(1, count_events(patch));
    try std.testing.expectEqual(3, count_events(patch ++ patch ++ patch));
    // Every line ending the format allows, mixed.
    try std.testing.expectEqual(3, count_events("data: a\r\n\r\ndata: b\r\rdata: c\n\r\n"));
    // "data" with no colon is a data field with an empty value.
    try std.testing.expectEqual(1, count_events("data\n\n"));
}

test "load: events: what dispatches nothing" {
    try std.testing.expectEqual(0, count_events(": a comment\n\n"));
    try std.testing.expectEqual(0, count_events("event: x\nid: 1\nretry: 5\n\n"));
    try std.testing.expectEqual(0, count_events("dat: a\n\ndatas: a\n\n data: a\n\n"));
    // Blank lines alone, and an event not ended yet.
    try std.testing.expectEqual(0, count_events("\n\n\r\n\rdata: a\n"));
    // CRLF is one line end, not two: no blank line between these fields.
    try std.testing.expectEqual(0, count_events("event: x\r\ndata: a\r\n"));
}

test "load: events: a stream split anywhere counts the same" {
    const stream = "event: e\r\ndata: one\r\n\r\n: ping\n\ndata\rdata: two\n\ndata: three\r\r";
    try std.testing.expectEqual(3, count_events(stream));
    for (0..stream.len + 1) |split| {
        var counter: EventCounter = .{};
        const events = counter.feed(stream[0..split]) + counter.feed(stream[split..]);
        try std.testing.expectEqual(3, events);
    }
}

test "load: a stream's head" {
    const chunked = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" ++
        "Transfer-Encoding: chunked";
    try std.testing.expect(is_event_stream_head(chunked));
    try std.testing.expect(is_event_stream_head("HTTP/1.1 200 OK\r\ntransfer-encoding:  Chunked "));
    try std.testing.expect(!is_event_stream_head("HTTP/1.1 404 Not Found\r\n" ++
        "Transfer-Encoding: chunked"));
    try std.testing.expect(!is_event_stream_head("HTTP/1.1 200 OK\r\nContent-Length: 5"));
    try std.testing.expect(!is_event_stream_head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip"));
    try std.testing.expect(!is_event_stream_head("HTTP/1.1 200 OK\r\nno colon"));
}
