//! fourneau-load: an HTTP/1.1 load generator light enough to saturate a
//! server from fewer cores than the server has.
//!
//!   fourneau-load --port P [--path /] [--connections N] [--threads T]
//!                 [--seconds S] [--pipeline K]
//!
//! Built as the server is: each thread owns an io_uring and a fixed array
//! of connections, each a small state machine (send K requests, read K
//! responses); nothing is allocated while it runs. Responses are parsed
//! only as far as framing needs (the head's end and Content-Length).
//! Latency goes into a log-linear histogram of fixed buckets, so the
//! percentiles cost no memory per request.
//!
//! Why our own: on one 8-core machine, oha on two cores saturated at
//! ~160k requests/s while a six-core server sat at 134% CPU (DIARY
//! 2026-10-05), so it measured oha, not servers.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

const Options = struct {
    port: u16 = 8080,
    path: []const u8 = "/",
    connections: u32 = 128,
    threads: u32 = 2,
    seconds: u32 = 10,
    pipeline: u32 = 1,
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
};

const Worker = struct {
    options: *const Options,
    ring: linux.IoUring,
    connections: []Connection,
    request: []const u8,
    histogram: Histogram = .{},
    responses: u64 = 0,
    errors: u64 = 0,
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
            .receiving => worker.on_receive(connection, cqe, now),
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
};

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
        } else return error.Usage;
    }
    if (options.pipeline == 0 or options.pipeline > 64) return error.Usage;
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
            connection.response = try gpa.alloc(u8, response_buffer_bytes);
        }
        const entries = try std.math.ceilPowerOfTwo(u32, @max(per_thread * 2, 64));
        worker.* = .{
            .options = &options,
            .ring = try linux.IoUring.init(@intCast(@min(entries, 32768)), 0),
            .connections = connections,
            .request = request,
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
    report(workers, now_ns() - start);
}

fn report(workers: []Worker, elapsed_ns: u64) void {
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
