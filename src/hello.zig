//! fourneau-hello on fibers, one shard per CPU.
//!
//!   fourneau-hello [--port P] [--address A] [--shards N] [--connections N]
//!                  [--counts on]
//!
//! `/` answers "hello"; `/echo` reads the whole body and answers with the
//! request it saw; anything else is 404. Shards default to the CPUs this
//! process may run on (its affinity mask, so `taskset` decides).

const std = @import("std");
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const server_module = @import("server.zig");
const http1_response = @import("http1_response.zig");
const Stop = @import("stop.zig").Stop;

const App = struct {
    pub const Response = struct {
        status: u16,
        headers: []const http1_response.Header,
        body: []const u8,
    };

    const text_plain: []const http1_response.Header = &.{
        .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
    };

    pub fn handle(app: *App, request: *Server.Request) Response {
        _ = app;
        const head = request.head;
        if (std.mem.eql(u8, head.path_and_query, "/")) {
            return .{ .status = 200, .headers = text_plain, .body = "hello\n" };
        }
        if (std.mem.eql(u8, head.path_and_query, "/echo")) return echo(request);
        return .{ .status = 404, .headers = text_plain, .body = "not found\n" };
    }

    fn echo(request: *Server.Request) Response {
        var body_bytes: u64 = 0;
        var chunk: [4096]u8 = undefined;
        for (0..std.math.maxInt(u32)) |_| {
            const got = request.read_body(&chunk) catch |err| {
                const status: u16 = switch (err) {
                    error.ContentTooLarge => 413,
                    error.BadRequest, error.Disconnected => 400,
                };
                return .{ .status = status, .headers = text_plain, .body = "bad body\n" };
            };
            if (got == 0) break;
            body_bytes += got;
        } else unreachable; // a body is bounded by body_bytes_max
        const head = request.head;
        const body = std.fmt.bufPrint(request.scratch, "{s} {s} host={s} headers={d} body={d}\n", .{
            head.method_text, head.target, head.host, head.headers.len, body_bytes,
        }) catch "too long\n";
        return .{ .status = 200, .headers = text_plain, .body = body };
    }

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const Server = server_module.ServerType(App, .{ .send_then_receive = Evented.sendThenReceive });

const Options = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    /// Shared nothing (experiment 1): this many independent shards, each
    /// a thread with its own single-threaded Evented, listener and slots.
    /// Zero: one per CPU in the affinity mask.
    shards: u32 = 0,
    connections: u32 = 1024,
    /// Print each shard's ring activity per 100 requests every 2 s
    /// (experiment 18): what the kernel is asked, request by request.
    counts: bool = false,
};

fn parse_options(init: std.process.Init.Minimal) !Options {
    var options: Options = .{};
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |arg| {
        const value = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--address")) {
            options.address = value;
        } else if (std.mem.eql(u8, arg, "--shards")) {
            options.shards = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--connections")) {
            options.connections = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--counts")) {
            options.counts = std.mem.eql(u8, value, "on");
        } else return error.Usage;
    }
    return options;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var options = try parse_options(init);
    if (options.shards == 0) options.shards = cpu_count();
    var stop: Stop = .{};
    try stop.watch(); // before any shard's thread
    try run_shards(options, &stop.requested);
    std.debug.print("fourneau-hello: stopped\n", .{});
}

/// The CPUs in this process's affinity mask.
fn cpu_count() u32 {
    const linux = std.os.linux;
    var set: linux.cpu_set_t = @splat(0);
    const result = linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &set);
    if (linux.errno(result) != .SUCCESS) return 1;
    var count: u32 = 0;
    for (set) |word| count += @popCount(word);
    assert(count >= 1); // we are running on one
    return count;
}

/// Shared nothing: `shards` threads, each a whole server on one thread.
/// The kernel spreads connections between their listeners (SO_REUSEPORT).
/// Returns once every shard has drained and returned.
fn run_shards(options: Options, stop: *const std.atomic.Value(bool)) !void {
    assert(options.shards > 0);
    const shards_max = 256;
    assert(options.shards <= shards_max);
    var threads: [shards_max]std.Thread = undefined;
    for (threads[1..options.shards]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, run_shard, .{ options, stop });
    }
    std.debug.print("fourneau-hello on http://127.0.0.1:{d} ({d} shards)\n", .{
        options.port,
        options.shards,
    });
    run_shard(options, stop);
    for (threads[1..options.shards]) |thread| thread.join();
}

fn run_shard(options: Options, stop: *const std.atomic.Value(bool)) void {
    run_shard_or_fail(options, stop) catch |err| std.debug.panic("shard: {t}", .{err});
}

fn run_shard_or_fail(options: Options, stop: *const std.atomic.Value(bool)) !void {
    const gpa = std.heap.page_allocator;
    const config: server_module.Config = .{
        .connections_max = @max(1, options.connections / options.shards),
        .stop = stop,
    };
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{
        .thread_limit = 0, // this thread only
        // Not the default 8: with hundreds of connections the queues overflowed,
        // costing ~3,000 kernel cycles a request (experiment 23).
        .log2_ring_entries = 12,
        .fibers_max = config.fibers_max() + 1, // and `print_counts`
    });
    defer runtime.deinit();

    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse(options.address, options.port);
    const listener = try address.listen(io, .{ .reuse_address = true, .kernel_backlog = 4096 });
    var app: App = .{};
    var server = try Server.init(gpa, io, &app, listener, config);
    defer server.deinit(gpa);
    var group: std.Io.Group = .init;
    defer group.cancel(io); // `print_counts`
    if (options.counts) try group.concurrent(io, print_counts, .{ &runtime, &server });
    try server.run();
}

/// Every 2 s: this shard's submissions, `io_uring_enter` calls and
/// completions per 100 requests.
fn print_counts(runtime: *Evented, server: *Server) void {
    const thread = &runtime.threads.allocated[0];
    var counts_last = thread.counts;
    var requests_last = server.stats.requests;
    for (0..std.math.maxInt(u64)) |_| {
        server.io.sleep(.fromSeconds(2), .awake) catch return;
        const counts = thread.counts;
        const requests = server.stats.requests;
        const delta = @max(1, requests - requests_last);
        std.debug.print("shard: requests={d} per 100: submissions={d} enters={d} " ++
            "completions={d} linked={d}\n", .{
            delta,
            (counts.submissions - counts_last.submissions) * 100 / delta,
            (counts.enters - counts_last.enters) * 100 / delta,
            (counts.completions - counts_last.completions) * 100 / delta,
            (counts.linked - counts_last.linked) * 100 / delta,
        });
        counts_last = counts;
        requests_last = requests;
    } else unreachable;
}

fn count_one(count: *u32) void {
    count.* += 1;
}

/// A client on plain system calls, on its own thread, for the drain test:
/// it orders every step by what it sees, never by sleeping.
const DrainClient = struct {
    port: u16,
    stop: *std.atomic.Value(bool),
    /// What the request in flight got: its response, then the end.
    answer: [512]u8 = undefined,
    answer_len: usize = 0,
    idle_ended: bool = false,

    const linux = std.os.linux;
    const request_start = "GET / HTTP/1.1\r\nHost: drain\r\n";

    fn run(client: *DrainClient) void {
        client.run_or_fail() catch |err| std.debug.panic("drain client: {t}", .{err});
    }

    fn run_or_fail(client: *DrainClient) !void {
        // In flight: half its first request, before the idle one connects,
        // so it is accepted first (one listener's backlog is in order).
        const in_flight = try connect(client.port);
        defer _ = linux.close(in_flight);
        try send(in_flight, request_start);
        // Idle: a whole request answered, so both are accepted.
        const idle = try connect(client.port);
        defer _ = linux.close(idle);
        try send(idle, request_start ++ "\r\n");
        var buffer: [512]u8 = undefined;
        const got = try receive_until_end_or(idle, &buffer, "hello\n");
        if (!std.mem.endsWith(u8, buffer[0..got], "hello\n")) return error.NoAnswer;
        client.stop.store(true, .release);
        // The drain closes the idle connection: it has begun.
        client.idle_ended = try receive_until_end_or(idle, &buffer, null) == 0;
        try send(in_flight, "\r\n");
        client.answer_len = try receive_until_end_or(in_flight, &client.answer, null);
    }

    fn connect(port: u16) !linux.fd_t {
        const fd: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
        if (fd < 0) return error.Socket;
        const address: linux.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        const result = linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
        if (linux.errno(result) != .SUCCESS) return error.Connect;
        return fd;
    }

    fn send(fd: linux.fd_t, bytes: []const u8) !void {
        const result = linux.write(fd, bytes.ptr, bytes.len);
        if (linux.errno(result) != .SUCCESS or result != bytes.len) return error.Send;
    }

    /// Reads until the peer closes, or until what was read ends with
    /// `until`; the count read.
    fn receive_until_end_or(fd: linux.fd_t, buffer: []u8, until: ?[]const u8) !usize {
        var used: usize = 0;
        for (0..buffer.len + 1) |_| {
            if (until) |end| if (std.mem.endsWith(u8, buffer[0..used], end)) return used;
            if (used == buffer.len) return error.TooLong;
            const result = linux.read(fd, buffer[used..].ptr, buffer.len - used);
            if (linux.errno(result) != .SUCCESS) return error.Receive;
            if (result == 0) return used;
            used += result;
        } else unreachable; // each pass reads a byte or returns
    }
};

test "a stopped server drains: the request in flight is answered and closed" {
    const gpa = std.testing.allocator;
    var stop: std.atomic.Value(bool) = .init(false);
    const config: server_module.Config = .{
        .connections_max = 4,
        .tick_ms = 10,
        .drain_timeout_ms = 5_000,
        .stop = &stop,
    };
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{ .thread_limit = 0, .fibers_max = config.fibers_max() });
    defer runtime.deinit();
    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const listener = try address.listen(io, .{ .reuse_address = false });
    var app: App = .{};
    var server = try Server.init(gpa, io, &app, listener, config);
    defer server.deinit(gpa); // its listener closed by the drain

    var client: DrainClient = .{ .port = listener.socket.address.getPort(), .stop = &stop };
    const thread = try std.Thread.spawn(.{}, DrainClient.run, .{&client});
    try server.run(); // returns: drained
    thread.join();
    try std.testing.expect(client.idle_ended);
    const answer = client.answer[0..client.answer_len];
    try std.testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, answer, "\r\nConnection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, answer, "\r\n\r\nhello\n"));
    try std.testing.expectEqual(1, server.stats.drain_idle);
    try std.testing.expectEqual(0, server.stats.drain_cut);
}

test "the port's fibers: a pool mapped at init, refused beyond it, reused" {
    const gpa = std.testing.allocator;
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{ .thread_limit = 0, .fibers_max = 2 });
    defer runtime.deinit();
    const io = runtime.io();
    var count: u32 = 0;
    for (0..3) |_| {
        var group: std.Io.Group = .init;
        errdefer group.cancel(io);
        try group.concurrent(io, count_one, .{&count});
        try group.concurrent(io, count_one, .{&count});
        const refused = group.concurrent(io, count_one, .{&count});
        try std.testing.expectError(error.ConcurrencyUnavailable, refused);
        try group.await(io);
    }
    try std.testing.expectEqual(6, count);
}
