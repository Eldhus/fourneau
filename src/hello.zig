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
    return run_shards(options);
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
fn run_shards(options: Options) !void {
    assert(options.shards > 0);
    const shards_max = 256;
    assert(options.shards <= shards_max);
    var threads: [shards_max]std.Thread = undefined;
    for (threads[1..options.shards]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, run_shard, .{options});
    }
    std.debug.print("fourneau-hello on http://127.0.0.1:{d} ({d} shards)\n", .{
        options.port,
        options.shards,
    });
    run_shard(options);
}

fn run_shard(options: Options) void {
    run_shard_or_fail(options) catch |err| std.debug.panic("shard: {t}", .{err});
}

fn run_shard_or_fail(options: Options) !void {
    const gpa = std.heap.page_allocator;
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{
        .thread_limit = 0, // this thread only
        // Not the default 8: with hundreds of connections the queues overflowed,
        // costing ~3,000 kernel cycles a request (experiment 23).
        .log2_ring_entries = 12,
    });
    defer runtime.deinit();

    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse(options.address, options.port);
    const listener = try address.listen(io, .{ .reuse_address = true, .kernel_backlog = 4096 });
    var app: App = .{};
    var server = try Server.init(gpa, io, &app, listener, .{
        .connections_max = @max(1, options.connections / options.shards),
    });
    var group: std.Io.Group = .init;
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
