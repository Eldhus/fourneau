//! The simulator: the server and our port of Evented, unchanged, on a
//! simulated kernel (sim_kernel.zig), from one seed: every line fourneau
//! runs above the system calls.
//!
//!   fourneau-sim --seed N              one run, replayed exactly
//!   fourneau-sim --seeds COUNT [--start N] [--canary]
//!
//! The seed picks the configuration (swarm testing: slot counts, limits,
//! timeouts, window sizes, latencies, the ring's size), the clients'
//! scripts, and every choice the kernel makes: how late each operation
//! completes, in what order, how many bytes it moves. Each tick (one
//! simulated millisecond), clients act, then the kernel completes what is
//! due and runs the process while it has completions to reap. The server's
//! invariants are checked between ticks; the clients check every response
//! against the model. Every run ends with the server stopped and returned:
//! told to by the plan, or, once its clients are done, by the simulator.
//!
//! Exit codes, so a sweep sorts its failures: 0 passed, 128 liveness,
//! 129 correctness; a crash is a panic (an assertion), which aborts
//! (SIGABRT). `--canary` makes the application answer one request
//! wrongly; the sweep must catch it.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("prng.zig").Prng;
const sim_kernel = @import("sim_kernel.zig");
const server_module = @import("server.zig");
const sim_client = @import("sim_client.zig");
const http1_response = @import("http1_response.zig");
const Evented = @import("zig_io_evented");

pub const exit_liveness: u8 = 128;
pub const exit_correctness: u8 = 129;

const tick_ns = std.time.ns_per_ms;
/// Ticks a server whose clients are done may take to drain and return
/// once the simulator tells it to stop: nothing is left to wait for but
/// its next tick and the closes.
const finish_ticks_max = 1000;

/// Everything a seed decides before the run.
pub const Setup = struct {
    server: server_module.Config,
    kernel: sim_kernel.Options,
    /// The ring: production's 4,096 entries, or Evented's default of 8,
    /// where submissions overflow and the port must submit to make room.
    log2_ring_entries: u4,
    limits: sim_client.Limits,
    clients_count: u32,
    /// Both of the server's ways to finish a turn: a write then a read, or
    /// the port's linked send-then-receive (production's, without kTLS).
    linked: bool,
    /// Clients start at random ticks up to this one.
    start_ticks_max: u32,
    ticks_max: u64,
    /// The tick the server is told to stop (`Config.stop`), if it is: it
    /// must drain and return within `drain_ticks_max` of it.
    stop_tick: ?u64,
    drain_ticks_max: u64,
};

pub fn setup(prng: *Prng) Setup {
    const connections_max = prng.int_at_most(u32, 1, 16);
    const head_bytes_max = prng.int_at_most(u32, 768, 4096);
    const window_bytes = if (prng.boolean()) prng.int_at_most(u32, 16, 256) else 8192;
    const latency_ticks_max = prng.int_at_most(u32, 0, 3);
    const body_bytes_max = prng.int_at_most(u32, 64, 4096);
    // A fast client must never be timed out: the deadlines leave room for
    // the slowest transfer the network allows (every operation as late as
    // it may be, a window at a time), with margin.
    const transfer_ms = (@max(head_bytes_max, body_bytes_max) / window_bytes + 4) *
        (latency_ticks_max + 1) * 4;
    const tick_ms = 10;
    const server: server_module.Config = .{
        .connections_max = connections_max,
        .head_bytes_max = head_bytes_max,
        .target_bytes_max = prng.int_at_most(u32, 64, head_bytes_max / 2),
        .headers_max = prng.int_at_most(u16, 12, 32),
        .body_bytes_max = body_bytes_max,
        .response_head_bytes_max = 512,
        // From exactly one head (every body sent direct) to room for many
        // responses (pipelined answers coalesced).
        .send_bytes_max = prng.int_at_most(u32, 512, 4096),
        .scratch_bytes_max = App.answer_bytes_max,
        .head_timeout_ms = transfer_ms + prng.int_at_most(u32, 20, 200) + tick_ms,
        .body_timeout_ms = transfer_ms + prng.int_at_most(u32, 20, 400) + tick_ms,
        .idle_timeout_ms = prng.int_at_most(u32, 20, 300) + tick_ms,
        .send_timeout_ms = transfer_ms + prng.int_at_most(u32, 20, 400) + tick_ms,
        .tick_ms = tick_ms,
        .tcp_nodelay = false,
    };
    const backlog_max = prng.int_at_most(u32, 1, 64);
    const realtime_seconds_start = 1_791_072_000 + prng.int_less_than(u64, 1_000_000);
    var plan: Setup = .{
        .server = server,
        .kernel = .{
            .tick_ns = tick_ns,
            .latency_ticks_max = latency_ticks_max,
            // Each fiber waits on at most a linked pair, and the port's
            // closes and cancels are in flight beside them.
            .operations_max = 4 * server.fibers_max() + 16,
            .network = .{
                .connections_max = 64,
                .backlog_max = backlog_max,
                .window_bytes = window_bytes,
            },
            .realtime_start_ns = realtime_seconds_start * std.time.ns_per_s,
        },
        .log2_ring_entries = 12,
        .limits = client_limits(prng, server, latency_ticks_max),
        .clients_count = prng.int_at_most(u32, 1, 32),
        .linked = prng.boolean(),
        .start_ticks_max = prng.int_at_most(u32, 0, 2000),
        .ticks_max = 2_000_000,
        .stop_tick = null,
        .drain_ticks_max = 0,
    };
    if (prng.boolean()) plan_stop(prng, &plan, latency_ticks_max); // see there
    if (prng.boolean()) plan.log2_ring_entries = 3;
    return plan;
}

/// What the clients may send and how long they may wait, from the server's
/// configuration and the network's latency.
fn client_limits(
    prng: *Prng,
    server: server_module.Config,
    latency_ticks_max: u32,
) sim_client.Limits {
    // After a stream cut short: the server's last writes and its close,
    // each a network turn late at most, with room for the scheduler.
    const cut_short_silence_ticks_max = (latency_ticks_max + 1) * 4 + 2;
    // A server that waits for the client after a stream cut short is
    // closed by its idle timeout at the soonest: the silence must be less.
    assert(cut_short_silence_ticks_max < server.idle_timeout_ms);
    return .{
        .head_bytes_max = server.head_bytes_max,
        .target_bytes_max = server.target_bytes_max,
        .headers_max = server.headers_max,
        .body_bytes_max = server.body_bytes_max,
        .big_bytes_max = prng.int_at_most(u32, 0, 16 * 1024),
        .idle_ticks_max = server.idle_timeout_ms * 2,
        .pause_ticks_max = server.head_timeout_ms * 2,
        .cut_short_silence_ticks_max = cut_short_silence_ticks_max,
        .drain_event_stream_ticks_max = 2 * server.tick_ms + cut_short_silence_ticks_max,
    };
}

/// When the server is told to stop, and how long its drain may take. Drawn
/// after everything but the ring's size, so adding it changed no other
/// draw.
fn plan_stop(prng: *Prng, plan: *Setup, latency_ticks_max: u32) void {
    const server = &plan.server;
    plan.stop_tick = prng.int_at_most(u64, 0, plan.start_ticks_max + 4000);
    // Never shorter than a fast client's longest wait, so the drain's
    // deadline cuts only slow clients, never a fast one's response. The
    // longest is the largest response through the window: a send per
    // window, each a ring operation with its latency, then the client's
    // turn (on the real port every send waits for its completion).
    const window_bytes = plan.kernel.network.window_bytes;
    const response_ms = (App.answer_bytes_max / window_bytes + 4) * (latency_ticks_max + 1) * 4;
    const waits_ms_max = @max(
        @max(server.head_timeout_ms, server.body_timeout_ms),
        @max(server.send_timeout_ms, response_ms),
    );
    server.drain_timeout_ms = waits_ms_max + prng.int_at_most(u32, 0, 500);
    // Noticed at the next tick; then the deadline; then the closes, each a
    // few network turns late at most. The server counts the deadline in its
    // own ticks, each a sleep that wakes as late as the kernel makes it: a
    // tick lasts up to `tick_ms` and a latency (its timer's completion,
    // then its wake), so the deadline stretches by as much per tick.
    const server_ticks = server.drain_timeout_ms / server.tick_ms + 2 + 6;
    const tick_ticks_max = server.tick_ms + latency_ticks_max + 1;
    plan.drain_ticks_max = server_ticks * tick_ticks_max + (latency_ticks_max + 1) * 8;
}

/// The simulated application: it reads every request body (the model
/// expects the whole body to be seen), then answers deterministically
/// (sim_client.answer) into the connection's scratch memory.
const App = struct {
    canary: bool,
    /// For the waits between pieces of a stream.
    io: std.Io,
    handled: u64 = 0,

    const answer_bytes_max = 16 * 1024 + 256;

    pub const Response = struct {
        status: u16,
        headers: []const http1_response.Header,
        body: []const u8,
    };

    const headers: []const http1_response.Header = &.{
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    const event_headers: []const http1_response.Header = &.{
        .{ .name = "content-type", .value = "Text/Event-Stream; charset=utf-8" },
    };

    /// `request` is either server type's (`ServerPlain`, `ServerLinked`).
    pub fn handle(app: *App, request: anytype) Response {
        var hash = sim_client.checksum_start;
        var body_bytes: u64 = 0;
        var chunk: [512]u8 = undefined;
        for (0..std.math.maxInt(u32)) |_| {
            const got = request.read_body(&chunk) catch |err| return .{
                .status = switch (err) {
                    error.ContentTooLarge => 413,
                    error.BadRequest, error.Disconnected => 400,
                },
                .headers = &.{},
                .body = "",
            };
            if (got == 0) break;
            hash = sim_client.checksum_add(hash, chunk[0..got]);
            body_bytes += got;
        } else unreachable; // a body is bounded by body_bytes_max
        const head = request.head;
        if (sim_client.stream_target(head.path_and_query)) |target| {
            app.handled += 1;
            return app.stream(request, target);
        }
        const result = sim_client.answer(
            head.method_text,
            head.path_and_query,
            body_bytes,
            hash,
            request.scratch,
        );
        app.handled += 1;
        // The canary: one wrong answer, which the clients must notice.
        const wrong = app.canary and app.handled == 2;
        return .{
            .status = if (wrong) result.status +% 1 else result.status,
            .headers = headers,
            .body = result.body,
        };
    }

    const streamed: Response = .{
        .status = server_module.streamed_status,
        .headers = &.{},
        .body = "",
    };

    /// `/stream/` and `/abort/`: the answer in pieces, a `stream_send` each;
    /// after some, a flush and a wait (other fibers run, the timekeeper
    /// ticks), as a stream whose events come over time. `/abort/` gives up
    /// after half of them, without the end.
    fn stream(app: *App, request: anytype, target: sim_client.StreamTarget) Response {
        const path = request.head.path_and_query;
        const whole = sim_client.answer("GET", path, 0, 0, request.scratch).body;
        assert(whole.len == target.stream.bytes);
        const events = target.kind == .events;
        request.stream_start(200, if (events) event_headers else headers) catch |err| switch (err) {
            // Nothing was started: an ordinary answer, which a peer that
            // is gone never gets.
            error.Disconnected => return .{ .status = 500, .headers = &.{}, .body = "" },
            error.HeadRefused => unreachable, // a 200 with plain headers
        };
        if (events) return app.send_events(request, target.stream, whole);
        const pieces = target.stream.pieces;
        const aborted = target.kind == .abort;
        const sent = if (aborted) sim_client.abort_pieces(pieces) else pieces;
        for (0..sent) |index| {
            const piece = sim_client.stream_piece(target.stream.bytes, pieces, @intCast(index));
            request.stream_send(whole[piece.start..piece.end]) catch return streamed;
            if ((piece.end + index) % 3 == 0) {
                request.stream_flush() catch return streamed;
                app.io.sleep(.fromMilliseconds(1), .awake) catch return streamed;
            }
        }
        if (!aborted) request.stream_end() catch return streamed;
        return streamed;
    }

    /// `/events/`: an event per piece, each sent as it is made, round after
    /// round, until a send fails (the client hung up, or a drain ended it).
    /// A HEAD has no events to send, and so nothing to notice a hang-up by:
    /// it ends at once.
    fn send_events(
        app: *App,
        request: anytype,
        round: sim_client.Stream,
        whole: []const u8,
    ) Response {
        if (request.head.method == .head) {
            request.stream_end() catch {};
            return streamed;
        }
        // Half the streams go quiet after each round, as roux's live banner
        // does: seconds of short sleeps that write nothing. A client gone,
        // or a drain's shutdown, is noticed only at the next write, so such
        // a handler outlives a drain's start and is asleep when its
        // deadline cancels it. It cannot
        // stop at the sleep, as roux's `Sleep.millis!` cannot: it re-arms
        // the cancel for its next write. The client sees no difference: it
        // has its round. Which half, the path decides.
        const quiet = round.bytes % 2 == 0;
        // Bounded only to say so: a send fails once the client is gone.
        for (0..std.math.maxInt(u32)) |_| {
            for (0..round.pieces) |index| {
                const piece = sim_client.stream_piece(round.bytes, round.pieces, @intCast(index));
                assert(piece.end > piece.start); // an event is never empty
                request.stream_send(whole[piece.start..piece.end]) catch return streamed;
                request.stream_flush() catch return streamed;
                app.io.sleep(.fromMilliseconds(10), .awake) catch return streamed;
            }
            if (quiet) for (0..quiet_sleeps) |_| {
                app.io.sleep(.fromMilliseconds(10), .awake) catch {
                    app.io.recancel();
                    break;
                };
            };
        } else unreachable;
    }

    /// A quiet stream's silence between rounds, in 10 ms sleeps: longer
    /// than most drains' deadlines (`plan_stop`).
    const quiet_sleeps = 500;

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const ServerPlain = server_module.ServerType(App, .{});
const ServerLinked = server_module.ServerType(App, .{
    .send_then_receive = Evented.sendThenReceive,
});

pub const Outcome = struct {
    exit_code: u8,
    ticks: u64,
    requests: u64,
    refused: u64,
    timeouts: u64,
    responses: u64,
    retries: u64,
    timed_out: u64,
    /// Streams the application gave up on, as the clients received them.
    cut_short: u64,
    /// Drains: runs stopped, connections closed idle at a drain's start
    /// and at its deadline, and new ones closed unserved.
    stopped: u64,
    drain_idle: u64,
    drain_streams: u64,
    drain_cut: u64,
    shut_out: u64,
};

pub fn run(gpa: std.mem.Allocator, seed: u64, canary: bool) !Outcome {
    // One root seed, split per subsystem, so new randomness in one does not
    // reshuffle the others.
    var root = Prng.init(seed);
    var setup_prng = Prng.init(root.next());
    const kernel_seed = root.next();
    const clients_seed = root.next();
    const plan = setup(&setup_prng);

    var kernel = try sim_kernel.Kernel.init(gpa, kernel_seed, plan.kernel);
    defer kernel.deinit(gpa);
    const listener: std.Io.net.Server = .{
        .socket = .{
            .handle = kernel.network.listen(),
            .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 80 } },
        },
        .options = {},
    };
    // The application's `Io` is the process's, set once the port is up.
    var app: App = .{ .canary = canary, .io = undefined };
    if (plan.linked) {
        return run_shard(ServerLinked, gpa, &kernel, &app, listener, plan, clients_seed);
    }
    return run_shard(ServerPlain, gpa, &kernel, &app, listener, plan, clients_seed);
}

/// The server's process on the simulated kernel: the port, then the server
/// on it, as a program runs a shard (static.zig).
fn Shard(comptime Server: type) type {
    return struct {
        const Process = @This();

        gpa: std.mem.Allocator,
        plan: *const Setup,
        app: *App,
        listener: std.Io.net.Server,
        stop: *std.atomic.Value(bool),
        /// While it runs: the server, on the process's stack.
        server: ?*Server = null,
        /// What it left when `run` returned.
        report: Report = .{},

        fn main(shard: *Process) void {
            shard.run() catch |err| std.debug.panic("shard: {t}", .{err});
        }

        fn run(shard: *Process) !void {
            var runtime: Evented = undefined;
            try runtime.init(shard.gpa, .{
                .thread_limit = 0, // one shard, one thread
                .fibers_max = shard.plan.server.fibers_max(),
                .log2_ring_entries = shard.plan.log2_ring_entries,
            });
            defer runtime.deinit();
            const io = runtime.io();
            shard.app.io = io;
            var config = shard.plan.server;
            config.stop = shard.stop;
            var server = try Server.init(shard.gpa, io, shard.app, shard.listener, config);
            defer server.deinit(shard.gpa);
            shard.server = &server;
            defer shard.server = null;
            try server.run();
            shard.report = .{
                .stats = server.stats,
                .draining = server.draining,
                .returned = true,
            };
        }

        /// The server's account, live or as it returned.
        fn now(shard: *const Process) Report {
            const server = shard.server orelse return shard.report;
            return .{ .stats = server.stats, .draining = server.draining, .returned = false };
        }
    };
}

const Report = struct {
    stats: server_module.Stats = .{},
    draining: bool = false,
    returned: bool = false,
};

fn run_shard(
    comptime Server: type,
    gpa: std.mem.Allocator,
    kernel: *sim_kernel.Kernel,
    app: *App,
    listener: std.Io.net.Server,
    plan: Setup,
    clients_seed: u64,
) !Outcome {
    var stop: std.atomic.Value(bool) = .init(false);
    var shard: Shard(Server) = .{
        .gpa = gpa,
        .plan = &plan,
        .app = app,
        .listener = listener,
        .stop = &stop,
    };
    const clients = try gpa.alloc(sim_client.Client, plan.clients_count);
    defer gpa.free(clients);
    var clients_prng = Prng.init(clients_seed);
    for (clients) |*client| {
        const start = clients_prng.int_at_most(u64, 0, plan.start_ticks_max);
        client.init(clients_prng.next(), plan.limits, start);
        client.report_failures = !app.canary;
    }

    kernel.start(Shard(Server).main, &shard);
    const ending = loop(kernel, &shard, clients, plan, &stop);
    var result = outcome(shard.now(), clients, ending.tick, &plan);
    // A run cut short (a failure, the canary) still ends its server, so
    // the process frees what it holds.
    defer if (!kernel.exited()) wind_down(kernel, &stop, plan);
    if (result.exit_code != 0) return result;
    const stop_tick = ending.stop_tick orelse {
        std.debug.print("server: never told to stop by tick {d}\n", .{ending.tick});
        result.exit_code = exit_liveness;
        return result;
    };
    // Told to stop, it must return within its bound.
    const bound = if (plan.stop_tick != null) plan.drain_ticks_max else finish_ticks_max;
    if (!kernel.exited() or ending.tick > stop_tick + bound) {
        std.debug.print("server: not returned by tick {d} (stopped at {d})\n", .{
            stop_tick + bound, stop_tick,
        });
        print_state(kernel, shard.now());
        result.exit_code = exit_liveness;
    } else if (kernel.network.backlog_count != 0) {
        // Refused at once, or answered: never left queued.
        const queued = kernel.network.backlog_count;
        std.debug.print("server: drained, {d} clients left queued\n", .{queued});
        result.exit_code = exit_correctness;
    }
    return result;
}

/// For a run that did not end: what the server counted, and what still
/// waits in the kernel.
fn print_state(kernel: *const sim_kernel.Kernel, report: Report) void {
    const stats = report.stats;
    std.debug.print("server: accepted {d} closed {d} draining {} returned {}\n", .{
        stats.accepted, stats.closed, report.draining, report.returned,
    });
    kernel.print_pending();
}

/// Told to stop, a server's drain ends by its deadline, when it cuts
/// what is left: within that, a tick, and the closes.
fn wind_down(kernel: *sim_kernel.Kernel, stop: *std.atomic.Value(bool), plan: Setup) void {
    stop.store(true, .release);
    const ticks_max = plan.server.drain_timeout_ms + 10 * plan.server.tick_ms + finish_ticks_max;
    for (0..ticks_max) |_| {
        if (kernel.exited()) return;
        kernel.step();
    }
    std.debug.print("server: not returned {d} ticks after a stop, to wind down\n", .{ticks_max});
}

/// Ticks for the clients to read the last bytes of a drained server.
const settle_ticks = 4;

const Ending = struct { tick: u64, stop_tick: ?u64 };

fn loop(
    kernel: *sim_kernel.Kernel,
    shard: anytype,
    clients: []sim_client.Client,
    plan: Setup,
    stop: *std.atomic.Value(bool),
) Ending {
    var stop_tick: ?u64 = null;
    var returned_tick: ?u64 = null;
    for (0..plan.ticks_max) |tick| {
        assert(kernel.tick == tick);
        if (plan.stop_tick == tick) {
            stop.store(true, .release);
            stop_tick = tick;
            for (clients) |*client| client.drain_started(tick);
        }
        for (clients) |*client| client.step(&kernel.network, tick);
        kernel.step();
        if (shard.server) |server| server.check_invariants();
        if (failed(clients)) return .{ .tick = tick, .stop_tick = stop_tick };
        if (returned_tick == null and kernel.exited()) returned_tick = tick;
        if (returned_tick) |returned| {
            if (tick >= returned + settle_ticks) return .{ .tick = tick, .stop_tick = stop_tick };
            continue;
        }
        // Its clients done, a server not told to stop by the plan is told now.
        if (stop_tick == null and plan.stop_tick == null and finished(shard.now(), clients)) {
            stop.store(true, .release);
            stop_tick = tick;
        }
        if (stop_tick) |stopped| {
            const bound = if (plan.stop_tick != null) plan.drain_ticks_max else finish_ticks_max;
            if (tick > stopped + bound) return .{ .tick = tick, .stop_tick = stopped };
        }
    }
    return .{ .tick = plan.ticks_max, .stop_tick = stop_tick };
}

fn finished(report: Report, clients: []const sim_client.Client) bool {
    for (clients) |*client| {
        if (client.state != .done) return false;
    }
    return report.stats.accepted == report.stats.closed;
}

fn failed(clients: []const sim_client.Client) bool {
    for (clients) |*client| {
        if (client.failure != .none) return true;
    }
    return false;
}

fn outcome(
    report: Report,
    clients: []const sim_client.Client,
    ticks: u64,
    plan: *const Setup,
) Outcome {
    const stats = report.stats;
    var result: Outcome = .{
        .exit_code = 0,
        .ticks = ticks,
        .requests = stats.requests,
        .refused = stats.refused,
        .timeouts = stats.timeouts,
        .responses = 0,
        .retries = 0,
        .timed_out = 0,
        .cut_short = 0,
        // Stopped by the plan, in the middle of its work: every run ends
        // drained, but these were cut into.
        .stopped = @intFromBool(plan.stop_tick != null and report.draining),
        .drain_idle = stats.drain_idle,
        .drain_streams = stats.drain_streams,
        .drain_cut = stats.drain_cut,
        .shut_out = 0,
    };
    for (clients, 0..) |*client, index| {
        result.responses += client.stats.responses;
        result.retries += client.stats.retries;
        result.timed_out += client.stats.timed_out;
        result.cut_short += client.stats.cut_short;
        result.shut_out += client.stats.shut_out;
        if (client.failure != .none) {
            if (client.report_failures) std.debug.print("client {d}: {s} at request {d}\n", .{
                index, @tagName(client.failure), client.failure_index,
            });
            result.exit_code = exit_correctness;
        }
    }
    // The pool is exactly what the server says it needs (`Shard.run`).
    if (stats.fiberless != 0) {
        std.debug.print("server: {d} connections found no fiber\n", .{stats.fiberless});
        result.exit_code = exit_correctness;
    }
    if (result.exit_code == 0 and ticks == plan.ticks_max) result.exit_code = exit_liveness;
    return result;
}

pub fn print(seed: u64, result: Outcome) void {
    std.debug.print("seed={d} exit={d} ticks={d} requests={d} responses={d} refused={d} ", .{
        seed, result.exit_code, result.ticks, result.requests, result.responses, result.refused,
    });
    std.debug.print("retries={d} timeouts={d}/{d} cut_short={d} ", .{
        result.retries, result.timed_out, result.timeouts, result.cut_short,
    });
    std.debug.print("stopped={d} drain_idle={d} drain_streams={d} drain_cut={d} ", .{
        result.stopped, result.drain_idle, result.drain_streams, result.drain_cut,
    });
    std.debug.print("shut_out={d}\n", .{result.shut_out});
}

fn add(total: *Outcome, result: Outcome) void {
    inline for (@typeInfo(Outcome).@"struct".field_names) |name| {
        if (comptime std.mem.eql(u8, name, "exit_code")) continue;
        @field(total, name) += @field(result, name);
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.skip();
    var seed_start: u64 = 0;
    var seeds: u64 = 1;
    var canary = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--seed") or std.mem.eql(u8, arg, "--start")) {
            seed_start = try std.fmt.parseInt(u64, args.next() orelse return error.Usage, 10);
        } else if (std.mem.eql(u8, arg, "--seeds")) {
            seeds = try std.fmt.parseInt(u64, args.next() orelse return error.Usage, 10);
        } else if (std.mem.eql(u8, arg, "--canary")) {
            canary = true;
        } else return error.Usage;
    }
    const gpa = std.heap.page_allocator;
    // The sweep's totals show which paths the seeds reached.
    var total: Outcome = std.mem.zeroes(Outcome);
    for (seed_start..seed_start + seeds) |seed| {
        const result = try run(gpa, seed, canary);
        if (seeds == 1 or result.exit_code != 0) print(seed, result);
        if (result.exit_code != 0) std.process.exit(result.exit_code);
        add(&total, result);
    }
    std.debug.print("{d} seeds from {d}: all passed\ntotal: ", .{ seeds, seed_start });
    print(seed_start, total);
}

test "sim: a sweep of seeds passes" {
    for (0..20) |seed| {
        const result = try run(std.testing.allocator, seed, false);
        if (result.exit_code != 0) print(seed, result);
        try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    }
}

test "sim: the canary is caught" {
    var caught: u32 = 0;
    for (0..10) |seed| {
        const result = try run(std.testing.allocator, seed, true);
        if (result.exit_code == exit_correctness) caught += 1;
    }
    try std.testing.expect(caught > 0);
}

test "sim: a seed replays exactly" {
    const first = try run(std.testing.allocator, 7, false);
    const second = try run(std.testing.allocator, 7, false);
    try std.testing.expectEqual(first.ticks, second.ticks);
    try std.testing.expectEqual(first.responses, second.responses);
    try std.testing.expectEqual(first.requests, second.requests);
}

// --- regressions: one scenario forced, over seeds -----------------------
//
// A seed is not a regression test: it names one run of the simulator as
// it is, and any change to what draws from it (the plan, the clients, the
// kernel) makes it another run. A bug a sweep found stays found by a test
// that forces its scenario with clients driven by hand, the kernel's
// choices still drawn, over enough seeds to reach its interleaving, and
// that says it reached it. Each was checked by putting its bug back.

/// A plan not drawn, for a scenario's test: generous timeouts, a window
/// of 64 bytes, the kernel's latencies up to 3 ticks.
fn scripted_plan(connections_max: u32) Setup {
    const server: server_module.Config = .{
        .connections_max = connections_max,
        .head_bytes_max = 1024,
        .target_bytes_max = 256,
        .headers_max = 16,
        .body_bytes_max = 1024,
        .response_head_bytes_max = 512,
        .send_bytes_max = 1024,
        .scratch_bytes_max = App.answer_bytes_max,
        .head_timeout_ms = 5000,
        .body_timeout_ms = 5000,
        .idle_timeout_ms = 5000,
        .send_timeout_ms = 5000,
        .tick_ms = 10,
        .tcp_nodelay = false,
    };
    return .{
        .server = server,
        .kernel = .{
            .tick_ns = tick_ns,
            .latency_ticks_max = 3,
            .operations_max = 4 * server.fibers_max() + 16,
            .network = .{ .connections_max = 8, .backlog_max = 8, .window_bytes = 64 },
        },
        .log2_ring_entries = 12,
        .limits = undefined, // no generated clients
        .clients_count = 0,
        .linked = false,
        .start_ticks_max = 0,
        .ticks_max = 20_000,
        .stop_tick = null,
        .drain_ticks_max = 0,
    };
}

/// The server on the simulated kernel, its clients the test's own, the
/// server's invariants checked after every tick.
const Scripted = struct {
    plan: Setup,
    kernel: sim_kernel.Kernel,
    app: App,
    stop: std.atomic.Value(bool),
    shard: Shard(ServerPlain),

    /// In place: the shard holds pointers into it.
    fn init(scripted: *Scripted, gpa: std.mem.Allocator, seed: u64, plan: Setup) !void {
        scripted.plan = plan;
        scripted.kernel = try .init(gpa, seed, plan.kernel);
        scripted.app = .{ .canary = false, .io = undefined };
        scripted.stop = .init(false);
        const listener: std.Io.net.Server = .{
            .socket = .{
                .handle = scripted.kernel.network.listen(),
                .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 80 } },
            },
            .options = {},
        };
        scripted.shard = .{
            .gpa = gpa,
            .plan = &scripted.plan,
            .app = &scripted.app,
            .listener = listener,
            .stop = &scripted.stop,
        };
        scripted.kernel.start(Shard(ServerPlain).main, &scripted.shard);
    }

    fn deinit(scripted: *Scripted, gpa: std.mem.Allocator) void {
        scripted.kernel.deinit(gpa);
        scripted.* = undefined;
    }

    fn tick(scripted: *Scripted) void {
        scripted.kernel.step();
        if (scripted.shard.server) |server| server.check_invariants();
    }

    fn ticks(scripted: *Scripted, count: u32) void {
        for (0..count) |_| scripted.tick();
    }

    /// Stop the server and run it until it returns.
    fn finish(scripted: *Scripted) !void {
        scripted.stop.store(true, .release);
        for (0..scripted.plan.ticks_max) |_| {
            if (scripted.kernel.exited()) return;
            scripted.tick();
        }
        return error.TestServerNeverReturned;
    }
};

/// A client the test drives: what it received, kept whole.
const HandClient = struct {
    connection: u32,
    received: [4096]u8 = undefined,
    received_count: u32 = 0,

    fn connect(network: *sim_kernel.Network) HandClient {
        return .{ .connection = network.client_connect().? };
    }

    fn send(client: *HandClient, network: *sim_kernel.Network, bytes: []const u8) void {
        const sent = network.client_send(client.connection, bytes);
        assert(sent == bytes.len); // the window has room for a test's request
    }

    fn receive(client: *HandClient, network: *sim_kernel.Network) void {
        const room = client.received[client.received_count..];
        client.received_count += network.client_receive(client.connection, room);
    }

    fn text(client: *const HandClient) []const u8 {
        return client.received[0..client.received_count];
    }

    /// Ticks until `done` holds of what it received, or the end is seen.
    fn await_until(
        client: *HandClient,
        scripted: *Scripted,
        comptime done: fn ([]const u8) bool,
    ) !void {
        for (0..scripted.plan.ticks_max) |_| {
            client.receive(&scripted.kernel.network);
            if (done(client.text())) return;
            if (scripted.kernel.network.client_sees_end(client.connection)) return;
            scripted.tick();
        }
        return error.TestClientNeverAnswered;
    }
};

/// Responses ending at their head (a 204, the only kind these tests ask
/// for when they count them), as many as `count`.
fn heads_at_least(comptime count: u32) fn ([]const u8) bool {
    return struct {
        fn done(bytes: []const u8) bool {
            return std.mem.count(u8, bytes, "\r\n\r\n") >= count;
        }
    }.done;
}

// A close waits for its completion on io_uring, and other fibers run
// meanwhile: its slot is then neither open nor free. The invariant must hold
// through it,
// and the test must see the window open at least once.
test "sim: a slot whose close is in flight is counted, neither open nor free" {
    const gpa = std.testing.allocator;
    var windows: u32 = 0;
    for (1..33) |seed| {
        var scripted: Scripted = undefined;
        try scripted.init(gpa, seed, scripted_plan(2));
        defer scripted.deinit(gpa);
        const network = &scripted.kernel.network;
        var client: HandClient = .connect(network);
        client.send(network, "GET /s/204 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        for (0..scripted.plan.ticks_max) |_| {
            client.receive(network);
            if (network.client_sees_end(client.connection)) break;
            scripted.tick();
            const server = scripted.shard.server orelse continue;
            windows += @intFromBool(server.closing_count > 0);
        }
        try std.testing.expect(std.mem.startsWith(u8, client.text(), "HTTP/1.1 204"));
        network.client_close(client.connection);
        try scripted.finish();
    }
    try std.testing.expect(windows > 0);
}

// A drain closes its idle connections before its first wait (the cancel
// of its acceptor waits for the acceptor's end): otherwise the server runs
// draining with an idle connection open, which its invariant forbids.
test "sim: a drain shuts its idle connections before it waits" {
    const gpa = std.testing.allocator;
    for (1..33) |seed| {
        var scripted: Scripted = undefined;
        try scripted.init(gpa, seed, scripted_plan(2));
        defer scripted.deinit(gpa);
        const network = &scripted.kernel.network;
        var client: HandClient = .connect(network);
        client.send(network, "GET /s/204 HTTP/1.1\r\nHost: a\r\n\r\n");
        try client.await_until(&scripted, heads_at_least(1));
        scripted.ticks(30); // idle, kept alive
        try scripted.finish();
        try std.testing.expectEqual(1, scripted.shard.report.stats.drain_idle);
        client.receive(network);
        try std.testing.expect(network.client_sees_end(client.connection));
        network.client_close(client.connection);
    }
}

// Slowloris (2009): a head sent a byte at a time, each just inside the head's
// timeout, so a timeout per read never fires. A server alone on the internet
// is taken down by enough of them, each holding a slot. The head's timeout
// bounds the whole head: the slot is free one timeout after its first byte,
// whatever the pace.
test "sim: a head trickled a byte at a time is cut at one head's timeout" {
    const gpa = std.testing.allocator;
    const value: [512]u8 = @splat('a');
    const head = "GET / HTTP/1.1\r\nHost: a\r\nX-Slow: " ++ value;
    for (1..17) |seed| {
        var plan = scripted_plan(1);
        plan.server.head_timeout_ms = 500;
        var scripted: Scripted = undefined;
        try scripted.init(gpa, seed, plan);
        defer scripted.deinit(gpa);
        const network = &scripted.kernel.network;
        var client: HandClient = .connect(network);
        // A byte each 400 ticks: one timeout per read never fires.
        var sent: u32 = 0;
        var cut_tick: ?u64 = null;
        for (0..scripted.plan.ticks_max) |tick| {
            if (tick % 400 == 0 and sent < head.len) {
                client.send(network, head[sent..][0..1]);
                sent += 1;
            }
            client.receive(network);
            if (network.client_sees_end(client.connection)) {
                cut_tick = tick;
                break;
            }
            scripted.tick();
        }
        // One timeout, in ticks of the server's clock (each up to a tick
        // and the kernel's latency late), with room for the shutdown.
        const server = plan.server;
        const server_ticks = server.head_timeout_ms / server.tick_ms + 2;
        const bound = server_ticks * (server.tick_ms + plan.kernel.latency_ticks_max + 1) + 64;
        try std.testing.expect(cut_tick != null);
        try std.testing.expect(cut_tick.? <= bound);
        try std.testing.expectEqual(1, scripted.shard.now().stats.timeouts);
        try std.testing.expectEqual(0, client.received_count); // cut, not answered
        network.client_close(client.connection);
        try scripted.finish();
    }
}

// A full server evicts its longest-idle connection for a new one. On
// io_uring the idle wait may already hold the client's next request,
// taken by the kernel before the fiber runs: served, its body would be read
// from a socket shut for reading, and a valid POST answered 400. It must
// close unanswered instead, which the
// client retries, and the test must reach that race at least once.
test "sim: an idle connection evicted as its next request arrives closes unanswered" {
    const gpa = std.testing.allocator;
    var raced: u64 = 0;
    for (1..65) |seed| {
        var scripted: Scripted = undefined;
        try scripted.init(gpa, seed, scripted_plan(1));
        defer scripted.deinit(gpa);
        const network = &scripted.kernel.network;
        var idle: HandClient = .connect(network);
        idle.send(network, "GET /s/204 HTTP/1.1\r\nHost: a\r\n\r\n");
        try idle.await_until(&scripted, heads_at_least(1));
        scripted.ticks(20);
        // In one tick: the idle client's next request, and a new client
        // the full server must evict for.
        idle.send(network, "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\n");
        var fresh: HandClient = .connect(network);
        fresh.send(network, "GET /s/204 HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n");
        scripted.ticks(5);
        if (!network.client_sees_end(idle.connection)) idle.send(network, "abcd");
        try idle.await_until(&scripted, heads_at_least(2));
        try fresh.await_until(&scripted, heads_at_least(1));
        try std.testing.expect(std.mem.startsWith(u8, fresh.text(), "HTTP/1.1 204"));
        // Its second answer, if any, is the POST's: never a 400.
        const first_end = std.mem.indexOf(u8, idle.text(), "\r\n\r\n").? + 4;
        const second = idle.text()[first_end..];
        try std.testing.expect(second.len == 0 or std.mem.startsWith(u8, second, "HTTP/1.1 200"));
        raced += scripted.shard.now().stats.shut_with_request;
        network.client_close(idle.connection);
        network.client_close(fresh.connection);
        try scripted.finish();
    }
    try std.testing.expect(raced > 0);
}
