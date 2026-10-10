//! The simulator: the evented server, unchanged, on a deterministic
//! `std.Io` (sim_io.zig), from one seed.
//!
//!   fourneau-sim --seed N              one run, replayed exactly
//!   fourneau-sim --seeds COUNT [--start N] [--canary]
//!
//! The seed picks the configuration (swarm testing: slot counts, limits,
//! timeouts, window sizes, latencies), the clients' scripts, every network
//! choice and every scheduling choice between fibers. Each tick (one
//! simulated millisecond), clients act, then every fiber that can run does,
//! in an order drawn from the seed. The server's invariants are checked
//! between ticks; the clients check every response against the model.
//!
//! Exit codes, so a sweep sorts its failures: 0 passed, 127 crash (a
//! panic: an assertion), 128 liveness, 129 correctness. `--canary` makes
//! the application answer one request wrongly; the sweep must catch it.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("prng.zig").Prng;
const sim_io = @import("sim_io.zig");
const server_module = @import("server.zig");
const sim_client = @import("sim_client.zig");
const http1_response = @import("http1_response.zig");

pub const exit_liveness: u8 = 128;
pub const exit_correctness: u8 = 129;

const tick_ns = std.time.ns_per_ms;
/// Fiber switches allowed in one tick: far beyond any real tick's work, so
/// reaching it means fibers wake each other without end (a livelock).
const runs_per_tick_max = 1_000_000;

/// Everything a seed decides before the run.
pub const Setup = struct {
    server: server_module.Config,
    network: sim_io.Options,
    limits: sim_client.Limits,
    clients_count: u32,
    /// Both of the server's ways to finish a turn: a write then a read, or
    /// the model of the port's linked send-then-receive.
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
    var plan: Setup = .{
        .server = server,
        .network = .{
            // The server's own count, and the fiber `run` itself runs on:
            // exact, so every interleaving tests the count.
            .fibers_max = server.fibers_max() + 1,
            .stack_bytes = 512 * 1024,
            .connections_max = 64,
            .window_bytes = window_bytes,
            .latency_ticks_max = latency_ticks_max,
            .backlog_max = prng.int_at_most(u32, 1, 64),
            .tick_ns = tick_ns,
            .realtime_seconds_start = 1_791_072_000 + prng.int_less_than(u64, 1_000_000),
        },
        .limits = client_limits(prng, server, latency_ticks_max),
        .clients_count = prng.int_at_most(u32, 1, 32),
        .linked = prng.boolean(),
        .start_ticks_max = prng.int_at_most(u32, 0, 2000),
        .ticks_max = 2_000_000,
        .stop_tick = null,
        .drain_ticks_max = 0,
    };
    if (prng.boolean()) plan_stop(prng, &plan, latency_ticks_max); // last: see there
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
/// after everything else, so a seed that does not stop replays as before.
fn plan_stop(prng: *Prng, plan: *Setup, latency_ticks_max: u32) void {
    const server = &plan.server;
    plan.stop_tick = prng.int_at_most(u64, 0, plan.start_ticks_max + 4000);
    // Never shorter than a fast client's longest wait, so the drain's
    // deadline cuts only slow clients, never a fast one's response.
    const waits_ms_max = @max(
        @max(server.head_timeout_ms, server.body_timeout_ms),
        server.send_timeout_ms,
    );
    server.drain_timeout_ms = waits_ms_max + prng.int_at_most(u32, 0, 500);
    // Noticed at the next tick; then the deadline; then the closes, each a
    // few network turns late at most.
    plan.drain_ticks_max = 6 * server.tick_ms + server.drain_timeout_ms +
        (latency_ticks_max + 1) * 8;
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
        // Bounded only to say so: a send fails once the client is gone.
        for (0..std.math.maxInt(u32)) |_| {
            for (0..round.pieces) |index| {
                const piece = sim_client.stream_piece(round.bytes, round.pieces, @intCast(index));
                assert(piece.end > piece.start); // an event is never empty
                request.stream_send(whole[piece.start..piece.end]) catch return streamed;
                request.stream_flush() catch return streamed;
                app.io.sleep(.fromMilliseconds(10), .awake) catch return streamed;
            }
        } else unreachable;
    }

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const ServerPlain = server_module.ServerType(App, .{});
const ServerLinked = server_module.ServerType(App, .{ .send_then_receive = send_then_receive });

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
    const network_seed = root.next();
    const clients_seed = root.next();
    const plan = setup(&setup_prng);

    var sim = try sim_io.Sim.init(gpa, network_seed, plan.network);
    defer sim.deinit(gpa);
    var app: App = .{ .canary = canary, .io = sim.io() };
    const listener: std.Io.net.Server = .{
        .socket = .{
            .handle = sim_io.listener_fd,
            .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 80 } },
        },
        .options = {},
    };
    if (plan.linked) return run_server(ServerLinked, gpa, &sim, &app, listener, plan, clients_seed);
    return run_server(ServerPlain, gpa, &sim, &app, listener, plan, clients_seed);
}

fn run_server(
    comptime Server: type,
    gpa: std.mem.Allocator,
    sim: *sim_io.Sim,
    app: *App,
    listener: std.Io.net.Server,
    plan: Setup,
    clients_seed: u64,
) !Outcome {
    const io = sim.io();
    var stop: std.atomic.Value(bool) = .init(false);
    var config = plan.server;
    config.stop = &stop;
    var server = try Server.init(gpa, io, app, listener, config);
    defer server.deinit(gpa);

    const clients = try gpa.alloc(sim_client.Client, plan.clients_count);
    defer gpa.free(clients);
    var clients_prng = Prng.init(clients_seed);
    for (clients) |*client| {
        const start = clients_prng.int_at_most(u64, 0, plan.start_ticks_max);
        client.init(clients_prng.next(), plan.limits, start);
        client.report_failures = !app.canary;
    }

    // The server runs on a fiber; this loop is the simulator's own. Its
    // future is never awaited: the simulator's loop is no fiber. A run
    // ends when the clients do, or, told to stop, when the server returns.
    const running = try io.concurrent(Server.run, .{&server});
    const run_task = running.any_future.?;
    const ticks = loop(sim, &server, clients, plan, &stop, run_task);
    var result = outcome(&server, clients, ticks, plan.ticks_max);
    if (result.exit_code == 0 and plan.stop_tick != null) {
        const stop_tick = plan.stop_tick.?;
        // Told to stop, it must return within the drain's bound.
        if (!sim.finished(run_task) or ticks > stop_tick + plan.drain_ticks_max) {
            std.debug.print("server: not drained by tick {d} (stopped at {d})\n", .{
                stop_tick + plan.drain_ticks_max, stop_tick,
            });
            result.exit_code = exit_liveness;
        } else if (sim.backlog_count != 0) {
            // Refused at once, or answered: never left queued.
            std.debug.print("server: drained, {d} clients left queued\n", .{sim.backlog_count});
            result.exit_code = exit_correctness;
        }
    }
    return result;
}

/// Ticks for the clients to read the last bytes of a drained server.
const settle_ticks = 4;

fn loop(
    sim: *sim_io.Sim,
    server: anytype,
    clients: []sim_client.Client,
    plan: Setup,
    stop: *std.atomic.Value(bool),
    run_task: *std.Io.AnyFuture,
) u64 {
    var returned_tick: ?u64 = null;
    for (0..plan.ticks_max) |tick| {
        sim.tick_now = tick;
        if (plan.stop_tick == tick) {
            stop.store(true, .release);
            for (clients) |*client| client.drain_started(tick);
        }
        for (clients) |*client| client.step(sim, tick);
        const runs = sim.run_ready(runs_per_tick_max);
        assert(runs < runs_per_tick_max); // fibers woke each other without end
        server.check_invariants();
        if (failed(clients)) return tick;
        if (returned_tick == null and sim.finished(run_task)) returned_tick = tick;
        if (returned_tick) |returned| {
            if (tick >= returned + settle_ticks) return tick;
            continue;
        }
        // One that will be stopped runs until it returns.
        if (plan.stop_tick == null and finished(server, clients)) return tick;
        if (plan.stop_tick) |stop_tick| {
            if (tick > stop_tick + plan.drain_ticks_max) return tick; // judged by the caller
        }
    }
    return plan.ticks_max;
}

fn finished(server: anytype, clients: []const sim_client.Client) bool {
    for (clients) |*client| {
        if (client.state != .done) return false;
    }
    const accepted = server.stats.accepted;
    return accepted == server.stats.closed;
}

fn failed(clients: []const sim_client.Client) bool {
    for (clients) |*client| {
        if (client.failure != .none) return true;
    }
    return false;
}

fn outcome(
    server: anytype,
    clients: []const sim_client.Client,
    ticks: u64,
    ticks_max: u64,
) Outcome {
    var result: Outcome = .{
        .exit_code = 0,
        .ticks = ticks,
        .requests = server.stats.requests,
        .refused = server.stats.refused,
        .timeouts = server.stats.timeouts,
        .responses = 0,
        .retries = 0,
        .timed_out = 0,
        .cut_short = 0,
        .stopped = @intFromBool(server.draining),
        .drain_idle = server.stats.drain_idle,
        .drain_streams = server.stats.drain_streams,
        .drain_cut = server.stats.drain_cut,
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
    // The pool is exactly what the server says it needs (`setup`).
    if (server.stats.fiberless != 0) {
        std.debug.print("server: {d} connections found no fiber\n", .{server.stats.fiberless});
        result.exit_code = exit_correctness;
    }
    if (result.exit_code == 0 and ticks == ticks_max) result.exit_code = exit_liveness;
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

/// The model of the port's `sendThenReceive`: every byte sent, then one
/// read; a send that cannot finish fails the pair, as the link cancels the
/// port's receive.
fn send_then_receive(
    io: std.Io,
    socket: std.Io.net.Socket.Handle,
    bytes: []const u8,
    buffer: []u8,
) error{ ConnectionResetByPeer, Canceled, Unexpected }!usize {
    assert(bytes.len > 0);
    assert(buffer.len > 0);
    var sent: usize = 0;
    for (0..bytes.len + 1) |_| {
        if (sent == bytes.len) break;
        const result = io.operate(.{ .net_write = .{
            .socket_handle = socket,
            .header = bytes[sent..],
            .data = &.{""},
        } }) catch return error.Canceled;
        const written = result.net_write catch return error.ConnectionResetByPeer;
        if (written == 0) return error.ConnectionResetByPeer;
        sent += written;
    } else unreachable; // each pass sends a byte or fails
    var parts = [_][]u8{buffer};
    const result = io.operate(.{ .net_read = .{ .socket_handle = socket, .data = &parts } }) catch
        return error.Canceled;
    const read = result.net_read catch return error.ConnectionResetByPeer;
    assert(read.data_len <= buffer.len);
    return read.data_len;
}
