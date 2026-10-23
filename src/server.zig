//! fourneau on green threads, HTTP/1.1 only: one fiber per connection,
//! written as plain blocking-style code against `std.Io`, on our vendored
//! io_uring `Evented`.
//!
//! A server is one shard: every fiber runs on one thread, and a machine
//! runs one shard per thread it gives the server, sharing nothing. So
//! nothing here is atomic or locked: fibers switch only where one waits,
//! and a step between two waits runs whole. `run` asserts it is never
//! called on two threads.
//!
//! Data-oriented, after Kelley and Muratori:
//! - Every byte a connection uses is carved at startup from one allocation
//!   per kind (receive buffers, header tables, send buffers, scratch),
//!   so N connections are N strides through flat arrays, and nothing is
//!   allocated per request.
//! - Deadlines are separate arrays of `u32` ticks, scanned by the
//!   timekeeper a tick at a time: no connection keeps a timer, and no
//!   request reads the clock (the tick is the time).
//! - The protocol is a sans-IO state machine (http1_head): a fiber only
//!   decides when to read more.
//!
//! A connection's life: accepted into a free slot, requests one after
//! another (head, the application, the response), then closed and its slot
//! freed. The application pulls the request body itself, so a handler that
//! refuses never causes a byte of body to be read. Bodies are framed by
//! `Content-Length` only: a chunked request is answered 411 and closed.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const stdx = @import("stdx.zig");
const maybe = stdx.maybe;
const http1_head = @import("http1_head.zig");
const http1_response = @import("http1_response.zig");
const http_date = @import("http_date.zig");

const Io = std.Io;
const net = Io.net;
const Header = http1_head.Header;

const log = std.log.scoped(.fourneau);

pub const Config = struct {
    connections_max: u32 = 1024,
    head_bytes_max: u32 = 16 * 1024,
    target_bytes_max: u32 = 8 * 1024,
    headers_max: u16 = 64,
    /// A `Content-Length` beyond it is 413.
    body_bytes_max: u32 = 1024 * 1024,
    response_head_bytes_max: u32 = 8 * 1024,
    /// Each connection's send buffer: responses wait here, and go out in
    /// one write when the connection would otherwise block on a read, so
    /// pipelined requests are answered in one send, not one per response.
    send_bytes_max: u32 = 16 * 1024,
    /// Memory a handler may use for its request and response bodies, per
    /// connection.
    scratch_bytes_max: u32 = 64 * 1024,
    head_timeout_ms: u32 = 10_000,
    idle_timeout_ms: u32 = 30_000,
    body_timeout_ms: u32 = 30_000,
    send_timeout_ms: u32 = 30_000,
    /// How often the timekeeper looks at the deadlines.
    tick_ms: u32 = 100,
    /// A bound on the keep-alive loop: generous, and asserted.
    requests_per_connection_max: u32 = 1 << 24,

    pub fn assert_valid(config: Config) void {
        assert(config.connections_max > 0);
        assert(config.response_head_bytes_max >= 256);
        // A head always fits whole in an empty send buffer.
        assert(config.send_bytes_max >= config.response_head_bytes_max);
        assert(config.tick_ms > 0);
        assert(config.tick_ms <= config.head_timeout_ms);
        config.head_limits().assert_valid();
        // Every connection's scratch starts aligned (`scratch_align`).
        assert(config.scratch_bytes_max % scratch_align == 0);
        // Each slab is one mapping of at most 4 GiB (`u32` strides).
        assert(@as(u64, config.connections_max) * config.scratch_bytes_max <= std.math.maxInt(u32));
        assert(@as(u64, config.connections_max) * config.send_bytes_max <= std.math.maxInt(u32));
        assert(@as(u64, config.connections_max) * config.recv_bytes() <= std.math.maxInt(u32));
    }

    /// The fibers a server runs at once, at most: one per connection slot
    /// and the acceptor (the timekeeper runs on `run`'s caller). A slot is
    /// given back as its fiber's last act, so a new connection never needs
    /// a fiber before the last one is free. An `Io`'s fiber pool is the sum
    /// of what runs on it.
    pub fn fibers_max(config: Config) u32 {
        return config.connections_max + 1;
    }

    fn head_limits(config: Config) http1_head.Limits {
        return .{
            .head_bytes_max = config.head_bytes_max,
            .target_bytes_max = config.target_bytes_max,
            .headers_max = config.headers_max,
            .body_bytes_max = config.body_bytes_max,
        };
    }

    /// Room past the largest head, so a full head never leaves no room to
    /// read the start of a body.
    fn recv_bytes(config: Config) u32 {
        return config.head_bytes_max + recv_window_bytes;
    }
};

const recv_window_bytes = 4096;

/// A full server's eviction closes this many of its longest idle at once,
/// at most: a scan of every slot admits a batch of new clients.
const evict_batch_max = 64;

/// An eighth of the slots, up to `evict_batch_max`: a small server closes
/// one at a time, as few idle clients as it can.
fn evict_batch(connections_max: u32) u32 {
    assert(connections_max > 0);
    return std.math.clamp(connections_max / 8, 1, evict_batch_max);
}

/// A request's scratch starts at a multiple of this: an application may
/// lay a table of its own there.
pub const scratch_align = 16;
/// The slabs a scratch is cut from start on a page.
const slab_align = std.heap.page_size_min;

/// A slab every slot takes a stride of, its pages untouched until a slot
/// first writes them (`stdx.alloc_untouched` says why).
fn slab_alloc(gpa: std.mem.Allocator, comptime T: type, count: usize) ![]align(slab_align) T {
    return stdx.alloc_untouched(gpa, T, .fromByteUnits(slab_align), count);
}

fn slab_free(gpa: std.mem.Allocator, comptime T: type, slab: []align(slab_align) T) void {
    stdx.free_untouched(gpa, T, .fromByteUnits(slab_align), slab);
}

pub const BodyError = error{Disconnected};

/// What the server's type is built with: what its `Io` offers beyond
/// `std.Io`, known at compile time, so a call is direct.
pub const Options = struct {
    /// Send waiting responses and then receive, as one operation, where
    /// the `Io` has one (our io_uring port: `Evented.sendThenReceive`, one
    /// completion per turn instead of two). Null: a write, then a read.
    send_then_receive: ?SendThenReceive = null,
};

/// Send all of the bytes, then receive into the buffer; the count received.
pub const SendThenReceive = fn (
    io: Io,
    socket: net.Socket.Handle,
    bytes: []const u8,
    buffer: []u8,
) error{ ConnectionResetByPeer, Canceled, Unexpected }!usize;

/// Responses go out whole, so Nagle's algorithm only delays them: with
/// pipelined requests it held each response after the first for the
/// client's delayed ACK, 40 ms (50k requests/s at pipeline 8 before
/// this). A plain system call: `std.Io` has no socket options.
fn no_delay(fd: std.posix.socket_t) void {
    const linux = std.os.linux;
    const on: u32 = 1;
    const result = linux.setsockopt(
        fd,
        linux.IPPROTO.TCP,
        linux.TCP.NODELAY,
        std.mem.asBytes(&on),
        4,
    );
    if (linux.errno(result) != .SUCCESS) log.warn("TCP_NODELAY: {t}", .{linux.errno(result)});
}

pub const Stats = struct {
    accepted: u64 = 0,
    closed: u64 = 0,
    requests: u64 = 0,
    refused: u64 = 0,
    timeouts: u64 = 0,
    /// Idle keep-alive connections closed to admit new ones.
    evicted: u64 = 0,
    /// Connections closed because the `Io` had no fiber for them: its pool
    /// is smaller than `Config.fibers_max` says. Always 0 when it is not.
    fiberless: u64 = 0,
    /// Requests that arrived as their connection was shut while idle
    /// (eviction), closed unanswered (`shut_idle`).
    shut_with_request: u64 = 0,
};

/// The address of this, per thread, names the thread a shard runs on.
threadlocal var thread_marker: u8 = 0;

/// `App` provides:
///   const Response: struct with `status: u16`, `headers: []const
///     http1_response.Header` and `body: []const u8`;
///   fn handle(app: *App, request: *Request) App.Response, called on the
///     connection's fiber: it may block (yield) as long as it likes;
///   fn release(app: *App, response: *App.Response) void, once sent.
/// `handle` runs on many fibers at once, all on the shard's thread: `App`
/// may hold per-shard state; per-request memory is `request.scratch`.
pub fn ServerType(comptime App: type, comptime type_options: Options) type {
    return struct {
        const Server = @This();

        io: Io,
        app: *App,
        config: Config,
        listener: net.Server,
        connections: []Connection,
        /// The tick at which each slot's current wait expires; 0 when it is
        /// not waiting. The timekeeper's array.
        deadlines: []u32,
        /// The tick by which each slot's current phase (a request's head)
        /// must end, however its bytes trickle in; 0 outside one. Every
        /// wait in a phase is armed no later than it, so a client sending a
        /// byte just inside each read's timeout (Slowloris) holds its slot
        /// for one phase's timeout, not hours.
        phase_deadlines: []u32,
        /// The tick since which each slot has waited, idle, for its next
        /// request (its last response sent); 0 when it is not idle. When
        /// every slot is taken, the oldest are closed to admit new clients.
        idle_since: []u32,
        /// Ticks since `run`, counted by the timekeeper: the server's clock.
        /// Starts at 1, so a deadline is never 0.
        tick: u32 = 1,
        /// The longest wait, in ticks (`ticks_for` the longest timeout).
        ticks_max: u32,
        /// The thread the shard runs on (`thread_marker`), from `run`.
        thread: ?*const u8 = null,
        free: []u32,
        free_count: u32,
        /// Slots between `open` and free: their socket's close is in
        /// flight, and on io_uring a close waits for its completion, so
        /// other fibers run meanwhile.
        closing_count: u32 = 0,
        /// Slots shut while idle (`shut_idle`) and not yet free: each frees
        /// as its fiber closes.
        shut_count: u32 = 0,
        /// Counts free slots: the acceptor waits on it, so a full server
        /// stops accepting and the kernel's backlog holds new clients.
        free_slots: Io.Semaphore,
        group: Io.Group = .init,
        /// The slabs every connection takes its strides of.
        recv_slab: []align(slab_align) u8 = &.{},
        send_slab: []align(slab_align) u8 = &.{},
        scratch_slab: []align(slab_align) u8 = &.{},
        headers_slab: []align(slab_align) Header = &.{},
        stats: Stats = .{},
        /// The Date header, refreshed by the timekeeper each tick, not read
        /// from the clock per response (that was 6% of a pipelined
        /// profile). One copy: a response is formatted between two
        /// waits, so the timekeeper never runs in the middle of one.
        date_text: [http_date.length]u8 = undefined,
        date_second: u64 = 0,

        pub const Request = struct {
            head: *const http1_head.Head,
            /// This connection's memory for the request and response
            /// bodies: valid until the response has been sent.
            scratch: []u8,
            connection: *Connection,

            /// Read up to `buffer.len` body bytes; 0 at the end of the
            /// body. Sends `100 Continue` first if the client waits for it.
            pub fn read_body(request: *Request, buffer: []u8) BodyError!usize {
                return request.connection.read_body(buffer);
            }
        };

        /// One connection's state and its strides of the flat arrays.
        const Connection = struct {
            server: *Server,
            index: u32,
            stream: net.Stream,
            open: bool,
            recv: []u8,
            recv_used: u32,
            parser: http1_head.Parser,
            /// Responses (and 100 Continue) not yet sent: flushed before
            /// any read that may block, and before close.
            send: []u8,
            send_used: u32,
            scratch: []u8,
            head: http1_head.Head,
            /// Where the next request starts in `recv`, once this one's
            /// body is consumed.
            request_end: u32,
            /// The body's bytes not yet read by the handler.
            body_remaining: u64,
            /// Shut while idle (eviction): it serves no further request.
            /// The shut ends its wait for one, but on io_uring the wait may
            /// already have its bytes, taken by the kernel before the fiber
            /// runs again; serving them would read a body from a socket
            /// shut for reading, where an empty read is the end (a 400 for
            /// a valid request). Closed unanswered instead: the race every
            /// keep-alive close has, which clients retry (RFC 9112, 9.3.1).
            shut_idle: bool,
            continue_sent: bool,
            keep_alive: bool,
            requests: u32,

            fn read_body(connection: *Connection, buffer: []u8) BodyError!usize {
                assert(buffer.len > 0);
                const remaining = connection.body_remaining;
                if (remaining == 0) return 0;
                const leftover = connection.recv_used - connection.request_end;
                const wanted: u32 = @intCast(@min(remaining, buffer.len));
                var got: u32 = 0;
                if (leftover > 0) {
                    got = @min(leftover, wanted);
                    const start = connection.request_end;
                    @memcpy(buffer[0..got], connection.recv[start..][0..got]);
                    connection.request_end += got;
                } else {
                    try connection.send_continue();
                    // Straight into the handler's buffer: no copy.
                    const timeout = connection.server.config.body_timeout_ms;
                    got = connection.read_some(buffer[0..wanted], timeout) catch
                        return error.Disconnected;
                    if (got == 0) return error.Disconnected;
                    // Bytes that bypassed `recv` leave it as it was.
                    assert(connection.request_end == connection.recv_used);
                }
                connection.body_remaining = remaining - got;
                return got;
            }

            /// A body the handler did not read, all of it already received:
            /// skipped, so the connection can serve the next request. One
            /// still on its way is not read for nothing: the connection
            /// closes.
            fn skip_buffered_body(connection: *Connection) void {
                const remaining = connection.body_remaining;
                if (remaining == 0) return;
                const buffered = connection.recv_used - connection.request_end;
                if (remaining > buffered) return;
                connection.request_end += @intCast(remaining);
                connection.body_remaining = 0;
            }

            fn send_continue(connection: *Connection) BodyError!void {
                if (!connection.head.expect_continue or connection.continue_sent) return;
                connection.continue_sent = true;
                const line = "HTTP/1.1 100 Continue\r\n\r\n";
                if (connection.send.len - connection.send_used < line.len) {
                    if (!connection.flush()) return error.Disconnected;
                }
                @memcpy(connection.send[connection.send_used..][0..line.len], line);
                connection.send_used += line.len;
            }

            /// A response head into the send buffer, after what waits
            /// there (flushed first when the largest head might not fit).
            /// Null: the peer is gone.
            fn write_head(
                connection: *Connection,
                status: u16,
                headers: []const http1_response.Header,
                framing: http1_response.Framing,
            ) ?http1_response.Result {
                const server = connection.server;
                const head_max = server.config.response_head_bytes_max;
                if (connection.send.len - connection.send_used < head_max) {
                    if (!connection.flush()) return null;
                }
                const start = connection.send_used;
                const result = http1_response.write(connection.send[start..][0..head_max], .{
                    .status = status,
                    .headers = headers,
                    .framing = framing,
                    .keep_alive = connection.keep_alive,
                    .date = server.date(),
                });
                switch (result) {
                    .bytes => |bytes| {
                        assert(bytes <= head_max);
                        connection.send_used = start + bytes;
                    },
                    .refusal => assert(connection.send_used == start),
                }
                return result;
            }

            /// Send what waits in the send buffer. False: the peer is gone.
            fn flush(connection: *Connection) bool {
                assert(connection.send_used <= connection.send.len);
                if (connection.send_used == 0) return true;
                const pending = connection.send[0..connection.send_used];
                connection.send_used = 0;
                return connection.write_all(pending, "");
            }

            /// Read what the socket has, with a deadline the timekeeper
            /// enforces by shutting the socket down (the read returns 0).
            /// Flushes first: a connection never waits for its client with
            /// a response the client may be waiting for.
            fn read_some(connection: *Connection, buffer: []u8, timeout_ms: u32) !u32 {
                assert(buffer.len > 0);
                const server = connection.server;
                if (type_options.send_then_receive != null and connection.send_used > 0) {
                    return connection.send_and_read(buffer, timeout_ms);
                }
                if (!connection.flush()) return error.Disconnected;
                assert(connection.send_used == 0);
                server.arm(connection.index, timeout_ms);
                defer server.disarm(connection.index);
                return connection.receive(buffer);
            }

            /// The read itself, no deadline of its own: in 0.17,
            /// `net.Stream.read` does not compile (it destructures a struct
            /// as a tuple).
            fn receive(connection: *Connection, buffer: []u8) !u32 {
                assert(buffer.len > 0);
                var parts = [_][]u8{buffer};
                const result = try connection.server.io.operate(.{ .net_read = .{
                    .socket_handle = connection.stream.socket.handle,
                    .data = &parts,
                } });
                const got = (try result.net_read).data_len;
                assert(got <= buffer.len);
                return @intCast(got);
            }

            /// The waiting responses, then a read, as one operation: the read
            /// returns only once they are sent, so the send buffer is free.
            fn send_and_read(connection: *Connection, buffer: []u8, timeout_ms: u32) !u32 {
                const send_then_receive = type_options.send_then_receive.?;
                const server = connection.server;
                assert(connection.send_used > 0);
                const pending = connection.send[0..connection.send_used];
                connection.send_used = 0;
                // One deadline for both: the read's is the longer, and a peer
                // that stops reading stops the send and so the read with it.
                const config = server.config;
                server.arm(connection.index, @max(timeout_ms, config.send_timeout_ms));
                defer server.disarm(connection.index);
                const socket = connection.stream.socket.handle;
                const got = try send_then_receive(server.io, socket, pending, buffer);
                assert(got <= buffer.len);
                return @intCast(got);
            }

            fn write_all(connection: *Connection, head: []const u8, body: []const u8) bool {
                const server = connection.server;
                const total = head.len + body.len;
                assert(total > 0);
                var sent: usize = 0;
                defer server.disarm(connection.index);
                for (0..total + 1) |_| {
                    if (sent == total) return true;
                    // The deadline is for progress, not for the whole
                    // response: re-armed before each write, so a slow but
                    // steady reader of a large response is never cut off.
                    server.arm(connection.index, server.config.send_timeout_ms);
                    const head_rest = if (sent < head.len) head[sent..] else "";
                    const body_rest = if (sent < head.len) body else body[sent - head.len ..];
                    const result = server.io.operate(.{ .net_write = .{
                        .socket_handle = connection.stream.socket.handle,
                        .header = head_rest,
                        .data = &.{body_rest},
                    } }) catch return false;
                    const written = result.net_write catch return false;
                    if (written == 0) return false;
                    sent += written;
                    assert(sent <= total);
                } else unreachable; // each pass writes a byte or returns
            }
        };

        pub fn init(
            gpa: std.mem.Allocator,
            io: Io,
            app: *App,
            listener: net.Server,
            config: Config,
        ) !Server {
            config.assert_valid();
            const count = config.connections_max;
            var server: Server = .{
                .io = io,
                .app = app,
                .config = config,
                .listener = listener,
                .connections = try gpa.alloc(Connection, count),
                .deadlines = try gpa.alloc(u32, count),
                .phase_deadlines = try gpa.alloc(u32, count),
                .idle_since = try gpa.alloc(u32, count),
                .ticks_max = undefined,
                .free = try gpa.alloc(u32, count),
                .free_count = count,
                .free_slots = .{ .permits = count },
            };
            const timeout_ms_max = @max(
                @max(config.head_timeout_ms, config.idle_timeout_ms),
                @max(config.body_timeout_ms, config.send_timeout_ms),
            );
            server.ticks_max = server.ticks_for(timeout_ms_max);
            const recv = try slab_alloc(gpa, u8, count * config.recv_bytes());
            const send = try slab_alloc(gpa, u8, count * config.send_bytes_max);
            const scratch = try slab_alloc(gpa, u8, count * config.scratch_bytes_max);
            const headers = try slab_alloc(gpa, Header, count * config.headers_max);
            for (server.connections, 0..) |*connection, index_usize| {
                const index: u32 = @intCast(index_usize);
                connection.* = undefined;
                connection.open = false;
                connection.recv = stride(u8, recv, config.recv_bytes(), index);
                connection.send = stride(u8, send, config.send_bytes_max, index);
                connection.scratch = stride(u8, scratch, config.scratch_bytes_max, index);
                assert(std.mem.isAligned(@intFromPtr(connection.scratch.ptr), scratch_align));
                const table = stride(Header, headers, config.headers_max, index);
                connection.parser = http1_head.Parser.init(config.head_limits(), table);
                server.deadlines[index] = 0;
                server.phase_deadlines[index] = 0;
                server.idle_since[index] = 0;
                server.free[index] = count - 1 - index; // slot 0 is used first
            }
            server.recv_slab = recv;
            server.send_slab = send;
            server.scratch_slab = scratch;
            server.headers_slab = headers;
            return server;
        }

        pub fn deinit(server: *Server, gpa: std.mem.Allocator) void {
            gpa.free(server.connections);
            gpa.free(server.deadlines);
            gpa.free(server.phase_deadlines);
            gpa.free(server.idle_since);
            gpa.free(server.free);
            slab_free(gpa, u8, server.recv_slab);
            slab_free(gpa, u8, server.send_slab);
            slab_free(gpa, u8, server.scratch_slab);
            slab_free(gpa, Header, server.headers_slab);
            server.* = undefined;
        }

        fn stride(comptime T: type, all: []T, size: u32, index: u32) []T {
            const start = @as(usize, index) * size;
            assert(start + size <= all.len);
            return all[start..][0..size];
        }

        /// Accept and serve for good: accepting on its own fiber, the
        /// timekeeper on this one.
        pub fn run(server: *Server) !noreturn {
            assert(server.thread == null); // run once
            server.thread = &thread_marker;
            server.refresh_date(); // before the first response needs it
            assert(server.date_second != 0);
            _ = try server.io.concurrent(accept_loop, .{server});
            server.timekeeper();
        }

        /// Accept first, then find a slot: when none is free, the
        /// connections idle longest are closed for the new one (a server
        /// full of idle keep-alives otherwise locks new clients out for the
        /// idle timeout). With none idle, the new client waits for a slot,
        /// and the kernel's backlog holds the rest.
        fn accept_loop(server: *Server) void {
            // Bounded only to say so: it runs for good.
            for (0..std.math.maxInt(u64)) |_| {
                const stream = server.listener.accept(server.io) catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        log.warn("accept: {t}", .{err});
                        // Out of descriptors: wait a tick rather than spin.
                        const tick: Io.Duration = .fromMilliseconds(server.config.tick_ms);
                        server.io.sleep(tick, .awake) catch return; // canceled
                        continue;
                    },
                };
                // Slots shut idle free as they close: wait for those rather
                // than shut more, so eviction stays with the longest idle.
                if (server.free_count == 0 and server.shut_count == 0) server.evict_idle();
                server.free_slots.wait(server.io) catch {
                    stream.close(server.io);
                    return;
                };
                const index = server.take_slot();
                server.open_connection(index, stream);
                server.stats.accepted += 1;
                server.group.concurrent(server.io, serve_connection, .{ server, index }) catch {
                    // No fiber to run it on: close it, as a full server would.
                    server.stats.fiberless += 1;
                    server.close_connection(&server.connections[index]);
                };
            } else unreachable;
        }

        /// Close the connections idle longest, a batch of them
        /// (`evict_batch`), if any are: each fiber waiting on one reads 0
        /// and closes, which frees its slot. One scan of one array, as the
        /// timekeeper's, keeping the batch's longest idle as it goes. Only
        /// the read side is shut: a response still being sent (the linked
        /// send-then-receive) is sent whole before the read returns 0, so
        /// none is ever cut short.
        ///
        /// A batch, not one: with more clients than slots, each coming back
        /// for its next request on a new connection, one per scan of every
        /// slot made the acceptor take one client per scan and wait for its
        /// close (32,768 slots: 104 us of CPU per request against 38 with
        /// every client held, p95 500 ms against 1; 2026-10-23).
        fn evict_idle(server: *Server) void {
            assert(server.free_count == 0);
            assert(server.shut_count == 0);
            const batch_max = evict_batch(server.config.connections_max);
            var batch: [evict_batch_max]u32 = undefined;
            var count: u32 = 0;
            // Where in the batch the most recently idle is: a longer idle
            // takes its place.
            var newest: u32 = 0;
            for (server.idle_since, 0..) |since, index_usize| {
                if (since == 0) continue;
                const index: u32 = @intCast(index_usize);
                if (count < batch_max) {
                    batch[count] = index;
                    if (since > server.idle_since[batch[newest]]) newest = count;
                    count += 1;
                    continue;
                }
                if (since >= server.idle_since[batch[newest]]) continue;
                batch[newest] = index;
                newest = 0;
                for (batch[0..count], 0..) |held, position| {
                    if (server.idle_since[held] > server.idle_since[batch[newest]]) {
                        newest = @intCast(position);
                    }
                }
            }
            assert(count <= batch_max);
            for (batch[0..count]) |index| {
                server.shut_idle(index);
                server.stats.evicted += 1;
            }
        }

        /// End an idle connection's wait for its next request: shut for
        /// reading, its wait returns, and it closes without serving one
        /// (`Connection.shut_idle`).
        fn shut_idle(server: *Server, index: u32) void {
            const connection = &server.connections[index];
            assert(connection.open);
            assert(server.idle_since[index] != 0);
            server.idle_since[index] = 0;
            connection.shut_idle = true;
            server.shut_count += 1;
            connection.stream.shutdown(server.io, .recv) catch {};
        }

        fn take_slot(server: *Server) u32 {
            server.assert_on_shard_thread();
            assert(server.free_count > 0); // the semaphore admitted us
            server.free_count -= 1;
            return server.free[server.free_count];
        }

        fn give_slot(server: *Server, index: u32) void {
            assert(server.free_count < server.free.len);
            server.free[server.free_count] = index;
            server.free_count += 1;
            server.free_slots.post(server.io);
        }

        fn assert_on_shard_thread(server: *const Server) void {
            assert(server.thread == &thread_marker);
        }

        fn open_connection(server: *Server, index: u32, stream: net.Stream) void {
            const connection = &server.connections[index];
            assert(!connection.open);
            no_delay(stream.socket.handle);
            connection.server = server;
            connection.index = index;
            connection.stream = stream;
            connection.open = true;
            connection.shut_idle = false;
            connection.recv_used = 0;
            connection.send_used = 0;
            connection.requests = 0;
            connection.body_remaining = 0;
        }

        fn close_connection(server: *Server, connection: *Connection) void {
            _ = connection.flush(); // the last response; the peer may be gone
            assert(connection.open);
            // Not open from here, so no fiber shuts a descriptor the close
            // may already have freed for another connection.
            connection.open = false;
            server.deadlines[connection.index] = 0;
            server.phase_deadlines[connection.index] = 0;
            server.idle_since[connection.index] = 0;
            server.closing_count += 1;
            connection.stream.close(server.io); // may wait: other fibers run
            assert(server.closing_count > 0);
            server.closing_count -= 1;
            server.stats.closed += 1;
            if (connection.shut_idle) {
                assert(server.shut_count > 0);
                server.shut_count -= 1;
            }
            server.give_slot(connection.index);
        }

        fn serve_connection(server: *Server, index: u32) void {
            const connection = &server.connections[index];
            defer server.close_connection(connection);
            for (0..server.config.requests_per_connection_max) |_| {
                if (!server.serve_request(connection)) return;
            }
        }

        /// One request, start to finish. False: close the connection.
        fn serve_request(server: *Server, connection: *Connection) bool {
            if (!server.read_head(connection)) return false;
            server.assert_on_shard_thread();
            server.stats.requests += 1;
            var request: Request = .{
                .head = &connection.head,
                .scratch = connection.scratch,
                .connection = connection,
            };
            var response = server.app.handle(&request);
            defer server.app.release(&response);
            // A body the handler left unread and not here cannot be
            // skipped safely: the connection closes after this response.
            connection.skip_buffered_body();
            if (connection.body_remaining != 0) connection.keep_alive = false;
            const written = server.write_response(connection, .{
                .status = response.status,
                .headers = response.headers,
                .body = response.body,
                .omit_body = connection.head.method == .head,
            });
            if (!written or !connection.keep_alive) return false;
            connection.requests += 1;
            server.next_request(connection);
            return true;
        }

        /// Read and parse until a whole head is here. Answers a refusal
        /// itself; false means close. The head is a phase: from its first
        /// byte (or once nothing is owed the client), all its reads end by
        /// one `head_timeout_ms`, however its bytes trickle in.
        fn read_head(server: *Server, connection: *Connection) bool {
            connection.parser.reset();
            defer server.phase_end(connection.index);
            const reads_max = server.config.recv_bytes() + 1;
            for (0..reads_max) |_| {
                const buffer = connection.recv[0..connection.recv_used];
                switch (connection.parser.parse(buffer)) {
                    .complete => |parsed| {
                        return server.start_request(connection, parsed.head, parsed.head_bytes);
                    },
                    .refusal => |refusal| {
                        server.stats.refused += 1;
                        connection.keep_alive = false;
                        _ = server.write_response(connection, .{ .status = refusal.status() });
                        return false;
                    },
                    .incomplete => {},
                }
                const idle = connection.recv_used == 0 and connection.requests > 0;
                const config = server.config;
                const timeout = if (idle) config.idle_timeout_ms else config.head_timeout_ms;
                // Responses still owed go out first, under the sender's
                // deadline: the head's time is the client's alone.
                const owed = connection.send_used > 0;
                const phased = server.phase_deadlines[connection.index] != 0;
                if (!idle and !owed and !phased) server.phase_start(connection.index, timeout);
                const window = connection.recv[connection.recv_used..];
                assert(window.len > 0); // the parser refuses before the buffer fills
                if (idle) server.idle_since[connection.index] = server.tick;
                defer server.idle_since[connection.index] = 0;
                const got = connection.read_some(window, timeout) catch return false;
                if (got == 0) return false; // closed, or timed out
                // Shut while it waited: what it read goes unanswered.
                if (connection.shut_idle) {
                    server.stats.shut_with_request += 1;
                    return false;
                }
                connection.recv_used += got;
            } else unreachable; // each pass reads a byte or finishes
        }

        /// False: refused (a chunked body, answered 411) and closed.
        fn start_request(
            server: *Server,
            connection: *Connection,
            head: http1_head.Head,
            head_bytes: u32,
        ) bool {
            connection.head = head;
            connection.request_end = head_bytes;
            connection.keep_alive = head.keep_alive;
            connection.continue_sent = false;
            connection.body_remaining = switch (head.body) {
                .none => 0,
                .length => |length| length,
                .chunked => {
                    server.stats.refused += 1;
                    connection.keep_alive = false;
                    _ = server.write_response(connection, .{ .status = 411 });
                    return false;
                },
            };
            maybe(head.expect_continue);
            return true;
        }

        /// Move what follows this request (pipelined bytes) to the front.
        fn next_request(server: *Server, connection: *Connection) void {
            _ = server;
            assert(connection.body_remaining == 0);
            const rest = connection.recv[connection.request_end..connection.recv_used];
            std.mem.copyForwards(u8, connection.recv[0..rest.len], rest);
            connection.recv_used = @intCast(rest.len);
            connection.request_end = 0;
        }

        const ResponseOptions = struct {
            status: u16,
            headers: []const http1_response.Header = &.{},
            body: []const u8 = "",
            omit_body: bool = false,
        };

        /// Into the send buffer, which goes out at the next read or close;
        /// a body too large to wait there goes out now, straight from the
        /// handler's memory, behind what was waiting.
        fn write_response(server: *Server, connection: *Connection, options: ResponseOptions) bool {
            const forbids_body = http1_response.status_forbids_body(options.status);
            const framing: http1_response.Framing = if (forbids_body and options.body.len == 0)
                .none
            else
                .{ .length = options.body.len };
            const result = connection.write_head(options.status, options.headers, framing) orelse
                return false;
            switch (result) {
                .bytes => {
                    const body = if (options.omit_body or forbids_body) "" else options.body;
                    const head_end = connection.send_used;
                    if (body.len <= connection.send.len - head_end) {
                        @memcpy(connection.send[head_end..][0..body.len], body);
                        connection.send_used = @intCast(head_end + body.len);
                        return true;
                    }
                    connection.send_used = 0;
                    return connection.write_all(connection.send[0..head_end], body);
                },
                .refusal => |refusal| {
                    // The application answered what cannot be sent: its bug.
                    log.err("response refused: {t} (status {d})", .{ refusal, options.status });
                    connection.keep_alive = false;
                    if (options.status == 500 and options.body.len == 0) return false;
                    return server.write_response(connection, .{ .status = 500 });
                },
            }
        }

        fn date(server: *Server) *const [http_date.length]u8 {
            assert(server.date_second != 0);
            return &server.date_text;
        }

        /// Called by the timekeeper (and once at start): the date, formatted
        /// when the second changes.
        fn refresh_date(server: *Server) void {
            const now: Io.Timestamp = .now(server.io, .real);
            const second: u64 = @intCast(@max(0, @divTrunc(now.nanoseconds, std.time.ns_per_s)));
            if (second == server.date_second) return;
            server.date_second = second;
            server.date_text = http_date.format(@min(second, http_date.seconds_max));
        }

        /// The slot accounting: every slot is free, open, or closing, and
        /// the counters agree.
        pub fn check_invariants(server: *Server) void {
            var open: u32 = 0;
            for (server.connections) |*connection| open += @intFromBool(connection.open);
            const held = open + server.closing_count;
            assert(held + server.free_count == server.config.connections_max);
            assert(server.shut_count <= held);
            assert(server.stats.accepted - server.stats.closed == held);
            for (server.free[0..server.free_count]) |index| {
                assert(!server.connections[index].open);
                assert(server.deadlines[index] == 0);
                assert(server.phase_deadlines[index] == 0);
            }
            for (server.connections, server.deadlines, server.phase_deadlines) |
                *connection,
                deadline,
                phase,
            | {
                if (deadline != 0) assert(connection.open);
                assert(deadline <= server.tick + server.ticks_max);
                // A phase bounds every wait in it: none outlives it.
                if (phase != 0) assert(connection.open);
                if (phase != 0) assert(deadline <= phase);
            }
        }

        /// The longest wait in ticks: deadlines stay within it of the clock.
        fn ticks_for(server: *const Server, timeout_ms: u32) u32 {
            // Rounded up, plus one: the tick in progress may be nearly over,
            // and a wait must last at least its whole timeout.
            return timeout_ms / server.config.tick_ms + 2;
        }

        /// The wait's own deadline, or its phase's if that comes first.
        fn arm(server: *Server, index: u32, timeout_ms: u32) void {
            const ticks = server.ticks_for(timeout_ms);
            assert(ticks <= server.ticks_max);
            const own = server.tick + ticks;
            const phase = server.phase_deadlines[index];
            server.deadlines[index] = if (phase == 0) own else @min(own, phase);
            assert(server.deadlines[index] != 0);
        }

        /// A phase starts: its waits, together, last at most `timeout_ms`.
        fn phase_start(server: *Server, index: u32, timeout_ms: u32) void {
            assert(server.phase_deadlines[index] == 0);
            assert(server.deadlines[index] == 0); // between two waits
            server.phase_deadlines[index] = server.tick + server.ticks_for(timeout_ms);
        }

        fn phase_end(server: *Server, index: u32) void {
            server.phase_deadlines[index] = 0;
        }

        fn disarm(server: *Server, index: u32) void {
            server.deadlines[index] = 0;
        }

        /// One fiber for every deadline: a scan of one array per tick.
        fn timekeeper(server: *Server) noreturn {
            // Bounded only to say so: it runs for good.
            for (0..std.math.maxInt(u64)) |_| {
                const tick: Io.Duration = .fromMilliseconds(server.config.tick_ms);
                server.io.sleep(tick, .awake) catch {};
                server.tick += 1;
                assert(server.tick < std.math.maxInt(u32) - server.ticks_max); // years away
                server.refresh_date();
                for (server.deadlines, 0..) |due, index| {
                    if (due != 0 and due <= server.tick) server.expire(@intCast(index));
                }
                if (builtin.mode == .debug) server.check_invariants();
            } else unreachable;
        }

        /// Shut the socket down: the fiber waiting on it reads 0 and closes.
        /// Between two waits, so the slot is the one the deadline was armed
        /// for: its fiber disarms before it closes.
        fn expire(server: *Server, index: u32) void {
            const connection = &server.connections[index];
            assert(connection.open);
            server.deadlines[index] = 0;
            connection.stream.shutdown(server.io, .both) catch {};
            server.stats.timeouts += 1;
        }
    };
}
