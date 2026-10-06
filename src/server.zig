//! fourneau on green threads: one fiber per connection, written as plain
//! blocking-style code against `std.Io`, so the same server runs on any
//! `Io` (our vendored io_uring `Evented` in production, a deterministic
//! simulator in tests).
//!
//! A server is one shard: every fiber runs on one thread, and a machine
//! runs one shard per core, sharing nothing (experiment 1). So nothing here
//! is atomic or locked: fibers switch only where one waits, and a step
//! between two waits runs whole. The simulator, one thread too, is then an
//! exact model of a shard. `run` asserts it is never called on two threads.
//!
//! Data-oriented, after Kelley and Muratori:
//! - Every byte a connection uses is carved at startup from one allocation
//!   per kind (receive buffers, header tables, response heads, response
//!   scratch), so N connections are N strides through flat arrays, and
//!   nothing is allocated per request.
//! - Deadlines are a separate array of `u32` ticks, scanned by one
//!   timekeeper fiber a tick at a time: the scan touches one cache-friendly
//!   array, not N connection records; no connection keeps a timer, and no
//!   request reads the clock (the tick is the time).
//! - The protocol is the sans-IO parsers of M1, unchanged: a fiber only
//!   decides when to read more.
//!
//! A connection's life: accepted into a free slot, requests one after
//! another (head, the application, the response), then closed and its slot
//! freed. The application pulls the request body itself, so a handler that
//! refuses never causes a byte of body to be read.

const std = @import("std");
const assert = std.debug.assert;
const maybe = @import("stdx.zig").maybe;
const http1_head = @import("http1_head.zig");
const http1_chunked = @import("http1_chunked.zig");
const http1_response = @import("http1_response.zig");
const http_date = @import("http_date.zig");
const tls = @import("tls.zig");

const Io = std.Io;
const net = Io.net;
const Header = http1_head.Header;

const log = std.log.scoped(.fourneau);

pub const Config = struct {
    connections_max: u32 = 1024,
    head_bytes_max: u32 = 16 * 1024,
    target_bytes_max: u32 = 8 * 1024,
    headers_max: u16 = 64,
    /// The ceiling on a chunked body; a `Content-Length` beyond it is 413.
    body_bytes_max: u32 = 1024 * 1024,
    response_head_bytes_max: u32 = 8 * 1024,
    /// Each connection's send buffer: responses wait here, and go out in
    /// one write when the connection would otherwise block on a read, so
    /// pipelined requests are answered in one send, not one per response.
    send_bytes_max: u32 = 16 * 1024,
    /// Memory a handler may use for its response body, per connection.
    scratch_bytes_max: u32 = 64 * 1024,
    head_timeout_ms: u32 = 10_000,
    idle_timeout_ms: u32 = 30_000,
    body_timeout_ms: u32 = 30_000,
    send_timeout_ms: u32 = 30_000,
    /// How often the timekeeper looks at the deadlines.
    tick_ms: u32 = 100,
    /// A bound on the keep-alive loop: generous, and asserted.
    requests_per_connection_max: u32 = 1 << 24,
    /// Real sockets want it (see `no_delay`); a simulated one has none.
    tcp_nodelay: bool = true,
    /// HTTPS: TLS 1.3 on every connection, the keys then given to the
    /// kernel (`tls.zig`). Real sockets only: a simulated one has no kTLS.
    tls: ?*const tls.Context = null,

    pub fn assert_valid(config: Config) void {
        assert(config.connections_max > 0);
        assert(config.response_head_bytes_max >= 256);
        // A head always fits whole in an empty send buffer.
        assert(config.send_bytes_max >= config.response_head_bytes_max);
        assert(config.tick_ms > 0);
        assert(config.tick_ms <= config.head_timeout_ms);
        config.head_limits().assert_valid();
        if (config.tls != null) {
            // The handshake borrows the scratch (both of tls.zig's buffers)
            // and receives the client's early bytes into `recv`.
            assert(config.scratch_bytes_max >= tls.input_bytes_min + tls.output_bytes_min);
        }
    }

    fn head_limits(config: Config) http1_head.Limits {
        return .{
            .head_bytes_max = config.head_bytes_max,
            .target_bytes_max = config.target_bytes_max,
            .headers_max = config.headers_max,
            .body_bytes_max = config.body_bytes_max,
        };
    }

    fn chunked_limits(config: Config) http1_chunked.Limits {
        return .{
            .body_bytes_max = config.body_bytes_max,
            .extension_bytes_max = 4096,
            .trailer_bytes_max = config.head_bytes_max,
        };
    }

    /// Room past the largest head, so a full head never leaves no room to
    /// read the start of a body or chunk framing.
    fn recv_bytes(config: Config) u32 {
        return config.head_bytes_max + recv_window_bytes;
    }
};

const recv_window_bytes = 4096;

pub const BodyError = error{ BadRequest, ContentTooLarge, Disconnected };

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
/// client's delayed ACK, 40 ms (DIARY 2026-10-05: 50k requests/s at
/// pipeline 8 before this). A plain system call: `std.Io` has no socket
/// options, and a simulated socket has no Nagle to switch off.
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
    handshakes: u64 = 0,
    handshakes_failed: u64 = 0,
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
        /// Ticks since `run`, counted by the timekeeper: the server's clock.
        /// Starts at 1, so a deadline is never 0.
        tick: u32 = 1,
        /// The longest wait, in ticks (`ticks_for` the longest timeout).
        ticks_max: u32,
        /// The thread the shard runs on (`thread_marker`), from `run`.
        thread: ?*const u8 = null,
        free: []u32,
        free_count: u32,
        /// Counts free slots: the acceptor waits on it, so a full server
        /// stops accepting and the kernel's backlog holds new clients.
        free_slots: Io.Semaphore,
        group: Io.Group = .init,
        /// The slabs every connection takes its strides of.
        recv_slab: []u8 = &.{},
        heads_slab: []u8 = &.{},
        scratch_slab: []u8 = &.{},
        headers_slab: []Header = &.{},
        stats: Stats = .{},
        /// The Date header, refreshed by the timekeeper each tick, not read
        /// from the clock per response (that was 6% of a pipelined profile,
        /// 2026-10-05). One copy: a response is formatted between two
        /// waits, so the timekeeper never runs in the middle of one.
        date_text: [http_date.length]u8 = undefined,
        date_second: u64 = 0,

        pub const Request = struct {
            head: *const http1_head.Head,
            /// This connection's memory for the response body: valid
            /// until the response has been sent.
            scratch: []u8,
            connection: *Connection,

            /// Read up to `buffer.len` body bytes; 0 at the end of the
            /// body. Sends `100 Continue` first if the client waits for it.
            pub fn read_body(request: *Request, buffer: []u8) BodyError!usize {
                return request.connection.read_body(buffer);
            }
        };

        const BodyState = union(enum) {
            none,
            length: u64,
            chunked: http1_chunked.Decoder,
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
            head_bytes: u32,
            /// Where the next request starts in `recv`, once this one's
            /// body is consumed.
            request_end: u32,
            body: BodyState,
            continue_sent: bool,
            keep_alive: bool,
            requests: u32,
            /// The kernel holds this connection's TLS keys (kTLS). Its
            /// sends refuse `MSG_WAITALL`, which the linked send-then-
            /// receive needs, so such a connection flushes, then reads.
            kernel_tls: bool,

            fn read_body(connection: *Connection, buffer: []u8) BodyError!usize {
                assert(buffer.len > 0);
                return switch (connection.body) {
                    .none => 0,
                    .length => connection.read_length_body(buffer),
                    .chunked => connection.read_chunked_body(buffer),
                };
            }

            fn read_length_body(connection: *Connection, buffer: []u8) BodyError!usize {
                const remaining = connection.body.length;
                assert(remaining > 0);
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
                connection.body = if (remaining == got) .none else .{ .length = remaining - got };
                return got;
            }

            fn read_chunked_body(connection: *Connection, buffer: []u8) BodyError!usize {
                const window_reads_max = connection.server.config.body_bytes_max + 2;
                for (0..window_reads_max) |_| {
                    const decoder = &connection.body.chunked;
                    const input = connection.recv[connection.head_bytes..connection.recv_used];
                    const progress = switch (decoder.decode(input, buffer)) {
                        .progress => |progress| progress,
                        .refusal => |refusal| {
                            connection.keep_alive = false;
                            connection.body = .none;
                            return switch (refusal) {
                                .bad_request => error.BadRequest,
                                .content_too_large => error.ContentTooLarge,
                            };
                        },
                    };
                    connection.keep_input(progress.consumed);
                    if (progress.done) {
                        connection.body = .none;
                        connection.request_end = connection.head_bytes;
                    }
                    if (progress.produced > 0 or progress.done) return progress.produced;
                    try connection.send_continue();
                    const timeout = connection.server.config.body_timeout_ms;
                    const window = connection.recv[connection.recv_used..];
                    const got = connection.read_some(window, timeout) catch
                        return error.Disconnected;
                    if (got == 0) return error.Disconnected;
                    connection.recv_used += got;
                } else unreachable; // each pass reads a byte or decodes one
            }

            /// Keep the undecoded tail right after the head, so the head's
            /// slices stay valid and the window never fills with framing.
            fn keep_input(connection: *Connection, consumed: u32) void {
                const start = connection.head_bytes;
                const rest = connection.recv[start + consumed .. connection.recv_used];
                std.mem.copyForwards(u8, connection.recv[start..][0..rest.len], rest);
                connection.recv_used = start + @as(u32, @intCast(rest.len));
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
            pub fn read_some(connection: *Connection, buffer: []u8, timeout_ms: u32) !u32 {
                assert(buffer.len > 0);
                const server = connection.server;
                const linked = type_options.send_then_receive != null and !connection.kernel_tls;
                if (linked and connection.send_used > 0) {
                    return connection.send_and_read(buffer, timeout_ms);
                }
                if (!connection.flush()) return error.Disconnected;
                assert(connection.send_used == 0);
                server.arm(connection.index, timeout_ms);
                defer server.disarm(connection.index);

                // The operation itself: in 0.17, `net.Stream.read` does not
                // compile (it destructures a struct as a tuple; DIARY).
                var parts = [_][]u8{buffer};
                const result = try server.io.operate(.{ .net_read = .{
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

            pub fn write_all(connection: *Connection, head: []const u8, body: []const u8) bool {
                const server = connection.server;
                const total = head.len + body.len;
                assert(total > 0);
                var sent: usize = 0;
                defer server.disarm(connection.index);

                for (0..total + 1) |_| {
                    if (sent == total) return true;
                    // The deadline is for progress, not for the whole response:
                    // re-armed before each write, so a slow but steady reader of a
                    // large response is never cut off (the simulator's seed 45 was).
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
            const recv = try gpa.alloc(u8, count * config.recv_bytes());
            const heads = try gpa.alloc(u8, count * config.send_bytes_max);
            const scratch = try gpa.alloc(u8, count * config.scratch_bytes_max);
            const headers = try gpa.alloc(Header, count * config.headers_max);
            for (server.connections, 0..) |*connection, index_usize| {
                const index: u32 = @intCast(index_usize);
                connection.* = undefined;
                connection.open = false;
                connection.recv = stride(u8, recv, config.recv_bytes(), index);
                connection.send = stride(u8, heads, config.send_bytes_max, index);
                connection.scratch = stride(u8, scratch, config.scratch_bytes_max, index);
                const table = stride(Header, headers, config.headers_max, index);
                connection.parser = http1_head.Parser.init(config.head_limits(), table);
                server.deadlines[index] = 0;
                server.free[index] = count - 1 - index; // slot 0 is used first
            }
            server.recv_slab = recv;
            server.heads_slab = heads;
            server.scratch_slab = scratch;
            server.headers_slab = headers;
            return server;
        }

        pub fn deinit(server: *Server, gpa: std.mem.Allocator) void {
            gpa.free(server.connections);
            gpa.free(server.deadlines);
            gpa.free(server.free);
            gpa.free(server.recv_slab);
            gpa.free(server.heads_slab);
            gpa.free(server.scratch_slab);
            gpa.free(server.headers_slab);
            server.* = undefined;
        }

        fn stride(comptime T: type, all: []T, size: u32, index: u32) []T {
            const start = @as(usize, index) * size;
            assert(start + size <= all.len);
            return all[start..][0..size];
        }

        /// Accept and serve until the process ends: the timekeeper on its
        /// own fiber, accepting on this one.
        pub fn run(server: *Server) !void {
            assert(server.thread == null); // run once
            server.thread = &thread_marker;
            server.refresh_date(); // before the first response needs it
            assert(server.date_second != 0);
            try server.group.concurrent(server.io, timekeeper, .{server});
            server.accept_loop();
        }

        fn accept_loop(server: *Server) void {
            // A server's accept loop does not end: bounded only to say so.
            for (0..std.math.maxInt(u64)) |_| {
                server.free_slots.waitUncancelable(server.io);
                const stream = server.listener.accept(server.io) catch |err| {
                    server.free_slots.post(server.io);
                    log.warn("accept: {t}", .{err});
                    // Out of descriptors: wait a tick rather than spin.
                    server.io.sleep(.fromMilliseconds(server.config.tick_ms), .awake) catch {};
                    continue;
                };
                const index = server.take_slot();
                server.open_connection(index, stream);
                server.stats.accepted += 1;
                server.group.concurrent(server.io, serve_connection, .{ server, index }) catch {
                    // No fiber to run it on: close it, as a full server would.
                    server.close_connection(&server.connections[index]);
                };
            } else unreachable;
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
            if (server.config.tcp_nodelay) no_delay(stream.socket.handle);
            connection.server = server;
            connection.index = index;
            connection.stream = stream;
            connection.open = true;
            connection.recv_used = 0;
            connection.send_used = 0;
            connection.requests = 0;
            connection.kernel_tls = false;
        }

        fn close_connection(server: *Server, connection: *Connection) void {
            _ = connection.flush(); // the last response; the peer may be gone
            assert(connection.open);
            connection.open = false;
            server.deadlines[connection.index] = 0;
            connection.stream.close(server.io);
            server.stats.closed += 1;
            server.give_slot(connection.index);
        }

        fn serve_connection(server: *Server, index: u32) void {
            const connection = &server.connections[index];
            defer server.close_connection(connection);
            if (server.config.tls) |context| {
                if (!server.handshake(connection, context)) return;
            }

            for (0..server.config.requests_per_connection_max) |_| {
                if (!server.serve_request(connection)) return;
            }
        }

        /// TLS 1.3 before the first request: tls.zig's handshake in the
        /// connection's scratch, then kTLS; the client's first bytes after
        /// it (decrypted) start `recv`. False: close the connection.
        fn handshake(server: *Server, connection: *Connection, context: *const tls.Context) bool {
            assert(connection.recv_used == 0);
            assert(connection.requests == 0);
            const Transport = tls.TransportType(Connection);
            var transport: Transport = undefined;
            const half = connection.scratch.len / 2;
            transport.init(
                connection,
                server.config.head_timeout_ms,
                connection.scratch[0..half],
                connection.scratch[half..],
            );
            const socket = connection.stream.socket.handle;
            const recv = connection.recv;
            const early = tls.handshake(server.io, &transport, socket, context, recv) catch |err| {
                server.stats.handshakes_failed += 1;
                log.debug("handshake: {t}", .{err});
                switch (err) {
                    error.NotTls => server.refuse_plain_http(connection),
                    error.HandshakeFailed, error.KernelTlsFailed, error.EarlyDataTooLarge => {},
                }
                return false;
            };
            assert(early <= connection.recv.len);
            connection.recv_used = early;
            connection.kernel_tls = true;
            server.stats.handshakes += 1;
            return true;
        }

        /// Plain HTTP sent to the HTTPS port: a plain 400 that says so (as
        /// nginx does), then close.
        fn refuse_plain_http(server: *Server, connection: *Connection) void {
            assert(!connection.kernel_tls);
            const body = "This port speaks HTTPS: use https://\n";
            connection.keep_alive = false;
            _ = server.write_response(connection, .{ .status = 400, .body = body });
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

            // A body the handler left unread cannot be skipped safely:
            // the connection closes after this response.
            if (connection.body != .none) connection.keep_alive = false;
            const omit_body = connection.head.method == .head;
            const written = server.write_response(connection, .{
                .status = response.status,
                .headers = response.headers,
                .body = response.body,
                .omit_body = omit_body,
            });
            if (!written or !connection.keep_alive) return false;
            connection.requests += 1;
            server.next_request(connection);
            return true;
        }

        /// Read and parse until a whole head is here. Answers a refusal
        /// itself; false means close.
        fn read_head(server: *Server, connection: *Connection) bool {
            connection.parser.reset();
            const reads_max = server.config.recv_bytes() + 1;
            for (0..reads_max) |_| {
                const buffer = connection.recv[0..connection.recv_used];
                switch (connection.parser.parse(buffer)) {
                    .complete => |parsed| {
                        server.start_request(connection, parsed.head, parsed.head_bytes);
                        return true;
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
                const window = connection.recv[connection.recv_used..];
                assert(window.len > 0); // the parser refuses before the buffer fills
                const got = connection.read_some(window, timeout) catch return false;
                if (got == 0) return false; // closed, or timed out
                connection.recv_used += got;
            } else unreachable; // each pass reads a byte or finishes
        }

        fn start_request(
            server: *Server,
            connection: *Connection,
            head: http1_head.Head,
            head_bytes: u32,
        ) void {
            connection.head = head;
            connection.head_bytes = head_bytes;
            connection.request_end = head_bytes;
            connection.keep_alive = head.keep_alive;
            connection.continue_sent = false;
            connection.body = switch (head.body) {
                .none => .none,
                .length => |length| .{ .length = length },
                .chunked => .{
                    .chunked = http1_chunked.Decoder.init(server.config.chunked_limits()),
                },
            };
            maybe(head.expect_continue);
        }

        /// Move what follows this request (pipelined bytes) to the front.
        fn next_request(server: *Server, connection: *Connection) void {
            _ = server;
            assert(connection.body == .none);
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
            const head_max = server.config.response_head_bytes_max;
            if (connection.send.len - connection.send_used < head_max) {
                if (!connection.flush()) return false;
            }
            const start = connection.send_used;
            const result = http1_response.write(connection.send[start..][0..head_max], .{
                .status = options.status,
                .headers = options.headers,
                .framing = framing,
                .keep_alive = connection.keep_alive,
                .date = server.date(),
            });
            switch (result) {
                .bytes => |bytes| {
                    const body = if (options.omit_body or forbids_body) "" else options.body;
                    const head_end = start + bytes;
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

        /// The slot accounting, for the simulator to check between steps:
        /// every slot is free or open, and the counters agree.
        pub fn check_invariants(server: *Server) void {
            var open: u32 = 0;
            for (server.connections) |*connection| open += @intFromBool(connection.open);
            assert(open + server.free_count == server.config.connections_max);
            assert(server.stats.accepted - server.stats.closed == open);
            for (server.free[0..server.free_count]) |index| {
                assert(!server.connections[index].open);
                assert(server.deadlines[index] == 0);
            }
            for (server.connections, server.deadlines) |*connection, deadline| {
                if (deadline != 0) assert(connection.open);
                assert(deadline <= server.tick + server.ticks_max);
            }
        }

        /// The longest wait in ticks: deadlines stay within it of the clock.
        fn ticks_for(server: *const Server, timeout_ms: u32) u32 {
            // Rounded up, plus one: the tick in progress may be nearly over,
            // and a wait must last at least its whole timeout.
            return timeout_ms / server.config.tick_ms + 2;
        }

        fn arm(server: *Server, index: u32, timeout_ms: u32) void {
            const ticks = server.ticks_for(timeout_ms);
            assert(ticks <= server.ticks_max);
            server.deadlines[index] = server.tick + ticks;
        }

        fn disarm(server: *Server, index: u32) void {
            server.deadlines[index] = 0;
        }

        /// One fiber for every deadline: a scan of one array per tick.
        fn timekeeper(server: *Server) void {
            for (0..std.math.maxInt(u64)) |_| {
                server.io.sleep(.fromMilliseconds(server.config.tick_ms), .awake) catch return;
                server.tick += 1;
                assert(server.tick < std.math.maxInt(u32) - server.ticks_max); // years away
                server.refresh_date();
                for (server.deadlines, 0..) |due, index| {
                    if (due != 0 and due <= server.tick) server.expire(@intCast(index));
                }
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
