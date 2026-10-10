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
    /// Set, from any thread (a signal's), to drain and return from `run`:
    /// accept no more, close the connections idle between requests, finish
    /// the requests in flight (their responses say `Connection: close`),
    /// and close what is left after `drain_timeout_ms`. Read once a tick.
    stop: ?*const std.atomic.Value(bool) = null,
    /// How long a drain waits for requests in flight (a stream, a slow
    /// client) before it closes them.
    drain_timeout_ms: u32 = 10_000,
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
        assert(config.tick_ms <= config.drain_timeout_ms);
        config.head_limits().assert_valid();
        if (config.tls != null) {
            // The handshake borrows the scratch (both of tls.zig's buffers)
            // and receives the client's early bytes into `recv`.
            assert(config.scratch_bytes_max >= tls.input_bytes_min + tls.output_bytes_min);
        }
    }

    /// The fibers a server runs at once, at most: one per connection slot
    /// and the timekeeper (accepting runs on `run`'s caller). A slot is
    /// given back as its fiber's last act, so a new connection never needs
    /// a fiber before the last one is free. An `Io`'s fiber pool is the
    /// sum of what runs on it.
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

pub const StreamError = error{
    /// The peer is gone, or stopped reading for longer than the send
    /// timeout: what was not sent never will be.
    Disconnected,
    /// The head cannot be sent (a status without a body, a header that
    /// could break the framing, a head too large): the application's bug.
    /// Nothing was sent, so it still answers, with a 500.
    HeadRefused,
};

/// The status a handler returns when it streamed its response: the
/// response is on its way already, and there is nothing more to send.
pub const streamed_status: u16 = 0;

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
    /// Idle keep-alive connections closed to admit new ones.
    evicted: u64 = 0,
    /// Connections closed because the `Io` had no fiber for them: its pool
    /// is smaller than `Config.fibers_max` says. Always 0 when it is not.
    fiberless: u64 = 0,
    /// Connections a drain closed: idle ones at its start, and those left
    /// at its deadline.
    drain_idle: u64 = 0,
    drain_cut: u64 = 0,
};

/// The address of this, per thread, names the thread a shard runs on.
threadlocal var thread_marker: u8 = 0;

/// `App` provides:
///   const Response: struct with `status: u16`, `headers: []const
///     http1_response.Header` and `body: []const u8`;
///   fn handle(app: *App, request: *Request) App.Response, called on the
///     connection's fiber: it may block (yield) as long as it likes; a
///     handler that streams (`Request.stream_start`) returns
///     `streamed_status`, and only such a handler does;
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
        /// The tick since which each slot has waited, idle, for its next
        /// request (its last response sent); 0 when it is not idle. When
        /// every slot is taken, the oldest is closed to admit a new client.
        idle_since: []u32,
        /// Ticks since `run`, counted by the timekeeper: the server's clock.
        /// Starts at 1, so a deadline is never 0.
        tick: u32 = 1,
        /// The longest wait, in ticks (`ticks_for` the longest timeout).
        ticks_max: u32,
        /// The thread the shard runs on (`thread_marker`), from `run`.
        thread: ?*const u8 = null,
        /// Stopping (`Config.stop`): no more accepts, no next requests.
        draining: bool = false,
        /// The tick at which a drain closes what is left; 0 once it has
        /// (or before a drain).
        drain_deadline: u32 = 0,
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

            /// A streamed response (server-sent events), chunked: this
            /// head, a chunk per `stream_send`, the last at `stream_end`;
            /// then the handler returns `streamed_status`. Read the body
            /// first: a body is not read once a stream has started.
            ///
            /// Chunks wait in the send buffer, as pipelined responses do,
            /// so chunks made together go out together; they are sent when
            /// the buffer fills, at `stream_flush`, and at the connection's
            /// next read. Flush before waiting on anything but this
            /// connection, or the client waits too. A handler that returns
            /// without `stream_end` (it failed, or the peer is gone) closes
            /// the connection without the last chunk: the client sees a
            /// response cut short, never a complete wrong one.
            pub fn stream_start(
                request: *Request,
                status: u16,
                headers: []const http1_response.Header,
            ) StreamError!void {
                return request.connection.stream_start(status, headers);
            }

            /// One chunk: these bytes, which may be reused once it returns.
            /// No bytes, no chunk (an empty one would end the stream).
            pub fn stream_send(request: *Request, bytes: []const u8) StreamError!void {
                return request.connection.stream_send(bytes);
            }

            /// Send what waits: every chunk so far reaches the client.
            pub fn stream_flush(request: *Request) StreamError!void {
                return request.connection.stream_flush();
            }

            /// The last chunk: the response is whole.
            pub fn stream_end(request: *Request) StreamError!void {
                return request.connection.stream_end();
            }

            /// Where this request's stream is: for a host whose application
            /// it does not trust to call the stream functions in order (a
            /// Roc app), so it refuses what would trip an assertion, and
            /// returns `streamed_status` exactly when it must.
            pub fn stream_state(request: *const Request) StreamState {
                return request.connection.stream_state;
            }
        };

        /// Where a request's streamed response is (`Request.stream_start`).
        pub const StreamState = enum { none, streaming, ended };

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
            stream_state: StreamState,
            continue_sent: bool,
            keep_alive: bool,
            requests: u32,
            /// The kernel holds this connection's TLS keys (kTLS). Its
            /// sends refuse `MSG_WAITALL`, which the linked send-then-
            /// receive needs, so such a connection flushes, then reads.
            kernel_tls: bool,

            fn read_body(connection: *Connection, buffer: []u8) BodyError!usize {
                assert(buffer.len > 0);
                // A 100 Continue after a stream's head would be a second
                // head: the body is read before the response starts.
                assert(connection.stream_state == .none);
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

            fn stream_start(
                connection: *Connection,
                status: u16,
                headers: []const http1_response.Header,
            ) StreamError!void {
                assert(connection.stream_state == .none);
                // A body left unread cannot be skipped safely: the
                // connection closes after this response, and its head
                // must say so now.
                if (connection.body != .none) connection.keep_alive = false;
                const result = connection.write_head(status, headers, .chunked) orelse
                    return error.Disconnected;
                switch (result) {
                    .bytes => {},
                    .refusal => |refusal| {
                        log.err("stream refused: {t} (status {d})", .{ refusal, status });
                        return error.HeadRefused;
                    },
                }
                connection.stream_state = .streaming;
            }

            fn stream_send(connection: *Connection, bytes: []const u8) StreamError!void {
                assert(connection.stream_state == .streaming);
                if (bytes.len == 0) return;
                // HEAD: the head said chunked; no body follows it (RFC
                // 9110 §9.3.2).
                if (connection.head.method == .head) return;
                var line_buffer: [http1_response.chunk_size_line_bytes_max]u8 = undefined;
                const line = http1_response.chunk_size_line(&line_buffer, bytes.len);
                const tail = http1_response.chunk_tail;
                const total = line.len + bytes.len + tail.len;
                if (total > connection.send.len - connection.send_used) {
                    if (!connection.flush()) return error.Disconnected;
                }
                if (total <= connection.send.len - connection.send_used) {
                    connection.append(line);
                    connection.append(bytes);
                    connection.append(tail);
                    return;
                }
                // Larger than the whole send buffer: straight from the
                // handler's memory, behind what was flushed.
                assert(connection.send_used == 0);
                if (!connection.write_all(line, bytes)) return error.Disconnected;
                connection.append(tail);
            }

            fn stream_flush(connection: *Connection) StreamError!void {
                assert(connection.stream_state == .streaming);
                if (!connection.flush()) return error.Disconnected;
                assert(connection.send_used == 0);
            }

            fn stream_end(connection: *Connection) StreamError!void {
                assert(connection.stream_state == .streaming);
                if (connection.head.method != .head) {
                    const last = http1_response.chunk_last;
                    if (connection.send.len - connection.send_used < last.len) {
                        if (!connection.flush()) return error.Disconnected;
                    }
                    connection.append(last);
                }
                connection.stream_state = .ended;
            }

            /// A response head into the send buffer, after what waits
            /// there (flushed first when the largest head might not fit).
            /// What the head says of the connection is the connection's:
            /// whether it stays open, the date, HTTPS. A draining server
            /// closes after every response, and says so. Null: the peer is
            /// gone.
            fn write_head(
                connection: *Connection,
                status: u16,
                headers: []const http1_response.Header,
                framing: http1_response.Framing,
            ) ?http1_response.Result {
                const server = connection.server;
                if (server.draining) connection.keep_alive = false;
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
                    .secure = connection.kernel_tls,
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

            /// Bytes into the send buffer, which has room for them.
            fn append(connection: *Connection, bytes: []const u8) void {
                assert(bytes.len <= connection.send.len - connection.send_used);
                @memcpy(connection.send[connection.send_used..][0..bytes.len], bytes);
                connection.send_used += @intCast(bytes.len);
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
                server.idle_since[index] = 0;
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
            gpa.free(server.idle_since);
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

        /// Accept and serve until `Config.stop` (or a cancelation of this
        /// task), then drain and return: accepting on its own fiber, the
        /// timekeeper on this one.
        pub fn run(server: *Server) !void {
            assert(server.thread == null); // run once
            server.thread = &thread_marker;
            server.refresh_date(); // before the first response needs it
            assert(server.date_second != 0);
            var acceptor = try server.io.concurrent(accept_loop, .{server});
            server.timekeeper(&acceptor);
            assert(server.draining);
            assert(server.free_count == server.config.connections_max);
            // Every connection is closed: its fiber ends with that.
            try server.group.await(server.io);
        }

        /// Accept first, then find a slot: when none is free, the connection
        /// idle longest is closed for the new one (a server full of idle
        /// keep-alives otherwise locks new clients out for the idle timeout).
        /// With none idle, the new client waits for a slot, and the kernel's
        /// backlog holds the rest. Ends when canceled (a drain).
        fn accept_loop(server: *Server) void {
            // Bounded only to say so: it ends by cancelation.
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
                if (server.free_count == 0) server.evict_idle();
                server.free_slots.wait(server.io) catch {
                    // Canceled while the server was full: never served.
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

        /// Close the connection idle longest, if any is: the fiber waiting
        /// on it reads 0 and closes, which frees its slot. One scan of one
        /// array, as the timekeeper's. Only the read side is shut: a
        /// response still being sent (the linked send-then-receive) is sent
        /// whole before the read returns 0, so none is ever cut short.
        fn evict_idle(server: *Server) void {
            var oldest: ?u32 = null;
            for (server.idle_since, 0..) |since, index| {
                if (since == 0) continue;
                if (oldest == null or since < server.idle_since[oldest.?]) oldest = @intCast(index);
            }
            const index = oldest orelse return;
            assert(server.connections[index].open);
            server.idle_since[index] = 0;
            server.connections[index].stream.shutdown(server.io, .recv) catch {};
            server.stats.evicted += 1;
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
            server.idle_since[connection.index] = 0;
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
                    error.HandshakeFailed,
                    error.PeerClosed,
                    error.KernelTlsFailed,
                    error.EarlyDataTooLarge,
                    => {},
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

            const streamed = connection.stream_state != .none;
            assert(streamed == (response.status == streamed_status));
            const written = switch (connection.stream_state) {
                .none => server.write_unstreamed(connection, response),
                .ended => true,
                // Left without its last chunk: closed without it, so the
                // client sees the response cut short.
                .streaming => false,
            };
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
                // Draining: no next request (one already here is served).
                if (idle and server.draining) return false;
                const config = server.config;
                const timeout = if (idle) config.idle_timeout_ms else config.head_timeout_ms;
                const window = connection.recv[connection.recv_used..];
                assert(window.len > 0); // the parser refuses before the buffer fills
                if (idle) server.idle_since[connection.index] = server.tick;
                defer server.idle_since[connection.index] = 0;
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
            connection.stream_state = .none;
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

        /// The handler's response, sent whole.
        fn write_unstreamed(server: *Server, connection: *Connection, response: App.Response) bool {
            assert(connection.stream_state == .none);
            // A body the handler left unread cannot be skipped safely:
            // the connection closes after this response.
            if (connection.body != .none) connection.keep_alive = false;
            return server.write_response(connection, .{
                .status = response.status,
                .headers = response.headers,
                .body = response.body,
                .omit_body = connection.head.method == .head,
            });
        }

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
            // A drain closed every idle connection, and none waits for a
            // next request since.
            if (server.draining) {
                for (server.idle_since) |since| assert(since == 0);
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

        /// One fiber for every deadline: a scan of one array per tick. It
        /// starts the drain, and returns when the drain has closed the
        /// last connection.
        fn timekeeper(server: *Server, acceptor: *Io.Future(void)) void {
            // Bounded only to say so: it ends with a drain.
            for (0..std.math.maxInt(u64)) |_| {
                const tick: Io.Duration = .fromMilliseconds(server.config.tick_ms);
                // A cancelation of `run` is a stop too.
                const canceled = if (server.io.sleep(tick, .awake)) false else |_| true;
                server.tick += 1;
                assert(server.tick < std.math.maxInt(u32) - server.ticks_max); // years away
                server.refresh_date();
                for (server.deadlines, 0..) |due, index| {
                    if (due != 0 and due <= server.tick) server.expire(@intCast(index));
                }
                if (!server.draining and (canceled or server.stop_requested())) {
                    server.drain_start(acceptor);
                }
                if (server.draining) {
                    if (server.free_count == server.config.connections_max) return;
                    if (server.drain_deadline != 0 and server.tick >= server.drain_deadline) {
                        server.drain_cut();
                    }
                }
            } else unreachable;
        }

        fn stop_requested(server: *const Server) bool {
            const stop = server.config.stop orelse return false;
            return stop.load(.acquire);
        }

        /// Stop accepting (the accept loop is canceled: the listening
        /// socket itself is untouched, for a successor that shares it),
        /// then close every connection idle between requests, by shutting
        /// it for reading as eviction does. Those in flight close after
        /// their response (`read_head`, `write_head`).
        fn drain_start(server: *Server, acceptor: *Io.Future(void)) void {
            assert(!server.draining);
            server.draining = true;
            const ticks = server.ticks_for(server.config.drain_timeout_ms);
            server.drain_deadline = server.tick + ticks;
            acceptor.cancel(server.io);
            for (server.idle_since, 0..) |since, index| {
                if (since == 0) continue;
                assert(server.connections[index].open);
                server.idle_since[index] = 0;
                server.connections[index].stream.shutdown(server.io, .recv) catch {};
                server.stats.drain_idle += 1;
            }
        }

        /// The drain's deadline: shut every connection still open, as a
        /// timeout does; its fiber reads 0, or fails to write, and closes.
        fn drain_cut(server: *Server) void {
            assert(server.draining);
            server.drain_deadline = 0;
            for (server.connections, 0..) |*connection, index| {
                if (!connection.open) continue;
                server.deadlines[index] = 0;
                connection.stream.shutdown(server.io, .both) catch {};
                server.stats.drain_cut += 1;
            }
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
