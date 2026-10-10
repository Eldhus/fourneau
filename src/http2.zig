//! HTTP/2 connections (RFC 9113), sans-IO: the state machine between the
//! frames a client sends and the server's handlers, layer 3 of
//! docs/http2.md. No socket and no clock: bytes in, events out, and the
//! frames to send in one send buffer.
//!
//! The server calls `receive` with the bytes read so far; it consumes
//! whole frames and stops at the first one that needs the server (a
//! request, body bytes, a reset, an opened window), at an incomplete
//! frame, or when the send buffer lacks room for a reply. Handlers answer
//! with `send_head` and `send_data`, which write frames into the same
//! buffer, and give their stream back with `release`.
//!
//! The limits are in the data. A stream holds its entry in the table,
//! counted against SETTINGS_MAX_CONCURRENT_STREAMS, until its handler
//! returns, whatever the protocol says: a client that resets streams
//! (Rapid Reset, CVE-2023-44487) or makes us reset them (MadeYouReset,
//! CVE-2025-8671) gets REFUSED_STREAM, not more work. A stream's receive
//! window is the protocol's default, never changed, and the server
//! buffers that much of its body. Frames that do no work are paid for in
//! bytes, by nginx's rule: past a free megabyte, every byte received
//! must be matched by one in eight that carries a request or a body.

const std = @import("std");
const assert = std.debug.assert;
const hpack = @import("hpack.zig");
const frame = @import("http2_frame.zig");
const http1_head = @import("http1_head.zig");
const http1_response = @import("http1_response.zig");
const stdx = @import("stdx.zig");
const Prng = @import("prng.zig").Prng;

pub const ErrorCode = frame.ErrorCode;
const header_bytes = frame.header_bytes;

pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Each stream's receive window, the protocol's initial one, never
/// changed: a client may send this much before our SETTINGS arrive
/// (RFC 9113 §6.9.2), so no smaller value would hold. The server buffers
/// this much body per stream.
pub const stream_window_bytes: u32 = 65_535;
/// A frame we accept is at most this large: SETTINGS_MAX_FRAME_SIZE is
/// never raised. The caller's input buffer holds one whole.
pub const input_bytes_min = header_bytes + frame.frame_size_default;
/// The most one received frame writes into the send buffer: a PING's ACK.
const reply_bytes_max = header_bytes + 8;
/// The frame flood rule (nginx's): received bytes past this allowance
/// must be at most `flood_ratio` times the bytes that did work.
const flood_bytes_free: u64 = 1 << 20;
const flood_ratio: u64 = 8;
const window_initial: i64 = 65_535;
/// HPACK's table, at the protocol's default size (never changed).
const header_table_bytes = 4096;
/// The longest header name a response may carry (lowercased on the way).
const response_name_bytes_max = 256;

pub const Limits = struct {
    /// SETTINGS_MAX_CONCURRENT_STREAMS: streams held at once, each until
    /// its handler returns.
    streams_max: u16,
    /// SETTINGS_MAX_HEADER_LIST_SIZE: a request's decoded header list,
    /// and its encoded block (the bound on a CONTINUATION flood).
    head_bytes_max: u32,
    /// The send buffer, where frames wait.
    out_bytes: u32,

    pub fn assert_valid(limits: Limits) void {
        assert(limits.streams_max > 0);
        assert(limits.head_bytes_max >= 64);
        assert(limits.head_bytes_max <= 1 << 24);
        // A whole frame of a handler's and one reply fit together.
        assert(limits.out_bytes >= input_bytes_min + reply_bytes_max);
    }

    /// The fields a list of `head_bytes_max` holds at most: each counts
    /// 32 besides its bytes (RFC 7541 §4.1).
    fn fields_max(limits: Limits) u32 {
        return limits.head_bytes_max / 32;
    }

    /// Decoded names and values, then room to join cookie crumbs.
    fn head_bytes(limits: Limits) u32 {
        return 2 * limits.head_bytes_max + 2 * limits.fields_max();
    }

    /// The connection's receive window: every stream's, at most.
    fn recv_window_max(limits: Limits) i64 {
        const all = @as(i64, limits.streams_max) * stream_window_bytes;
        return @min(all, frame.window_max);
    }
};

/// A request's head, from its pseudo-header fields and fields.
pub const Head = struct {
    method: []const u8,
    scheme: []const u8,
    /// `:authority`, else `host`; empty without either.
    authority: []const u8,
    path: []const u8,
    /// The fields, names lowercase, cookie crumbs joined (§8.2.3).
    headers: []const hpack.Header,
    content_length: ?u64,
    /// No body follows.
    end_stream: bool,
};

pub const Event = union(enum) {
    /// Every whole frame is handled: read more.
    incomplete,
    /// The send buffer lacks room for a reply: send, then call again.
    flush,
    /// A new stream's request, its head valid until the next call. The
    /// server takes the stream, or gives it back with `refuse`.
    request: Request,
    /// Body bytes, valid until the next call; none at a trailer's end.
    data: Data,
    /// A held stream was reset, by the peer or by us: its handler should
    /// stop. The stream stays held until `release`.
    reset: u16,
    /// A send window opened: senders waiting on one may go on.
    window,
    /// The connection is over: send what waits, then close.
    close,

    pub const Request = struct { index: u16, id: u31, head: Head };
    pub const Data = struct { index: u16, bytes: []const u8, end_stream: bool };
};

pub const Step = struct { consumed: u32, event: Event };

pub const SendError = error{
    /// The stream was reset, or the connection is over: nothing more goes
    /// out on it.
    Reset,
    /// The send buffer lacks room: send, then call again.
    NoRoom,
    /// A head that cannot be sent (as `http1_response` refuses one): the
    /// application's bug. Nothing was written.
    HeadRefused,
};

pub const Counters = struct {
    requests: u64 = 0,
    /// Streams refused for want of room (REFUSED_STREAM).
    refused: u64 = 0,
    /// Requests malformed (§8.1.1), reset with PROTOCOL_ERROR.
    malformed: u64 = 0,
    resets_received: u64 = 0,
    resets_sent: u64 = 0,
    /// The error that ended the connection, ours.
    failed: ?ErrorCode = null,
};

pub const Stream = struct {
    reset: Reset = .none,
    /// Our RST_STREAM, waiting for room in the send buffer.
    reset_pending: ?ErrorCode = null,
    /// The peer sends no more: its END_STREAM, or a reset.
    remote_closed: bool,
    /// We send no more: our END_STREAM, or a reset.
    local_closed: bool = false,
    /// The server's until `release`: its handler runs.
    held: bool = true,
    send_window: i64,
    recv_window: i64 = stream_window_bytes,
    /// Bytes read by the handler (and padding) not yet given back.
    recv_credit: u32 = 0,
    /// What a `content-length` says is still to come.
    body_left: ?u64,

    pub const Reset = enum {
        none,
        /// Ours: frames the peer sent before it knew are discarded.
        ours,
        /// The peer's: any frame after it is an error.
        peers,
    };
};

const Phase = enum { preface, settings, frames, closed };

pub const Connection = struct {
    limits: Limits,
    decoder: hpack.Decoder,
    /// A field block gathered from HEADERS and CONTINUATION frames.
    block: []u8,
    /// Decoded names and values, and joined cookies.
    head: []u8,
    fields: []hpack.Header,
    /// Frames waiting to be sent: ours and the handlers'.
    out: []u8,
    /// The stream table, as two arrays: ids (0: a free entry), scanned to
    /// find a stream, and the streams.
    stream_ids: []u32,
    streams: []Stream,

    phase: Phase = .preface,
    out_used: u32 = 0,
    block_used: u32 = 0,
    /// The stream whose block is being gathered; 0 when none.
    block_stream: u31 = 0,
    block_end_stream: bool = false,
    block_depends_on_itself: bool = false,
    /// The highest stream the peer has opened (§5.1.1).
    last_stream: u31 = 0,
    streams_used: u16 = 0,
    /// What the peer lets us send on the connection, and each new stream.
    send_window: i64 = window_initial,
    send_window_initial: i64 = window_initial,
    /// What the peer may still send, and what is ready to give back.
    recv_window: i64 = window_initial,
    recv_credit: u64 = 0,
    goaway_pending: ?ErrorCode = null,
    /// Our GOAWAY is decided: new streams are decoded, then ignored.
    goaway_sent: bool = false,
    /// The last stream processed when it was: those after it may be
    /// retried elsewhere (§6.8).
    goaway_last: u31 = 0,
    /// Some stream has a frame waiting for room (`write_deferred`).
    deferred: bool = false,
    bytes_received: u64 = 0,
    bytes_useful: u64 = 0,
    counters: Counters = .{},

    pub fn init(gpa: std.mem.Allocator, limits: Limits) std.mem.Allocator.Error!Connection {
        limits.assert_valid();
        var decoder: hpack.Decoder = try .init(gpa, header_table_bytes);
        errdefer decoder.deinit(gpa);
        const block = try gpa.alloc(u8, limits.head_bytes_max);
        errdefer gpa.free(block);
        const head = try gpa.alloc(u8, limits.head_bytes());
        errdefer gpa.free(head);
        const fields = try gpa.alloc(hpack.Header, limits.fields_max());
        errdefer gpa.free(fields);
        const out = try gpa.alloc(u8, limits.out_bytes);
        errdefer gpa.free(out);
        const stream_ids = try gpa.alloc(u32, limits.streams_max);
        errdefer gpa.free(stream_ids);
        const streams = try gpa.alloc(Stream, limits.streams_max);
        return .{
            .limits = limits,
            .decoder = decoder,
            .block = block,
            .head = head,
            .fields = fields,
            .out = out,
            .stream_ids = stream_ids,
            .streams = streams,
        };
    }

    pub fn deinit(connection: *Connection, gpa: std.mem.Allocator) void {
        connection.decoder.deinit(gpa);
        gpa.free(connection.block);
        gpa.free(connection.head);
        gpa.free(connection.fields);
        gpa.free(connection.out);
        gpa.free(connection.stream_ids);
        gpa.free(connection.streams);
        connection.* = undefined;
    }

    /// A new connection: every state reset, and our preface (SETTINGS,
    /// and the connection window raised) waiting to be sent.
    pub fn start(connection: *Connection) void {
        connection.decoder.reset();
        @memset(connection.stream_ids, 0);
        const fresh: Connection = .{
            .limits = connection.limits,
            .decoder = connection.decoder,
            .block = connection.block,
            .head = connection.head,
            .fields = connection.fields,
            .out = connection.out,
            .stream_ids = connection.stream_ids,
            .streams = connection.streams,
        };
        connection.* = fresh;
        const settings = [_]frame.SettingEntry{
            .{ .id = .max_concurrent_streams, .value = connection.limits.streams_max },
            .{ .id = .max_header_list_size, .value = connection.limits.head_bytes_max },
        };
        connection.out_used = @intCast(frame.write_settings(connection.out, &settings));
        const raise = connection.limits.recv_window_max() - window_initial;
        if (raise > 0) {
            frame.write_window_update(connection.take(13), 0, @intCast(raise));
            assert(connection.recv_window == window_initial);
            connection.recv_window += raise;
        }
        connection.check_invariants();
    }

    // --- receiving ------------------------------------------------------------

    /// Consume whole frames from `input` until one needs the server.
    pub fn receive(connection: *Connection, input: []const u8) Step {
        if (connection.phase == .closed) {
            return .{ .consumed = @intCast(input.len), .event = .close };
        }
        var consumed: usize = 0;
        if (connection.phase == .preface) {
            const length = @min(input.len, preface.len);
            if (!std.mem.eql(u8, input[0..length], preface[0..length])) {
                // Not HTTP/2: no GOAWAY (§3.4).
                connection.phase = .closed;
                return .{ .consumed = @intCast(input.len), .event = .close };
            }
            if (length < preface.len) return .{ .consumed = 0, .event = .incomplete };
            consumed = preface.len;
            connection.phase = .settings;
        }
        // Each pass consumes a frame, of nine bytes at least.
        for (0..input.len / header_bytes + 1) |_| {
            const rest = input[consumed..];
            if (rest.len < header_bytes) break;
            const header = frame.parse_header(rest[0..header_bytes]);
            if (header.length > frame.frame_size_default) {
                const event = connection.fail(.frame_size_error);
                return .{ .consumed = @intCast(input.len), .event = event };
            }
            const size = header_bytes + header.length;
            if (rest.len < size) break;
            if (connection.out_free() < reply_bytes_max) {
                return .{ .consumed = @intCast(consumed), .event = .flush };
            }
            consumed += size;
            connection.bytes_received += size;
            var event = connection.on_frame(header, rest[header_bytes..size]);
            if (connection.phase != .closed and connection.flooded()) {
                event = connection.fail(.enhance_your_calm);
            }
            if (event) |happened| {
                if (happened == .close) consumed = input.len;
                return .{ .consumed = @intCast(consumed), .event = happened };
            }
        } else unreachable;
        return .{ .consumed = @intCast(consumed), .event = .incomplete };
    }

    fn flooded(connection: *const Connection) bool {
        const allowed = flood_ratio * connection.bytes_useful + flood_bytes_free;
        return connection.bytes_received > allowed;
    }

    fn on_frame(connection: *Connection, header: frame.Header, payload: []const u8) ?Event {
        if (connection.phase == .settings) {
            // The client's preface ends with a SETTINGS frame (§3.4).
            const settings = header.type == .settings and header.flags & frame.flag_ack == 0;
            if (!settings) return connection.fail(.protocol_error);
        }
        if (connection.block_stream != 0) {
            // Nothing between a block's frames (§6.10).
            const next = header.type == .continuation and header.stream == connection.block_stream;
            if (!next) return connection.fail(.protocol_error);
        }
        switch (frame.parse(header, payload)) {
            .refusal => |refusal| {
                if (refusal.connection) return connection.fail(refusal.code);
                return connection.stream_error(refusal.stream, refusal.code);
            },
            .frame => |parsed| return connection.on_parsed(parsed),
        }
    }

    fn on_parsed(connection: *Connection, parsed: frame.Frame) ?Event {
        switch (parsed) {
            .data => |data| return connection.on_data(data),
            .headers => |headers| return connection.on_headers(headers),
            .continuation => |continuation| return connection.on_continuation(continuation),
            .rst_stream => |reset| return connection.on_reset(reset.stream),
            .settings => |settings| {
                if (settings.ack) return null;
                return connection.on_settings(settings.entries);
            },
            .ping => |ping| {
                if (!ping.ack) frame.write_ping_ack(connection.take(17), ping.opaque_data);
                return null;
            },
            .window_update => |update| return connection.on_window_update(update),
            // A peer's GOAWAY: it opens no more streams; those open finish.
            .goaway, .priority, .unknown => return null,
        }
    }

    fn on_headers(connection: *Connection, headers: frame.Frame.Headers) ?Event {
        if (headers.stream % 2 == 0) return connection.fail(.protocol_error);
        if (headers.end_headers) {
            return connection.on_block(.{
                .id = headers.stream,
                .block = headers.fragment,
                .end_stream = headers.end_stream,
                .depends_on_itself = headers.depends_on_itself,
            });
        }
        if (headers.fragment.len > connection.block.len) {
            return connection.fail(.enhance_your_calm);
        }
        @memcpy(connection.block[0..headers.fragment.len], headers.fragment);
        connection.block_used = @intCast(headers.fragment.len);
        connection.block_stream = headers.stream;
        connection.block_end_stream = headers.end_stream;
        connection.block_depends_on_itself = headers.depends_on_itself;
        return null;
    }

    fn on_continuation(connection: *Connection, continuation: frame.Frame.Continuation) ?Event {
        // Not after a HEADERS without END_HEADERS: a protocol error (§6.10).
        if (connection.block_stream == 0) return connection.fail(.protocol_error);
        assert(continuation.stream == connection.block_stream);
        const fragment = continuation.fragment;
        if (fragment.len > connection.block.len - connection.block_used) {
            return connection.fail(.enhance_your_calm);
        }
        @memcpy(connection.block[connection.block_used..][0..fragment.len], fragment);
        connection.block_used += @intCast(fragment.len);
        if (!continuation.end_headers) return null;
        connection.block_stream = 0;
        return connection.on_block(.{
            .id = continuation.stream,
            .block = connection.block[0..connection.block_used],
            .end_stream = connection.block_end_stream,
            .depends_on_itself = connection.block_depends_on_itself,
        });
    }

    const Block = struct {
        id: u31,
        block: []const u8,
        end_stream: bool,
        depends_on_itself: bool,
    };

    /// A whole field block: decoded first, whatever becomes of it, so the
    /// table stays in step with the peer's (§4.3).
    fn on_block(connection: *Connection, block: Block) ?Event {
        assert(block.id % 2 == 1);
        const storage = connection.head[0..connection.limits.head_bytes_max];
        const decoded = connection.decoder.decode(block.block, storage, connection.fields);
        // Too large, too: our table would miss the entries after the
        // overflow, so the peer's and ours could not agree again.
        const count = decoded catch |err| switch (err) {
            error.Compression, error.HeaderListTooLarge => {
                return connection.fail(.compression_error);
            },
        };
        if (connection.find(block.id)) |index| {
            return connection.on_trailers(index, count, block.end_stream);
        }
        if (block.id <= connection.last_stream) return connection.fail(.protocol_error);
        connection.last_stream = block.id;
        if (block.depends_on_itself) {
            connection.write_reset(block.id, .protocol_error);
            return null;
        }
        if (connection.goaway_sent) return null;
        if (connection.streams_used == connection.limits.streams_max) {
            connection.counters.refused += 1;
            connection.write_reset(block.id, .refused_stream);
            return null;
        }
        const head = connection.request_head(count, block.end_stream) orelse {
            connection.counters.malformed += 1;
            connection.write_reset(block.id, .protocol_error);
            return null;
        };
        const index = connection.open(block.id, head);
        connection.bytes_useful += block.block.len;
        connection.counters.requests += 1;
        return .{ .request = .{ .index = index, .id = block.id, .head = head } };
    }

    /// A second block on a stream: trailers, which end it (§8.1).
    fn on_trailers(connection: *Connection, index: u16, count: usize, end_stream: bool) ?Event {
        const stream = &connection.streams[index];
        if (stream.reset == .ours) return null;
        if (stream.remote_closed) return connection.closed_stream_error(index);
        const fields = connection.fields[0..count];
        const pseudo = for (fields) |field| {
            if (field.name.len > 0 and field.name[0] == ':') break true;
        } else false;
        const whole = if (stream.body_left) |left| left == 0 else true;
        if (!end_stream or pseudo or !whole) {
            connection.counters.malformed += 1;
            return connection.reset_stream(index, .protocol_error);
        }
        stream.remote_closed = true;
        return .{ .data = .{ .index = index, .bytes = "", .end_stream = true } };
    }

    fn on_data(connection: *Connection, data: frame.Frame.Data) ?Event {
        // The connection's window counts every DATA frame, whatever becomes
        // of its stream (§6.9); its credit goes back at once, since every
        // stream's own window bounds what is buffered.
        if (data.flow_length > connection.recv_window) return connection.fail(.flow_control_error);
        connection.recv_window -= data.flow_length;
        connection.recv_credit += data.flow_length;
        const index = connection.find(data.stream) orelse {
            if (data.stream > connection.last_stream) return connection.fail(.protocol_error);
            connection.write_reset(data.stream, .stream_closed);
            return null;
        };
        const stream = &connection.streams[index];
        if (stream.reset == .ours) return null;
        if (stream.remote_closed) return connection.closed_stream_error(index);
        if (data.flow_length > stream.recv_window) {
            return connection.reset_stream(index, .flow_control_error);
        }
        stream.recv_window -= data.flow_length;
        // Padding is never read: its credit goes back with the next update.
        stream.recv_credit += @intCast(data.flow_length - data.data.len);
        if (stream.body_left) |left| {
            const over = data.data.len > left;
            if (over or (data.end_stream and data.data.len != left)) {
                connection.counters.malformed += 1;
                return connection.reset_stream(index, .protocol_error);
            }
            stream.body_left = left - data.data.len;
        }
        if (data.end_stream) stream.remote_closed = true;
        connection.bytes_useful += data.data.len;
        if (data.data.len == 0 and !data.end_stream) return null;
        return .{ .data = .{ .index = index, .bytes = data.data, .end_stream = data.end_stream } };
    }

    fn on_reset(connection: *Connection, id: u31) ?Event {
        const index = connection.find(id) orelse {
            if (id > connection.last_stream) return connection.fail(.protocol_error);
            return null;
        };
        connection.counters.resets_received += 1;
        const stream = &connection.streams[index];
        if (stream.reset != .none) return null;
        assert(stream.held);
        stream.reset = .peers;
        stream.remote_closed = true;
        stream.local_closed = true;
        return .{ .reset = index };
    }

    fn on_window_update(connection: *Connection, update: frame.Frame.WindowUpdate) ?Event {
        if (update.stream == 0) {
            const window = connection.send_window + update.increment;
            if (window > frame.window_max) return connection.fail(.flow_control_error);
            connection.send_window = window;
            return .window;
        }
        const index = connection.find(update.stream) orelse {
            if (update.stream > connection.last_stream) return connection.fail(.protocol_error);
            return null;
        };
        const stream = &connection.streams[index];
        if (stream.reset != .none) return null;
        const window = stream.send_window + update.increment;
        if (window > frame.window_max) return connection.reset_stream(index, .flow_control_error);
        stream.send_window = window;
        return .window;
    }

    fn on_settings(connection: *Connection, entries: []const u8) ?Event {
        var opened = false;
        for (0..entries.len / 6) |entry_index| {
            const entry = frame.setting_at(entries, entry_index * 6);
            // The rest bind a sender we are not: we never push, never
            // index (so the peer's table size is moot), and send frames
            // of the least size every peer takes.
            if (entry.id != .initial_window_size) continue;
            // Every stream's window moves by the change (§6.9.2).
            const delta = @as(i64, entry.value) - connection.send_window_initial;
            for (connection.stream_ids, connection.streams) |id, *stream| {
                if (id == 0) continue;
                const window = stream.send_window + delta;
                if (window > frame.window_max) return connection.fail(.flow_control_error);
                stream.send_window = window;
            }
            connection.send_window_initial = entry.value;
            opened = opened or delta > 0;
        }
        frame.write_settings_ack(connection.take(header_bytes));
        if (connection.phase == .settings) connection.phase = .frames;
        return if (opened) .window else null;
    }

    // --- stream states ----------------------------------------------------------

    fn find(connection: *const Connection, id: u31) ?u16 {
        assert(id != 0);
        for (connection.stream_ids, 0..) |entry, index| {
            if (entry == id) return @intCast(index);
        }
        return null;
    }

    fn open(connection: *Connection, id: u31, head: Head) u16 {
        assert(connection.streams_used < connection.limits.streams_max);
        const index = connection.find_free();
        connection.stream_ids[index] = id;
        connection.streams[index] = .{
            .remote_closed = head.end_stream,
            .send_window = connection.send_window_initial,
            .body_left = head.content_length,
        };
        connection.streams_used += 1;
        return index;
    }

    fn find_free(connection: *const Connection) u16 {
        for (connection.stream_ids, 0..) |entry, index| {
            if (entry == 0) return @intCast(index);
        }
        unreachable;
    }

    /// A stream error (§5.4.2): our RST_STREAM. A stream in the table
    /// keeps its entry until its handler returns and the reset is sent.
    fn stream_error(connection: *Connection, id: u31, code: ErrorCode) ?Event {
        if (connection.find(id)) |index| return connection.reset_stream(index, code);
        connection.write_reset(id, code);
        return null;
    }

    fn reset_stream(connection: *Connection, index: u16, code: ErrorCode) ?Event {
        const stream = &connection.streams[index];
        if (stream.reset != .none) return null;
        stream.reset = .ours;
        stream.reset_pending = code;
        stream.remote_closed = true;
        stream.local_closed = true;
        connection.deferred = true;
        return if (stream.held) .{ .reset = index } else null;
    }

    /// A frame on a stream the peer has closed (§5.1): STREAM_CLOSED.
    fn closed_stream_error(connection: *Connection, index: u16) ?Event {
        const stream = &connection.streams[index];
        assert(stream.remote_closed);
        assert(stream.reset != .ours);
        if (stream.reset == .peers) {
            connection.write_reset(@intCast(connection.stream_ids[index]), .stream_closed);
            return null;
        }
        return connection.reset_stream(index, .stream_closed);
    }

    /// A connection error (§5.4.1): GOAWAY, then the end.
    fn fail(connection: *Connection, code: ErrorCode) Event {
        assert(connection.phase != .closed);
        connection.phase = .closed;
        connection.counters.failed = code;
        connection.goaway_pending = code;
        connection.goaway_sent = true;
        connection.goaway_last = connection.last_stream;
        return .close;
    }

    fn maybe_free(connection: *Connection, index: u16) void {
        const stream = &connection.streams[index];
        if (stream.held or stream.reset_pending != null) return;
        connection.stream_ids[index] = 0;
        connection.streams_used -= 1;
    }

    // --- the server's side ------------------------------------------------------

    /// A request the server cannot take (no room in the shard): REFUSED_STREAM,
    /// which a client retries.
    pub fn refuse(connection: *Connection, index: u16) void {
        connection.counters.refused += 1;
        _ = connection.reset_stream(index, .refused_stream);
        connection.release(index);
    }

    /// The handler has returned: its stream is given back. A response cut
    /// short is reset (INTERNAL_ERROR): the client sees an error, never a
    /// complete wrong response. A request still sending its body is told
    /// to stop (NO_ERROR, §8.1).
    pub fn release(connection: *Connection, index: u16) void {
        const stream = &connection.streams[index];
        assert(connection.stream_ids[index] != 0);
        assert(stream.held);
        if (stream.reset == .none and connection.phase != .closed) {
            if (!stream.local_closed) {
                _ = connection.reset_stream(index, .internal_error);
            } else if (!stream.remote_closed) {
                _ = connection.reset_stream(index, .no_error);
            }
        }
        stream.held = false;
        if (connection.phase == .closed) stream.reset_pending = null;
        connection.maybe_free(index);
    }

    /// The handler has read `count` body bytes: the peer may send them again.
    pub fn body_read(connection: *Connection, index: u16, count: u32) void {
        const stream = &connection.streams[index];
        assert(stream.held);
        stream.recv_credit += count;
        assert(stream.recv_window + stream.recv_credit <= stream_window_bytes);
        if (stream.recv_credit >= stream_window_bytes / 2) connection.deferred = true;
    }

    /// A held stream ended by the server (a drain ending an event stream):
    /// CANCEL, and its handler's sends refused.
    pub fn cancel(connection: *Connection, index: u16) void {
        assert(connection.streams[index].held);
        _ = connection.reset_stream(index, .cancel);
    }

    /// The socket is gone: nothing more is sent, and no GOAWAY.
    pub fn abandon(connection: *Connection) void {
        if (connection.phase == .closed) return;
        connection.phase = .closed;
        connection.goaway_pending = null;
        connection.goaway_sent = true;
        connection.goaway_last = connection.last_stream;
    }

    pub fn closed(connection: *const Connection) bool {
        return connection.phase == .closed;
    }

    /// Draining: GOAWAY, no new streams; those open finish.
    pub fn goaway(connection: *Connection) void {
        if (connection.goaway_sent) return;
        connection.goaway_sent = true;
        connection.goaway_pending = .no_error;
        connection.goaway_last = connection.last_stream;
    }

    pub fn streams_held(connection: *const Connection) u16 {
        var held: u16 = 0;
        for (connection.stream_ids, connection.streams) |id, stream| {
            if (id != 0 and stream.held) held += 1;
        }
        return held;
    }

    /// A response's head: HEADERS, with END_STREAM when no body follows.
    /// `keep_alive` has no meaning here; the framing's length becomes
    /// `content-length`, and a chunked one none (DATA frames end it).
    pub fn send_head(
        connection: *Connection,
        index: u16,
        head: http1_response.Head,
        end_stream: bool,
    ) SendError!void {
        const stream = &connection.streams[index];
        assert(stream.held);
        if (connection.phase == .closed or stream.reset != .none) return error.Reset;
        assert(!stream.local_closed);
        try head_check(head, end_stream);
        const at = connection.out_used;
        const room = connection.out.len - at;
        if (room <= header_bytes) return error.NoRoom;
        const fits = @min(room - header_bytes, frame.frame_size_default);
        var block: BlockWriter = .{ .bytes = connection.out[at + header_bytes ..][0..fits] };
        block.write_head(head);
        if (block.overflow) {
            return if (fits < frame.frame_size_default) error.NoRoom else error.HeadRefused;
        }
        var flags: u8 = frame.flag_end_headers;
        if (end_stream) flags |= frame.flag_end_stream;
        const id: u31 = @intCast(connection.stream_ids[index]);
        const header = frame.frame_header(.headers, flags, id, block.used);
        frame.write_header(connection.out[at..][0..header_bytes], header);
        connection.out_used += @intCast(header_bytes + block.used);
        if (end_stream) stream.local_closed = true;
    }

    /// Body bytes, as many as both windows and the send buffer allow, in
    /// one DATA frame: the count written. 0 when a window is closed: wait
    /// for `Event.window`. END_STREAM goes with the last of `bytes`.
    pub fn send_data(
        connection: *Connection,
        index: u16,
        bytes: []const u8,
        end_stream: bool,
    ) SendError!u32 {
        const stream = &connection.streams[index];
        assert(stream.held);
        if (connection.phase == .closed or stream.reset != .none) return error.Reset;
        assert(!stream.local_closed);
        const room = connection.out_free();
        if (room <= header_bytes) return error.NoRoom;
        const window: usize = @intCast(@max(0, @min(stream.send_window, connection.send_window)));
        const fits = @min(room - header_bytes, frame.frame_size_default);
        const count: u32 = @intCast(@min(bytes.len, window, fits));
        if (count == 0 and bytes.len > 0) return 0;
        const last = end_stream and count == bytes.len;
        const id: u31 = @intCast(connection.stream_ids[index]);
        const flags: u8 = if (last) frame.flag_end_stream else 0;
        const at = connection.out[connection.out_used..][0 .. header_bytes + count];
        frame.write_header(at[0..header_bytes], frame.frame_header(.data, flags, id, count));
        @memcpy(at[header_bytes..], bytes[0..count]);
        connection.out_used += header_bytes + count;
        stream.send_window -= count;
        connection.send_window -= count;
        connection.bytes_useful += count;
        if (last) stream.local_closed = true;
        return count;
    }

    // --- the send buffer --------------------------------------------------------

    pub fn wants_flush(connection: *const Connection) bool {
        const credit = connection.phase != .closed and connection.recv_credit_due();
        return connection.out_used > 0 or connection.deferred or
            connection.goaway_pending != null or credit;
    }

    /// The bytes to send, deferred frames first written as room allows.
    /// The buffer may grow while they are sent; `sent` drops them after.
    pub fn pending(connection: *Connection) []const u8 {
        connection.write_deferred();
        return connection.out[0..connection.out_used];
    }

    pub fn sent(connection: *Connection, count: u32) void {
        assert(count <= connection.out_used);
        const rest = connection.out[count..connection.out_used];
        std.mem.copyForwards(u8, connection.out[0..rest.len], rest);
        connection.out_used -= count;
    }

    fn out_free(connection: *const Connection) u32 {
        return @intCast(connection.out.len - connection.out_used);
    }

    fn take(connection: *Connection, comptime bytes: u32) *[bytes]u8 {
        assert(connection.out_free() >= bytes);
        const at = connection.out[connection.out_used..][0..bytes];
        connection.out_used += bytes;
        return at;
    }

    fn write_reset(connection: *Connection, id: u31, code: ErrorCode) void {
        frame.write_rst_stream(connection.take(13), id, code);
        connection.counters.resets_sent += 1;
    }

    fn recv_credit_due(connection: *const Connection) bool {
        return connection.recv_credit >= @divTrunc(connection.limits.recv_window_max(), 2);
    }

    /// Frames decided while the buffer may have been full: resets, window
    /// updates, GOAWAY last. What does not fit waits for the next flush.
    fn write_deferred(connection: *Connection) void {
        if (connection.deferred) connection.write_deferred_streams();
        if (connection.phase != .closed and connection.recv_credit_due() and
            connection.out_free() >= 13)
        {
            const credit: u31 = @intCast(connection.recv_credit);
            frame.write_window_update(connection.take(13), 0, credit);
            connection.recv_window += credit;
            connection.recv_credit = 0;
        }
        if (connection.goaway_pending) |code| {
            if (connection.out_free() < 17) return;
            frame.write_goaway(connection.take(17), connection.goaway_last, code);
            connection.goaway_pending = null;
        }
    }

    fn write_deferred_streams(connection: *Connection) void {
        connection.deferred = false;
        for (connection.stream_ids, connection.streams, 0..) |id, *stream, index| {
            if (id == 0) continue;
            if (connection.out_free() < 13) {
                connection.deferred = true;
                return;
            }
            if (stream.reset_pending) |code| {
                connection.write_reset(@intCast(id), code);
                stream.reset_pending = null;
                connection.maybe_free(@intCast(index));
            } else if (!stream.remote_closed and stream.recv_credit >= stream_window_bytes / 2) {
                const at = connection.take(13);
                frame.write_window_update(at, @intCast(id), @intCast(stream.recv_credit));
                stream.recv_window += stream.recv_credit;
                stream.recv_credit = 0;
            }
        }
    }

    pub fn check_invariants(connection: *const Connection) void {
        var used: u16 = 0;
        for (connection.stream_ids, connection.streams) |id, stream| {
            if (id == 0) continue;
            used += 1;
            assert(id % 2 == 1 and id <= connection.last_stream);
            assert(stream.held or stream.reset_pending != null);
            assert(stream.reset == .none or (stream.remote_closed and stream.local_closed));
            assert(stream.recv_window >= 0);
            assert(stream.recv_window + stream.recv_credit <= stream_window_bytes);
            assert(stream.send_window <= frame.window_max);
        }
        assert(used == connection.streams_used);
        assert(used <= connection.limits.streams_max);
        assert(connection.out_used <= connection.out.len);
        assert(connection.recv_window >= 0);
        const outstanding = connection.recv_window + @as(i64, @intCast(connection.recv_credit));
        assert(outstanding <= connection.limits.recv_window_max());
        assert(connection.send_window <= frame.window_max);
        assert(connection.block_used <= connection.block.len);
        assert(connection.block_stream == 0 or connection.phase != .preface);
    }

    // --- requests (§8.1.1, §8.2, §8.3) -----------------------------------------

    /// The head of a request, or null when it is malformed.
    fn request_head(connection: *Connection, count: usize, end_stream: bool) ?Head {
        const fields = connection.fields[0..count];
        var pseudo: [4]?[]const u8 = @splat(null);
        var pseudo_count: usize = 0;
        for (fields) |field| {
            if (field.name.len == 0 or field.name[0] != ':') break;
            const which = pseudo_index(field.name) orelse return null;
            if (pseudo[which] != null) return null;
            pseudo[which] = field.value;
            pseudo_count += 1;
        }
        const regular = fields[pseudo_count..];
        var head: Head = .{
            .method = pseudo[0] orelse return null,
            .scheme = pseudo[1] orelse return null,
            .authority = pseudo[2] orelse "",
            .path = pseudo[3] orelse return null,
            .headers = &.{},
            .content_length = null,
            .end_stream = end_stream,
        };
        if (!pseudo_valid(head)) return null;
        var host: ?[]const u8 = null;
        var cookies: u32 = 0;
        for (regular) |field| {
            if (!field_valid(field)) return null;
            if (std.mem.eql(u8, field.name, "content-length")) {
                const length = parse_length(field.value) orelse return null;
                if (head.content_length) |known| if (known != length) return null;
                head.content_length = length;
            } else if (std.mem.eql(u8, field.name, "host")) {
                if (host != null) return null;
                host = field.value;
            } else if (std.mem.eql(u8, field.name, "cookie")) {
                cookies += 1;
            }
        }
        if (host) |value| {
            if (pseudo[2] == null) head.authority = value;
            if (!stdx.equal_ignoring_case(value, head.authority)) return null;
        }
        if (end_stream) if (head.content_length) |length| if (length != 0) return null;
        head.headers = if (cookies > 1) connection.join_cookies(regular) else regular;
        return head;
    }

    /// Cookie crumbs as one field, "; " between them (§8.2.3), after the
    /// others: what an HTTP/1.1 application expects.
    fn join_cookies(connection: *Connection, regular: []hpack.Header) []hpack.Header {
        const joined = connection.head[connection.limits.head_bytes_max..];
        var used: usize = 0;
        var kept: usize = 0;
        for (regular) |field| {
            if (!std.mem.eql(u8, field.name, "cookie")) {
                regular[kept] = field;
                kept += 1;
                continue;
            }
            if (used > 0) {
                joined[used..][0..2].* = "; ".*;
                used += 2;
            }
            @memcpy(joined[used..][0..field.value.len], field.value);
            used += field.value.len;
        }
        assert(kept < regular.len);
        regular[kept] = .{ .name = "cookie", .value = joined[0..used] };
        return regular[0 .. kept + 1];
    }
};

fn pseudo_index(name: []const u8) ?usize {
    const names = [_][]const u8{ ":method", ":scheme", ":authority", ":path" };
    for (names, 0..) |known, index| {
        if (std.mem.eql(u8, name, known)) return index;
    }
    return null;
}

fn pseudo_valid(head: Head) bool {
    if (head.method.len == 0) return false;
    if (!http1_head.all_in(head.method, &http1_head.token_table)) return false;
    if (head.scheme.len == 0) return false;
    if (!http1_head.all_in(head.scheme, &http1_head.token_table)) return false;
    if (!http1_head.all_in(head.authority, &http1_head.target_table)) return false;
    if (head.path.len == 0) return false;
    if (!http1_head.all_in(head.path, &http1_head.target_table)) return false;
    const asterisk = std.mem.eql(u8, head.path, "*") and std.mem.eql(u8, head.method, "OPTIONS");
    return head.path[0] == '/' or asterisk;
}

/// A regular field (§8.2.1, §8.2.2): a lowercase token for a name, a
/// value with no controls and no surrounding whitespace, and no field
/// that belongs to an HTTP/1.1 connection.
fn field_valid(field: hpack.Header) bool {
    if (field.name.len == 0) return false;
    if (!http1_head.all_in(field.name, &name_table)) return false;
    if (!http1_head.all_in(field.value, &http1_head.value_table)) return false;
    if (field.value.len > 0) {
        const first = field.value[0];
        const last = field.value[field.value.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return false;
    }
    const connection_specific = [_][]const u8{
        "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
    };
    for (connection_specific) |name| {
        if (std.mem.eql(u8, field.name, name)) return false;
    }
    if (std.mem.eql(u8, field.name, "te")) return std.mem.eql(u8, field.value, "trailers");
    return true;
}

/// A token without capitals (§8.2.1).
const name_table = table: {
    var table = http1_head.token_table;
    for ('A'..'Z' + 1) |byte| table[byte] = false;
    break :table table;
};

fn parse_length(text: []const u8) ?u64 {
    // 19 digits always fit a u64.
    if (text.len == 0 or text.len > 19) return null;
    var value: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
        value = value * 10 + (byte - '0');
    }
    return value;
}

fn head_check(head: http1_response.Head, end_stream: bool) SendError!void {
    if (head.status < 100 or head.status > 999) return error.HeadRefused;
    if (http1_response.status_forbids_body(head.status) != (head.framing == .none)) {
        return error.HeadRefused;
    }
    // An interim response never ends a stream (§8.1).
    if (head.status < 200 and end_stream) return error.HeadRefused;
    for (head.headers) |header| {
        if (http1_response.header_refusal(header) != null) return error.HeadRefused;
        if (header.name.len > response_name_bytes_max) return error.HeadRefused;
    }
}

/// A response's field block, encoded into a frame's room.
const BlockWriter = struct {
    bytes: []u8,
    used: usize = 0,
    overflow: bool = false,

    fn write_head(writer: *BlockWriter, head: http1_response.Head) void {
        const status: [3]u8 = .{
            @intCast('0' + head.status / 100),
            @intCast('0' + head.status / 10 % 10),
            @intCast('0' + head.status % 10),
        };
        writer.field(":status", &status);
        writer.field("date", head.date);
        switch (head.framing) {
            .length => |length| {
                var text: [20]u8 = undefined;
                const digits = std.fmt.bufPrint(&text, "{d}", .{length}) catch unreachable;
                writer.field("content-length", digits);
            },
            .chunked, .none => {},
        }
        if (head.secure) {
            writer.field("strict-transport-security", http1_response.strict_transport_security);
        }
        for (head.headers) |header| {
            var lower: [response_name_bytes_max]u8 = undefined;
            for (header.name, 0..) |byte, index| lower[index] = stdx.lower(byte);
            writer.field(lower[0..header.name.len], header.value);
        }
    }

    fn field(writer: *BlockWriter, name: []const u8, value: []const u8) void {
        if (writer.overflow) return;
        if (writer.bytes.len - writer.used < hpack.field_size_max(name, value)) {
            writer.overflow = true;
            return;
        }
        writer.used += hpack.encode_field(writer.bytes[writer.used..], name, value);
    }
};

// --- tests: scripted conversations ---------------------------------------------

const testing = std.testing;
const ratio = @import("prng.zig").ratio;

const test_limits: Limits = .{ .streams_max = 4, .head_bytes_max = 4096, .out_bytes = 32 * 1024 };
const test_date = "Sat, 10 Oct 2026 12:00:00 GMT".*;

/// What a client sends, built frame by frame.
const Script = struct {
    bytes: [24 * 1024]u8 = undefined,
    used: usize = 0,

    fn raw(script: *Script, bytes: []const u8) void {
        @memcpy(script.bytes[script.used..][0..bytes.len], bytes);
        script.used += bytes.len;
    }

    fn add(script: *Script, kind: frame.Type, flags: u8, stream: u31, payload: []const u8) void {
        var header: [header_bytes]u8 = undefined;
        frame.write_header(&header, frame.frame_header(kind, flags, stream, payload.len));
        script.raw(&header);
        script.raw(payload);
    }

    fn handshake(script: *Script) void {
        script.raw(preface);
        script.add(.settings, 0, 0, "");
    }

    /// A field block, unpadded and whole (END_HEADERS).
    fn headers(script: *Script, stream: u31, flags: u8, fields: []const hpack.Header) void {
        var block: [2048]u8 = undefined;
        const used = encode_block(&block, fields);
        script.add(.headers, flags | frame.flag_end_headers, stream, block[0..used]);
    }

    fn window_update(script: *Script, stream: u31, increment: u31) void {
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment, .big);
        script.add(.window_update, 0, stream, &payload);
    }

    fn input(script: *const Script) []const u8 {
        return script.bytes[0..script.used];
    }
};

fn encode_block(out: []u8, fields: []const hpack.Header) usize {
    var used: usize = 0;
    for (fields) |field| used += hpack.encode_field(out[used..], field.name, field.value);
    return used;
}

const get: []const hpack.Header = &.{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "example.com" },
};

fn with(comptime extra: []const hpack.Header) []const hpack.Header {
    return get ++ extra;
}

/// The events a run saw, in brief (a request's head is gone by its end).
const Seen = struct {
    tag: std.meta.Tag(Event),
    index: u16 = 0,
    bytes: usize = 0,
    end: bool = false,
};

const Run = struct {
    seen: [64]Seen = undefined,
    count: usize = 0,
    /// What the server sent, every frame.
    output: [64 * 1024]u8 = undefined,
    output_used: usize = 0,

    fn tags(run: *const Run) [64]std.meta.Tag(Event) {
        var result: [64]std.meta.Tag(Event) = @splat(.incomplete);
        for (run.seen[0..run.count], 0..) |seen, index| result[index] = seen.tag;
        return result;
    }

    fn collect(run: *Run, connection: *Connection) void {
        const bytes = connection.pending();
        @memcpy(run.output[run.output_used..][0..bytes.len], bytes);
        run.output_used += bytes.len;
        connection.sent(@intCast(bytes.len));
    }

    /// The first frame of `kind` on `stream` that the server sent.
    fn find(run: *const Run, kind: frame.Type, stream: u31) ?[]const u8 {
        var at: usize = 0;
        for (0..run.output_used / header_bytes + 1) |_| {
            if (at == run.output_used) return null;
            const header = frame.parse_header(run.output[at..][0..header_bytes]);
            const payload = run.output[at + header_bytes ..][0..header.length];
            at += header_bytes + header.length;
            if (header.type == kind and header.stream == stream) return payload;
        } else unreachable;
    }

    fn reset_code(run: *const Run, stream: u31) ?ErrorCode {
        const payload = run.find(.rst_stream, stream) orelse return null;
        return @fromBackingInt(std.mem.readInt(u32, payload[0..4], .big));
    }

    fn goaway_code(run: *const Run) ?ErrorCode {
        const payload = run.find(.goaway, 0) orelse return null;
        return @fromBackingInt(std.mem.readInt(u32, payload[4..8], .big));
    }
};

/// All of `input` through the connection, the server taking every request
/// and sending whatever waits when asked to.
fn drive(connection: *Connection, run: *Run, input: []const u8) void {
    var at: usize = 0;
    for (0..input.len + 2) |_| {
        const step = connection.receive(input[at..]);
        at += step.consumed;
        connection.check_invariants();
        switch (step.event) {
            .incomplete => break,
            .flush => {
                run.collect(connection);
                continue;
            },
            else => {},
        }
        var seen: Seen = .{ .tag = step.event };
        switch (step.event) {
            .request => |request| seen.index = request.index,
            .data => |data| {
                seen.index = data.index;
                seen.bytes = data.bytes.len;
                seen.end = data.end_stream;
            },
            .reset => |index| seen.index = index,
            else => {},
        }
        run.seen[run.count] = seen;
        run.count += 1;
        if (step.event == .close) break;
    } else unreachable;
    run.collect(connection);
}

fn run_script(script: *const Script) !struct { connection: Connection, run: *Run } {
    var connection: Connection = try .init(testing.allocator, test_limits);
    connection.start();
    const run = try testing.allocator.create(Run);
    run.* = .{};
    drive(&connection, run, script.input());
    return .{ .connection = connection, .run = run };
}

fn expect_connection_error(script: *const Script, code: ErrorCode) !void {
    var result = try run_script(script);
    defer testing.allocator.destroy(result.run);
    defer result.connection.deinit(testing.allocator);
    try testing.expectEqual(code, result.run.goaway_code());
    try testing.expectEqual(Event.close, result.run.seen[result.run.count - 1].tag);
}

fn expect_stream_error(script: *const Script, stream: u31, code: ErrorCode) !void {
    var result = try run_script(script);
    defer testing.allocator.destroy(result.run);
    defer result.connection.deinit(testing.allocator);
    try testing.expectEqual(code, result.run.reset_code(stream));
    try testing.expectEqual(null, result.run.goaway_code());
}

test "http2: a GET, answered in frames" {
    var script: Script = .{};
    script.handshake();
    script.headers(1, frame.flag_end_stream, with(&.{.{ .name = "accept", .value = "*/*" }}));
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const step = connection.receive(script.input());
    const request = step.event.request;
    try testing.expectEqual(1, request.id);
    try testing.expectEqualStrings("GET", request.head.method);
    try testing.expectEqualStrings("/", request.head.path);
    try testing.expectEqualStrings("example.com", request.head.authority);
    try testing.expectEqual(1, request.head.headers.len);
    try testing.expect(request.head.end_stream);
    const rest = script.input()[step.consumed..];
    try testing.expectEqual(Event.incomplete, connection.receive(rest).event);

    const response: http1_response.Head = .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .framing = .{ .length = 5 },
        .keep_alive = true,
        .date = &test_date,
        .secure = true,
    };
    try connection.send_head(request.index, response, false);
    try testing.expectEqual(5, try connection.send_data(request.index, "hello", true));
    connection.release(request.index);
    try testing.expectEqual(0, connection.streams_used);
    try expect_answer(&connection);
}

fn expect_answer(connection: *Connection) !void {
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    run.collect(connection);
    try testing.expect(run.find(.settings, 0) != null);
    try testing.expectEqualStrings("hello", run.find(.data, 1).?);
    var decoder: hpack.Decoder = try .init(testing.allocator, 4096);
    defer decoder.deinit(testing.allocator);
    var storage: [512]u8 = undefined;
    var fields: [8]hpack.Header = undefined;
    const count = try decoder.decode(run.find(.headers, 1).?, &storage, &fields);
    const expected = [_]hpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "date", .value = &test_date },
        .{ .name = "content-length", .value = "5" },
        .{ .name = "strict-transport-security", .value = "max-age=31536000" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    try testing.expectEqual(expected.len, count);
    for (expected, fields[0..count]) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

test "http2: connection errors, as RFC 9113 and h2spec name them" {
    const p = ErrorCode.protocol_error;
    var script: Script = .{};
    script.raw("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    script.add(.ping, 0, 0, "12345678");
    try expect_connection_error(&script, p); // the first frame is not SETTINGS
    inline for (.{ frame.Type.data, .rst_stream, .continuation }) |kind| {
        script = .{};
        script.handshake();
        script.add(kind, 0, 1, &.{ 0, 0, 0, 8 });
        try expect_connection_error(&script, p); // an idle stream
    }
    script = .{};
    script.handshake();
    script.window_update(1, 1);
    try expect_connection_error(&script, p);
    script = .{};
    script.handshake();
    script.headers(2, frame.flag_end_stream, get);
    try expect_connection_error(&script, p); // even
    script = .{};
    script.handshake();
    script.headers(5, frame.flag_end_stream, get);
    script.headers(3, frame.flag_end_stream, get);
    try expect_connection_error(&script, p); // lower than the last
    script = .{};
    script.handshake();
    script.add(.headers, 0, 1, &.{0x82});
    script.add(.priority, 0, 3, &.{ 0, 0, 0, 1, 16 });
    try expect_connection_error(&script, p); // inside a block
    script = .{};
    script.handshake();
    script.add(.headers, 0, 1, &.{0x82});
    script.headers(3, frame.flag_end_stream, get);
    try expect_connection_error(&script, p);
    script = .{};
    script.handshake();
    script.add(.headers, frame.flag_end_headers, 1, &.{0x80});
    try expect_connection_error(&script, .compression_error);
}

test "http2: connection errors: sizes, windows, floods" {
    var script: Script = .{};
    script.handshake();
    script.raw(&.{ 0, 0x40, 1, 0, 0, 0, 0, 0, 0 }); // 16,385 bytes
    try expect_connection_error(&script, .frame_size_error);
    script = .{};
    script.handshake();
    script.window_update(0, frame.window_max);
    try expect_connection_error(&script, .flow_control_error);
    script = .{};
    script.handshake();
    script.add(.settings, 0, 0, &.{ 0, 4, 0x80, 0, 0, 0 });
    try expect_connection_error(&script, .flow_control_error);
    // A CONTINUATION flood: a block past `head_bytes_max`.
    script = .{};
    script.handshake();
    script.add(.headers, 0, 1, &.{0x82});
    const fragment: [1024]u8 = @splat(0x82);
    for (0..4) |_| script.add(.continuation, 0, 1, &fragment);
    try expect_connection_error(&script, .enhance_your_calm);
}

test "http2: stream errors, the connection kept" {
    var script: Script = .{};
    script.handshake();
    script.headers(1, frame.flag_end_stream, get);
    script.add(.data, 0, 1, "late");
    try expect_stream_error(&script, 1, .stream_closed); // half-closed (remote)
    script = .{};
    script.handshake();
    script.headers(1, 0, get);
    script.add(.rst_stream, 0, 1, &.{ 0, 0, 0, 8 });
    script.add(.data, 0, 1, "late");
    try expect_stream_error(&script, 1, .stream_closed); // after the peer's reset
    script = .{};
    script.handshake();
    var block: [256]u8 = undefined;
    block[0..5].* = .{ 0, 0, 0, 1, 16 };
    const used = encode_block(block[5..], get);
    script.add(.headers, frame.flag_priority | frame.flag_end_headers, 1, block[0 .. 5 + used]);
    try expect_stream_error(&script, 1, .protocol_error); // depends on itself
    script = .{};
    script.handshake();
    script.add(.priority, 0, 1, &.{ 0, 0, 0, 1, 16 });
    try expect_stream_error(&script, 1, .protocol_error);
    script = .{};
    script.handshake();
    script.headers(1, 0, get);
    script.add(.window_update, 0, 1, &.{ 0, 0, 0, 0 });
    try expect_stream_error(&script, 1, .protocol_error);
    script = .{};
    script.handshake();
    script.headers(1, 0, get);
    script.add(.settings, 0, 0, &.{ 0, 4, 0x7f, 0xff, 0xff, 0xff });
    script.window_update(1, 1);
    try expect_stream_error(&script, 1, .flow_control_error); // past 2^31-1
}

test "http2: malformed requests are reset, never seen (§8.1.1)" {
    const length: []const hpack.Header = &.{.{ .name = "content-length", .value = "3" }};
    var script: Script = .{};
    script.handshake();
    script.headers(1, 0, with(length));
    script.add(.data, frame.flag_end_stream, 1, "ab");
    try expect_stream_error(&script, 1, .protocol_error); // content-length disagrees
    const malformed = [_][]const hpack.Header{
        with(length), // and END_STREAM, so no body
        with(&.{.{ .name = "Accept", .value = "x" }}),
        with(&.{.{ .name = "connection", .value = "close" }}),
        with(&.{.{ .name = "te", .value = "gzip" }}),
        with(&.{.{ .name = "x", .value = " padded" }}),
        with(&.{.{ .name = "host", .value = "other.example" }}),
        with(&.{.{ .name = ":path", .value = "/twice" }}),
        with(&.{ .{ .name = "x", .value = "y" }, .{ .name = ":status", .value = "200" } }),
        get[0..2] ++ get[3..4], // no :path
        get[0..2] ++ [_]hpack.Header{.{ .name = ":path", .value = "" }},
        get[0..2] ++ [_]hpack.Header{.{ .name = ":path", .value = "relative" }},
        get ++ [_]hpack.Header{.{ .name = ":protocol", .value = "websocket" }},
    };
    inline for (malformed) |fields| {
        script = .{};
        script.handshake();
        script.headers(1, frame.flag_end_stream, fields);
        var result = try run_script(&script);
        defer testing.allocator.destroy(result.run);
        defer result.connection.deinit(testing.allocator);
        try testing.expectEqual(ErrorCode.protocol_error, result.run.reset_code(1));
        try testing.expectEqual(0, result.run.count);
        try testing.expectEqual(1, result.connection.counters.malformed);
    }
}

test "http2: a stream is held until its handler returns (Rapid Reset)" {
    var limits = test_limits;
    limits.streams_max = 2;
    var connection: Connection = try .init(testing.allocator, limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    script.headers(1, 0, get);
    script.headers(3, 0, get);
    script.add(.rst_stream, 0, 1, &.{ 0, 0, 0, 8 });
    script.add(.rst_stream, 0, 3, &.{ 0, 0, 0, 8 });
    script.headers(5, frame.flag_end_stream, get);
    drive(&connection, run, script.input());
    const expected = [_]std.meta.Tag(Event){ .request, .request, .reset, .reset };
    try testing.expectEqualSlices(std.meta.Tag(Event), &expected, run.tags()[0..run.count]);
    // Reset by the client, still running: the third is refused, not run.
    try testing.expectEqual(ErrorCode.refused_stream, run.reset_code(5));
    connection.release(run.seen[0].index);
    script = .{};
    script.headers(7, frame.flag_end_stream, get);
    run.count = 0;
    drive(&connection, run, script.input());
    try testing.expectEqual(Event.request, run.seen[0].tag);
    try testing.expectEqual(2, connection.counters.resets_received);
}

test "http2: send windows: SETTINGS, WINDOW_UPDATE, a negative window" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.raw(preface);
    script.add(.settings, 0, 0, &.{ 0, 4, 0, 0, 0, 1 }); // a window of one byte
    script.headers(1, frame.flag_end_stream, get);
    drive(&connection, run, script.input());
    const index = run.seen[0].index;
    const head: http1_response.Head = .{
        .status = 200,
        .headers = &.{},
        .framing = .chunked,
        .keep_alive = true,
        .date = &test_date,
        .secure = false,
    };
    try connection.send_head(index, head, false);
    try testing.expectEqual(1, try connection.send_data(index, "hello", true));
    try testing.expectEqual(0, try connection.send_data(index, "ello", true));
    script = .{};
    script.add(.settings, 0, 0, &.{ 0, 4, 0, 0, 0, 0 }); // now -1
    script.window_update(1, 1);
    run.count = 0;
    drive(&connection, run, script.input());
    try testing.expectEqual(0, try connection.send_data(index, "ello", true));
    script = .{};
    script.window_update(1, 10);
    drive(&connection, run, script.input());
    try testing.expectEqual(Event.window, run.seen[run.count - 1].tag);
    try testing.expectEqual(4, try connection.send_data(index, "ello", true));
    connection.release(index);
    try testing.expectEqual(0, connection.streams_used);
}

test "http2: receive windows: given back as the handler reads, and enforced" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    script.headers(1, 0, get);
    const chunk: [16_384]u8 = @splat('x');
    script.add(.data, 0, 1, &chunk);
    drive(&connection, run, script.input());
    const index = run.seen[0].index;
    try testing.expectEqual(16_384, run.seen[1].bytes);
    connection.body_read(index, 16_384);
    run.collect(&connection);
    try testing.expectEqual(null, run.find(.window_update, 1)); // under half
    for (0..3) |_| {
        script = .{};
        script.add(.data, 0, 1, &chunk);
        drive(&connection, run, script.input());
    }
    // 65,536 sent into a window of 65,535 less the 16,384 read and not
    // yet given back: the last frame overruns it.
    try testing.expectEqual(ErrorCode.flow_control_error, run.reset_code(1));
    try testing.expectEqual(Event.reset, run.seen[run.count - 1].tag);
    try testing.expectEqual(null, run.goaway_code());
}

test "http2: the window given back once half is read" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    script.headers(1, 0, get);
    const chunk: [16_384]u8 = @splat('x');
    script.add(.data, 0, 1, &chunk);
    drive(&connection, run, script.input());
    script = .{};
    script.add(.data, 0, 1, &chunk);
    drive(&connection, run, script.input());
    connection.body_read(run.seen[0].index, 32_768);
    run.collect(&connection);
    const update = run.find(.window_update, 1).?;
    try testing.expectEqual(32_768, std.mem.readInt(u32, update[0..4], .big));
}

test "http2: trailers end a stream; cookie crumbs are joined" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    var script: Script = .{};
    script.handshake();
    script.headers(1, 0, with(&.{
        .{ .name = "cookie", .value = "a=b" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "cookie", .value = "c=d" },
    }));
    script.add(.data, 0, 1, "ab");
    script.headers(3, frame.flag_end_stream, &.{.{ .name = "x-checksum", .value = "1" }});
    const first = connection.receive(script.input());
    const head = first.event.request.head;
    try testing.expectEqual(2, head.headers.len);
    try testing.expectEqualStrings("accept", head.headers[0].name);
    try testing.expectEqualStrings("a=b; c=d", head.headers[1].value);
    var at: usize = first.consumed;
    const data = connection.receive(script.input()[at..]);
    try testing.expectEqualStrings("ab", data.event.data.bytes);
    at += data.consumed;
    // Stream 3's block is trailers on no stream: a new stream, malformed.
    _ = connection.receive(script.input()[at..]);
    try testing.expectEqual(1, connection.counters.malformed);
    script = .{};
    script.headers(1, frame.flag_end_stream, &.{.{ .name = "x-checksum", .value = "1" }});
    const trailers = connection.receive(script.input());
    try testing.expect(trailers.event.data.end_stream);
    try testing.expectEqual(0, trailers.event.data.bytes.len);
}

test "http2: a PING flood is cut, past a megabyte that did no work" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    drive(&connection, run, script.input());
    script = .{};
    for (0..1200) |_| script.add(.ping, 0, 0, "flooding");
    for (0..100) |round| {
        run.output_used = 0;
        drive(&connection, run, script.input());
        if (connection.phase == .closed) {
            // 1 MiB of 17-byte frames: the 52nd round of 1,200.
            try testing.expectEqual(51, round);
            try testing.expectEqual(ErrorCode.enhance_your_calm, run.goaway_code());
            return;
        }
    }
    return error.TestFloodNotCut;
}

test "http2: draining: GOAWAY names the last stream taken" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    script.headers(1, frame.flag_end_stream, get);
    drive(&connection, run, script.input());
    connection.goaway();
    script = .{};
    script.headers(3, frame.flag_end_stream, get);
    drive(&connection, run, script.input());
    try testing.expectEqual(1, run.count); // stream 3 decoded, ignored
    const goaway = run.find(.goaway, 0).?;
    try testing.expectEqual(1, std.mem.readInt(u32, goaway[0..4], .big));
    try testing.expectEqual(1, connection.streams_held());
}

test "http2: release: a response cut short, a body never read, a late frame" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    const run = try testing.allocator.create(Run);
    defer testing.allocator.destroy(run);
    run.* = .{};
    var script: Script = .{};
    script.handshake();
    script.headers(1, frame.flag_end_stream, get);
    script.headers(3, 0, get);
    drive(&connection, run, script.input());
    var head: http1_response.Head = .{
        .status = 200,
        .headers = &.{},
        .framing = .chunked,
        .keep_alive = true,
        .date = &test_date,
        .secure = false,
    };
    try connection.send_head(run.seen[0].index, head, false);
    connection.release(run.seen[0].index);
    head.status = 204;
    head.framing = .none;
    try connection.send_head(run.seen[1].index, head, true);
    connection.release(run.seen[1].index);
    run.collect(&connection);
    try testing.expectEqual(ErrorCode.internal_error, run.reset_code(1));
    try testing.expectEqual(ErrorCode.no_error, run.reset_code(3));
    try testing.expectEqual(0, connection.streams_used);
    script = .{};
    script.add(.data, 0, 3, "late");
    script.headers(1, frame.flag_end_stream, get);
    run.output_used = 0;
    drive(&connection, run, script.input());
    try testing.expectEqual(ErrorCode.stream_closed, run.reset_code(3));
    try testing.expectEqual(ErrorCode.protocol_error, run.goaway_code());
}

test "http2: random conversations never break the machine" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    var totals: [2]u64 = @splat(0);
    for (0..500) |seed| {
        const outcome = random_conversation(&connection, seed);
        totals[@intFromBool(outcome.closed)] += 1;
        assert(connection.streams_used == 0);
    }
    // Both endings are reached: the test is not all errors, nor none.
    try testing.expect(totals[0] > 50 and totals[1] > 50);
}

/// A server acting at random on what it is told.
const RandomServer = struct {
    prng: Prng,
    held: [4]bool = @splat(false),
    head_sent: [4]bool = @splat(false),
    ended: [4]bool = @splat(false),
    unread: [4]u64 = @splat(0),

    fn on_event(server: *RandomServer, connection: *Connection, event: Event) void {
        switch (event) {
            .request => |request| {
                if (server.prng.chance(ratio(1, 8))) {
                    connection.refuse(request.index);
                    return;
                }
                server.held[request.index] = true;
                server.head_sent[request.index] = false;
                server.ended[request.index] = false;
                server.unread[request.index] = 0;
            },
            .data => |data| server.unread[data.index] += data.bytes.len,
            else => {},
        }
    }

    fn act(server: *RandomServer, connection: *Connection) void {
        const index: u16 = @intCast(server.prng.int_less_than(usize, 4));
        if (!server.held[index]) return;
        if (server.unread[index] > 0 and server.prng.boolean()) {
            const count = server.prng.int_at_most(u64, 1, server.unread[index]);
            connection.body_read(index, @intCast(count));
            server.unread[index] -= count;
        }
        if (server.ended[index] or server.prng.chance(ratio(1, 6))) {
            server.release(connection, index);
            return;
        }
        const sent = server.send(connection, index) catch |err| switch (err) {
            error.Reset => return server.release(connection, index),
            error.NoRoom => return connection.sent(@intCast(connection.pending().len)),
            error.HeadRefused => unreachable,
        };
        _ = sent;
    }

    fn send(server: *RandomServer, connection: *Connection, index: u16) SendError!void {
        const end = server.prng.chance(ratio(1, 3));
        if (!server.head_sent[index]) {
            const head: http1_response.Head = .{
                .status = 200,
                .headers = &.{.{ .name = "X-Random", .value = "yes" }},
                .framing = .chunked,
                .keep_alive = true,
                .date = &test_date,
                .secure = false,
            };
            try connection.send_head(index, head, end);
            server.head_sent[index] = true;
            server.ended[index] = end;
            return;
        }
        const body: [3000]u8 = @splat('b');
        const length = server.prng.int_less_than(usize, body.len);
        const count = try connection.send_data(index, body[0..length], end);
        server.ended[index] = end and count == length;
    }

    fn release(server: *RandomServer, connection: *Connection, index: u16) void {
        connection.release(index);
        server.held[index] = false;
    }

    fn release_all(server: *RandomServer, connection: *Connection) void {
        for (0..4) |index| {
            if (server.held[index]) server.release(connection, @intCast(index));
        }
    }
};

fn random_conversation(connection: *Connection, seed: u64) struct { closed: bool } {
    var prng = Prng.init(seed);
    connection.start();
    var script: Script = .{};
    script.handshake();
    var next_id: u31 = 1;
    for (0..prng.int_at_most(usize, 1, 60)) |_| random_frame(&prng, &script, &next_id);
    if (prng.chance(ratio(1, 8))) {
        const at = prng.int_at_most(usize, preface.len, script.used - 1);
        script.bytes[at] ^= @as(u8, 1) << @intCast(prng.int_less_than(u8, 8));
    }
    var server: RandomServer = .{ .prng = Prng.init(seed ^ 0x5eed) };
    var at: usize = 0;
    const closed = for (0..4 * script.used + 16) |_| {
        const end = @min(script.used, at + prng.int_at_most(usize, 1, 4096));
        const step = connection.receive(script.bytes[at..end]);
        at += step.consumed;
        connection.check_invariants();
        switch (step.event) {
            .close => break true,
            .flush => connection.sent(@intCast(connection.pending().len)),
            .incomplete => if (end == script.used) break false,
            else => server.on_event(connection, step.event),
        }
        server.act(connection);
        connection.check_invariants();
    } else unreachable;
    server.release_all(connection);
    // Deferred frames wait for room: each flush makes some.
    for (0..connection.limits.streams_max + 2) |_| {
        if (!connection.wants_flush()) break;
        connection.sent(@intCast(connection.pending().len));
    } else unreachable;
    connection.check_invariants();
    return .{ .closed = closed };
}

fn random_frame(prng: *Prng, script: *Script, next_id: *u31) void {
    if (script.used > script.bytes.len - 4096) return;
    // Mostly a stream already opened; now and then any.
    const opened: u32 = (next_id.* - 1) / 2;
    const stream: u31 = if (opened > 0 and !prng.chance(ratio(1, 10)))
        @intCast(2 * prng.int_less_than(u32, opened) + 1)
    else
        @intCast(prng.int_less_than(u32, next_id.* + 2));
    switch (prng.int_less_than(u8, 20)) {
        0...5 => {
            random_request(prng, script, next_id.*);
            next_id.* += 2;
        },
        6...10 => {
            const body: [300]u8 = @splat('d');
            const flags: u8 = if (prng.boolean()) frame.flag_end_stream else 0;
            script.add(.data, flags, stream, body[0..prng.int_less_than(usize, body.len)]);
        },
        11, 12 => {
            const increment: u31 = @intCast(prng.int_at_most(u32, 1, 70_000));
            script.window_update(if (prng.boolean()) 0 else stream, increment);
        },
        13 => script.add(.rst_stream, 0, stream, &.{ 0, 0, 0, 8 }),
        14 => {
            var entry: [6]u8 = .{ 0, 4, 0, 0, 0, 0 };
            std.mem.writeInt(u32, entry[2..6], @intCast(prng.int_less_than(u32, 100_000)), .big);
            script.add(.settings, 0, 0, &entry);
        },
        15, 16 => script.add(.ping, 0, 0, "randomly"),
        17, 18 => script.add(.priority, 0, stream +| 2, &.{ 0, 0, 0, 1, 16 }),
        else => {
            var payload: [20]u8 = undefined;
            for (&payload) |*byte| byte.* = @truncate(prng.next());
            const type_: frame.Type = @fromBackingInt(prng.int_less_than(u8, 12));
            const length = prng.int_less_than(usize, payload.len);
            script.add(type_, @truncate(prng.next()), stream, payload[0..length]);
        },
    }
}

fn random_request(prng: *Prng, script: *Script, id: u31) void {
    const fields = if (prng.chance(ratio(1, 8)))
        with(&.{.{ .name = "Upper", .value = "case" }})
    else if (prng.boolean())
        with(&.{.{ .name = "content-length", .value = "120" }})
    else
        get;
    const flags: u8 = if (prng.boolean()) frame.flag_end_stream else 0;
    if (prng.boolean()) return script.headers(id, flags, fields);
    // Split across a CONTINUATION.
    var block: [512]u8 = undefined;
    const used = encode_block(&block, fields);
    const split = prng.int_less_than(usize, used + 1);
    script.add(.headers, flags, id, block[0..split]);
    script.add(.continuation, frame.flag_end_headers, id, block[split..used]);
}

test "http2: response heads the server will not send" {
    var connection: Connection = try .init(testing.allocator, test_limits);
    defer connection.deinit(testing.allocator);
    connection.start();
    var script: Script = .{};
    script.handshake();
    script.headers(1, frame.flag_end_stream, get);
    const index = connection.receive(script.input()).event.request.index;
    var head: http1_response.Head = .{
        .status = 200,
        .headers = &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
        .framing = .chunked,
        .keep_alive = true,
        .date = &test_date,
        .secure = false,
    };
    try testing.expectError(error.HeadRefused, connection.send_head(index, head, false));
    head.headers = &.{.{ .name = "X-Bad", .value = "a\r\nb" }};
    try testing.expectError(error.HeadRefused, connection.send_head(index, head, false));
    head.headers = &.{};
    head.status = 204;
    try testing.expectError(error.HeadRefused, connection.send_head(index, head, true));
    head.status = 100;
    head.framing = .none;
    try testing.expectError(error.HeadRefused, connection.send_head(index, head, true));
    const big: [9000]u8 = @splat('v');
    head.status = 200;
    head.framing = .chunked;
    head.headers = &.{ .{ .name = "x-a", .value = &big }, .{ .name = "x-b", .value = &big } };
    try testing.expectError(error.HeadRefused, connection.send_head(index, head, false));
}
