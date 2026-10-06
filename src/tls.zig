//! TLS 1.3 for fourneau: tls.zig's handshake on the connection's own fiber,
//! then the session keys to the kernel (kTLS), so from the first request on
//! the connection reads and writes plaintext through the same io_uring path
//! as plain HTTP, and Linux encrypts and decrypts (DESIGN.md, Layers: tls).
//!
//! The handshake borrows the connection's memory: before its first request
//! the receive buffer and the response scratch are unused, and each is
//! larger than tls.zig needs (asserted at comptime by the server). Nothing
//! is allocated per connection.
//!
//! What a client sends right behind its Finished (usually its first
//! request) may already sit, encrypted, in the handshake's input buffer.
//! The kernel never saw those bytes, so they are decrypted here, in user
//! space, and handed to the HTTP parser; only then do the keys, with their
//! record counters advanced past them, go to the kernel.

const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");

const Io = std.Io;
const linux = std.os.linux;

pub const CertKeyPair = tls.config.CertKeyPair;

/// What tls.zig needs to hold a record: the handshake's two buffers must
/// be at least this large.
pub const input_bytes_min = tls.input_buffer_len;
pub const output_bytes_min = tls.output_buffer_len;

/// A server's TLS: its certificate and key, loaded at startup.
pub const Context = struct {
    auth: *CertKeyPair,
    /// ALPN: HTTP/1.1 only, until HTTP/2 (M9).
    alpn: []const []const u8 = &.{"http/1.1"},
};

pub const HandshakeError = error{ HandshakeFailed, KernelTlsFailed, EarlyDataTooLarge };

/// A connection's reads and writes as `std.Io`'s reader and writer, for
/// tls.zig. `Connection` offers `read_some(buffer, timeout_ms) !u32` (0
/// at end of stream; deadline enforced) and `write_all(head, body) bool`.
pub fn TransportType(comptime Connection: type) type {
    return struct {
        const Transport = @This();

        connection: *Connection,
        timeout_ms: u32,
        reader: Io.Reader,
        writer: Io.Writer,

        pub fn init(
            transport: *Transport,
            connection: *Connection,
            timeout_ms: u32,
            input: []u8,
            output: []u8,
        ) void {
            assert(input.len >= input_bytes_min);
            assert(output.len >= output_bytes_min);
            transport.* = .{
                .connection = connection,
                .timeout_ms = timeout_ms,
                .reader = .{
                    .vtable = &.{ .stream = stream, .readVec = read_vec },
                    .buffer = input,
                    .seek = 0,
                    .end = 0,
                },
                .writer = .{ .vtable = &.{ .drain = drain }, .buffer = output },
            };
        }

        fn stream(
            reader: *Io.Reader,
            writer: *Io.Writer,
            limit: Io.Limit,
        ) Io.Reader.StreamError!usize {
            const destination = limit.slice(try writer.writableSliceGreedy(1));
            const transport: *Transport = @fieldParentPtr("reader", reader);
            const got = transport.read(destination) catch return error.ReadFailed;
            if (got == 0) return error.EndOfStream;
            writer.advance(got);
            return got;
        }

        /// Reads into the reader's own buffer, as a `readVec` may.
        fn read_vec(reader: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
            _ = data;
            const transport: *Transport = @fieldParentPtr("reader", reader);
            if (reader.end == reader.buffer.len) {
                // Keep the unread bytes; make room behind them.
                const unread = reader.buffer[reader.seek..reader.end];
                std.mem.copyForwards(u8, reader.buffer[0..unread.len], unread);
                reader.seek = 0;
                reader.end = unread.len;
            }
            assert(reader.end < reader.buffer.len);
            const got = transport.read(reader.buffer[reader.end..]) catch return error.ReadFailed;
            if (got == 0) return error.EndOfStream;
            reader.end += got;
            return 0;
        }

        fn read(transport: *Transport, buffer: []u8) !u32 {
            assert(buffer.len > 0);
            const got = try transport.connection.read_some(buffer, transport.timeout_ms);
            assert(got <= buffer.len);
            return got;
        }

        fn drain(writer: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            assert(data.len > 0);
            const transport: *Transport = @fieldParentPtr("writer", writer);
            const connection = transport.connection;
            const buffered = writer.buffered();
            if (buffered.len > 0) {
                if (!connection.write_all(buffered, "")) return error.WriteFailed;
                writer.end = 0;
            }
            var written: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                if (bytes.len == 0) continue;
                if (!connection.write_all(bytes, "")) return error.WriteFailed;
                written += bytes.len;
            }
            const last = data[data.len - 1];
            if (last.len > 0) {
                for (0..splat) |_| {
                    if (!connection.write_all(last, "")) return error.WriteFailed;
                    written += last.len;
                }
            }
            return written;
        }
    };
}

/// The handshake, then kTLS. Writes into `early` whatever the client sent
/// after its Finished that the input buffer already holds, decrypted, and
/// returns its length: the first bytes of the HTTP stream.
pub fn handshake(
    io: Io,
    transport: anytype,
    socket: std.posix.socket_t,
    context: *const Context,
    early: []u8,
) HandshakeError!u32 {
    const random_source: std.Random.IoSource = .{ .io = io };
    var session = tls.server(&transport.reader, &transport.writer, .{
        .rng = random_source.interface(),
        .auth = context.auth,
        .alpn_protocols = context.alpn,
        .now = Io.Clock.real.now(io),
    }) catch return error.HandshakeFailed;
    const early_bytes = try take_buffered(&session, &transport.reader, early);
    var keys = tls.Ktls.init(session.cipher);
    try kernel_tls(socket, &keys);
    return early_bytes;
}

/// Decrypts the records the input buffer already holds (and the rest of a
/// record it holds part of), advancing the session's receive counter.
fn take_buffered(session: anytype, reader: *Io.Reader, early: []u8) HandshakeError!u32 {
    var used: u32 = 0;
    // Each pass consumes a record; a buffer holds fewer records than bytes.
    for (0..reader.buffer.len + 1) |_| {
        if (reader.end == reader.seek) return used;
        const plaintext = (session.next() catch return error.HandshakeFailed) orelse
            return used;
        if (plaintext.len > early.len - used) return error.EarlyDataTooLarge;
        @memcpy(early[used..][0..plaintext.len], plaintext);
        used += @intCast(plaintext.len);
    } else unreachable;
}

fn kernel_tls(socket: std.posix.socket_t, keys: *tls.Ktls) HandshakeError!void {
    const ulp = "tls";
    const steps = [_]struct { level: i32, name: u32, value: []const u8 }{
        .{ .level = linux.IPPROTO.TCP, .name = linux.TCP.ULP, .value = ulp },
        .{ .level = linux.SOL.TLS, .name = tls.Ktls.TX, .value = keys.txBytes() },
        .{ .level = linux.SOL.TLS, .name = tls.Ktls.RX, .value = keys.rxBytes() },
    };
    for (steps) |step| {
        assert(step.value.len > 0);
        const result = linux.setsockopt(
            socket,
            step.level,
            step.name,
            step.value.ptr,
            @intCast(step.value.len),
        );
        switch (linux.errno(result)) {
            .SUCCESS => {},
            else => |errno| {
                std.log.scoped(.fourneau).warn("kTLS: {t} (is the tls module loadable?)", .{errno});
                return error.KernelTlsFailed;
            },
        }
    }
}
