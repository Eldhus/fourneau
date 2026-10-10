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
};

/// What the server speaks, offered by ALPN (RFC 7301) in its order of
/// preference: HTTP/2 first when it speaks it. A client offering neither
/// is refused; one offering nothing gets HTTP/1.1.
pub const Protocols = enum {
    http1,
    http2_and_http1,

    fn names(protocols: Protocols) []const []const u8 {
        return switch (protocols) {
            .http1 => &.{"http/1.1"},
            .http2_and_http1 => &.{ "h2", "http/1.1" },
        };
    }
};

pub const Established = struct {
    /// The first bytes of the HTTP stream, already decrypted into `early`.
    early_bytes: u32,
    /// ALPN chose HTTP/2.
    http2: bool,
};

pub const HandshakeError = error{
    HandshakeFailed,
    /// The client left between its Finished and its keys reaching the
    /// kernel: Linux attaches TLS only to an established connection
    /// (TCP_ULP: ENOTCONN). A client that hangs up at once, a scanner, or
    /// one that refused the certificate: routine, not a fault here.
    PeerClosed,
    KernelTlsFailed,
    EarlyDataTooLarge,
    /// The first byte is not a TLS handshake record: plain HTTP, most
    /// likely, which deserves an answer rather than a timeout.
    NotTls,
};

/// A TLS record's content type for a handshake message (RFC 8446 §5.1).
const record_type_handshake = 0x16;

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
/// after its Finished that the input buffer already holds, decrypted:
/// the first bytes of the HTTP stream.
pub fn handshake(
    io: Io,
    transport: anytype,
    socket: std.posix.socket_t,
    context: *const Context,
    options: struct { early: []u8, protocols: Protocols },
) HandshakeError!Established {
    transport.reader.fill(1) catch return error.HandshakeFailed;
    if (transport.reader.buffered()[0] != record_type_handshake) return error.NotTls;
    const random_source: std.Random.IoSource = .{ .io = io };
    var session = tls.server(&transport.reader, &transport.writer, .{
        .rng = random_source.interface(),
        .auth = context.auth,
        .alpn_protocols = options.protocols.names(),
        .now = Io.Clock.real.now(io),
    }) catch return error.HandshakeFailed;
    const early_bytes = try take_buffered(&session, &transport.reader, options.early);
    var keys = tls.Ktls.init(session.cipher);
    try kernel_tls(socket, &keys);
    const chosen = session.alpn_protocol orelse "http/1.1";
    const http2 = std.mem.eql(u8, chosen, "h2");
    assert(!http2 or options.protocols == .http2_and_http1);
    return .{ .early_bytes = early_bytes, .http2 = http2 };
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

/// The keys to the kernel. That the kernel has TLS at all was checked at
/// startup (`check_kernel`), so a failure here is about this connection.
fn kernel_tls(socket: std.posix.socket_t, keys: *tls.Ktls) HandshakeError!void {
    try set_option(socket, attach_step);
    try set_option(socket, .{
        .label = "TLS_TX",
        .level = linux.SOL.TLS,
        .name = tls.Ktls.TX,
        .value = keys.txBytes(),
    });
    try set_option(socket, .{
        .label = "TLS_RX",
        .level = linux.SOL.TLS,
        .name = tls.Ktls.RX,
        .value = keys.rxBytes(),
    });
}

const SocketOption = struct { label: []const u8, level: i32, name: u32, value: []const u8 };

/// TLS onto the connection, before its keys.
const attach_step: SocketOption = .{
    .label = "TCP_ULP",
    .level = linux.IPPROTO.TCP,
    .name = linux.TCP.ULP,
    .value = ulp,
};

fn set_option(socket: std.posix.socket_t, option: SocketOption) HandshakeError!void {
    assert(option.label.len > 0);
    assert(option.value.len > 0);
    const result = linux.setsockopt(
        socket,
        option.level,
        option.name,
        option.value.ptr,
        @intCast(option.value.len),
    );
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .NOTCONN => return error.PeerClosed,
        else => |errno| {
            std.log.scoped(.fourneau).warn("kTLS: {s}: {t}", .{ option.label, errno });
            return error.KernelTlsFailed;
        },
    }
}

/// The upper layer protocol kTLS attaches as (TCP_ULP).
const ulp = "tls";

/// Linux's list of the upper layer protocols it has, space-separated:
/// `tls` there once the tls module is loaded (or built in).
const available_ulp_path = "/proc/sys/net/ipv4/tcp_available_ulp";

pub const KernelError = error{KernelTlsUnavailable};

/// Whether this kernel can take TLS keys, checked once at startup: without
/// it every handshake would end at `kernel_tls`, each connection logging
/// the same fault. A server without CAP_NET_ADMIN cannot have the module
/// loaded on demand, so it is loaded at boot (modules-load.d).
pub fn check_kernel(io: Io) KernelError!void {
    var buffer: [4096]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, available_ulp_path, &buffer) catch |err| {
        std.log.scoped(.fourneau).err("kTLS: {s}: {t}", .{ available_ulp_path, err });
        return error.KernelTlsUnavailable;
    };
    if (!listed(text, ulp)) {
        std.log.scoped(.fourneau).err("kTLS: the kernel has no `{s}` ({s} lists \"{s}\"): " ++
            "load the tls module (modprobe tls; at boot, /etc/modules-load.d)", .{
            ulp,
            available_ulp_path,
            std.mem.trim(u8, text, " \n"),
        });
        return error.KernelTlsUnavailable;
    }
}

/// Whether `name` is one of the whitespace-separated words of `text`.
fn listed(text: []const u8, name: []const u8) bool {
    assert(name.len > 0);
    var words = std.mem.tokenizeAny(u8, text, " \t\n");
    while (words.next()) |word| {
        if (std.mem.eql(u8, word, name)) return true;
    }
    return false;
}

test "tls: the kernel's list of upper layer protocols" {
    try std.testing.expect(listed("espintcp mptcp tls\n", ulp));
    try std.testing.expect(listed("tls\n", ulp));
    try std.testing.expect(!listed("espintcp mptcp\n", ulp));
    try std.testing.expect(!listed("\n", ulp));
    // A word, not a part of one.
    try std.testing.expect(!listed("ktls tlsx\n", ulp));
}

test "tls: a client gone before its keys is PeerClosed, not a kernel fault" {
    var buffer: [4096]u8 = undefined;
    const available = Io.Dir.cwd().readFile(std.testing.io, available_ulp_path, &buffer) catch
        return error.SkipZigTest;
    if (!listed(available, ulp)) return error.SkipZigTest; // no kTLS on this kernel
    const listener = try test_listener();
    defer _ = linux.close(listener.socket);
    // Established: TLS attaches.
    const open = try test_pair(listener);
    defer _ = linux.close(open.client);
    defer _ = linux.close(open.server);
    try set_option(open.server, attach_step);
    // The client closed, and its FIN is in (read says end of stream): the
    // connection is CLOSE_WAIT, and Linux refuses TLS with ENOTCONN.
    const gone = try test_pair(listener);
    defer _ = linux.close(gone.server);
    _ = try test_syscall(linux.close(gone.client));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), try test_syscall(linux.read(gone.server, &byte, 1)));
    try std.testing.expectError(error.PeerClosed, set_option(gone.server, attach_step));
}

fn test_syscall(result: usize) !u32 {
    if (linux.errno(result) != .SUCCESS) return error.Unexpected;
    return @intCast(result);
}

fn test_listener() !struct { socket: i32, address: linux.sockaddr.in } {
    const stream = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
    const socket: i32 = @intCast(try test_syscall(linux.socket(linux.AF.INET, stream, 0)));
    errdefer _ = linux.close(socket);
    var address: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    var length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = try test_syscall(linux.bind(socket, @ptrCast(&address), length));
    _ = try test_syscall(linux.listen(socket, 4));
    _ = try test_syscall(linux.getsockname(socket, @ptrCast(&address), &length));
    assert(address.port != 0);
    return .{ .socket = socket, .address = address };
}

fn test_pair(listener: anytype) !struct { client: i32, server: i32 } {
    const stream = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
    const client: i32 = @intCast(try test_syscall(linux.socket(linux.AF.INET, stream, 0)));
    errdefer _ = linux.close(client);
    const length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = try test_syscall(linux.connect(client, &listener.address, length));
    const server: i32 = @intCast(try test_syscall(linux.accept(listener.socket, null, null)));
    return .{ .client = client, .server = server };
}
