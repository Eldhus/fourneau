//! Tests of our port of Evented (vendor/zig-io-evented) on a real
//! io_uring: what the simulator cannot reach, for it replaces the port.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const listen = @import("listen.zig");

// A cancel that cuts a sleep short: the sleep says so, and a fiber that
// cannot stop there (roux's `Sleep.millis!`, which has no error for Roc)
// re-arms it, so its next operation takes it: a stream write, which must
// fail as canceled. Two port bugs met here (the drag race's live banner,
// cut by a drain): the sleep returned as though its time
// had passed, leaving the cancel pending; and the write's cancel region,
// nested in `operate`'s, took it and left the fiber marked as awaiting the
// ring, which the outer region's end asserts it is not.
test "port: a sleep reports its cancel, and a write takes it re-armed" {
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, std.testing.allocator, .{
        .thread_limit = 0, // this thread only: the task runs when main waits
        .fibers_max = 1,
    });
    defer runtime.deinit();
    const io = runtime.io();
    var fds: [2]linux.fd_t = undefined;
    const paired = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    try std.testing.expectEqual(.SUCCESS, linux.errno(paired));
    defer for (fds) |fd| {
        _ = linux.close(fd);
    };

    var future = try io.concurrent(sleep_then_write, .{ io, fds[0] });
    // Main waits, so the task runs to its sleep; then the cancel cuts it.
    try io.sleep(.fromMilliseconds(1), .awake);
    const written = future.cancel(io);
    try std.testing.expectError(error.Canceled, written);
}

fn sleep_then_write(io: Io, socket: linux.fd_t) Io.Cancelable!usize {
    if (io.sleep(.fromSeconds(60), .awake)) {
        unreachable; // canceled long before
    } else |err| switch (err) {
        error.Canceled => io.recancel(), // as `Sleep.millis!` must
    }
    const result = try io.operate(.{ .net_write = .{
        .socket_handle = socket,
        .data = &.{"x"},
    } });
    const written = result.net_write catch unreachable; // a pair's buffer has room
    assert(written == 1);
    return written;
}

const Waiters = struct {
    const count = 3;
    word: u32 = 0,
    woken: u32 = 0,
};

// A wake of "all" (`Signal.notify`'s, an HTTP/2 connection's streams on
// one word) wakes every waiter: the kernel takes the count as an int, and
// `std.math.maxInt(u32)` as it is arrives as -1, one waiter. A wake that
// left some asleep is followed by one that cannot, so the test fails
// rather than hangs.
test "port: a wake of all wakes every fiber waiting on the word" {
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, std.testing.allocator, .{
        .thread_limit = 0, // this thread only: the tasks run when main waits
        .fibers_max = Waiters.count,
    });
    defer runtime.deinit();
    const io = runtime.io();
    var waiters: Waiters = .{};
    var group: Io.Group = .init;
    for (0..Waiters.count) |_| try group.concurrent(io, wait_one, .{ io, &waiters });
    // Main waits, so every task runs to its wait.
    try io.sleep(.fromMilliseconds(1), .awake);
    assert(waiters.woken == 0);
    @atomicStore(u32, &waiters.word, 1, .monotonic);
    io.futexWake(u32, &waiters.word, std.math.maxInt(u32));
    try io.sleep(.fromMilliseconds(10), .awake);
    const woken = waiters.woken;
    io.futexWake(u32, &waiters.word, std.math.maxInt(i32));
    try group.await(io);
    try std.testing.expectEqual(Waiters.count, woken);
}

fn wait_one(io: Io, waiters: *Waiters) Io.Cancelable!void {
    // A wait may end spuriously: each looks at the word again, a few times at most.
    for (0..4) |_| {
        if (@atomicLoad(u32, &waiters.word, .monotonic) != 0) break;
        try io.futexWait(u32, &waiters.word, 0);
    } else unreachable;
    waiters.woken += 1;
}

/// A connection in the ring's file table, its client a descriptor the
/// test drives, never blocking. The client's receive buffer is the
/// kernel's smallest and it reads nothing until told, so a response past
/// the socket's send buffer (4 MB at most, `tcp_wmem`) stalls in the
/// kernel, the server's send in flight.
const Retired = struct {
    listener: Io.net.Server,
    client: linux.fd_t,
    /// The chain's fiber, named by itself as a connection's is.
    fiber: usize = 0,
    /// What the chain returned, once it has.
    count: ?usize = null,
    failed: bool = false,

    const response_bytes = 8 * 1024 * 1024;

    fn open(io: Io) !Retired {
        const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
        var listener = try address.listen(io, .{ .reuse_address = false });
        errdefer listener.deinit(io);
        const fd: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
        if (fd < 0) return error.Socket;
        errdefer _ = linux.close(fd);
        try set_buffer(fd, 1); // the kernel raises it to its minimum
        const peer: linux.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, listener.socket.address.getPort()),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        const connected = linux.connect(fd, @ptrCast(&peer), @sizeOf(linux.sockaddr.in));
        if (linux.errno(connected) != .SUCCESS) return error.Connect;
        const flags = linux.fcntl(fd, linux.F.GETFL, 0);
        const nonblocking = linux.fcntl(fd, linux.F.SETFL, flags | linux.SOCK.NONBLOCK);
        if (linux.errno(nonblocking) != .SUCCESS) return error.Fcntl;
        return .{ .listener = listener, .client = fd };
    }

    fn close(retired: *Retired, io: Io) void {
        _ = linux.close(retired.client);
        retired.listener.deinit(io);
    }

    fn set_buffer(fd: linux.fd_t, bytes: u32) !void {
        const value = std.mem.asBytes(&bytes);
        const set = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, value.ptr, value.len);
        if (linux.errno(set) != .SUCCESS) return error.Setsockopt;
    }

    /// The server's turn: the response, then the next request's receive,
    /// one chain.
    fn chain(io: Io, retired: *Retired, handle: Io.net.Socket.Handle) Io.Cancelable!void {
        retired.fiber = Evented.currentFiber();
        const response = std.testing.allocator.alloc(u8, response_bytes) catch unreachable;
        defer std.testing.allocator.free(response);
        @memset(response, 'x');
        var buffer: [64]u8 = undefined;
        retired.count = Evented.sendThenReceive(io, handle, response, &buffer) catch {
            retired.failed = true;
            return;
        };
    }

    /// The client reads everything to the end. Returns the bytes read,
    /// and how many waits of a millisecond it took after its last byte to
    /// see the end.
    fn read_to_end(retired: *Retired, io: Io) !struct { bytes: usize, waits_after: u32 } {
        try set_buffer(retired.client, 4 * 1024 * 1024); // let it flow now
        var chunk: [64 * 1024]u8 = undefined;
        var bytes: usize = 0;
        var waits_after: u32 = 0;
        for (0..20_000) |_| {
            const got = linux.read(retired.client, &chunk, chunk.len);
            switch (linux.errno(got)) {
                .SUCCESS => {
                    if (got == 0) return .{ .bytes = bytes, .waits_after = waits_after };
                    bytes += got;
                    waits_after = 0;
                },
                .AGAIN => {
                    waits_after += 1;
                    try io.sleep(.fromMilliseconds(1), .awake);
                },
                .CONNRESET => return .{ .bytes = bytes, .waits_after = waits_after },
                else => return error.Read,
            }
        }
        return error.TestNeverEnded;
    }
};

// The server's idle shut (eviction, a drain) of a linked turn whose
// response is still going out: the receive behind the send is not yet
// issued, so the wake's cancel finds nothing, and the fiber waited for
// the client's next request or the send's deadline. Retired, the slot
// holds the dead socket: the response goes out whole on the socket the
// send holds, then the receive, issued on the dead one, reads the end.
test "port: a turn retired while its response goes out sends it whole, then ends" {
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, std.testing.allocator, .{
        .thread_limit = 0,
        .fibers_max = 1,
        .direct_sockets_max = 1,
    });
    defer runtime.deinit();
    const io = runtime.io();
    var retired = try Retired.open(io);
    defer retired.close(io);
    const stream = try Evented.acceptDirect(io, retired.listener.socket.handle);
    defer stream.close(io);
    const handle = stream.socket.handle;
    var future = try io.concurrent(Retired.chain, .{ io, &retired, handle });
    try io.sleep(.fromMilliseconds(20), .awake); // the send stalls
    assert(retired.fiber != 0);
    Evented.wakeRead(retired.fiber);
    Evented.retire(io, handle, .recv);
    try io.sleep(.fromMilliseconds(20), .awake);
    try std.testing.expect(retired.count == null and !retired.failed); // still sending
    const read = try retired.read_to_end(io);
    try future.await(io);
    try std.testing.expectEqual(Retired.response_bytes, read.bytes);
    try std.testing.expect(read.waits_after <= 20); // the end came with the last bytes
    try std.testing.expectEqual(0, retired.count.?);
}

// The same turn, retired for reading, then shut both ways (its deadline):
// the slot holds the dead socket now, so a cancel by the slot reaches
// nothing on the socket the chain is still on; the chain is named by its
// fiber too, and its send is cut.
test "port: a turn retired for reading is cut by its deadline all the same" {
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, std.testing.allocator, .{
        .thread_limit = 0,
        .fibers_max = 1,
        .direct_sockets_max = 1,
    });
    defer runtime.deinit();
    const io = runtime.io();
    var retired = try Retired.open(io);
    defer retired.close(io);
    const stream = try Evented.acceptDirect(io, retired.listener.socket.handle);
    defer stream.close(io);
    const handle = stream.socket.handle;
    var future = try io.concurrent(Retired.chain, .{ io, &retired, handle });
    try io.sleep(.fromMilliseconds(20), .awake); // the send stalls
    assert(retired.fiber != 0);
    Evented.wakeRead(retired.fiber);
    Evented.retire(io, handle, .recv);
    try io.sleep(.fromMilliseconds(20), .awake);
    try std.testing.expect(retired.count == null and !retired.failed); // still sending
    Evented.wakeBoth(handle);
    Evented.wakeChain(retired.fiber);
    Evented.retire(io, handle, .both);
    try future.await(io);
    try std.testing.expect(retired.failed); // the send cut: reset, as the pair reports it
    const read = try retired.read_to_end(io);
    try std.testing.expect(read.bytes < Retired.response_bytes);
}
