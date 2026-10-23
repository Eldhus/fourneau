//! Tests of our port of Evented (vendor/zig-io-evented) on a real
//! io_uring: what the simulator cannot reach, for it replaces the port.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const listen = @import("listen.zig");
const server_module = @import("server.zig");
const http1_response = @import("http1_response.zig");

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

/// The server's application in the test below: `/echo` answers its body,
/// anything else "hello".
const EchoApp = struct {
    pub const Response = struct {
        status: u16,
        headers: []const http1_response.Header,
        body: []const u8,
    };

    pub fn handle(app: *EchoApp, request: *EchoServer.Request) Response {
        _ = app;
        if (!std.mem.eql(u8, request.head.path(), "/echo")) {
            return .{ .status = 200, .headers = &.{}, .body = "hello" };
        }
        var used: usize = 0;
        for (0..request.scratch.len + 1) |_| {
            const got = request.read_body(request.scratch[used..]) catch
                return .{ .status = 400, .headers = &.{}, .body = "" };
            if (got == 0) break;
            used += got;
        } else unreachable; // each pass reads a byte or ends
        return .{ .status = 200, .headers = &.{}, .body = request.scratch[0..used] };
    }

    pub fn release(app: *EchoApp, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const EchoServer = server_module.ServerType(EchoApp, .{
    .send_then_receive = Evented.sendThenReceive,
});

/// Set by the server's thread once it listens: the port it bound.
var echo_port: std.atomic.Value(u16) = .init(0);

fn run_echo_server() void {
    run_echo_server_or_fail() catch |err| std.debug.panic("echo server: {t}", .{err});
}

fn run_echo_server_or_fail() !void {
    const gpa = std.heap.page_allocator;
    const config: server_module.Config = .{ .connections_max = 8 };
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, gpa, .{
        .thread_limit = 0,
        .fibers_max = config.fibers_max(),
    });
    const io = runtime.io();
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    const listener = try address.listen(io, .{ .reuse_address = true });
    var bound: linux.sockaddr.in = undefined;
    var bound_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const named = linux.getsockname(listener.socket.handle, @ptrCast(&bound), &bound_len);
    assert(linux.errno(named) == .SUCCESS);
    var app: EchoApp = .{};
    var server = try EchoServer.init(gpa, io, &app, listener, config);
    echo_port.store(std.mem.bigToNative(u16, bound.port), .release);
    try server.run();
}

/// What the server answers to `request` on a connection of its own; all
/// of it, up to the close or `expected` bytes.
fn exchange(socket: linux.fd_t, request: []const u8, buffer: []u8, expected: usize) ![]const u8 {
    var sent: usize = 0;
    for (0..request.len + 1) |_| {
        if (sent == request.len) break;
        const result = linux.write(socket, request[sent..].ptr, request.len - sent);
        if (linux.errno(result) != .SUCCESS) return error.Write;
        sent += result;
    } else unreachable;
    var got: usize = 0;
    for (0..buffer.len + 1) |_| {
        if (got >= expected) break;
        const result = linux.read(socket, buffer[got..].ptr, buffer.len - got);
        if (linux.errno(result) != .SUCCESS) return error.Read;
        if (result == 0) break;
        got += result;
    } else unreachable;
    return buffer[0..got];
}

fn connect_echo() !linux.fd_t {
    const socket: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, echo_port.load(.acquire)),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connected = linux.connect(socket, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    if (linux.errno(connected) != .SUCCESS) return error.Connect;
    return socket;
}

// The server end to end on a real ring: two requests on one connection, a
// body read by the handler, and a chunked request refused and closed. The
// server runs for good on its own thread (it has no stop).
test "server: keep-alive, a body, and a chunked request refused" {
    const thread = try std.Thread.spawn(.{}, run_echo_server, .{});
    thread.detach();
    for (0..1000) |_| {
        if (echo_port.load(.acquire) != 0) break;
        const wait: linux.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = linux.nanosleep(&wait, null);
    } else return error.ServerNeverListened;
    var buffer: [1024]u8 = undefined;

    const keep = try connect_echo();
    defer _ = linux.close(keep);
    for (0..2) |_| {
        const answer = try exchange(keep, "GET / HTTP/1.1\r\nHost: a\r\n\r\n", &buffer, 1);
        try std.testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200 OK\r\n"));
        try std.testing.expect(std.mem.endsWith(u8, answer, "\r\n\r\nhello"));
    }
    const echo = "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    const echoed = try exchange(keep, echo, &buffer, 1);
    try std.testing.expect(std.mem.endsWith(u8, echoed, "\r\n\r\nabc"));

    const chunked = try connect_echo();
    defer _ = linux.close(chunked);
    const refused = try exchange(
        chunked,
        "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        &buffer,
        buffer.len,
    );
    try std.testing.expect(std.mem.startsWith(u8, refused, "HTTP/1.1 411 "));
    try std.testing.expect(std.mem.indexOf(u8, refused, "Connection: close\r\n") != null);
}

fn wait_one(io: Io, waiters: *Waiters) Io.Cancelable!void {
    // A wait may end spuriously: each looks at the word again, a few times at most.
    for (0..4) |_| {
        if (@atomicLoad(u32, &waiters.word, .monotonic) != 0) break;
        try io.futexWait(u32, &waiters.word, 0);
    } else unreachable;
    waiters.woken += 1;
}
