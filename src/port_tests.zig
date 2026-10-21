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
