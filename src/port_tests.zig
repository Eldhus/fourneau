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
