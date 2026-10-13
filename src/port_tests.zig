//! Tests of our port of Evented (vendor/zig-io-evented) on a real
//! io_uring: what the simulator cannot reach, for it replaces the port.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const listen = @import("listen.zig");

// A cancel that reaches a sleep is left pending: the port's sleep returns
// without it, and roux's `Sleep.millis!` would drop it anyway. The next
// stream write must take it, and fail as canceled. It once failed an
// assertion instead (the drag race's live banner, cut by a drain): the
// write's cancel region was nested in `operate`'s, and taking the cancel
// left the fiber marked as awaiting the ring, which the outer region's
// end asserts it is not.
test "port: a stream write takes a cancel its fiber's sleep left" {
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
    io.sleep(.fromSeconds(60), .awake) catch {}; // as `Sleep.millis!` does
    const result = try io.operate(.{ .net_write = .{
        .socket_handle = socket,
        .data = &.{"x"},
    } });
    const written = result.net_write catch unreachable; // a pair's buffer has room
    assert(written == 1);
    return written;
}
