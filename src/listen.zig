//! A shard's ring, waited for: a ring's locked memory is freed some time
//! after its process (a restart's predecessor) exits.

const std = @import("std");
const linux = std.os.linux;

const runtime_tries = 40;
const runtime_wait_ns = 50 * std.time.ns_per_ms;

/// `Runtime.init`, tried again while the kernel has not yet given back the
/// memory an exited ring locked (`SystemResources`): up to 2 s.
pub fn runtime_init(
    comptime Runtime: type,
    runtime: *Runtime,
    gpa: std.mem.Allocator,
    options: Runtime.InitOptions,
) !void {
    for (1..runtime_tries + 1) |tries| {
        runtime.init(gpa, options) catch |err| switch (err) {
            error.SystemResources => {
                if (tries == runtime_tries) return err;
                const wait: linux.timespec = .{ .sec = 0, .nsec = runtime_wait_ns };
                _ = linux.nanosleep(&wait, null);
                continue;
            },
            else => return err,
        };
        return;
    } else unreachable;
}
