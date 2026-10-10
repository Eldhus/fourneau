//! Stopping on a signal: SIGTERM (systemd's stop) or SIGINT (Ctrl-C) asks
//! every shard to drain (`server.Config.stop`), and the process exits when
//! the last one has returned; a second signal exits at once.
//!
//! The signals are blocked in every thread and taken by one waiting
//! thread, so no handler runs in the middle of a shard's work, and shards
//! learn of it only from the flag their timekeepers read each tick.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

const log = std.log.scoped(.fourneau);

pub const Stop = struct {
    requested: std.atomic.Value(bool) = .init(false),

    /// Blocks SIGTERM and SIGINT in this thread, and so in every thread it
    /// spawns after, and starts the thread that waits for them. Call once,
    /// before any shard's thread exists.
    pub fn watch(stop: *Stop) !void {
        const set = signals();
        const blocked = linux.sigprocmask(linux.SIG.BLOCK, &set, null);
        if (linux.errno(blocked) != .SUCCESS) return error.Unexpected;
        const thread = try std.Thread.spawn(.{}, wait, .{ stop, set });
        thread.detach();
    }

    fn signals() linux.sigset_t {
        var set = linux.sigemptyset();
        linux.sigaddset(&set, .TERM);
        linux.sigaddset(&set, .INT);
        return set;
    }

    fn wait(stop: *Stop, set: linux.sigset_t) void {
        const first = take(&set);
        log.info("{t}: draining (again to quit now)", .{first});
        stop.requested.store(true, .release);
        const second = take(&set);
        log.info("{t}: quitting", .{second});
        std.process.exit(1);
    }

    /// The next of the signals in `set`; a wait interrupted is resumed.
    fn take(set: *const linux.sigset_t) linux.SIG {
        // Bounded only to say so: interruptions are rare and each is retried.
        for (0..std.math.maxInt(u32)) |_| {
            const result = linux.syscall4(
                .rt_sigtimedwait,
                @intFromPtr(set),
                0, // no siginfo
                0, // no timeout
                linux.NSIG / 8,
            );
            switch (linux.errno(result)) {
                .SUCCESS => {
                    const signal: linux.SIG = @fromBackingInt(@as(u32, @intCast(result)));
                    assert(signal == .TERM or signal == .INT);
                    return signal;
                },
                .INTR => continue,
                else => |err| std.debug.panic("rt_sigtimedwait: {t}", .{err}),
            }
        } else unreachable;
    }
};
