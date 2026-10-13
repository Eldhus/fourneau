//! The kernel our port of Evented calls (vendor/zig-io-evented imports it
//! as `kernel`): Linux's own. The simulator gives the port another with the
//! same declarations (`sim_kernel.zig`), so the port runs under a seed
//! unchanged: the simulator's edge is the kernel. What a
//! shard's serving path reaches is here; the rest of the port calls Linux
//! itself, and fails loudly in the simulator if it is ever reached there.

const std = @import("std");
const linux = std.os.linux;

/// The ring: what a shard submits to, and reaps its completions from.
pub const IoUring = linux.IoUring;

/// `Io.now`'s clock.
pub const clock_gettime = linux.clock_gettime;

/// A plain system call, not a ring operation: the timekeeper's way to end
/// a wait without yielding (server.zig, `expire`).
pub const shutdown = linux.shutdown;
