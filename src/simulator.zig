//! The root of the simulator's own compilation: the real server and our
//! port of Evented over a simulated kernel (being built, beside
//! `sim_io`'s simulator until it replaces it).
//!
//! It is its own compilation because the port takes its kernel by import,
//! and a file belongs to one module per compilation: the suite's port
//! calls Linux (src/kernel.zig), this one calls `sim_kernel.zig`. The port
//! imports this file as `kernel`, so these declarations are the system
//! calls it makes, exactly src/kernel.zig's.

const std = @import("std");
const sim_kernel = @import("sim_kernel.zig");

pub const IoUring = sim_kernel.Ring;
pub const clock_gettime = sim_kernel.clock_gettime;

/// No sockets yet: nothing calls it until there are.
pub fn shutdown(fd: std.os.linux.fd_t, how: i32) usize {
    std.debug.panic("sim_kernel: shutdown({d}, {d}) not simulated", .{ fd, how });
}

test {
    _ = sim_kernel;
}
