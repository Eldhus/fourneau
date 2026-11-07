//! The kernel our port of Evented calls (vendor/zig-io-evented imports it
//! as `kernel`): Linux's own. The simulator gives the port another with the
//! same declarations (`sim_kernel.zig`), so the port runs under a seed
//! unchanged. What a
//! shard's serving path reaches is here; the rest of the port calls Linux
//! itself, and fails loudly in the simulator if it is ever reached there.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

/// The ring: what a shard submits to, and reaps its completions from.
pub const IoUring = linux.IoUring;

/// Free entries in the ring's submission queue: a chain must fit in one
/// submission (the port's `Thread.reserve`).
pub fn sq_space_left(ring: *IoUring) u32 {
    const entries: u32 = @intCast(ring.sq.sqes.len);
    const ready = ring.sq_ready();
    assert(ready <= entries);
    return entries - ready;
}

/// `Io.now`'s clock.
pub const clock_gettime = linux.clock_gettime;

/// A plain system call, not a ring operation: the timekeeper's way to end
/// a wait without yielding (server.zig, `expire`).
pub const shutdown = linux.shutdown;

/// A plain system call too: whether clients wait in a listener's backlog
/// (the port's `listenBacklog`, for an acceptor short of descriptors).
pub const getsockopt = linux.getsockopt;

/// The head of Linux's `tcp_info` (TCP_INFO), as far as `unacked`, which
/// on a listening socket is its backlog's length. The kernel copies as
/// many bytes as are asked for.
pub const TcpInfoHead = extern struct {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    scales: u8,
    flags: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
};
