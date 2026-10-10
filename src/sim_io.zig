//! A deterministic `std.Io`: real fibers on one OS thread, scheduled from a
//! seed, over a simulated network. Code written against `std.Io` (the
//! evented server, and later Roc handlers) runs here unchanged, and one
//! seed replays one run exactly: TigerBeetle's simulator, for Zig's `Io`.
//!
//! - Fibers are real stacks, switched by `fourneau_context_switch`
//!   (context_switch_x86_64.S: std's inline-assembly switch is miscompiled
//!   in ReleaseSafe; DIARY 2026-10-05).
//!   Their stacks are carved at startup from one mapping, each with a
//!   `PROT_NONE` guard page below it, so an overflow faults rather than
//!   corrupting a neighbour.
//! - Only the simulator's own loop (`run_ready`) switches into fibers; a
//!   fiber that would block records what it waits for and switches back.
//!   Which ready fiber runs next is drawn from the PRNG: every interleaving
//!   the seed picks, and nothing else.
//! - Time is ticks, advanced by the simulator. `now` and `sleep` use them.
//! - The network is byte queues, as the first simulator's were: a read returns any
//!   number of the waiting bytes, a write any number that fits the window,
//!   and each blocking operation is held back a random number of ticks.
//!
//! The vtable is `Io.failing`'s with the operations we simulate replaced,
//! so anything else fails loudly instead of touching the real system.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const linux = std.os.linux;
const Io = std.Io;
const net = Io.net;
const Prng = @import("prng.zig").Prng;

comptime {
    // The fiber entry stub below is x86_64's; others follow Uring.zig's.
    assert(builtin.cpu.arch == .x86_64);
}

pub const Options = struct {
    fibers_max: u32,
    /// Usable stack per fiber; a guard page is added below each.
    stack_bytes: u32,
    connections_max: u32,
    /// Bytes each direction of a connection holds: the receive window.
    window_bytes: u32,
    latency_ticks_max: u32,
    backlog_max: u32,
    tick_ns: u64,
    realtime_seconds_start: u64,
};

const page_bytes = std.heap.page_size_min;
const context_bytes_max = 256;
const result_bytes_max = 64;
const fd_base: i32 = 1000;
pub const listener_fd: i32 = 3;

const errno_connection_reset = error.ConnectionResetByPeer;

const Wait = union(enum) {
    accept,
    read: u32,
    write: u32,
    /// Until `now_ns` reaches this.
    sleep: u64,
    futex: *const u32,
    /// Until the fiber with this index finishes.
    fiber: u32,
    group: *Io.Group,
};

const Start = union(enum) {
    future: *const fn (context: *const anyopaque, result: *anyopaque) void,
    group: struct {
        group: *Io.Group,
        function: *const fn (context: *const anyopaque) void,
    },
};

const Fiber = struct {
    state: enum { free, ready, blocked, done },
    context: Io.fiber.Context,
    stack: []u8,
    wait: Wait,
    /// A blocked fiber is not resumed before this tick (latency).
    not_before_tick: u64,
    start: Start,
    cancel_protection: Io.CancelProtection,
    /// A cancelation was requested and not yet delivered: the fiber's next
    /// cancelation point returns `error.Canceled` (`Future.cancel`).
    cancel_requested: bool,
    /// Blocked at a cancelation point: a cancel request wakes it.
    wait_cancelable: bool,
    context_bytes: [context_bytes_max]u8 align(16),
    result_bytes: [result_bytes_max]u8 align(16),
};

/// What the entry stub hands to `call`: placed at the top of the stack.
const Closure = extern struct {
    sim: *Sim,
    fiber: u32,
};

/// context_switch_x86_64.S: std.Io.fiber.contextSwitch's contract as an
/// ordinary call, shared with our Io.Evented port.
extern fn fourneau_context_switch(s: *const Io.fiber.Switch) callconv(.c) *const Io.fiber.Switch;

fn context_switch(old: *Io.fiber.Context, new: *const Io.fiber.Context) void {
    const message: Io.fiber.Switch = .{ .old = old, .new = @constCast(new) };
    _ = fourneau_context_switch(&message);
}

const ByteQueue = struct {
    bytes: []u8,
    head: u32 = 0,
    count: u32 = 0,

    fn free(queue: *const ByteQueue) u32 {
        return @as(u32, @intCast(queue.bytes.len)) - queue.count;
    }

    fn push(queue: *ByteQueue, data: []const u8) u32 {
        const pushed: u32 = @intCast(@min(data.len, queue.free()));
        const capacity: u32 = @intCast(queue.bytes.len);
        for (data[0..pushed], 0..) |byte, offset| {
            queue.bytes[(queue.head + queue.count + offset) % capacity] = byte;
        }
        queue.count += pushed;
        return pushed;
    }

    fn pop(queue: *ByteQueue, out: []u8) u32 {
        const popped: u32 = @intCast(@min(out.len, queue.count));
        const capacity: u32 = @intCast(queue.bytes.len);
        for (out[0..popped], 0..) |*byte, offset| {
            byte.* = queue.bytes[(queue.head + offset) % capacity];
        }
        queue.head = (queue.head + popped) % capacity;
        queue.count -= popped;
        return popped;
    }
};

const Connection = struct {
    state: enum { free, backlog, open } = .free,
    to_server: ByteQueue,
    to_client: ByteQueue,
    client_closed: bool = false,
    reset: bool = false,
    server_shutdown: bool = false,
    /// Shut for reading only (eviction): reads see the end, writes go on.
    server_read_shut: bool = false,
    server_closed: bool = false,
};

pub const Sim = struct {
    options: Options,
    prng: Prng,
    tick_now: u64 = 0,
    fibers: []Fiber,
    stacks: []align(page_bytes) u8,
    /// The simulator loop's own context, while a fiber runs.
    main_context: Io.fiber.Context = undefined,
    current: ?u32 = null,
    connections: []Connection,
    backlog: []u32,
    backlog_count: u32 = 0,
    /// Fiber indices to choose among, reused each pick.
    runnable: []u32,

    pub fn init(gpa: std.mem.Allocator, seed: u64, options: Options) !Sim {
        assert(options.fibers_max > 0);
        assert(options.stack_bytes % page_bytes == 0);
        const stride: u32 = options.stack_bytes + @as(u32, @intCast(page_bytes));
        const stacks = try map_stacks(options.fibers_max, stride);
        const fibers = try gpa.alloc(Fiber, options.fibers_max);
        for (fibers, 0..) |*fiber, index| {
            fiber.* = undefined;
            fiber.state = .free;
            // The guard page is the lowest page of each stride.
            fiber.stack = stacks[index * stride + page_bytes ..][0..options.stack_bytes];
        }
        const connections = try gpa.alloc(Connection, options.connections_max);
        for (connections) |*connection| {
            connection.* = .{
                .to_server = .{ .bytes = try gpa.alloc(u8, options.window_bytes) },
                .to_client = .{ .bytes = try gpa.alloc(u8, options.window_bytes) },
            };
        }
        return .{
            .options = options,
            .prng = Prng.init(seed),
            .fibers = fibers,
            .stacks = stacks,
            .connections = connections,
            .backlog = try gpa.alloc(u32, options.backlog_max),
            .runnable = try gpa.alloc(u32, options.fibers_max),
        };
    }

    fn map_stacks(count: u32, stride: u32) ![]align(page_bytes) u8 {
        const bytes = @as(usize, count) * stride;
        const prot: linux.PROT = .{ .READ = true, .WRITE = true };
        const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
        const address = linux.mmap(null, bytes, prot, flags, -1, 0);
        if (linux.errno(address) != .SUCCESS) return error.OutOfMemory;
        const stacks: [*]align(page_bytes) u8 = @ptrFromInt(address);
        for (0..count) |index| {
            const guard: [*]align(page_bytes) u8 = @alignCast(stacks + index * stride);
            const result = linux.mprotect(guard, page_bytes, .{});
            assert(linux.errno(result) == .SUCCESS);
        }
        return stacks[0..bytes];
    }

    pub fn deinit(sim: *Sim, gpa: std.mem.Allocator) void {
        _ = linux.munmap(sim.stacks.ptr, sim.stacks.len);
        for (sim.connections) |*connection| {
            gpa.free(connection.to_server.bytes);
            gpa.free(connection.to_client.bytes);
        }
        gpa.free(sim.connections);
        gpa.free(sim.fibers);
        gpa.free(sim.backlog);
        gpa.free(sim.runnable);
        sim.* = undefined;
    }

    pub fn io(sim: *Sim) Io {
        return .{ .userdata = sim, .vtable = &vtable };
    }

    /// Whether a task (`io.concurrent`'s) has finished: for the
    /// simulator's own loop, which cannot await.
    pub fn finished(sim: *const Sim, any_future: *Io.AnyFuture) bool {
        return sim.fibers[sim.fiber_index(any_future)].state == .done;
    }

    pub fn now_ns(sim: *const Sim) u64 {
        return sim.tick_now * sim.options.tick_ns;
    }

    // --- the scheduler ------------------------------------------------------

    /// Run fibers until none can make progress this tick. Returns how many
    /// times a fiber ran.
    pub fn run_ready(sim: *Sim, runs_max: u32) u32 {
        assert(sim.current == null);
        for (0..runs_max) |runs| {
            const index = sim.pick() orelse return @intCast(runs);
            sim.switch_to(index);
        }
        return runs_max;
    }

    fn pick(sim: *Sim) ?u32 {
        var count: u32 = 0;
        for (sim.fibers, 0..) |*fiber, index| {
            if (sim.can_run(fiber)) {
                sim.runnable[count] = @intCast(index);
                count += 1;
            }
        }
        if (count == 0) return null;
        return sim.runnable[sim.prng.int_less_than(u32, count)];
    }

    fn can_run(sim: *const Sim, fiber: *const Fiber) bool {
        switch (fiber.state) {
            .ready => return true,
            .free, .done => return false,
            .blocked => {},
        }
        if (sim.tick_now < fiber.not_before_tick) return false;
        return switch (fiber.wait) {
            .accept => sim.backlog_count > 0,
            .read => |index| sim.readable(&sim.connections[index]),
            .write => |index| sim.writable(&sim.connections[index]),
            .sleep => |until_ns| sim.now_ns() >= until_ns,
            // Woken explicitly: they become `.ready`.
            .futex, .fiber, .group => false,
        };
    }

    fn readable(sim: *const Sim, connection: *const Connection) bool {
        _ = sim;
        return connection.to_server.count > 0 or connection.client_closed or
            connection.reset or connection.server_shutdown or connection.server_read_shut;
    }

    fn writable(sim: *const Sim, connection: *const Connection) bool {
        _ = sim;
        return connection.to_client.free() > 0 or connection.reset or connection.server_shutdown;
    }

    fn switch_to(sim: *Sim, index: u32) void {
        assert(sim.current == null);
        const fiber = &sim.fibers[index];
        assert(fiber.state == .ready or fiber.state == .blocked);
        fiber.state = .ready;
        sim.current = index;
        context_switch(&sim.main_context, &fiber.context);
        sim.current = null;
    }

    /// From a fiber: wait for `wait`, then return to the caller (which
    /// re-checks its condition). Not a cancelation point.
    fn block(sim: *Sim, wait: Wait) void {
        const index = sim.current.?; // the simulator's own loop never blocks
        const fiber = &sim.fibers[index];
        fiber.state = .blocked;
        fiber.wait = wait;
        fiber.wait_cancelable = false;
        const latency = sim.prng.int_at_most(u64, 0, sim.options.latency_ticks_max);
        fiber.not_before_tick = sim.tick_now + latency;
        context_switch(&fiber.context, &sim.main_context);
        assert(sim.current == index);
        assert(fiber.state == .ready);
    }

    /// `block` at a cancelation point: a request made before the wait is
    /// delivered here; one made during it wakes the fiber, whose caller
    /// re-checks and blocks again, and so is delivered then.
    fn block_cancelable(sim: *Sim, wait: Wait) Io.Cancelable!void {
        try sim.check_cancel();
        const index = sim.current.?;
        const fiber = &sim.fibers[index];
        fiber.state = .blocked;
        fiber.wait = wait;
        fiber.wait_cancelable = true;
        const latency = sim.prng.int_at_most(u64, 0, sim.options.latency_ticks_max);
        fiber.not_before_tick = sim.tick_now + latency;
        context_switch(&fiber.context, &sim.main_context);
        assert(sim.current == index);
        assert(fiber.state == .ready);
        fiber.wait_cancelable = false;
    }

    /// A cancelation point that does not wait: delivers a pending request.
    fn check_cancel(sim: *Sim) Io.Cancelable!void {
        const fiber = &sim.fibers[sim.current orelse return];
        if (!fiber.cancel_requested or fiber.cancel_protection == .blocked) return;
        fiber.cancel_requested = false;
        return error.Canceled;
    }

    /// Ask a fiber to stop: its next cancelation point returns
    /// `error.Canceled`, and one it is blocked at returns it now.
    fn request_cancel(sim: *Sim, index: u32) void {
        const fiber = &sim.fibers[index];
        assert(fiber.state != .free);
        if (fiber.state == .done) return;
        fiber.cancel_requested = true;
        if (fiber.state == .blocked and fiber.wait_cancelable and
            fiber.cancel_protection == .unblocked)
        {
            fiber.state = .ready;
        }
    }

    fn spawn(sim: *Sim, context: []const u8, start: Start) ?u32 {
        assert(context.len <= context_bytes_max);
        const index = for (sim.fibers, 0..) |*fiber, index| {
            if (fiber.state == .free) break @as(u32, @intCast(index));
        } else return null;
        const fiber = &sim.fibers[index];
        @memcpy(fiber.context_bytes[0..context.len], context);
        fiber.start = start;
        fiber.cancel_protection = .unblocked;
        fiber.cancel_requested = false;
        fiber.wait_cancelable = false;
        fiber.state = .ready;
        // The closure sits at the top of the stack, 16-aligned; the stub
        // finds it 8 bytes above the stack pointer it starts with.
        const top = @intFromPtr(fiber.stack.ptr) + fiber.stack.len;
        const closure_address = std.mem.alignBackward(usize, top - @sizeOf(Closure), 16);
        const closure: *Closure = @ptrFromInt(closure_address);
        closure.* = .{ .sim = sim, .fiber = index };
        fiber.context = .{ .rsp = closure_address - 8, .rbp = 0, .rip = @intFromPtr(&entry) };
        return index;
    }

    fn entry() callconv(.naked) void {
        asm volatile (
            \\ leaq 8(%%rsp), %%rdi
            \\ jmp %[call:P]
            :
            : [call] "X" (&call),
        );
    }

    fn call(closure: *Closure) callconv(.withStackAlign(.c, @alignOf(Closure))) noreturn {
        const sim = closure.sim;
        const index = closure.fiber;
        const fiber = &sim.fibers[index];
        switch (fiber.start) {
            .future => |start| start(&fiber.context_bytes, &fiber.result_bytes),
            .group => |group| group.function(&fiber.context_bytes),
        }
        sim.finish(index);
        unreachable; // a finished fiber is never resumed
    }

    fn finish(sim: *Sim, index: u32) noreturn {
        const fiber = &sim.fibers[index];
        fiber.state = .done;
        switch (fiber.start) {
            .group => |group| {
                assert(group.group.state > 0);
                group.group.state -= 1;
                if (group.group.state == 0) sim.wake_where(.group, group.group);
                fiber.state = .free; // nobody awaits a group member alone
            },
            .future => sim.wake_fiber_awaiters(index),
        }
        context_switch(&fiber.context, &sim.main_context);
        unreachable;
    }

    fn wake_where(sim: *Sim, comptime tag: std.meta.Tag(Wait), key: anytype) void {
        for (sim.fibers) |*fiber| {
            if (fiber.state != .blocked or fiber.wait != tag) continue;
            if (@field(fiber.wait, @tagName(tag)) == key) fiber.state = .ready;
        }
    }

    fn wake_fiber_awaiters(sim: *Sim, index: u32) void {
        for (sim.fibers) |*fiber| {
            if (fiber.state == .blocked and fiber.wait == .fiber and fiber.wait.fiber == index) {
                fiber.state = .ready;
            }
        }
    }

    // --- the network: the server's side -------------------------------------

    fn connection_of(sim: *Sim, fd: i32) u32 {
        assert(fd >= fd_base);
        const index: u32 = @intCast(fd - fd_base);
        const connection = &sim.connections[index];
        assert(connection.state == .open);
        assert(!connection.server_closed); // no operation on a closed socket
        return index;
    }

    fn accept(sim: *Sim) Io.Cancelable!net.Socket {
        for (0..std.math.maxInt(u32)) |_| {
            if (sim.backlog_count > 0) {
                const index = sim.backlog[0];
                const rest = sim.backlog[1..sim.backlog_count];
                std.mem.copyForwards(u32, sim.backlog[0..rest.len], rest);
                sim.backlog_count -= 1;
                assert(sim.connections[index].state == .backlog);
                sim.connections[index].state = .open;
                return .{
                    .handle = fd_base + @as(i32, @intCast(index)),
                    .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } },
                };
            }
            try sim.block_cancelable(.accept);
        } else unreachable; // bounded by the simulation's own end
    }

    const ReadError = Io.Cancelable || Io.Operation.NetRead.Error;

    fn read(sim: *Sim, fd: i32, buffers: [][]u8) ReadError!usize {
        const index = sim.connection_of(fd);
        const buffer = for (buffers) |buffer| {
            if (buffer.len > 0) break buffer;
        } else return 0;
        for (0..std.math.maxInt(u32)) |_| {
            const connection = &sim.connections[index];
            if (connection.reset) return errno_connection_reset;
            if (connection.server_shutdown or connection.server_read_shut) return 0;
            if (connection.to_server.count > 0) {
                const available = @min(buffer.len, connection.to_server.count);
                const wanted = sim.prng.int_at_most(usize, 1, available);
                return connection.to_server.pop(buffer[0..wanted]);
            }
            if (connection.client_closed) return 0;
            try sim.block_cancelable(.{ .read = index });
        } else unreachable;
    }

    const WriteError = Io.Cancelable || Io.Operation.NetWrite.Error;

    fn write(
        sim: *Sim,
        fd: i32,
        header: []const u8,
        data: []const []const u8,
    ) WriteError!usize {
        const index = sim.connection_of(fd);
        var total: usize = header.len;
        for (data) |part| total += part.len;
        assert(total > 0);
        for (0..std.math.maxInt(u32)) |_| {
            const connection = &sim.connections[index];
            if (connection.reset or connection.server_shutdown) return errno_connection_reset;
            const room = connection.to_client.free();
            if (room > 0) {
                var left = sim.prng.int_at_most(usize, 1, @min(total, room));
                const sent = left;
                left -= connection.to_client.push(header[0..@min(left, header.len)]);
                for (data) |part| {
                    if (left == 0) break;
                    left -= connection.to_client.push(part[0..@min(left, part.len)]);
                }
                assert(left == 0);
                return sent;
            }
            try sim.block_cancelable(.{ .write = index });
        } else unreachable;
    }

    fn close(sim: *Sim, fd: i32) void {
        const index = sim.connection_of(fd);
        sim.connections[index].server_closed = true;
        sim.release_if_done(index);
    }

    fn shutdown(sim: *Sim, fd: i32, how: net.ShutdownHow) void {
        const index = sim.connection_of(fd);
        switch (how) {
            .both => sim.connections[index].server_shutdown = true,
            .recv => sim.connections[index].server_read_shut = true,
            .send => unreachable, // the server never shuts only its sending side
        }
    }

    fn release_if_done(sim: *Sim, index: u32) void {
        const connection = &sim.connections[index];
        const client_done = connection.client_closed or connection.reset;
        if (!connection.server_closed or !client_done) return;
        connection.* = .{
            .to_server = .{ .bytes = connection.to_server.bytes },
            .to_client = .{ .bytes = connection.to_client.bytes },
        };
    }

    // --- the network: the client's side (for sim_client) --------

    pub fn client_connect(sim: *Sim) ?u32 {
        if (sim.backlog_count == sim.backlog.len) return null;
        for (sim.connections, 0..) |*connection, index| {
            if (connection.state != .free) continue;
            connection.state = .backlog;
            sim.backlog[sim.backlog_count] = @intCast(index);
            sim.backlog_count += 1;
            return @intCast(index);
        }
        return null;
    }

    pub fn client_send(sim: *Sim, index: u32, bytes: []const u8) u32 {
        const connection = &sim.connections[index];
        assert(connection.state != .free);
        assert(!connection.client_closed);
        const gone = connection.server_closed or connection.server_shutdown;
        if (connection.reset or gone or connection.server_read_shut) {
            return @intCast(bytes.len); // into the void, as a real socket would
        }
        return connection.to_server.push(bytes);
    }

    pub fn client_receive(sim: *Sim, index: u32, out: []u8) u32 {
        const connection = &sim.connections[index];
        assert(connection.state != .free);
        return connection.to_client.pop(out);
    }

    pub fn client_sees_end(sim: *const Sim, index: u32) bool {
        const connection = &sim.connections[index];
        const server_done = connection.server_closed or connection.server_shutdown;
        return server_done and connection.to_client.count == 0;
    }

    pub fn client_close(sim: *Sim, index: u32) void {
        const connection = &sim.connections[index];
        assert(!connection.client_closed);
        connection.client_closed = true;
        if (connection.state == .backlog) sim.drop_from_backlog(index);
        sim.release_if_done(index);
    }

    pub fn client_reset(sim: *Sim, index: u32) void {
        const connection = &sim.connections[index];
        assert(!connection.client_closed);
        connection.reset = true;
        connection.client_closed = true;
        if (connection.state == .backlog) sim.drop_from_backlog(index);
        sim.release_if_done(index);
    }

    fn drop_from_backlog(sim: *Sim, index: u32) void {
        for (sim.backlog[0..sim.backlog_count], 0..) |entry_index, position| {
            if (entry_index != index) continue;
            const rest = sim.backlog[position + 1 .. sim.backlog_count];
            std.mem.copyForwards(u32, sim.backlog[position..][0..rest.len], rest);
            sim.backlog_count -= 1;
            sim.connections[index].server_closed = true;
            return;
        }
        unreachable;
    }

    // --- the vtable -------------------------------------------------------------

    const vtable: Io.VTable = table: {
        var table = Io.failing.vtable.*;
        table.async = vtable_async;
        table.concurrent = vtable_concurrent;
        table.await = vtable_await;
        table.cancel = vtable_cancel;
        table.groupAsync = vtable_group_async;
        table.groupConcurrent = vtable_group_concurrent;
        table.groupAwait = vtable_group_await;
        table.groupCancel = vtable_group_cancel;
        table.recancel = vtable_recancel;
        table.swapCancelProtection = vtable_swap_cancel_protection;
        table.checkCancel = vtable_check_cancel;
        table.futexWait = vtable_futex_wait;
        table.futexWaitUncancelable = vtable_futex_wait_uncancelable;
        table.futexWake = vtable_futex_wake;
        table.operate = vtable_operate;
        table.netAccept = vtable_net_accept;
        table.netClose = vtable_net_close;
        table.netShutdown = vtable_net_shutdown;
        table.now = vtable_now;
        table.sleep = vtable_sleep;
        break :table table;
    };

    fn from(userdata: ?*anyopaque) *Sim {
        return @ptrCast(@alignCast(userdata.?));
    }

    fn vtable_async(
        userdata: ?*anyopaque,
        result: []u8,
        result_alignment: std.mem.Alignment,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) ?*Io.AnyFuture {
        const result_len = result.len;
        return vtable_concurrent(
            userdata,
            result_len,
            result_alignment,
            context,
            context_alignment,
            start,
        ) catch {
            start(context.ptr, result.ptr);
            return null;
        };
    }

    fn vtable_concurrent(
        userdata: ?*anyopaque,
        result_len: usize,
        result_alignment: std.mem.Alignment,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Io.ConcurrentError!*Io.AnyFuture {
        assert(result_len <= result_bytes_max);
        assert(result_alignment.compare(.lte, .@"16"));
        assert(context_alignment.compare(.lte, .@"16"));
        const sim = from(userdata);
        const index = sim.spawn(context, .{ .future = start }) orelse
            return error.ConcurrencyUnavailable;
        return @ptrCast(&sim.fibers[index]);
    }

    fn fiber_index(sim: *const Sim, any_future: *Io.AnyFuture) u32 {
        const fiber: *Fiber = @ptrCast(@alignCast(any_future));
        const index = (@intFromPtr(fiber) - @intFromPtr(sim.fibers.ptr)) / @sizeOf(Fiber);
        assert(index < sim.fibers.len);
        return @intCast(index);
    }

    fn vtable_await(
        userdata: ?*anyopaque,
        any_future: *Io.AnyFuture,
        result: []u8,
        result_alignment: std.mem.Alignment,
    ) void {
        _ = result_alignment;
        const sim = from(userdata);
        const index = sim.fiber_index(any_future);
        for (0..std.math.maxInt(u32)) |_| {
            if (sim.fibers[index].state == .done) break;
            sim.block(.{ .fiber = index });
        } else unreachable;
        @memcpy(result, sim.fibers[index].result_bytes[0..result.len]);
        sim.fibers[index].state = .free;
    }

    fn vtable_group_async(
        userdata: ?*anyopaque,
        group: *Io.Group,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start: *const fn (context: *const anyopaque) void,
    ) void {
        vtable_group_concurrent(userdata, group, context, context_alignment, start) catch
            start(context.ptr);
    }

    fn vtable_group_concurrent(
        userdata: ?*anyopaque,
        group: *Io.Group,
        context: []const u8,
        context_alignment: std.mem.Alignment,
        start: *const fn (context: *const anyopaque) void,
    ) Io.ConcurrentError!void {
        assert(context_alignment.compare(.lte, .@"16"));
        const sim = from(userdata);
        _ = sim.spawn(context, .{ .group = .{ .group = group, .function = start } }) orelse
            return error.ConcurrencyUnavailable;
        group.state += 1;
        group.token.store(@ptrCast(sim), .release);
    }

    fn vtable_group_await(
        userdata: ?*anyopaque,
        group: *Io.Group,
        token: *anyopaque,
    ) Io.Cancelable!void {
        _ = token;
        const sim = from(userdata);
        for (0..std.math.maxInt(u32)) |_| {
            if (group.state == 0) break;
            sim.block(.{ .group = group });
        } else unreachable;
        group.token.store(null, .release);
    }

    fn vtable_cancel(
        userdata: ?*anyopaque,
        any_future: *Io.AnyFuture,
        result: []u8,
        result_alignment: std.mem.Alignment,
    ) void {
        const sim = from(userdata);
        sim.request_cancel(sim.fiber_index(any_future));
        vtable_await(userdata, any_future, result, result_alignment);
    }

    fn vtable_group_cancel(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) void {
        const sim = from(userdata);
        for (sim.fibers, 0..) |*fiber, index| {
            if (fiber.state == .free or fiber.state == .done) continue;
            switch (fiber.start) {
                .group => |member| if (member.group == group) sim.request_cancel(@intCast(index)),
                .future => {},
            }
        }
        // The canceler itself is not a member: its own request, if any,
        // waits for its next cancelation point.
        const protection = vtable_swap_cancel_protection(userdata, .blocked);
        defer _ = vtable_swap_cancel_protection(userdata, protection);
        vtable_group_await(userdata, group, token) catch unreachable; // protected
    }

    /// Re-arm a delivered request: the next cancelation point returns
    /// `error.Canceled` again.
    fn vtable_recancel(userdata: ?*anyopaque) void {
        const sim = from(userdata);
        const fiber = &sim.fibers[sim.current.?];
        assert(!fiber.cancel_requested);
        fiber.cancel_requested = true;
    }

    fn vtable_swap_cancel_protection(
        userdata: ?*anyopaque,
        new: Io.CancelProtection,
    ) Io.CancelProtection {
        const sim = from(userdata);
        const index = sim.current orelse return .unblocked;
        const old = sim.fibers[index].cancel_protection;
        sim.fibers[index].cancel_protection = new;
        return old;
    }

    fn vtable_check_cancel(userdata: ?*anyopaque) Io.Cancelable!void {
        return from(userdata).check_cancel();
    }

    fn vtable_futex_wait(
        userdata: ?*anyopaque,
        ptr: *const u32,
        expected: u32,
        timeout: Io.Timeout,
    ) Io.Cancelable!void {
        assert(timeout == .none); // the server waits without timeouts
        const sim = from(userdata);
        try sim.check_cancel();
        if (@atomicLoad(u32, ptr, .acquire) != expected) return;
        try sim.block_cancelable(.{ .futex = ptr });
    }

    fn vtable_futex_wait_uncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
        const sim = from(userdata);
        // One thread: the value cannot change between this check and the
        // block, so a wake cannot be missed.
        if (@atomicLoad(u32, ptr, .acquire) != expected) return;
        sim.block(.{ .futex = ptr });
    }

    fn vtable_futex_wake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
        const sim = from(userdata);
        var woken: u32 = 0;
        for (sim.fibers) |*fiber| {
            if (woken == max_waiters) break;
            if (fiber.state == .blocked and fiber.wait == .futex and fiber.wait.futex == ptr) {
                fiber.state = .ready;
                woken += 1;
            }
        }
    }

    fn vtable_operate(
        userdata: ?*anyopaque,
        operation: Io.Operation,
    ) Io.Cancelable!Io.Operation.Result {
        const sim = from(userdata);
        return switch (operation) {
            .net_read => |o| .{ .net_read = try sim.operate_read(o) },
            .net_write => |o| .{ .net_write = try sim.operate_write(o) },
            else => unreachable, // the server uses no other operation
        };
    }

    const NetRead = Io.Operation.NetRead;
    const NetWrite = Io.Operation.NetWrite;

    /// A cancelation is the operation's outer error, as the port's is.
    fn operate_read(sim: *Sim, o: NetRead) Io.Cancelable!NetRead.Result {
        const got = sim.read(o.socket_handle, o.data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |other| return @as(NetRead.Result, other),
        };
        return .{ .data_len = got };
    }

    fn operate_write(sim: *Sim, o: NetWrite) Io.Cancelable!NetWrite.Result {
        return sim.write(o.socket_handle, o.header, o.data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |other| return @as(NetWrite.Result, other),
        };
    }

    fn vtable_net_accept(
        userdata: ?*anyopaque,
        server: net.Socket.Handle,
        options: net.Server.AcceptOptions,
    ) net.Server.AcceptError!net.Socket {
        _ = options;
        assert(server == listener_fd);
        return from(userdata).accept();
    }

    fn vtable_net_close(userdata: ?*anyopaque, sockets: []const net.Socket) void {
        const sim = from(userdata);
        for (sockets) |socket| sim.close(socket.handle);
    }

    fn vtable_net_shutdown(
        userdata: ?*anyopaque,
        handle: net.Socket.Handle,
        how: net.ShutdownHow,
    ) net.ShutdownError!void {
        from(userdata).shutdown(handle, how);
    }

    fn vtable_now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
        const sim = from(userdata);
        const elapsed: i96 = sim.now_ns();
        const start_ns = @as(i96, sim.options.realtime_seconds_start) * std.time.ns_per_s;
        return switch (clock) {
            .real => .{ .nanoseconds = start_ns + elapsed },
            else => .{ .nanoseconds = elapsed },
        };
    }

    fn vtable_sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
        const sim = from(userdata);
        const duration = switch (timeout) {
            .duration => |duration| duration.raw.nanoseconds,
            .none, .deadline => unreachable, // the server sleeps for durations
        };
        assert(duration >= 0);
        const until = sim.now_ns() + @as(u64, @intCast(duration));
        for (0..std.math.maxInt(u32)) |_| {
            if (sim.now_ns() >= until) return;
            try sim.block_cancelable(.{ .sleep = until });
        } else unreachable;
    }
};

/// Tasks for the cancelation test: each says whether it saw what it must.
const CancelTasks = struct {
    const hour: Io.Duration = .fromSeconds(3600);

    fn sleeps(io: Io) bool {
        io.sleep(hour, .awake) catch |err| switch (err) {
            error.Canceled => return true,
        };
        return false;
    }

    fn accepts(io: Io) bool {
        var listener: net.Server = .{
            .socket = .{
                .handle = listener_fd,
                .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 80 } },
            },
            .options = {},
        };
        _ = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return true,
            else => return false,
        };
        return false;
    }

    /// Protected while it sleeps, so the request waits; delivered at the
    /// next cancelation point after, once; re-armed by `recancel`.
    fn protected(io: Io) bool {
        const old = io.swapCancelProtection(.blocked);
        io.sleep(.fromNanoseconds(3 * tick_ns_test), .awake) catch return false;
        _ = io.swapCancelProtection(old);
        io.checkCancel() catch |err| switch (err) {
            error.Canceled => {
                io.checkCancel() catch return false; // delivered once
                io.recancel();
                io.checkCancel() catch return true;
                return false;
            },
        };
        return false;
    }

    fn drive(io: Io, seen: *[3]bool) void {
        var sleeping = io.concurrent(sleeps, .{io}) catch unreachable;
        var accepting = io.concurrent(accepts, .{io}) catch unreachable;
        var protecting = io.concurrent(protected, .{io}) catch unreachable;
        io.sleep(.fromNanoseconds(tick_ns_test), .awake) catch unreachable; // all blocked
        seen[0] = sleeping.cancel(io);
        seen[1] = accepting.cancel(io);
        seen[2] = protecting.cancel(io);
    }
};

const tick_ns_test = 1_000_000;

test "sim_io: a cancel reaches a sleep, an accept and a protected task" {
    const gpa = std.testing.allocator;
    for (0..20) |seed| {
        var sim = try Sim.init(gpa, seed, .{
            .fibers_max = 4,
            .stack_bytes = 64 * 1024,
            .connections_max = 1,
            .window_bytes = 16,
            .latency_ticks_max = 2,
            .backlog_max = 1,
            .tick_ns = tick_ns_test,
            .realtime_seconds_start = 0,
        });
        defer sim.deinit(gpa);
        const io = sim.io();
        var seen: [3]bool = @splat(false);
        var driver = try io.concurrent(CancelTasks.drive, .{ io, &seen });
        for (0..100) |tick| {
            sim.tick_now = tick;
            _ = sim.run_ready(1000);
        }
        driver.await(io); // done by now: awaiting from outside a fiber would block
        try std.testing.expectEqual([3]bool{ true, true, true }, seen);
    }
}
