//! A simulated Linux: as much of it as one shard reaches, and nothing
//! else. Our port of Evented runs on it unchanged (simulator.zig gives it
//! to the port as its `kernel`), so every line above the system calls runs
//! under a seed: the port, the server, the application.
//!
//! - The process (the port, and all that runs on it) is a coroutine on a
//!   stack of its own. It runs until it waits on its ring with nothing to
//!   reap, then switches back to the simulator, whose loop is the world:
//!   each `step` is a tick, which completes what is due and resumes the
//!   process when it has something to reap.
//! - The ring is the ABI's: submissions in, completions out, matched by
//!   `user_data`, with the flags the port sets. Each operation's latency
//!   is drawn from the seed, and the completions due in one tick are
//!   posted in an order drawn from it: the kernel's own nondeterminism
//!   (what completes when), and nothing else. A cancel lands at its own
//!   time, so it races its target as the kernel's does.
//! - The clock is ticks; `clock_gettime` reads them.
//! - An opcode or flag not simulated panics with its name: nothing in the
//!   process reaches the real kernel by accident through the ring.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const Io = std.Io;
const Prng = @import("prng.zig").Prng;
const sim_network = @import("sim_network.zig");

pub const Network = sim_network.Network;
pub const listener_fd = sim_network.listener_fd;

pub const Options = struct {
    tick_ns: u64,
    /// The most ticks an operation takes beyond what it waits for.
    latency_ticks_max: u32,
    /// Operations in flight at once.
    operations_max: u32,
    network: sim_network.Options,
    /// The ring's submission queue, at most; the completion queue is twice
    /// it, as the kernel makes it.
    ring_entries_max: u16 = 4096,
    process_stack_bytes: u32 = 8 * 1024 * 1024,
    /// What `clock_gettime(REALTIME)` reads at tick 0: 2026-01-01 unless
    /// the simulator draws another (the Date header's every day).
    realtime_start_ns: u64 = 1_767_225_600 * std.time.ns_per_s,
};
/// The ring's descriptor, as the process sees it: never a real one.
const ring_fd: linux.fd_t = 1 << 20;
const page_bytes = std.heap.page_size_min;
/// Times the process may run without waiting before it is called stuck.
const runs_without_wait_max = 1 << 20;
/// A tick's passes, far beyond any real tick's work (sim_io's bound).
const passes_per_tick_max = 1_000_000;

/// The kernel the process is running on: set by `step` while it runs, so
/// the ring's functions (which the port calls with no context) find it.
var running: ?*Kernel = null;

const Operation = struct {
    /// `linked`: behind another (IOSQE_IO_LINK), started when it succeeds.
    state: enum { free, pending, linked } = .free,
    opcode: linux.IORING_OP = .NOP,
    flags: u8 = 0,
    user_data: u64 = 0,
    /// What it cancels (ASYNC_CANCEL), or posts (MSG_RING).
    target: u64 = 0,
    message_result: i32 = 0,
    /// Not before this tick; a socket's operation then waits for its
    /// socket too.
    due_tick: u64 = 0,
    /// The result posted when it is done, unless canceled first.
    result: i32 = 0,
    fd: linux.fd_t = -1,
    /// The buffer (RECV, SEND), the msghdr (RECVMSG, SENDMSG), or the
    /// address and its length (ACCEPT, `addr2` in `off`), in the process.
    addr: u64 = 0,
    addr2: u64 = 0,
    len: u32 = 0,
    /// The MSG_ flags: MSG_WAITALL sends until every byte is sent.
    message_flags: u32 = 0,
    /// Bytes moved so far (a send with MSG_WAITALL).
    moved: u32 = 0,
    /// The operation linked behind this one.
    next: ?u32 = null,
    /// A LINK_TIMEOUT's: the operation it times, which it cancels if it
    /// fires first.
    guards: ?u32 = null,
    /// A FUTEX_WAIT's: decided at submission, as the kernel issues it.
    futex: enum { none, waiting, woken, mismatch } = .none,
    /// The order of submission: a futex wakes its waiters oldest first.
    sequence: u64 = 0,
};

pub const Stats = struct {
    submissions: u64 = 0,
    completions: u64 = 0,
    /// Completions the process asked not to see (CQE_SKIP_SUCCESS).
    skipped: u64 = 0,
    canceled: u64 = 0,
    resumes: u64 = 0,
    futex_woken: u64 = 0,
    timed_out: u64 = 0,
    /// Submissions that ended on an IO_LINK: the chain cut there.
    chains_cut: u64 = 0,
};

pub const Kernel = struct {
    options: Options,
    prng: Prng,
    tick: u64 = 0,
    operations: []Operation,
    /// Indices of the operations due this tick, in the order drawn.
    due: []u32,
    submissions: []linux.io_uring_sqe,
    submissions_count: u32 = 0,
    completions: []linux.io_uring_cqe,
    completions_head: u32 = 0,
    completions_count: u32 = 0,
    ring_open: bool = false,
    ring_entries: u16 = 0,
    process: Process,
    network: Network,
    /// The next submission's place in the order of all of them.
    sequence: u64 = 0,
    stats: Stats = .{},

    pub fn init(gpa: std.mem.Allocator, seed: u64, options: Options) !Kernel {
        assert(options.tick_ns > 0);
        assert(options.operations_max > 0);
        assert(options.process_stack_bytes % page_bytes == 0);
        const entries_max: u32 = options.ring_entries_max;
        const operations = try gpa.alloc(Operation, options.operations_max);
        errdefer gpa.free(operations);
        @memset(operations, .{});
        const due = try gpa.alloc(u32, options.operations_max);
        errdefer gpa.free(due);
        const submissions = try gpa.alloc(linux.io_uring_sqe, entries_max);
        errdefer gpa.free(submissions);
        const completions = try gpa.alloc(linux.io_uring_cqe, 2 * entries_max);
        errdefer gpa.free(completions);
        var network: Network = try .init(gpa, options.network);
        errdefer network.deinit(gpa);
        return .{
            .options = options,
            .prng = Prng.init(seed),
            .operations = operations,
            .due = due,
            .submissions = submissions,
            .completions = completions,
            .process = try .map(options.process_stack_bytes),
            .network = network,
        };
    }

    pub fn deinit(kernel: *Kernel, gpa: std.mem.Allocator) void {
        assert(running == null);
        kernel.network.deinit(gpa);
        kernel.process.unmap();
        gpa.free(kernel.operations);
        gpa.free(kernel.due);
        gpa.free(kernel.submissions);
        gpa.free(kernel.completions);
        kernel.* = undefined;
    }

    pub fn now_ns(kernel: *const Kernel) u64 {
        return kernel.tick * kernel.options.tick_ns;
    }

    /// Start the process: `main(args)`, on its own stack, at the next step.
    pub fn start(kernel: *Kernel, comptime main: anytype, args: anytype) void {
        const process = &kernel.process;
        assert(process.state == .none);
        const Entry = ProcessEntry(main, @TypeOf(args));
        // The closure sits at the top of the stack, 16-aligned; the stub
        // finds it 8 bytes above the stack pointer it starts with.
        const top = @intFromPtr(process.stack.ptr) + process.stack.len;
        const address = std.mem.alignBackward(usize, top - @sizeOf(Entry.Closure), 16);
        const closure: *Entry.Closure = @ptrFromInt(address);
        closure.* = .{ .kernel = kernel, .args = args };
        process.context = .{ .rsp = address - 8, .rbp = 0, .rip = @intFromPtr(&Entry.stub) };
        process.state = .ready;
    }

    /// From the process, when its main returns: it never runs again.
    fn exit_process(kernel: *Kernel) noreturn {
        assert(running == kernel);
        kernel.process.state = .exited;
        context_switch(&kernel.process.context, &kernel.process.kernel_context);
        unreachable; // an exited process is never resumed
    }

    pub fn exited(kernel: *const Kernel) bool {
        return kernel.process.state == .exited;
    }

    /// One tick: complete what is due, in an order drawn from the seed, and
    /// run the process while it has something to reap. Then the clock moves.
    pub fn step(kernel: *Kernel) void {
        assert(running == null);
        if (kernel.process.state == .ready) kernel.resume_process();
        // Each pass completes an operation or runs the process, which may
        // submit more due this tick: a busy tick has many. Reaching the
        // bound means completions and the process feed each other without
        // end (a livelock).
        for (0..passes_per_tick_max) |_| {
            const completed = kernel.complete_due();
            if (kernel.process.state == .waiting and kernel.reapable()) {
                kernel.resume_process();
            } else if (completed == 0) break;
        } else @panic("sim_kernel: a tick that never ends (a livelock)");
        kernel.tick += 1;
    }

    /// What waits in the kernel, for a run that did not end: each operation
    /// not yet complete, and the process's state.
    pub fn print_pending(kernel: *const Kernel) void {
        std.debug.print("kernel at tick {d}: process {t}, {d} completions unreaped\n", .{
            kernel.tick, kernel.process.state, kernel.completions_count,
        });
        for (kernel.operations, 0..) |*operation, index| {
            if (operation.state == .free) continue;
            std.debug.print("  op {d}: {t} {t} fd {d} due {d} user_data 0x{x} futex {t}\n", .{
                index,           operation.state,    operation.opcode,
                operation.fd,    operation.due_tick, operation.user_data,
                operation.futex,
            });
        }
    }

    fn reapable(kernel: *const Kernel) bool {
        return kernel.completions_count >= @max(1, kernel.process.wait_completions);
    }

    fn resume_process(kernel: *Kernel) void {
        assert(kernel.process.state == .ready or kernel.process.state == .waiting);
        kernel.process.state = .running;
        kernel.process.runs_without_wait = 0;
        kernel.stats.resumes += 1;
        running = kernel;
        context_switch(&kernel.process.kernel_context, &kernel.process.context);
        running = null;
        assert(kernel.process.state == .waiting or kernel.process.state == .exited);
    }

    // --- the ring, from the process -------------------------------------

    fn open_ring(kernel: *Kernel, entries: u16, flags: u32) Ring {
        assert(!kernel.ring_open); // a shard has one ring
        assert(entries > 0 and entries <= kernel.options.ring_entries_max);
        assert(std.math.isPowerOfTwo(entries));
        const known = linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_SINGLE_ISSUER;
        if (flags & ~@as(u32, known) != 0) unsimulated("a ring setup flag", flags);
        kernel.ring_open = true;
        kernel.ring_entries = entries;
        return .{ .fd = ring_fd };
    }

    fn close_ring(kernel: *Kernel) void {
        assert(kernel.ring_open);
        kernel.ring_open = false;
    }

    fn next_submission(kernel: *Kernel) ?*linux.io_uring_sqe {
        assert(kernel.ring_open);
        if (kernel.submissions_count == kernel.ring_entries) return null;
        const sqe = &kernel.submissions[kernel.submissions_count];
        kernel.submissions_count += 1;
        sqe.* = std.mem.zeroes(linux.io_uring_sqe);
        return sqe;
    }

    /// The submission queue taken in, in order, as `io_uring_enter` does. A
    /// submission flagged IO_LINK has the next one wait behind it; a
    /// LINK_TIMEOUT behind it instead runs beside it, and ends it if it
    /// fires first. As in the kernel, a chain ends with its submission: an
    /// IO_LINK on the last entry links to nothing, and the next entry,
    /// submitted later, starts on its own (a LINK_TIMEOUT alone: -EINVAL).
    fn take_submissions(kernel: *Kernel) u32 {
        const count = kernel.submissions_count;
        var linking: ?u32 = null;
        for (kernel.submissions[0..count]) |*sqe| {
            const index = kernel.submit_one(sqe);
            if (linking) |before| {
                kernel.operations[before].next = index;
                if (sqe.opcode == .LINK_TIMEOUT) {
                    kernel.operations[index].guards = before;
                } else {
                    kernel.operations[index].state = .linked;
                }
            } else if (sqe.opcode == .LINK_TIMEOUT) {
                const alone = &kernel.operations[index];
                alone.result = errno(.INVAL);
                alone.due_tick = kernel.tick + kernel.latency();
            }
            linking = if (sqe.flags & linux.IOSQE_IO_LINK != 0) index else null;
        }
        if (linking != null) kernel.stats.chains_cut += 1;
        kernel.submissions_count = 0;
        kernel.stats.submissions += count;
        return count;
    }

    fn submit_one(kernel: *Kernel, sqe: *const linux.io_uring_sqe) u32 {
        const flags_known: u8 = linux.IOSQE_CQE_SKIP_SUCCESS | linux.IOSQE_IO_LINK;
        if (sqe.flags & ~flags_known != 0) unsimulated("a submission flag", sqe.flags);
        const index = kernel.free_operation();
        const operation = &kernel.operations[index];
        operation.* = .{
            .state = .pending,
            .opcode = sqe.opcode,
            .flags = sqe.flags,
            .user_data = sqe.user_data,
            .due_tick = kernel.tick + kernel.latency(),
            .fd = sqe.fd,
            .addr = sqe.addr,
            .len = sqe.len,
            .sequence = kernel.sequence,
        };
        kernel.sequence += 1;
        switch (sqe.opcode) {
            .NOP, .CLOSE => {},
            .FUTEX_WAIT, .FUTEX_WAKE => kernel.submit_futex(operation, sqe),
            .LINK_TIMEOUT => kernel.submit_timeout(operation, sqe),
            .RECV, .SEND, .RECVMSG, .SENDMSG => {
                const known: u32 = linux.MSG.NOSIGNAL | linux.MSG.WAITALL;
                if (sqe.rw_flags & ~known != 0) unsimulated("a MSG_ flag", sqe.rw_flags);
                operation.message_flags = sqe.rw_flags;
            },
            .ACCEPT => operation.addr2 = sqe.off,
            .TIMEOUT => kernel.submit_timeout(operation, sqe),
            .ASYNC_CANCEL => {
                assert(sqe.rw_flags == 0); // by user_data, the first match
                operation.target = sqe.addr;
            },
            .MSG_RING => {
                assert(sqe.fd == ring_fd); // to itself: one ring
                assert(sqe.addr == @backingInt(linux.IORING_MSG_RING_COMMAND.DATA));
                operation.target = sqe.off;
                operation.message_result = @bitCast(sqe.len);
            },
            else => unsimulated("an opcode", @backingInt(sqe.opcode)),
        }
        return index;
    }

    fn latency(kernel: *Kernel) u64 {
        return kernel.prng.int_at_most(u64, 0, kernel.options.latency_ticks_max);
    }

    /// Futexes on 32-bit words of this process, every bit of the mask:
    /// what the port asks for. The wait compares and the wake wakes now,
    /// as the kernel issues them at submission; their completions come
    /// with the latency.
    fn submit_futex(kernel: *Kernel, operation: *Operation, sqe: *const linux.io_uring_sqe) void {
        const flags: u32 = @bitCast(linux.FUTEX2_FLAGS{ .size = .U32, .private = true });
        assert(@as(u32, @bitCast(sqe.fd)) == flags);
        assert(sqe.addr3 == std.math.maxInt(u32)); // every bit
        const word: *const u32 = @ptrFromInt(sqe.addr);
        const value: u32 = @truncate(sqe.off);
        if (sqe.opcode == .FUTEX_WAIT) {
            const same = @atomicLoad(u32, word, .monotonic) == value;
            operation.futex = if (same) .waiting else .mismatch;
            return;
        }
        // The kernel takes the count as an int: `std.math.maxInt(u32)`,
        // "all", arrives as -1, and its loop stops after the first waiter
        // (Evented's futexWake wakes one waiter). So here too.
        const count: i32 = @bitCast(value);
        var woken: i32 = 0;
        // io_uring's wake is strict: a count of 0 wakes none.
        if (count != 0) for (0..kernel.operations.len) |_| {
            const waiter = kernel.oldest_waiter(sqe.addr) orelse break;
            waiter.futex = .woken;
            waiter.due_tick = kernel.tick + kernel.latency();
            woken += 1;
            kernel.stats.futex_woken += 1;
            if (woken >= count) break;
        };
        operation.result = woken;
    }

    fn oldest_waiter(kernel: *Kernel, address: u64) ?*Operation {
        var oldest: ?*Operation = null;
        for (kernel.operations) |*operation| {
            if (operation.state != .pending or operation.futex != .waiting) continue;
            if (operation.addr != address) continue;
            if (oldest == null or operation.sequence < oldest.?.sequence) oldest = operation;
        }
        return oldest;
    }

    /// A timer: its count (`off`) is 0, so it ends only by time: -ETIME.
    fn submit_timeout(kernel: *Kernel, operation: *Operation, sqe: *const linux.io_uring_sqe) void {
        assert(sqe.off == 0);
        assert(sqe.len == 1);
        const known = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_CLOCK_MASK;
        if (sqe.rw_flags & ~@as(u32, known) != 0) unsimulated("a timeout flag", sqe.rw_flags);
        const timespec: *const linux.kernel_timespec = @ptrFromInt(sqe.addr);
        assert(timespec.sec >= 0 and timespec.nsec >= 0);
        const ns = std.math.mul(u64, @intCast(timespec.sec), std.time.ns_per_s) catch
            std.math.maxInt(u64);
        const given = ns +| @as(u64, @intCast(timespec.nsec));
        const realtime = sqe.rw_flags & linux.IORING_TIMEOUT_REALTIME != 0;
        const base: u64 = if (realtime) kernel.options.realtime_start_ns else 0;
        const until_ns = if (sqe.rw_flags & linux.IORING_TIMEOUT_ABS != 0)
            given -| base
        else
            kernel.now_ns() +| given;
        // Its tick: the first at or after the time asked, then the latency.
        const tick_ns = kernel.options.tick_ns;
        const until_tick = until_ns / tick_ns + @intFromBool(until_ns % tick_ns != 0);
        const late = operation.due_tick - kernel.tick;
        operation.due_tick = @max(kernel.tick, until_tick) +| late;
        operation.result = -@as(i32, @backingInt(linux.E.TIME));
    }

    fn free_operation(kernel: *Kernel) u32 {
        for (kernel.operations, 0..) |*operation, index| {
            if (operation.state == .free) return @intCast(index);
        }
        @panic("sim_kernel: operations_max in flight");
    }

    // --- completions ----------------------------------------------------

    /// Complete every operation due by now, in an order drawn from the
    /// seed, while the completion queue has room. Returns how many.
    fn complete_due(kernel: *Kernel) u32 {
        var count: u32 = 0;
        for (kernel.operations, 0..) |*operation, index| {
            if (operation.state != .pending or operation.due_tick > kernel.tick) continue;
            kernel.due[count] = @intCast(index);
            count += 1;
        }
        // Fisher-Yates: every order of the due equally likely.
        var left = count;
        while (left > 1) : (left -= 1) {
            const pick = kernel.prng.int_less_than(u32, left);
            std.mem.swap(u32, &kernel.due[pick], &kernel.due[left - 1]);
        }
        var completed: u32 = 0;
        for (kernel.due[0..count]) |index| {
            const operation = &kernel.operations[index];
            if (operation.state != .pending) continue; // canceled by one before it
            // Room for what it posts: itself, a canceled or messaged one, and
            // what a failure cancels behind it.
            if (kernel.completions_count + 3 > kernel.completions.len) break; // full: later
            if (kernel.complete(index)) completed += 1;
        }
        return completed;
    }

    /// What the operation does when it is due. False: its socket cannot
    /// proceed yet, and it stays pending.
    fn complete(kernel: *Kernel, index: u32) bool {
        const operation = &kernel.operations[index];
        assert(operation.state == .pending);
        switch (operation.opcode) {
            // The first operation with that `user_data` ends at once,
            // -ECANCELED. None: -ENOENT (it completed already, or never was).
            .ASYNC_CANCEL => if (kernel.find(operation.target)) |victim| {
                kernel.unlink(victim);
                kernel.operations[victim].state = .pending;
                kernel.operations[victim].result = errno(.CANCELED);
                kernel.finish(victim);
                kernel.stats.canceled += 1;
                operation.result = 0;
            } else {
                operation.result = errno(.NOENT);
            },
            .MSG_RING => kernel.post(operation.target, operation.message_result, 0),
            .ACCEPT, .RECV, .SEND, .RECVMSG, .SENDMSG, .CLOSE => {
                operation.result = kernel.attempt(operation) orelse return false;
            },
            .FUTEX_WAIT => operation.result = switch (operation.futex) {
                .waiting => return false, // until a wake, or a cancel
                .woken => 0,
                .mismatch => errno(.AGAIN),
                .none => unreachable,
            },
            // Alone (its chain cut): -EINVAL, set at submission.
            .LINK_TIMEOUT => if (operation.guards != null) kernel.time_out(operation),
            else => {},
        }
        kernel.finish(index);
        return true;
    }

    /// A LINK_TIMEOUT fired: what it guards ends, -ECANCELED, unless it is
    /// already done and only its completion is on its way (a woken futex).
    fn time_out(kernel: *Kernel, operation: *Operation) void {
        const guarded_index = operation.guards.?;
        const guarded = &kernel.operations[guarded_index];
        assert(guarded.state == .pending);
        assert(guarded.next != null);
        guarded.next = null; // it no longer ends this timeout
        operation.guards = null;
        operation.result = errno(.TIME);
        kernel.stats.timed_out += 1;
        if (guarded.futex == .woken) return;
        guarded.result = errno(.CANCELED);
        kernel.finish(guarded_index);
    }

    /// A socket's operation, tried now: its result, or null when its socket
    /// cannot proceed yet.
    fn attempt(kernel: *Kernel, operation: *Operation) ?i32 {
        const network = &kernel.network;
        switch (operation.opcode) {
            .CLOSE => return if (network.close(operation.fd)) 0 else errno(.BADF),
            .ACCEPT => return kernel.attempt_accept(operation),
            .RECV, .RECVMSG => {
                const index = network.connection_of(operation.fd) orelse return errno(.BADF);
                const buffer = receive_buffer(operation);
                assert(buffer.len > 0);
                return switch (network.receive(index, buffer, &kernel.prng)) {
                    .bytes => |count| @intCast(count),
                    .end => 0,
                    .reset => errno(.CONNRESET),
                    .would_block => null,
                };
            },
            .SEND, .SENDMSG => return kernel.attempt_send(operation),
            else => unreachable,
        }
    }

    fn attempt_accept(kernel: *Kernel, operation: *Operation) ?i32 {
        const network = &kernel.network;
        if (operation.fd != listener_fd) return errno(.NOTSOCK);
        if (network.listener_closed) return errno(.INVAL);
        const fd = network.accept() orelse return null;
        if (operation.addr != 0) {
            const address: *linux.sockaddr.in = @ptrFromInt(operation.addr);
            const length: *linux.socklen_t = @ptrFromInt(operation.addr2);
            assert(length.* >= @sizeOf(linux.sockaddr.in));
            address.* = .{
                .port = std.mem.nativeToBig(u16, 1),
                .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
            };
            length.* = @sizeOf(linux.sockaddr.in);
        }
        return fd;
    }

    /// Some bytes sent; with MSG_WAITALL it stays pending until all are.
    fn attempt_send(kernel: *Kernel, operation: *Operation) ?i32 {
        const network = &kernel.network;
        const index = network.connection_of(operation.fd) orelse return errno(.BADF);
        var parts_buffer: [iovecs_max][]const u8 = undefined;
        const total = send_parts(operation, &parts_buffer);
        const parts = parts_buffer[0..total.count];
        switch (network.send(index, parts, &kernel.prng)) {
            .broken => return errno(.PIPE),
            .would_block => return null,
            .bytes => |count| {
                operation.moved += count;
                const all = operation.message_flags & linux.MSG.WAITALL != 0;
                if (all and operation.moved < total.bytes) return null;
                return @intCast(operation.moved);
            },
        }
    }

    /// An operation not yet complete, pending or linked, by `user_data`.
    fn find(kernel: *const Kernel, user_data: u64) ?u32 {
        for (kernel.operations, 0..) |*operation, index| {
            if (operation.state == .free or operation.user_data != user_data) continue;
            if (operation.opcode == .ASYNC_CANCEL) continue;
            // Woken, it is done: only its completion is on its way.
            if (operation.futex == .woken) continue;
            return @intCast(index);
        }
        return null;
    }

    /// A linked operation canceled before it started: the one before it
    /// no longer starts it.
    fn unlink(kernel: *Kernel, index: u32) void {
        if (kernel.operations[index].state != .linked) return;
        for (kernel.operations) |*operation| {
            if (operation.state != .free and operation.next == index) operation.next = null;
        }
    }

    /// Freed, and its completion posted unless the process asked not to
    /// see a success. What is linked behind it starts if it succeeded,
    /// and is canceled if it did not.
    fn finish(kernel: *Kernel, index: u32) void {
        var current: ?u32 = index;
        // Bounded: a chain is at most every operation.
        for (0..kernel.operations.len + 1) |_| {
            const this = current orelse return;
            const operation = &kernel.operations[this];
            assert(operation.state == .pending);
            operation.state = .free;
            const skip = operation.flags & linux.IOSQE_CQE_SKIP_SUCCESS != 0;
            if (skip and operation.result >= 0) {
                kernel.stats.skipped += 1;
            } else {
                kernel.post(operation.user_data, operation.result, 0);
            }
            current = operation.next;
            const next = operation.next orelse return;
            const behind = &kernel.operations[next];
            if (behind.opcode == .LINK_TIMEOUT) {
                // Done before its timeout: the timeout ends, -ECANCELED.
                assert(behind.state == .pending and behind.guards == this);
                behind.guards = null;
                behind.result = errno(.CANCELED);
                continue;
            }
            assert(behind.state == .linked);
            behind.state = .pending;
            behind.due_tick = kernel.tick + kernel.latency();
            if (operation.result >= 0) return; // it starts, in its own time
            behind.result = errno(.CANCELED); // and ends with this one
        } else unreachable;
    }

    fn post(kernel: *Kernel, user_data: u64, result: i32, flags: u32) void {
        assert(kernel.completions_count < kernel.completions.len);
        const capacity: u32 = @intCast(kernel.completions.len);
        const slot = (kernel.completions_head + kernel.completions_count) % capacity;
        kernel.completions[slot] = .{ .user_data = user_data, .res = result, .flags = flags };
        kernel.completions_count += 1;
        kernel.stats.completions += 1;
    }

    fn reap(kernel: *Kernel, out: []linux.io_uring_cqe) u32 {
        const count: u32 = @intCast(@min(out.len, kernel.completions_count));
        const capacity: u32 = @intCast(kernel.completions.len);
        for (out[0..count], 0..) |*cqe, offset| {
            cqe.* = kernel.completions[(kernel.completions_head + offset) % capacity];
        }
        kernel.completions_head = (kernel.completions_head + count) % capacity;
        kernel.completions_count -= count;
        return count;
    }

    /// From the process: wait until `count` completions can be reaped.
    fn wait(kernel: *Kernel, count: u32) void {
        assert(running == kernel);
        assert(kernel.process.state == .running);
        kernel.process.runs_without_wait += 1;
        if (kernel.process.runs_without_wait > runs_without_wait_max) {
            @panic("sim_kernel: the process submits without ever waiting");
        }
        if (count == 0 or kernel.completions_count >= count) return;
        kernel.process.state = .waiting;
        kernel.process.wait_completions = count;
        context_switch(&kernel.process.context, &kernel.process.kernel_context);
        assert(kernel.process.state == .running);
        assert(kernel.completions_count > 0);
    }
};

fn unsimulated(comptime what: []const u8, value: u64) noreturn {
    std.debug.panic("sim_kernel: " ++ what ++ " not simulated: {d}", .{value});
}

/// A completion's result for an error: the negated errno, as the kernel
/// posts it.
fn errno(err: linux.E) i32 {
    return -@as(i32, @backingInt(err));
}

/// The most iovecs a message may have (the port's `stream_iovecs_max`).
const iovecs_max = 16;

/// Where a receive puts its bytes, in the process: its buffer, or its
/// message's first non-empty iovec (a short read is a read).
fn receive_buffer(operation: *const Operation) []u8 {
    if (operation.opcode == .RECV) {
        const buffer: [*]u8 = @ptrFromInt(operation.addr);
        return buffer[0..operation.len];
    }
    const message: *const linux.msghdr = @ptrFromInt(operation.addr);
    assert(message.iovlen <= iovecs_max);
    for (message.iov[0..message.iovlen]) |iovec| {
        if (iovec.len > 0) return iovec.base[0..iovec.len];
    }
    unreachable; // the port never receives into nothing
}

/// What a send has left to send, as slices of the process's memory past
/// the bytes it has moved, and how many bytes it had in all.
fn send_parts(
    operation: *const Operation,
    out: *[iovecs_max][]const u8,
) struct { count: u32, bytes: u32 } {
    var whole: [iovecs_max][]const u8 = undefined;
    var whole_count: u32 = 0;
    if (operation.opcode == .SEND) {
        const buffer: [*]const u8 = @ptrFromInt(operation.addr);
        whole[0] = buffer[0..operation.len];
        whole_count = 1;
    } else {
        const message: *const linux.msghdr_const = @ptrFromInt(operation.addr);
        assert(message.iovlen <= iovecs_max);
        for (message.iov[0..message.iovlen]) |iovec| {
            whole[whole_count] = iovec.base[0..iovec.len];
            whole_count += 1;
        }
    }
    var bytes: u32 = 0;
    var skip = operation.moved;
    var count: u32 = 0;
    for (whole[0..whole_count]) |part| {
        bytes += @intCast(part.len);
        const skipped = @min(skip, part.len);
        skip -= @intCast(skipped);
        if (part.len - skipped == 0) continue;
        out[count] = part[skipped..];
        count += 1;
    }
    assert(skip == 0);
    return .{ .count = count, .bytes = bytes };
}

/// Free entries in the submission queue (src/kernel.zig).
pub fn sq_space_left(ring: *Ring) u32 {
    assert(ring.fd == ring_fd);
    const kernel = running.?;
    assert(kernel.submissions_count <= kernel.ring_entries);
    return kernel.ring_entries - kernel.submissions_count;
}

/// The timekeeper's way to end a socket's wait (src/kernel.zig).
pub fn shutdown(fd: linux.fd_t, how: i32) usize {
    const kernel = running.?;
    if (kernel.network.shutdown(fd, how)) return 0;
    return @bitCast(@as(isize, errno(.BADF)));
}

/// The ring, as the port holds it: `std.os.linux.IoUring`'s declarations
/// that the port uses, on the running kernel.
pub const Ring = struct {
    fd: linux.fd_t,

    /// What `io_uring_enter` may fail with, as std's ring says; the
    /// simulated one never does.
    pub const EnterError = error{ SignalInterrupt, SystemResources };

    pub fn init(entries: u16, flags: u32) error{SystemResources}!Ring {
        return running.?.open_ring(entries, flags);
    }

    /// A worker thread's ring: a shard has none.
    pub fn init_params(entries: u16, params: *linux.io_uring_params) error{SystemResources}!Ring {
        _ = entries;
        _ = params;
        @panic("sim_kernel: a second ring (a shard is one thread)");
    }

    pub fn deinit(ring: *Ring) void {
        assert(ring.fd == ring_fd);
        running.?.close_ring();
        ring.* = undefined;
    }

    pub fn get_sqe(ring: *Ring) error{SubmissionQueueFull}!*linux.io_uring_sqe {
        assert(ring.fd == ring_fd);
        return running.?.next_submission() orelse error.SubmissionQueueFull;
    }

    pub fn submit(ring: *Ring) EnterError!u32 {
        return ring.submit_and_wait(0);
    }

    pub fn submit_and_wait(ring: *Ring, wait_count: u32) EnterError!u32 {
        assert(ring.fd == ring_fd);
        const kernel = running.?;
        const submitted = kernel.take_submissions();
        kernel.wait(wait_count);
        return submitted;
    }

    pub fn copy_cqes(ring: *Ring, cqes: []linux.io_uring_cqe, wait_count: u32) EnterError!u32 {
        assert(ring.fd == ring_fd);
        assert(cqes.len > 0);
        const kernel = running.?;
        kernel.wait(wait_count);
        return kernel.reap(cqes);
    }
};

/// `Io.now`'s clock: the ticks, in nanoseconds; REALTIME from its start.
pub fn clock_gettime(clock: linux.clockid_t, timespec: *linux.timespec) usize {
    const kernel = running.?;
    const base: u64 = switch (clock) {
        .REALTIME, .REALTIME_COARSE => kernel.options.realtime_start_ns,
        .MONOTONIC, .MONOTONIC_COARSE, .MONOTONIC_RAW, .BOOTTIME => 0,
        else => unsimulated("a clock", @backingInt(clock)),
    };
    const ns = base + kernel.now_ns();
    timespec.* = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    return 0;
}

/// The process: a coroutine on a stack of its own, a guard page below it.
const Process = struct {
    state: enum { none, ready, running, waiting, exited } = .none,
    mapping: []align(page_bytes) u8,
    stack: []u8,
    context: Io.fiber.Context = undefined,
    /// Where the kernel's loop waits while the process runs.
    kernel_context: Io.fiber.Context = undefined,
    wait_completions: u32 = 0,
    runs_without_wait: u32 = 0,

    fn map(stack_bytes: u32) !Process {
        const bytes = stack_bytes + page_bytes;
        const prot: linux.PROT = .{ .READ = true, .WRITE = true };
        const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .NORESERVE = true };
        const address = linux.mmap(null, bytes, prot, flags, -1, 0);
        if (linux.errno(address) != .SUCCESS) return error.OutOfMemory;
        const mapping: [*]align(page_bytes) u8 = @ptrFromInt(address);
        const guarded = linux.mprotect(mapping, page_bytes, .{});
        assert(linux.errno(guarded) == .SUCCESS);
        return .{ .mapping = mapping[0..bytes], .stack = mapping[page_bytes..bytes] };
    }

    fn unmap(process: *Process) void {
        _ = linux.munmap(process.mapping.ptr, process.mapping.len);
    }
};

/// The process's first frame, for one `main`: chosen at comptime, so the
/// kernel holds no function pointer.
fn ProcessEntry(comptime main: anytype, comptime Args: type) type {
    return struct {
        const Closure = struct { kernel: *Kernel, args: Args };

        fn stub() callconv(.naked) void {
            asm volatile (
                \\ leaq 8(%%rsp), %%rdi
                \\ jmp %[call:P]
                :
                : [call] "X" (&call),
            );
        }

        fn call(closure: *Closure) callconv(.withStackAlign(.c, @alignOf(Closure))) noreturn {
            main(closure.args);
            closure.kernel.exit_process();
        }
    };
}

/// context_switch_x86_64.S, shared with the port.
extern fn fourneau_context_switch(s: *const Io.fiber.Switch) callconv(.c) *const Io.fiber.Switch;

fn context_switch(old: *Io.fiber.Context, new: *const Io.fiber.Context) void {
    const message: Io.fiber.Switch = .{ .old = old, .new = @constCast(new) };
    _ = fourneau_context_switch(&message);
}

// --- tests: the real port, on the simulated kernel ---------------------

const Evented = @import("zig_io_evented");
const testing = std.testing;

const test_options: Options = .{
    .tick_ns = std.time.ns_per_ms,
    .latency_ticks_max = 3,
    .operations_max = 64,
    // A window of a few bytes: every read and write is cut short somewhere.
    .network = .{ .connections_max = 2, .backlog_max = 2, .window_bytes = 5 },
    .process_stack_bytes = 1024 * 1024,
};

/// Run the process to its exit: every test's own loop, bounded.
fn run_to_exit(kernel: *Kernel, ticks_max: u64) !void {
    for (0..ticks_max) |_| {
        if (kernel.exited()) return;
        kernel.step();
    }
    return error.TestProcessNeverExited;
}

fn process_init(runtime: *Evented, fibers_max: u32) !void {
    try runtime.init(testing.allocator, .{ .thread_limit = 0, .fibers_max = fibers_max });
}

const Sleeps = struct {
    durations_ms: [3]u32 = .{ 30, 10, 20 },
    woke_ns: [3]u64 = @splat(0),
    order: [3]u32 = @splat(0),
    woken: u32 = 0,
};

fn sleeps_main(sleeps: *Sleeps) void {
    sleeps_run(sleeps) catch |err| std.debug.panic("sleeps: {t}", .{err});
}

fn sleeps_run(sleeps: *Sleeps) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 3);
    defer runtime.deinit();
    const io = runtime.io();
    var group: Io.Group = .init;
    for (0..sleeps.durations_ms.len) |index| {
        try group.concurrent(io, sleep_one, .{ io, sleeps, @as(u32, @intCast(index)) });
    }
    try group.await(io);
}

fn sleep_one(io: Io, sleeps: *Sleeps, index: u32) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(sleeps.durations_ms[index]), .awake);
    sleeps.woke_ns[index] = @intCast(Io.Timestamp.now(io, .awake).toNanoseconds());
    sleeps.order[sleeps.woken] = index;
    sleeps.woken += 1;
}

test "sim_kernel: the port's fibers sleep on simulated time, in order" {
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        var sleeps: Sleeps = .{};
        kernel.start(sleeps_main, &sleeps);
        try run_to_exit(&kernel, 1000);
        try testing.expectEqual(3, sleeps.woken);
        try testing.expectEqual([3]u32{ 1, 2, 0 }, sleeps.order);
        for (sleeps.durations_ms, sleeps.woke_ns) |ms, ns| {
            // Never early; late by at most the latencies on the way.
            const latest_ms = ms + 4 * (test_options.latency_ticks_max + 1);
            try testing.expect(ns >= ms * std.time.ns_per_ms);
            try testing.expect(ns <= latest_ms * std.time.ns_per_ms);
        }
    }
}

test "sim_kernel: a seed replays exactly; seeds differ" {
    var ticks: [2]u64 = undefined;
    var stats: [2]Stats = undefined;
    for (0..2) |run| {
        var kernel = try Kernel.init(testing.allocator, 7, test_options);
        defer kernel.deinit(testing.allocator);
        var sleeps: Sleeps = .{};
        kernel.start(sleeps_main, &sleeps);
        try run_to_exit(&kernel, 1000);
        ticks[run] = kernel.tick;
        stats[run] = kernel.stats;
    }
    try testing.expectEqual(ticks[0], ticks[1]);
    try testing.expectEqual(stats[0], stats[1]);
    // The latencies are drawn: some seed ends on another tick.
    const different = for (8..40) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        var sleeps: Sleeps = .{};
        kernel.start(sleeps_main, &sleeps);
        try run_to_exit(&kernel, 1000);
        if (kernel.tick != ticks[0]) break true;
    } else false;
    try testing.expect(different);
}

const Cut = struct {
    /// Each sleep's verdict, and when the first one ended.
    first: Io.Cancelable!void = {},
    second: Io.Cancelable!void = {},
    first_ended_ns: u64 = 0,
};

fn cut_main(cut: *Cut) void {
    cut_run(cut) catch |err| std.debug.panic("cut: {t}", .{err});
}

fn cut_run(cut: *Cut) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 1);
    defer runtime.deinit();
    const io = runtime.io();
    var future = try io.concurrent(sleep_then_sleep, .{ io, cut });
    try io.sleep(.fromMilliseconds(5), .awake);
    future.cancel(io);
}

fn sleep_then_sleep(io: Io, cut: *Cut) void {
    cut.first = io.sleep(.fromSeconds(60), .awake);
    cut.first_ended_ns = @intCast(Io.Timestamp.now(io, .awake).toNanoseconds());
    io.recancel(); // as roux's `Sleep.millis!` must: it has no error for Roc
    cut.second = io.sleep(.fromSeconds(1), .awake);
}

// A cancel cuts a sleep short and the sleep says so (the port's once
// returned as though its time had passed); re-armed,
// the next wait takes it at once.
test "sim_kernel: a cancel cuts a sleep short, and the next wait takes it re-armed" {
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        var cut: Cut = .{};
        kernel.start(cut_main, &cut);
        try run_to_exit(&kernel, 100_000);
        try testing.expectError(error.Canceled, cut.first);
        try testing.expectError(error.Canceled, cut.second);
        try testing.expect(cut.first_ended_ns < std.time.ns_per_s);
        try testing.expect(kernel.stats.canceled >= 1);
    }
}

// --- tests: sockets -----------------------------------------------------

fn accept_one(io: Io) !Io.net.Stream {
    var listener: Io.net.Server = .{
        .socket = .{
            .handle = listener_fd,
            .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 80 } },
        },
        .options = {},
    };
    return listener.accept(io);
}

fn read_some(io: Io, socket: linux.fd_t, buffer: []u8) !usize {
    var parts = [_][]u8{buffer};
    const result = try io.operate(.{ .net_read = .{ .socket_handle = socket, .data = &parts } });
    return (try result.net_read).data_len;
}

fn write_some(io: Io, socket: linux.fd_t, bytes: []const u8) !usize {
    const result = try io.operate(.{ .net_write = .{
        .socket_handle = socket,
        .data = &.{bytes},
    } });
    return result.net_write;
}

/// A client in the test's own loop: it connects, sends `request`, and
/// keeps what comes back; it closes once it has `expected_bytes`.
const TestClient = struct {
    request: []const u8,
    expected_bytes: u32,
    connection: ?u32 = null,
    sent: u32 = 0,
    received: [64]u8 = undefined,
    received_count: u32 = 0,
    closed: bool = false,

    fn step(client: *TestClient, network: *Network) void {
        if (client.closed) return;
        const connection = client.connection orelse {
            client.connection = network.client_connect();
            return;
        };
        if (client.sent < client.request.len) {
            client.sent += network.client_send(connection, client.request[client.sent..]);
        }
        const room = client.received[client.received_count..];
        client.received_count += network.client_receive(connection, room);
        if (client.received_count >= client.expected_bytes) {
            network.client_close(connection);
            client.closed = true;
        }
    }
};

/// Steps the client and the kernel until the process exits.
fn run_with_client(kernel: *Kernel, client: *TestClient, ticks_max: u64) !void {
    for (0..ticks_max) |_| {
        if (kernel.exited()) return;
        client.step(&kernel.network);
        kernel.step();
    }
    return error.TestProcessNeverExited;
}

const Echo = struct { echoed: u32 = 0 };

fn echo_main(echo: *Echo) void {
    echo_run(echo) catch |err| std.debug.panic("echo: {t}", .{err});
}

/// Echoes what one client sends until it closes.
fn echo_run(echo: *Echo) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 1);
    defer runtime.deinit();
    const io = runtime.io();
    const stream = try accept_one(io);
    defer stream.close(io);
    const socket = stream.socket.handle;
    var buffer: [7]u8 = undefined;
    for (0..1000) |_| {
        const got = try read_some(io, socket, &buffer);
        if (got == 0) return; // the client closed
        var sent: usize = 0;
        for (0..got) |_| {
            if (sent == got) break;
            sent += try write_some(io, socket, buffer[sent..got]);
        }
        assert(sent == got);
        echo.echoed += @intCast(got);
    }
    return error.TestTooManyReads;
}

test "sim_kernel: a connection accepted, read and written through a small window" {
    const request = "the quick brown fox jumps over the lazy dog";
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        _ = kernel.network.listen();
        var echo: Echo = .{};
        var client: TestClient = .{ .request = request, .expected_bytes = request.len };
        kernel.start(echo_main, &echo);
        try run_with_client(&kernel, &client, 10_000);
        try testing.expectEqual(request.len, echo.echoed);
        try testing.expectEqualStrings(request, client.received[0..client.received_count]);
    }
}

const Linked = struct { got: [4]u8 = @splat(0), count: usize = 0 };

fn linked_main(linked: *Linked) void {
    linked_run(linked) catch |err| std.debug.panic("linked: {t}", .{err});
}

/// The server's turn as one submission: all of a response sent, then the
/// next request read (`sendThenReceive`: SEND with MSG_WAITALL, linked).
fn linked_run(linked: *Linked) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 1);
    defer runtime.deinit();
    const io = runtime.io();
    const stream = try accept_one(io);
    defer stream.close(io);
    const reply = "a response longer than the window";
    linked.count = try Evented.sendThenReceive(io, stream.socket.handle, reply, &linked.got);
}

test "sim_kernel: a send with MSG_WAITALL, then the receive linked behind it" {
    const reply = "a response longer than the window";
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        _ = kernel.network.listen();
        var linked: Linked = .{};
        // It answers only once the whole response is in, so the receive
        // returns only what was sent after the send completed. It never
        // has all it expects, so it never closes.
        var client: TestClient = .{ .request = "", .expected_bytes = 64 };
        kernel.start(linked_main, &linked);
        for (0..10_000) |_| {
            if (kernel.exited()) break;
            if (client.received_count == reply.len and client.sent == 0) {
                client.sent = kernel.network.client_send(client.connection.?, "next");
                assert(client.sent == 4);
            }
            client.step(&kernel.network);
            kernel.step();
        } else return error.TestProcessNeverExited;
        try testing.expectEqualStrings(reply, client.received[0..client.received_count]);
        try testing.expect(linked.count > 0);
        try testing.expectEqualStrings("next"[0..linked.count], linked.got[0..linked.count]);
    }
}

const Dropped = struct { written: Io.Cancelable!usize = 0 };

fn dropped_main(dropped: *Dropped) void {
    dropped_run(dropped) catch |err| std.debug.panic("dropped: {t}", .{err});
}

fn dropped_run(dropped: *Dropped) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 1);
    defer runtime.deinit();
    const io = runtime.io();
    const stream = try accept_one(io);
    defer stream.close(io);
    var future = try io.concurrent(sleep_then_write, .{ io, stream.socket.handle });
    try io.sleep(.fromMilliseconds(5), .awake);
    dropped.written = future.cancel(io);
}

fn sleep_then_write(io: Io, socket: linux.fd_t) Io.Cancelable!usize {
    io.sleep(.fromSeconds(60), .awake) catch io.recancel(); // as `Sleep.millis!` must
    const result = try io.operate(.{ .net_write = .{ .socket_handle = socket, .data = &.{"x"} } });
    return result.net_write catch unreachable; // the window has room
}

// Under a seed: the drain's cancel, cutting a sleep, re-armed, taken by the
// stream's next write (port_tests.zig has it on a real ring).
test "sim_kernel: a stream write takes the cancel its fiber's sleep re-armed" {
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        _ = kernel.network.listen();
        var dropped: Dropped = .{};
        var client: TestClient = .{ .request = "", .expected_bytes = 1 };
        kernel.start(dropped_main, &dropped);
        try run_with_client(&kernel, &client, 100_000);
        try testing.expectError(error.Canceled, dropped.written);
    }
}

const Split = struct {
    reply: [40]u8 = "a reply that takes windows and windows!!".*,
    got: [8]u8 = @splat(0),
    count: usize = 0,
};

fn split_main(split: *Split) void {
    split_run(split) catch |err| std.debug.panic("split: {t}", .{err});
}

/// Seven sleeps fill the ring of 8 (Evented's default) but one entry; then
/// the send-then-receive pair, which must still go in as one chain. The
/// port runs the fibers it starts newest first: the pair's is started
/// first, so it runs last.
fn split_run(split: *Split) !void {
    var runtime: Evented = undefined;
    try process_init(&runtime, 8);
    defer runtime.deinit();
    const io = runtime.io();
    const stream = try accept_one(io);
    defer stream.close(io);
    var group: Io.Group = .init;
    try group.concurrent(io, send_pair, .{ io, stream.socket.handle, split });
    for (0..7) |_| try group.concurrent(io, sleep_a_while, .{io});
    try group.await(io);
}

fn sleep_a_while(io: Io) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(50), .awake);
}

fn send_pair(io: Io, socket: linux.fd_t, split: *Split) Io.Cancelable!void {
    split.count = Evented.sendThenReceive(io, socket, &split.reply, &split.got) catch |err|
        switch (err) {
            error.Canceled => return error.Canceled,
            error.ConnectionResetByPeer, error.Unexpected => unreachable,
        };
    // As the server does: its send buffer is free once the pair returns.
    @memset(&split.reply, '#');
}

// The kernel ends a chain with its submission. The port's pair was split
// when the queue filled between its two entries: the receive then ran
// unlinked, returned while the send still read the buffer, and the
// buffer's next use went out on the wire.
test "sim_kernel: a send-then-receive stays one chain when the ring is nearly full" {
    const reply = "a reply that takes windows and windows!!";
    for (1..33) |seed| {
        var kernel = try Kernel.init(testing.allocator, seed, test_options);
        defer kernel.deinit(testing.allocator);
        _ = kernel.network.listen();
        var split: Split = .{};
        // It sends its next request at once, so a receive that did not
        // wait for the send would have it at once.
        var client: TestClient = .{ .request = "next", .expected_bytes = reply.len };
        kernel.start(split_main, &split);
        try run_with_client(&kernel, &client, 10_000);
        try testing.expectEqualStrings(reply, client.received[0..client.received_count]);
        try testing.expectEqual(0, kernel.stats.chains_cut);
        try testing.expect(split.count > 0);
    }
}
