//! fourneau-hybrid: experiment 3's hybrid, as an instrument.
//!
//! The I/O is a state machine on raw io_uring, as on fourneau-floor (each
//! turn a send linked to the next receive), but the HTTP is fourneau's: the
//! real head parser, the real response writer, the Date. Handlers run
//! either inline or on a fiber from a small last-in first-out pool, so the
//! cost of a fiber when it is warm is measured on its own:
//!
//!   --handler inline   called on the loop's stack
//!   --handler fiber    switched to on a pooled fiber and back, as a
//!                      handler that may wait (on a body, a database) would
//!                      be; the pool's top fiber is the one used last
//!
//! Data layout, the other thing on trial: a connection is a few entries in
//! flat arrays (descriptor, bytes received, bytes to send) and its two
//! buffers. Parsing has no per-connection state: a head is parsed whole when
//! its bytes are in, by the shard's one parser into the shard's one header
//! table, and a head that arrives in pieces is parsed again from its start.
//!
//! Knows only `GET /` (hello) and 404; no bodies, no timeouts. An instrument
//! for experiment 3, not a server.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const Io = std.Io;
const http1_head = @import("http1_head.zig");
const http1_response = @import("http1_response.zig");
const http_date = @import("http_date.zig");
const floor = @import("floor.zig");

const ring_entries = 4096;
const connections_max = 1024;
const recv_bytes = 16 * 1024;
const send_bytes = 64 * 1024;
const headers_max = 64;
const fibers_max = 8;
const fiber_stack_bytes = 256 * 1024;
const completions_batch_max = 256;
/// The send's completion when it fails; a sent send posts none.
const send_failed = std.math.maxInt(u64);

const limits: http1_head.Limits = .{
    .head_bytes_max = 8 * 1024,
    .target_bytes_max = 4 * 1024,
    .headers_max = headers_max,
    .body_bytes_max = 0,
};

const Handler = enum { inline_call, fiber };

const Options = struct {
    port: u16 = 8130,
    shards: u32 = 1,
    handler: Handler = .inline_call,
};

const text_plain: []const http1_response.Header = &.{
    .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
};

const Response = struct { status: u16, body: []const u8 };

fn handle(head: *const http1_head.Head) Response {
    if (std.mem.eql(u8, head.path_and_query, "/")) return .{ .status = 200, .body = "hello\n" };
    return .{ .status = 404, .body = "not found\n" };
}

extern fn fourneau_context_switch(s: *const Io.fiber.Switch) callconv(.c) *const Io.fiber.Switch;

fn context_switch(old: *Io.fiber.Context, new: *const Io.fiber.Context) void {
    const message: Io.fiber.Switch = .{ .old = old, .new = @constCast(new) };
    _ = fourneau_context_switch(&message);
}

/// A pooled fiber: runs one handler call per switch to it, then switches
/// back to the loop.
const Fiber = struct {
    context: Io.fiber.Context,
    shard: *Shard,
    head: *const http1_head.Head = undefined,
    response: Response = undefined,

    fn entry() callconv(.naked) void {
        asm volatile (
            \\ leaq 8(%%rsp), %%rdi
            \\ jmp %[call:P]
            :
            : [call] "X" (&run),
        );
    }

    fn run(closure: *const *Fiber) callconv(.withStackAlign(.c, 16)) noreturn {
        const fiber = closure.*;
        // A pooled fiber's loop does not end: bounded only to say so.
        for (0..std.math.maxInt(u64)) |_| {
            fiber.response = handle(fiber.head);
            context_switch(&fiber.context, &fiber.shard.loop_context);
        } else unreachable;
    }
};

const Shard = struct {
    ring: IoUring,
    options: Options,
    listener: linux.fd_t,
    /// The rows: -1 when the slot is free.
    fds: [connections_max]i32 = @splat(-1),
    recv_used: [connections_max]u32 = @splat(0),
    send_used: [connections_max]u32 = @splat(0),
    /// The close after the response a request asked for.
    closing: [connections_max]bool = @splat(false),
    recv_buffers: [connections_max][recv_bytes]u8 = undefined,
    send_buffers: [connections_max][send_bytes]u8 = undefined,
    parser: http1_head.Parser = undefined,
    headers: [headers_max]http1_head.Header = undefined,
    date_text: [http_date.length]u8 = undefined,
    date_second: u64 = 0,
    loop_context: Io.fiber.Context = undefined,
    fibers: [fibers_max]Fiber = undefined,
    /// Fibers not in use, a stack: the top ran last.
    fibers_free: [fibers_max]u8 = undefined,
    fibers_free_count: u8 = 0,
    stacks: []align(std.heap.page_size_min) u8 = &.{},

    fn init_fibers(shard: *Shard) !void {
        shard.stacks = try std.heap.page_allocator.alignedAlloc(
            u8,
            .fromByteUnits(std.heap.page_size_min),
            fibers_max * fiber_stack_bytes,
        );
        for (&shard.fibers, 0..) |*fiber, index| {
            const stack = shard.stacks[index * fiber_stack_bytes ..][0..fiber_stack_bytes];
            const top = @intFromPtr(stack.ptr) + stack.len;
            const closure_address = std.mem.alignBackward(usize, top - @sizeOf(*Fiber), 16);
            const closure: **Fiber = @ptrFromInt(closure_address);
            closure.* = fiber;
            fiber.* = .{
                .context = .{
                    .rsp = closure_address - 8,
                    .rbp = 0,
                    .rip = @intFromPtr(&Fiber.entry),
                },
                .shard = shard,
            };
            shard.fibers_free[fibers_max - 1 - index] = @intCast(index);
        }
        shard.fibers_free_count = fibers_max;
    }

    fn call(shard: *Shard, head: *const http1_head.Head) Response {
        if (shard.options.handler == .inline_call) return handle(head);
        assert(shard.fibers_free_count > 0); // handlers here never wait
        shard.fibers_free_count -= 1;
        const index = shard.fibers_free[shard.fibers_free_count];
        const fiber = &shard.fibers[index];
        fiber.head = head;
        context_switch(&shard.loop_context, &fiber.context);
        shard.fibers_free[shard.fibers_free_count] = index;
        shard.fibers_free_count += 1;
        return fiber.response;
    }

    /// Answer every whole head in the row's buffer; keep a partial one.
    fn answer(shard: *Shard, row: u32) void {
        var start: u32 = 0;
        for (0..recv_bytes) |_| {
            const input = shard.recv_buffers[row][start..shard.recv_used[row]];
            if (input.len == 0) break;
            shard.parser.reset();
            switch (shard.parser.parse(input)) {
                .incomplete => break,
                .refusal => |refusal| {
                    shard.respond(row, refusal.status(), "", false);
                    shard.closing[row] = true;
                    start = shard.recv_used[row];
                    break;
                },
                .complete => |complete| {
                    const response = shard.call(&complete.head);
                    shard.respond(row, response.status, response.body, complete.head.keep_alive);
                    if (!complete.head.keep_alive) shard.closing[row] = true;
                    start += complete.head_bytes;
                },
            }
        } else unreachable; // each pass answers a head or stops
        const rest = shard.recv_buffers[row][start..shard.recv_used[row]];
        std.mem.copyForwards(u8, shard.recv_buffers[row][0..rest.len], rest);
        shard.recv_used[row] = @intCast(rest.len);
    }

    fn respond(shard: *Shard, row: u32, status: u16, body: []const u8, keep_alive: bool) void {
        const used = shard.send_used[row];
        const buffer = shard.send_buffers[row][used..];
        const result = http1_response.write(buffer, .{
            .status = status,
            .headers = text_plain,
            .framing = .{ .length = body.len },
            .keep_alive = keep_alive,
            .date = &shard.date_text,
        });
        const bytes = result.bytes; // a canned response cannot be refused
        assert(bytes + body.len <= buffer.len); // fourneau-load pipelines at most 64
        @memcpy(buffer[bytes..][0..body.len], body);
        shard.send_used[row] = used + bytes + @as(u32, @intCast(body.len));
    }

    fn on_recv(shard: *Shard, row: u32, cqe: linux.io_uring_cqe) !void {
        if (shard.fds[row] < 0) return;
        if (cqe.res <= 0) return shard.close(row);
        shard.recv_used[row] += @intCast(cqe.res);
        shard.answer(row);
        if (shard.send_used[row] == 0) return shard.arm_recv(row);
        // The turn: send everything, then receive, linked.
        const bytes = shard.send_buffers[row][0..shard.send_used[row]];
        const fd = shard.fds[row];
        const send = try shard.ring.send(send_failed, fd, bytes, linux.MSG.WAITALL);
        send.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
        shard.send_used[row] = 0;
        if (shard.closing[row]) return shard.close_after_send(row);
        try shard.arm_recv(row);
    }

    fn arm_recv(shard: *Shard, row: u32) !void {
        const window = shard.recv_buffers[row][shard.recv_used[row]..];
        assert(window.len > 0); // the parser refuses a head before it fills
        _ = try shard.ring.recv(row, shard.fds[row], .{ .buffer = window }, 0);
    }

    fn close_after_send(shard: *Shard, row: u32) !void {
        // The close is linked behind the send too.
        _ = try shard.ring.close(send_failed, shard.fds[row]);
        shard.fds[row] = -1;
    }

    fn close(shard: *Shard, row: u32) void {
        _ = linux.close(shard.fds[row]);
        shard.fds[row] = -1;
    }

    fn on_accept(shard: *Shard, cqe: linux.io_uring_cqe) !void {
        if (cqe.res < 0) return;
        const row: u32 = for (shard.fds, 0..) |fd, index| {
            if (fd < 0) break @intCast(index);
        } else {
            _ = linux.close(cqe.res); // full
            return;
        };
        shard.fds[row] = cqe.res;
        shard.recv_used[row] = 0;
        shard.send_used[row] = 0;
        shard.closing[row] = false;
        floor.no_delay(cqe.res);
        try shard.arm_recv(row);
    }

    fn refresh_date(shard: *Shard) void {
        var now: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &now);
        const second: u64 = @intCast(now.sec);
        if (second == shard.date_second) return;
        shard.date_second = second;
        shard.date_text = http_date.format(@min(second, http_date.seconds_max));
    }

    fn run(shard: *Shard) !void {
        const accept_data = std.math.maxInt(u64) - 1;
        _ = try shard.ring.accept_multishot(accept_data, shard.listener, null, null, 0);
        var cqes: [completions_batch_max]linux.io_uring_cqe = undefined;
        for (0..std.math.maxInt(u64)) |_| {
            _ = try shard.ring.submit_and_wait(1);
            shard.refresh_date(); // once a batch, not once a response
            const count = try shard.ring.copy_cqes(&cqes, 0);
            for (cqes[0..count]) |cqe| {
                if (cqe.user_data == accept_data) {
                    try shard.on_accept(cqe);
                } else if (cqe.user_data == send_failed) {
                    // The linked receive is cancelled; its completion closes.
                } else try shard.on_recv(@intCast(cqe.user_data), cqe);
            }
        } else unreachable; // a server's loop does not end
    }
};

fn run_shard(options: Options) void {
    run_shard_or_fail(options) catch |err| std.debug.panic("hybrid shard: {t}", .{err});
}

fn run_shard_or_fail(options: Options) !void {
    var params = std.mem.zeroInit(linux.io_uring_params, .{
        .flags = linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_SINGLE_ISSUER,
    });
    const shard = try std.heap.page_allocator.create(Shard);
    shard.* = .{
        .ring = try .init_params(ring_entries, &params),
        .options = options,
        .listener = try floor.listen(options.port),
    };
    shard.parser = .init(limits, &shard.headers);
    if (options.handler == .fiber) try shard.init_fibers();
    shard.refresh_date();
    try shard.run();
}

pub fn main(init: std.process.Init.Minimal) !void {
    var options: Options = .{};
    var args = init.args.iterate();
    _ = args.skip();
    for (0..8) |_| {
        const arg = args.next() orelse break;
        const value = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--shards")) {
            options.shards = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--handler")) {
            const fiber = std.mem.eql(u8, value, "fiber");
            options.handler = if (fiber) .fiber else .inline_call;
        } else return error.Usage;
    }
    assert(options.shards >= 1);
    var threads: [64]std.Thread = undefined;
    assert(options.shards <= threads.len);
    for (threads[1..options.shards]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, run_shard, .{options});
    }
    run_shard(options);
}
