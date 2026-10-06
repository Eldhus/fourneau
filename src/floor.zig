//! fourneau-floor: the least a server can do for fourneau-load's workload,
//! to find the kernel's floor under fourneau (experiment 18).
//!
//! An instrument, not a server: it answers every head (up to a blank line)
//! with the same canned response, the size fourneau-hello sends, and knows
//! nothing else about HTTP. One io_uring per shard, no fibers, no `std.Io`:
//! connections are rows in flat arrays, and completions drive them. Each
//! io_uring feature fourneau might adopt is a flag, so its kernel cost can
//! be measured alone:
//!
//!   --receive single      one receive per completion, into the row's buffer
//!   --receive multishot   one receive armed for the connection's life, into
//!                         provided buffers, copied into the row's buffer
//!   --files               registered (direct) descriptors: no fd lookup
//!   --link                each send linked to the next receive, its success
//!                         completion skipped: one completion per request
//!                         (single receive only)
//!   --poll-first          receives skip their first try and wait for data
//!                         (IORING_RECVSEND_POLL_FIRST): after a response,
//!                         the client has not sent yet, so the try fails.
//!                         Measured 2026-10-05: 7% slower at saturation, where
//!                         the next request has usually arrived by then
//!
//! The rows: `fds`, `recv_used`, `send_used`, `send_busy`, one buffer each
//! for receive and send. 256 connections per shard by default.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const IoUring = linux.IoUring;

const response = "HTTP/1.1 200 OK\r\n" ++
    "Date: Mon, 05 Oct 2026 12:36:47 GMT\r\n" ++
    "Content-Length: 6\r\n" ++
    "Content-Type: text/plain; charset=utf-8\r\n\r\nhello\n";
comptime {
    assert(response.len == 122); // fourneau-hello's response, byte for byte in size
}

const ring_entries = 4096;
const connections_max = 1024;
const recv_bytes = 4096;
const send_bytes = 64 * 1024;
const provided_bytes = 4096;
const provided_count = 1024;
const group_id = 1;
const completions_batch_max = 256;

const Receive = enum { single, multishot };

const Options = struct {
    port: u16 = 8130,
    shards: u32 = 1,
    receive: Receive = .single,
    files: bool = false,
    link: bool = false,
    poll_first: bool = false,
};

/// What a completion is for: the operation in the low bits, the connection's
/// row above them.
const Operation = enum(u2) { accept, recv, send, close };

fn user_data(operation: Operation, row: u32) u64 {
    return (@as(u64, row) << 2) | @backingInt(operation);
}

const Shard = struct {
    ring: IoUring,
    options: Options,
    listener: linux.fd_t,
    group: ?IoUring.BufferGroup,
    /// The rows: -1 when the slot is free.
    fds: [connections_max]i32 = @splat(-1),
    recv_used: [connections_max]u32 = @splat(0),
    send_used: [connections_max]u32 = @splat(0),
    send_busy: [connections_max]bool = @splat(false),
    recv_buffers: [connections_max][recv_bytes]u8 = undefined,
    send_buffers: [connections_max][send_bytes]u8 = undefined,

    fn arm_recv(shard: *Shard, row: u32) !void {
        const fd = shard.fds[row];
        assert(fd >= 0);
        const sqe = switch (shard.options.receive) {
            .single => try shard.ring.recv(
                user_data(.recv, row),
                fd,
                .{ .buffer = shard.recv_buffers[row][shard.recv_used[row]..] },
                0,
            ),
            .multishot => try shard.group.?.recv_multishot(user_data(.recv, row), fd, 0),
        };
        if (shard.options.files) sqe.flags |= linux.IOSQE_FIXED_FILE;
        if (shard.options.poll_first) sqe.ioprio |= linux.IORING_RECVSEND_POLL_FIRST;
    }

    fn arm_send(shard: *Shard, row: u32) !void {
        assert(!shard.send_busy[row]);
        assert(shard.send_used[row] > 0);
        const bytes = shard.send_buffers[row][0..shard.send_used[row]];
        const sqe = try shard.ring.send(user_data(.send, row), shard.fds[row], bytes, 0);
        if (shard.options.files) sqe.flags |= linux.IOSQE_FIXED_FILE;
        shard.send_busy[row] = true;
    }

    /// The send, then the receive linked behind it: the receive starts
    /// once every byte is sent (MSG_WAITALL), so its completion says the
    /// send buffer is free, and a sent send posts no completion. A failed
    /// send cancels the receive, whose completion closes the connection.
    fn arm_send_linked(shard: *Shard, row: u32) !void {
        const bytes = shard.send_buffers[row][0..shard.send_used[row]];
        const fd = shard.fds[row];
        const sqe = try shard.ring.send(user_data(.send, row), fd, bytes, linux.MSG.WAITALL);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
        if (shard.options.files) sqe.flags |= linux.IOSQE_FIXED_FILE;
        shard.send_used[row] = 0;
    }

    fn close(shard: *Shard, row: u32) !void {
        const fd = shard.fds[row];
        assert(fd >= 0);
        if (shard.options.files) {
            _ = try shard.ring.close_direct(user_data(.close, row), @intCast(fd));
        } else {
            _ = try shard.ring.close(user_data(.close, row), fd);
        }
        shard.fds[row] = -1;
    }

    fn free_row(shard: *Shard) ?u32 {
        for (shard.fds, 0..) |fd, row| if (fd < 0) return @intCast(row);
        return null;
    }

    fn on_accept(shard: *Shard, cqe: linux.io_uring_cqe) !void {
        assert(cqe.flags & linux.IORING_CQE_F_MORE != 0); // multishot accept stays armed
        if (cqe.res < 0) return;
        const row = shard.free_row() orelse {
            _ = linux.close(cqe.res); // full: refuse (direct descriptors: never full here)
            return;
        };
        shard.fds[row] = cqe.res;
        shard.recv_used[row] = 0;
        shard.send_used[row] = 0;
        shard.send_busy[row] = false;
        if (!shard.options.files) no_delay(cqe.res);
        try shard.arm_recv(row);
    }

    fn on_recv(shard: *Shard, row: u32, cqe: linux.io_uring_cqe) !void {
        if (shard.fds[row] < 0) return; // a multishot's last completion after close
        if (cqe.res <= 0) {
            if (cqe.res == -@as(i32, @backingInt(linux.E.NOBUFS))) return shard.arm_recv(row);
            return shard.close(row);
        }
        const got: u32 = @intCast(cqe.res);
        if (shard.options.receive == .multishot) {
            var group = &shard.group.?;
            const bytes = try group.get(cqe);
            const start = shard.recv_used[row];
            assert(start + bytes.len <= recv_bytes); // fourneau-load's requests are small
            @memcpy(shard.recv_buffers[row][start..][0..bytes.len], bytes);
            try group.put(cqe);
        }
        shard.recv_used[row] += got;
        shard.answer(row);
        if (shard.options.link) {
            assert(shard.options.receive == .single);
            if (shard.send_used[row] > 0) try shard.arm_send_linked(row);
            return shard.arm_recv(row);
        }
        if (shard.send_used[row] > 0 and !shard.send_busy[row]) try shard.arm_send(row);
        const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
        if (shard.options.receive == .single or !more) try shard.arm_recv(row);
    }

    /// One canned response per complete head; the partial tail stays.
    fn answer(shard: *Shard, row: u32) void {
        const input = shard.recv_buffers[row][0..shard.recv_used[row]];
        var start: usize = 0;
        for (0..input.len) |_| {
            const end = std.mem.indexOfPos(u8, input, start, "\r\n\r\n") orelse break;
            const used = shard.send_used[row];
            assert(used + response.len <= send_bytes);
            @memcpy(shard.send_buffers[row][used..][0..response.len], response);
            shard.send_used[row] = used + @as(u32, response.len);
            start = end + 4;
        }
        const rest = input[start..];
        std.mem.copyForwards(u8, shard.recv_buffers[row][0..rest.len], rest);
        shard.recv_used[row] = @intCast(rest.len);
    }

    fn on_send(shard: *Shard, row: u32, cqe: linux.io_uring_cqe) !void {
        if (shard.options.link) {
            assert(cqe.res < 0); // only a failed send completes
            return; // its receive is canceled; that completion closes
        }
        assert(shard.send_busy[row]);
        shard.send_busy[row] = false;
        if (shard.fds[row] < 0) return;
        if (cqe.res <= 0) return shard.close(row);
        const sent: u32 = @intCast(cqe.res);
        const rest = shard.send_buffers[row][sent..shard.send_used[row]];
        std.mem.copyForwards(u8, shard.send_buffers[row][0..rest.len], rest);
        shard.send_used[row] = @intCast(rest.len);
        if (shard.send_used[row] > 0) try shard.arm_send(row);
    }

    fn run(shard: *Shard) !void {
        const accept_data = user_data(.accept, 0);
        if (shard.options.files) {
            _ = try shard.ring.accept_multishot_direct(accept_data, shard.listener, null, null, 0);
        } else {
            _ = try shard.ring.accept_multishot(accept_data, shard.listener, null, null, 0);
        }
        var cqes: [completions_batch_max]linux.io_uring_cqe = undefined;
        for (0..std.math.maxInt(u64)) |_| {
            _ = try shard.ring.submit_and_wait(1);
            const count = try shard.ring.copy_cqes(&cqes, 0);
            for (cqes[0..count]) |cqe| {
                const row: u32 = @intCast(cqe.user_data >> 2);
                const operation_bits: u2 = @truncate(cqe.user_data);
                const operation: Operation = @fromBackingInt(operation_bits);
                switch (operation) {
                    .accept => try shard.on_accept(cqe),
                    .recv => try shard.on_recv(row, cqe),
                    .send => try shard.on_send(row, cqe),
                    .close => {},
                }
            }
        } else unreachable; // a server's loop does not end
    }
};

pub fn no_delay(fd: i32) void {
    const on: u32 = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&on), 4);
}

pub fn listen(port: u16) !linux.fd_t {
    const fd: i32 = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    assert(fd >= 0);
    const on: u32 = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&on), 4);
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&on), 4);
    var address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        return error.Bind;
    }
    if (linux.errno(linux.listen(fd, 4096)) != .SUCCESS) return error.Listen;
    return fd;
}

fn run_shard(options: Options) void {
    run_shard_or_fail(options) catch |err| std.debug.panic("floor shard: {t}", .{err});
}

fn run_shard_or_fail(options: Options) !void {
    var params = std.mem.zeroInit(linux.io_uring_params, .{
        .flags = linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_SINGLE_ISSUER,
    });
    const shard = try std.heap.page_allocator.create(Shard);
    shard.* = .{
        .ring = try .init_params(ring_entries, &params),
        .options = options,
        .listener = try listen(options.port),
        .group = null,
    };
    if (options.receive == .multishot) {
        shard.group = try .init(
            &shard.ring,
            std.heap.page_allocator,
            group_id,
            provided_bytes,
            provided_count,
        );
    }
    if (options.files) try shard.ring.register_files_sparse(connections_max);
    try shard.run();
}

pub fn main(init: std.process.Init.Minimal) !void {
    var options: Options = .{};
    var args = init.args.iterate();
    _ = args.skip();
    for (0..16) |_| {
        const arg = args.next() orelse break;
        const value = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--shards")) {
            options.shards = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--receive")) {
            options.receive = std.meta.stringToEnum(Receive, value) orelse return error.Usage;
        } else if (std.mem.eql(u8, arg, "--files")) {
            options.files = std.mem.eql(u8, value, "on");
        } else if (std.mem.eql(u8, arg, "--link")) {
            options.link = std.mem.eql(u8, value, "on");
        } else if (std.mem.eql(u8, arg, "--poll-first")) {
            options.poll_first = std.mem.eql(u8, value, "on");
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
