//! Listening sockets inherited from systemd's socket activation
//! (sd_listen_fds(3)), and a shard's runtime that waits for its ring.
//!
//! The graceful restart: systemd holds the listening socket, so a
//! restart is a stop, then a start, and no client is refused between: one
//! connecting while the old process drains (its own copy of the socket
//! closed, the socket kept) and the new one starts waits in the socket's
//! queue, and the new process accepts it. Without activation a restart
//! leaves the port closed for that while.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const net = std.Io.net;

/// What systemd sets for an activated process: whom the sockets are for,
/// how many, and their names (FileDescriptorName=), colon-separated. Read
/// by the caller, however it reads its environment.
pub const Activation = struct {
    pid: ?[]const u8,
    fds: ?[]const u8,
    names: ?[]const u8,

    pub fn from_environ(environ: std.process.Environ) Activation {
        return .{
            .pid = environ.getPosix("LISTEN_PID"),
            .fds = environ.getPosix("LISTEN_FDS"),
            .names = environ.getPosix("LISTEN_FDNAMES"),
        };
    }
};

/// The first descriptor systemd passes (SD_LISTEN_FDS_START).
const fds_start = 3;
const fds_max = 64;

/// The descriptor systemd passed as `name`, or null: not activated, the
/// sockets meant for another process, or none of that name.
pub fn inherited(activation: Activation, name: []const u8) ?linux.fd_t {
    return inherited_from(activation, .{
        .pid = linux.getpid(),
        .first = fds_start,
        .name = name,
    });
}

const Find = struct { pid: linux.pid_t, first: linux.fd_t, name: []const u8 };

fn inherited_from(activation: Activation, find: Find) ?linux.fd_t {
    assert(find.name.len > 0);
    const pid_text = activation.pid orelse return null;
    const pid = std.fmt.parseInt(linux.pid_t, pid_text, 10) catch return null;
    if (pid != find.pid) return null;
    const count = std.fmt.parseInt(u32, activation.fds orelse return null, 10) catch return null;
    if (count == 0 or count > fds_max) return null;
    var names = std.mem.splitScalar(u8, activation.names orelse "", ':');
    for (0..count) |index| {
        const name = names.next() orelse return null;
        if (std.mem.eql(u8, name, find.name)) return find.first + @as(linux.fd_t, @intCast(index));
    }
    return null;
}

pub const ServerError = error{ NotListening, Unexpected };

/// A server on its own copy of `fd` (close-on-exec): each shard has one and
/// closes it as it drains, the socket living on while systemd holds it.
pub fn server_from(fd: linux.fd_t) ServerError!net.Server {
    var accepting: u32 = 0;
    var length: linux.socklen_t = @sizeOf(u32);
    const level = linux.SOL.SOCKET;
    const option = linux.getsockopt(fd, level, linux.SO.ACCEPTCONN, @ptrCast(&accepting), &length);
    if (linux.errno(option) != .SUCCESS or accepting != 1) return error.NotListening;
    var storage: linux.sockaddr.storage = undefined;
    var storage_length: linux.socklen_t = @sizeOf(linux.sockaddr.storage);
    const named = linux.getsockname(fd, @ptrCast(&storage), &storage_length);
    if (linux.errno(named) != .SUCCESS) return error.Unexpected;
    const address = ip_address(&storage) orelse return error.NotListening;
    const copied = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, fds_start);
    if (linux.errno(copied) != .SUCCESS) return error.Unexpected;
    return .{ .socket = .{ .handle = @intCast(copied), .address = address }, .options = {} };
}

fn ip_address(storage: *const linux.sockaddr.storage) ?net.IpAddress {
    switch (storage.family) {
        linux.AF.INET => {
            const in: *const linux.sockaddr.in = @ptrCast(@alignCast(storage));
            const bytes: [4]u8 = @bitCast(in.addr);
            return .{ .ip4 = .{ .bytes = bytes, .port = std.mem.bigToNative(u16, in.port) } };
        },
        linux.AF.INET6 => {
            const in6: *const linux.sockaddr.in6 = @ptrCast(@alignCast(storage));
            return .{ .ip6 = .{ .bytes = in6.addr, .port = std.mem.bigToNative(u16, in6.port) } };
        },
        else => return null,
    }
}

/// How long a shard waits for its ring's locked memory: 40 tries, 50 ms
/// apart.
const runtime_tries = 40;
const runtime_wait_ns = 50 * std.time.ns_per_ms;

/// The shard's runtime and its ring. A start right after a stop (a
/// restart) can find the old process's rings not yet freed: the kernel
/// frees them after the process is gone, and until then their memory counts
/// against the user's locked memory (`RLIMIT_MEMLOCK`, often 8 MiB, shared
/// with every other server the user runs). So `SystemResources` is waited
/// out, two seconds at most. `Runtime`
/// is the importer's Evented (the port is its module, not fourneau's).
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

/// What a process is left with when its limit cannot be read: Linux's
/// default soft limit.
const descriptor_limit_default = 1024;

/// The soft descriptor limit (`RLIMIT_NOFILE`: 1,024 by default under
/// systemd and most shells, the hard limit far above) raised to `need`
/// when it is below it, bounded by the hard limit; the limit then in
/// force. Raised to the need, not to the hard limit, so that a leak of
/// descriptors still fails near the server's own bound instead of at
/// half a million (Redis sizes its limit the same way). Never lowered:
/// an operator's higher setting stands. A limit that cannot be read or
/// raised stays what it is: the server sizes itself to what it got
/// (`connections_fitting`), and the acceptor evicts on EMFILE.
pub fn descriptor_limit_raise(need: u64) u64 {
    assert(need >= 1);
    var limit = std.posix.getrlimit(.NOFILE) catch return descriptor_limit_default;
    if (limit.cur < need and limit.cur < limit.max) {
        limit.cur = @min(need, limit.max);
        std.posix.setrlimit(.NOFILE, limit) catch {
            limit = std.posix.getrlimit(.NOFILE) catch return descriptor_limit_default;
        };
    }
    assert(limit.cur <= limit.max);
    return limit.cur;
}

/// The descriptors this process holds open now, counted in /proc, so a
/// server can check its reserve against what it really opened before its
/// shards start. Null where /proc cannot be read (a container without
/// it): the check is skipped, not failed.
pub fn descriptors_open() ?u32 {
    const flags: linux.O = .{ .DIRECTORY = true, .CLOEXEC = true, .ACCMODE = .RDONLY };
    const opened = linux.open("/proc/self/fd", flags, 0);
    if (linux.errno(opened) != .SUCCESS) return null;
    const dir: linux.fd_t = @intCast(opened);
    defer _ = linux.close(dir);
    var buffer: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;
    var count: u32 = 0;
    for (0..descriptors_open_reads_max) |_| {
        const read = linux.getdents64(dir, &buffer, @intCast(buffer.len));
        if (linux.errno(read) != .SUCCESS) return null;
        if (read == 0) break;
        var offset: usize = 0;
        while (offset < read) {
            const entry: *const linux.dirent64 = @ptrCast(@alignCast(&buffer[offset]));
            assert(entry.reclen >= @sizeOf(linux.dirent64)); // the walk advances
            const name: [*:0]const u8 = @ptrCast(&entry.name);
            // `.` and `..` are no descriptors; the directory's own is.
            if (name[0] != '.') count += 1;
            offset += entry.reclen;
        }
    } else return null;
    assert(count >= 1); // the directory's own descriptor was listed
    return count - 1;
}

/// /proc/self/fd read in 4 KiB pieces: enough for a million entries.
const descriptors_open_reads_max = 1 << 14;

pub const Fitting = struct {
    /// The descriptor limit in force (`descriptor_limit_raise`).
    descriptors: u64,
    /// The process's descriptors that are no connection: stdio, each
    /// shard's ring and listener, files, a margin. The caller's sum.
    reserved: u32,
    /// The connections the server would hold, every shard together.
    wanted: u32,
    /// Fewer than these and the server cannot run.
    minimum: u32,
};

/// The connections the descriptor limit leaves room for: `wanted` when
/// they fit past `reserved`, else what does, down to `minimum`. Null
/// when not even `minimum` fit: the environment cannot run the server,
/// which says what limit to set and exits (before this, the slots never
/// filled, eviction never ran, and the acceptor logged EMFILE ten times a
/// second while clients waited in the backlog).
pub fn connections_fitting(fitting: Fitting) ?u32 {
    assert(fitting.minimum >= 1);
    assert(fitting.wanted >= fitting.minimum);
    if (fitting.descriptors <= fitting.reserved) return null;
    const room = fitting.descriptors - fitting.reserved;
    const connections: u32 = @intCast(@min(room, fitting.wanted));
    if (connections < fitting.minimum) return null;
    assert(connections <= fitting.wanted);
    return connections;
}

test "listen: the socket systemd passed, by name, for this process only" {
    const activation: Activation = .{ .pid = "42", .fds = "2", .names = "https:http" };
    try std.testing.expectEqual(3, find_in(activation, 42, "https"));
    try std.testing.expectEqual(4, find_in(activation, 42, "http"));
    try std.testing.expectEqual(null, find_in(activation, 42, "ssh"));
    // Another process's (a parent's, passed down): not ours.
    try std.testing.expectEqual(null, find_in(activation, 7, "https"));
    const unnamed: Activation = .{ .pid = "42", .fds = "1", .names = null };
    try std.testing.expectEqual(null, find_in(unnamed, 42, "https"));
    const none: Activation = .{ .pid = null, .fds = null, .names = null };
    try std.testing.expectEqual(null, find_in(none, 42, "https"));
    const garbled: Activation = .{ .pid = "4x", .fds = "1", .names = "https" };
    try std.testing.expectEqual(null, find_in(garbled, 42, "https"));
}

fn find_in(activation: Activation, pid: linux.pid_t, name: []const u8) ?linux.fd_t {
    return inherited_from(activation, .{ .pid = pid, .first = fds_start, .name = name });
}

test "listen: a server on a copy of a listening socket; not on another kind" {
    const io = std.Io.Threaded.global_single_threaded.io();
    const address = try net.IpAddress.parse("127.0.0.1", 0);
    var original = try address.listen(io, .{ .reuse_address = false });
    defer original.deinit(io);
    var copy = try server_from(original.socket.handle);
    defer copy.deinit(io);
    try std.testing.expect(copy.socket.handle != original.socket.handle);
    try std.testing.expectEqual(original.socket.address.getPort(), copy.socket.address.getPort());
    const plain: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer _ = linux.close(plain);
    try std.testing.expectError(error.NotListening, server_from(plain));
}

test "listen: connections sized to the descriptor limit" {
    // Room for every connection wanted: wanted; no limit at all: wanted.
    try std.testing.expectEqual(1024, fits(524_288));
    try std.testing.expectEqual(1024, fits(256 + 1024));
    try std.testing.expectEqual(1024, fits(linux.RLIM.INFINITY));
    // Room for fewer: what fits, down to the minimum.
    try std.testing.expectEqual(768, fits(1024));
    try std.testing.expectEqual(8, fits(256 + 8));
    // Fewer than the minimum, or no room at all: the server cannot run.
    try std.testing.expectEqual(null, fits(256 + 7));
    try std.testing.expectEqual(null, fits(256));
    try std.testing.expectEqual(null, fits(0));
}

fn fits(descriptors: u64) ?u32 {
    return connections_fitting(.{
        .descriptors = descriptors,
        .reserved = 256,
        .wanted = 1024,
        .minimum = 8,
    });
}

test "listen: the soft limit raised to the need, never past the hard one, never lowered" {
    const before = try std.posix.getrlimit(.NOFILE);
    defer std.posix.setrlimit(.NOFILE, before) catch {};
    // Lowered to 64 first (always allowed), then raised to the need.
    try std.posix.setrlimit(.NOFILE, .{ .cur = 64, .max = before.max });
    try std.testing.expectEqual(64, (try std.posix.getrlimit(.NOFILE)).cur);
    try std.testing.expectEqual(200, descriptor_limit_raise(200));
    try std.testing.expectEqual(200, (try std.posix.getrlimit(.NOFILE)).cur);
    // A limit already past the need stands.
    try std.testing.expectEqual(200, descriptor_limit_raise(100));
    // A need past the hard limit: the hard limit, and no error.
    const past: u64 = if (before.max == linux.RLIM.INFINITY) before.max else before.max + 1;
    try std.testing.expectEqual(before.max, descriptor_limit_raise(past));
    try std.testing.expectEqual(before.max, (try std.posix.getrlimit(.NOFILE)).cur);
}

test "listen: the descriptors open are counted in /proc" {
    const before = descriptors_open() orelse return error.SkipZigTest; // no /proc
    try std.testing.expect(before >= 3); // stdio
    const extra: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer _ = linux.close(extra);
    try std.testing.expectEqual(before + 1, descriptors_open().?);
}
