//! Listening sockets inherited from systemd's socket activation
//! (sd_listen_fds(3)), and a shard's runtime that waits for its ring.
//!
//! The graceful restart (M10): systemd holds the listening socket, so a
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
/// against the user's locked memory (`RLIMIT_MEMLOCK`, 8 MiB on the laptop,
/// shared with every other server the user runs). So `SystemResources` is
/// waited out, two seconds at most (roux's host did this first). `Runtime`
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
