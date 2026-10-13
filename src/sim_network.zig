//! The simulated kernel's sockets: one listening socket, its backlog, and
//! each connection as two byte queues, one each way, with the states a TCP
//! connection's ends can be in. The server's side never blocks: it says
//! whether an operation can proceed, and the kernel keeps the operation
//! pending until it can (sim_kernel.zig). The clients' side is what the
//! simulator's clients call (sim_client.zig), the same as `sim_io`'s, so
//! they run on either.
//!
//! How much a read or a write moves is drawn from the seed: any number of
//! the waiting bytes, any number that fits the window, never none.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const Prng = @import("prng.zig").Prng;

pub const Options = struct {
    connections_max: u32,
    backlog_max: u32,
    /// Each direction's queue: the most bytes in flight one way.
    window_bytes: u32,
};

/// Descriptors, as the process sees them: never real ones.
pub const listener_fd: linux.fd_t = 1 << 21;
const connection_fd_base: linux.fd_t = listener_fd + 1;

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

/// What a receive can do now.
pub const Receive = union(enum) {
    bytes: u32,
    /// The end: the client closed, or the server shut its reading side.
    end,
    reset,
    would_block,
};

/// What a send can do now.
pub const Send = union(enum) {
    bytes: u32,
    /// The connection is gone for writing (reset, or shut by the server).
    broken,
    would_block,
};

pub const Network = struct {
    connections: []Connection,
    backlog: []u32,
    backlog_count: u32 = 0,
    listening: bool = false,
    /// The server closed its listening socket (a drain).
    listener_closed: bool = false,

    pub fn init(gpa: std.mem.Allocator, options: Options) !Network {
        assert(options.connections_max > 0);
        assert(options.window_bytes > 0);
        const backlog = try gpa.alloc(u32, options.backlog_max);
        errdefer gpa.free(backlog);
        const connections = try gpa.alloc(Connection, options.connections_max);
        errdefer gpa.free(connections);
        for (connections, 0..) |*connection, index| {
            errdefer for (connections[0..index]) |*made| {
                gpa.free(made.to_server.bytes);
                gpa.free(made.to_client.bytes);
            };

            const to_server = try gpa.alloc(u8, options.window_bytes);
            errdefer gpa.free(to_server);
            connection.* = .{
                .to_server = .{ .bytes = to_server },
                .to_client = .{ .bytes = try gpa.alloc(u8, options.window_bytes) },
            };
        }
        return .{ .connections = connections, .backlog = backlog };
    }

    pub fn deinit(network: *Network, gpa: std.mem.Allocator) void {
        for (network.connections) |*connection| {
            gpa.free(connection.to_server.bytes);
            gpa.free(connection.to_client.bytes);
        }
        gpa.free(network.connections);
        gpa.free(network.backlog);
        network.* = undefined;
    }

    // --- the server's side ----------------------------------------------

    /// The listening socket, made by the simulator before the server runs.
    pub fn listen(network: *Network) linux.fd_t {
        assert(!network.listening);
        network.listening = true;
        return listener_fd;
    }

    /// The connection at the head of the backlog, now open; none waiting:
    /// null.
    pub fn accept(network: *Network) ?linux.fd_t {
        assert(network.listening and !network.listener_closed);
        if (network.backlog_count == 0) return null;
        const index = network.backlog[0];
        const rest = network.backlog[1..network.backlog_count];
        std.mem.copyForwards(u32, network.backlog[0..rest.len], rest);
        network.backlog_count -= 1;
        assert(network.connections[index].state == .backlog);
        network.connections[index].state = .open;
        return connection_fd_base + @as(linux.fd_t, @intCast(index));
    }

    /// The connection a descriptor names, if it is an open one the server
    /// has not closed.
    pub fn connection_of(network: *const Network, fd: linux.fd_t) ?u32 {
        if (fd < connection_fd_base) return null;
        const index: u32 = @intCast(fd - connection_fd_base);
        if (index >= network.connections.len) return null;
        const connection = &network.connections[index];
        if (connection.state != .open or connection.server_closed) return null;
        return index;
    }

    pub fn receive(network: *Network, index: u32, out: []u8, prng: *Prng) Receive {
        assert(out.len > 0);
        const connection = &network.connections[index];
        if (connection.reset) return .reset;
        if (connection.server_shutdown or connection.server_read_shut) return .end;
        if (connection.to_server.count > 0) {
            const available = @min(out.len, connection.to_server.count);
            const wanted = prng.int_at_most(usize, 1, available);
            return .{ .bytes = connection.to_server.pop(out[0..wanted]) };
        }
        if (connection.client_closed) return .end;
        return .would_block;
    }

    /// Some of `parts`, in order: how many bytes is drawn, at most what
    /// fits the window.
    pub fn send(
        network: *Network,
        index: u32,
        parts: []const []const u8,
        prng: *Prng,
    ) Send {
        const connection = &network.connections[index];
        if (connection.reset or connection.server_shutdown) return .broken;
        var total: usize = 0;
        for (parts) |part| total += part.len;
        assert(total > 0);
        const room = connection.to_client.free();
        if (room == 0) return .would_block;
        var left = prng.int_at_most(usize, 1, @min(total, room));
        const sent: u32 = @intCast(left);
        for (parts) |part| {
            if (left == 0) break;
            left -= connection.to_client.push(part[0..@min(left, part.len)]);
        }
        assert(left == 0);
        return .{ .bytes = sent };
    }

    /// False: no such descriptor (EBADF).
    pub fn close(network: *Network, fd: linux.fd_t) bool {
        if (fd == listener_fd) {
            if (!network.listening or network.listener_closed) return false;
            network.close_listener();
            return true;
        }
        const index = network.connection_of(fd) orelse return false;
        network.connections[index].server_closed = true;
        network.release_if_done(index);
        return true;
    }

    /// As the kernel does: connections waiting in the backlog are reset
    /// (each client sees its connection end, never answered), and every
    /// later connect is refused.
    fn close_listener(network: *Network) void {
        network.listener_closed = true;
        for (network.backlog[0..network.backlog_count]) |index| {
            const connection = &network.connections[index];
            assert(connection.state == .backlog);
            connection.state = .open;
            connection.server_closed = true;
        }
        network.backlog_count = 0;
    }

    /// False: no such descriptor (EBADF).
    pub fn shutdown(network: *Network, fd: linux.fd_t, how: i32) bool {
        const index = network.connection_of(fd) orelse return false;
        const connection = &network.connections[index];
        switch (how) {
            linux.SHUT.RDWR => connection.server_shutdown = true,
            linux.SHUT.RD => connection.server_read_shut = true,
            else => unreachable, // the server never shuts only its sending side
        }
        return true;
    }

    fn release_if_done(network: *Network, index: u32) void {
        const connection = &network.connections[index];
        const client_done = connection.client_closed or connection.reset;
        if (!connection.server_closed or !client_done) return;
        connection.* = .{
            .to_server = .{ .bytes = connection.to_server.bytes },
            .to_client = .{ .bytes = connection.to_client.bytes },
        };
    }

    // --- the clients' side (sim_client.zig) -----------------------------

    pub fn client_connect(network: *Network) ?u32 {
        if (!network.listening or network.listener_closed) return null; // refused
        if (network.backlog_count == network.backlog.len) return null;
        for (network.connections, 0..) |*connection, index| {
            if (connection.state != .free) continue;
            connection.state = .backlog;
            network.backlog[network.backlog_count] = @intCast(index);
            network.backlog_count += 1;
            return @intCast(index);
        }
        return null;
    }

    pub fn client_send(network: *Network, index: u32, bytes: []const u8) u32 {
        const connection = &network.connections[index];
        assert(connection.state != .free);
        assert(!connection.client_closed);
        const gone = connection.server_closed or connection.server_shutdown;
        if (connection.reset or gone or connection.server_read_shut) {
            return @intCast(bytes.len); // into the void, as a real socket would
        }
        return connection.to_server.push(bytes);
    }

    pub fn client_receive(network: *Network, index: u32, out: []u8) u32 {
        const connection = &network.connections[index];
        assert(connection.state != .free);
        return connection.to_client.pop(out);
    }

    pub fn client_sees_end(network: *const Network, index: u32) bool {
        const connection = &network.connections[index];
        const server_done = connection.server_closed or connection.server_shutdown;
        return server_done and connection.to_client.count == 0;
    }

    pub fn client_close(network: *Network, index: u32) void {
        const connection = &network.connections[index];
        assert(!connection.client_closed);
        connection.client_closed = true;
        if (connection.state == .backlog) network.drop_from_backlog(index);
        network.release_if_done(index);
    }

    pub fn client_reset(network: *Network, index: u32) void {
        const connection = &network.connections[index];
        assert(!connection.client_closed);
        connection.reset = true;
        connection.client_closed = true;
        if (connection.state == .backlog) network.drop_from_backlog(index);
        network.release_if_done(index);
    }

    fn drop_from_backlog(network: *Network, index: u32) void {
        for (network.backlog[0..network.backlog_count], 0..) |entry_index, position| {
            if (entry_index != index) continue;
            const rest = network.backlog[position + 1 .. network.backlog_count];
            std.mem.copyForwards(u32, network.backlog[position..][0..rest.len], rest);
            network.backlog_count -= 1;
            network.connections[index].server_closed = true;
            return;
        }
        unreachable;
    }
};
