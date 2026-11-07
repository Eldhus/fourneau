//! fourneau-static: a directory of files, served from memory.
//!
//!   fourneau-static --root DIR [--address A] [--port P] [--shards N]
//!                   [--cert CHAIN.pem --key KEY.pem]
//!                   [--acme-directory URL --acme-identifier IP-OR-NAME
//!                    --acme-state DIR [--acme-profile P] [--acme-http-port N]
//!                    [--acme-ca BUNDLE.pem]]
//!                   [--redirect-port N [--https-host HOST]]
//!
//! With a certificate and key, every connection is HTTPS (TLS 1.3, the
//! keys then the kernel's: server.zig, tls.zig). With ACME, the server
//! obtains its certificate itself at startup when it has none fresh
//! (acme.zig), then serves HTTPS with it. With --redirect-port, plain HTTP
//! on N redirects to https://HOST (default: the ACME identifier; needs
//! --cert/--key or ACME). HTTP/2: h2 by ALPN over TLS, h2c by prior
//! knowledge when plain.
//!
//! The files are site.zig's: read once at startup into one table, which
//! the shards share read-only. A new site is a restart; under systemd's
//! socket activation (`https`, `http`; listen.zig) no client is refused.

const std = @import("std");
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const server_module = @import("server.zig");
const site_module = @import("site.zig");
const tls = @import("tls.zig");
const https = @import("https.zig");
const Stop = @import("stop.zig").Stop;
const listen = @import("listen.zig");

const log = std.log.scoped(.fourneau);

const shards_max = 256;

/// The files, from site.zig; the app answers with them, or the 404 page.
const App = struct {
    site: *const site_module.Site,

    pub const Response = site_module.Response;

    pub fn handle(app: *App, request: *Server.Request) Response {
        const head = request.head;
        if (head.method != .get and head.method != .head) {
            return .{ .status = 405, .headers = &.{}, .body = "" };
        }
        return app.site.respond(head, request.scratch) orelse app.site.not_found_response(head);
    }

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

/// What our port offers the server beyond `std.Io`.
const port_options: server_module.Options = .{
    .send_then_receive = Evented.sendThenReceive,
    .listen_backlog = Evented.listenBacklog,
    .wake_read = Evented.wakeRead,
    .wake_both = Evented.wakeBoth,
    .current_fiber = Evented.currentFiber,
    .receive = Evented.receive,
    .send = Evented.send,
    .accept = Evented.acceptDirect,
    .set_option = Evented.setSocketOption,
};

const Server = server_module.ServerType(App, port_options);

/// Port 80 beside HTTPS: redirects (https.zig).
const Redirect = https.RedirectType(port_options);

const Options = struct {
    root: ?[]const u8 = null,
    address: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    shards: u32 = 0,
    /// Per shard (`connections_per_shard`), set in `main`.
    connections_max: u32 = 0,
    /// The certificate (files or ACME) and the redirect: https.zig.
    https: https.Options = .{},
};

/// Connections across all shards, when that gives a shard at least
/// `connections_per_shard_min` (256 shards want 16,384). A connection is
/// a slot in its shard's ring file table (`Evented.acceptDirect`), not a
/// descriptor: the descriptor limit does not bound them.
const connections_max = 1024;
/// A shard holds at least these.
const connections_per_shard_min = 64;

fn connections_per_shard(shards: u32) u32 {
    assert(shards >= 1);
    assert(shards <= shards_max);
    return @max(connections_per_shard_min, connections_max / shards);
}

/// The process's descriptors, ready: the soft limit raised to the reserve
/// (1,024 by default under systemd, which the reserve is under until 460
/// shards), and what is open before the shards start checked against the
/// reserve, or the server refuses with the counts and the number to set,
/// instead of running short of descriptors under load.
fn descriptors_ready(shards: u32, redirect: bool) !void {
    assert(shards >= 1);
    assert(shards <= shards_max);
    const reserved = descriptors_reserved(shards, redirect);
    const limit = listen.descriptor_limit_raise(reserved);
    if (limit < reserved) {
        log.err("the descriptor limit is {d}; {d} shards need {d}: set it to {d} (ulimit -n " ++
            "{d}; LimitNOFILE={d} under systemd)", .{
            limit, shards, reserved, reserved, reserved, reserved,
        });
        return error.DescriptorLimit;
    }
    const open = listen.descriptors_open() orelse return; // no /proc: unchecked
    if (open + 2 * shards > reserved) {
        log.err("{d} descriptors open before {d} shards start, past the {d} reserved for " ++
            "them: inherited descriptors, or the reserve's sum is short", .{
            open, shards, reserved,
        });
        return error.DescriptorsReserved;
    }
}

/// The process's descriptors, as a sum (a connection is none): stdio (3);
/// a ring and a listener a shard; with a redirect, its listener a shard;
/// ACME's responder, its listener and the one client it answers at a time
/// (3); the site's directory while it loads (1); and a margin for what a
/// library opens (64). What is open before the shards start is checked
/// against it (`descriptors_ready`); what opens later is in the sum by
/// count.
fn descriptors_reserved(shards: u32, redirect: bool) u32 {
    assert(shards <= shards_max);
    const redirects: u32 = if (redirect) shards else 0;
    return 3 + 2 * shards + redirects + 3 + 1 + 64;
}

fn parse_options(init: std.process.Init.Minimal) !Options {
    var options: Options = .{};
    var args = init.args.iterate();
    _ = args.skip();
    for (0..16) |_| {
        const arg = args.next() orelse break;
        const value = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, arg, "--root")) {
            options.root = value;
        } else if (std.mem.eql(u8, arg, "--address")) {
            options.address = value;
        } else if (std.mem.eql(u8, arg, "--port")) {
            options.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--shards")) {
            options.shards = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            options.https.cert = value;
        } else if (std.mem.eql(u8, arg, "--key")) {
            options.https.key = value;
        } else if (std.mem.eql(u8, arg, "--acme-directory")) {
            options.https.acme_directory = value;
        } else if (std.mem.eql(u8, arg, "--acme-identifier")) {
            options.https.acme_identifier = value;
        } else if (std.mem.eql(u8, arg, "--acme-state")) {
            options.https.acme_state = value;
        } else if (std.mem.eql(u8, arg, "--acme-profile")) {
            options.https.acme_profile = value;
        } else if (std.mem.eql(u8, arg, "--acme-http-port")) {
            options.https.acme_http_port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--acme-ca")) {
            options.https.acme_ca = value;
        } else if (std.mem.eql(u8, arg, "--redirect-port")) {
            options.https.redirect_port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--https-host")) {
            options.https.https_host = value;
        } else return error.Usage;
    }
    if (options.root == null) return error.Usage;
    try options.https.check();
    return options;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var options = try parse_options(init);
    const gpa = std.heap.page_allocator;
    // Loading is a startup step: blocking reads on this thread, before any
    // shard exists.
    const io = std.Io.Threaded.global_single_threaded.io();
    const site = try site_module.Site.load(gpa, io, options.root.?, .{});
    if (site.routes.count() == 0) return error.EmptySite;
    // The certificate, loaded once and shared read-only by every shard;
    // ACME answers on systemd's port-80 socket when it holds one.
    const activation: listen.Activation = .from_environ(init.environ);
    options.https.acme_http_listener = listen.inherited(activation, "http");
    const tls_context = try https.context(gpa, io, options.https);
    var stop: Stop = .{};
    try stop.watch(); // before any shard's thread
    const shared: Shared = .{
        .site = &site,
        .tls = tls_context,
        .stop = &stop.requested,
        .activation = activation,
    };
    if (options.shards == 0) options.shards = cpu_count();
    assert(options.shards <= shards_max);
    options.connections_max = connections_per_shard(options.shards);
    try descriptors_ready(options.shards, options.https.redirect_port != null);
    var threads: [shards_max]std.Thread = undefined;
    for (threads[1..options.shards]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, run_shard, .{ &shared, options });
    }
    std.debug.print("fourneau-static: {d} routes on {s}://{s}:{d} ({d} shards)\n", .{
        site.routes.count(),
        if (shared.tls != null) "https" else "http",
        options.address,
        options.port,
        options.shards,
    });
    run_shard(&shared, options);
    for (threads[1..options.shards]) |thread| thread.join();
    std.debug.print("fourneau-static: stopped\n", .{});
}

/// What every shard reads and none writes.
const Shared = struct {
    site: *const site_module.Site,
    tls: ?*const tls.Context,
    /// Set by a signal: every shard drains and returns.
    stop: *const std.atomic.Value(bool),
    /// Sockets systemd holds across a restart (listen.zig): `https` for
    /// the site over TLS, `http` for it plain or for the redirect.
    activation: listen.Activation,
};

/// systemd's socket of that name, the shard's own copy; else one bound now.
fn listen_on(
    io: std.Io,
    shared: *const Shared,
    name: []const u8,
    address: std.Io.net.IpAddress,
) !std.Io.net.Server {
    if (listen.inherited(shared.activation, name)) |fd| return listen.server_from(fd);
    return address.listen(io, .{ .reuse_address = true, .kernel_backlog = 4096 });
}

fn cpu_count() u32 {
    const linux = std.os.linux;
    var set: linux.cpu_set_t = @splat(0);
    const result = linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &set);
    if (linux.errno(result) != .SUCCESS) return 1;
    var count: u32 = 0;
    for (set) |word| count += @popCount(word);
    assert(count >= 1);
    return @min(count, shards_max);
}

fn run_redirect(redirect_server: *Redirect.Server) void {
    redirect_server.run() catch |err| std.debug.panic("redirect: {t}", .{err});
}

fn run_shard(shared: *const Shared, options: Options) void {
    run_shard_or_fail(shared, options) catch |err| std.debug.panic("shard: {t}", .{err});
}

fn run_shard_or_fail(shared: *const Shared, options: Options) !void {
    const gpa = std.heap.page_allocator;
    assert(options.connections_max >= 1); // `main` sized it
    const config: server_module.Config = .{
        .connections_max = options.connections_max,
        .tls = shared.tls,
        .stop = shared.stop,
        // Browsers: one connection, every request and event stream on it.
        .http2 = .{},
    };
    var runtime: Evented = undefined;
    try listen.runtime_init(Evented, &runtime, gpa, .{
        .thread_limit = 0, // this thread only
        .log2_ring_entries = 12, // not the default 8: queues overflowed
        .fibers_max = config.fibers_max() +
            if (options.https.redirect_port != null) Redirect.fibers_max else 0,
        // Each server's slots, and the one it accepts while all are held.
        .direct_sockets_max = config.connections_max + 1 +
            if (options.https.redirect_port != null) Redirect.config.connections_max + 1 else 0,
    });
    defer runtime.deinit();
    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse(options.address, options.port);
    const name = if (shared.tls != null) "https" else "http";
    const listener = try listen_on(io, shared, name, address);
    var app: App = .{ .site = shared.site };
    var server = try Server.init(gpa, io, &app, listener, config);
    defer server.deinit(gpa); // its listener closed by the drain
    var group: std.Io.Group = .init;
    var redirect: Redirect = undefined;
    var redirect_server: Redirect.Server = undefined;
    if (options.https.redirect_port) |port| {
        assert(shared.tls != null); // redirecting to an HTTPS site
        redirect = .{ .host = options.https.https_host.? };
        const plain = try std.Io.net.IpAddress.parse(options.address, port);
        const redirect_listener = try listen_on(io, shared, "http", plain);
        redirect_server = try redirect.server_on(gpa, io, redirect_listener, shared.stop);
        try group.concurrent(io, run_redirect, .{&redirect_server});
    }
    try server.run();
    try group.await(io); // the redirect drains too
    if (options.https.redirect_port != null) redirect_server.deinit(gpa);
}
