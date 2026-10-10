//! fourneau-static: a directory of files, served from memory.
//!
//!   fourneau-static --root DIR [--address A] [--port P] [--shards N]
//!                   [--cert CHAIN.pem --key KEY.pem]
//!                   [--acme-directory URL --acme-identifier IP-OR-NAME
//!                    --acme-state DIR [--acme-profile P] [--acme-http-port N]
//!                    [--acme-ca BUNDLE.pem]]
//!
//! With a certificate and key, every connection is HTTPS (TLS 1.3, the
//! keys then the kernel's: server.zig, tls.zig). With ACME, the server
//! obtains its certificate itself at startup when it has none fresh
//! (acme.zig), then serves HTTPS with it.
//!
//! The files are site.zig's: read once at startup into one table, which
//! the shards share read-only. A new site is a restart: fourneau-dragrace's
//! host restarts the service when a deploy lands.

const std = @import("std");
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const server_module = @import("server.zig");
const site_module = @import("site.zig");
const tls = @import("tls.zig");
const https = @import("https.zig");
const Stop = @import("stop.zig").Stop;

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

const Server = server_module.ServerType(App, .{ .send_then_receive = Evented.sendThenReceive });

/// Port 80 beside HTTPS: redirects (https.zig).
const Redirect = https.RedirectType(.{ .send_then_receive = Evented.sendThenReceive });

const Options = struct {
    root: ?[]const u8 = null,
    address: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    shards: u32 = 0,
    /// The certificate (files or ACME) and the redirect: https.zig.
    https: https.Options = .{},
};

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
    const site = try site_module.Site.load(gpa, io, options.root.?, "", .{});
    if (site.routes.count() == 0) return error.EmptySite;
    // The certificate, loaded once and shared read-only by every shard.
    const tls_context = try https.context(gpa, io, options.https);
    var stop: Stop = .{};
    try stop.watch(); // before any shard's thread
    const shared: Shared = .{ .site = &site, .tls = tls_context, .stop = &stop.requested };
    if (options.shards == 0) options.shards = cpu_count();
    assert(options.shards <= shards_max);
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
};

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
    const config: server_module.Config = .{
        .connections_max = @max(64, 1024 / options.shards),
        .tls = shared.tls,
        .stop = shared.stop,
    };
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{
        .thread_limit = 0, // this thread only
        .log2_ring_entries = 12, // not the default 8 (experiment 23)
        .fibers_max = config.fibers_max() +
            if (options.https.redirect_port != null) Redirect.fibers_max else 0,
    });
    defer runtime.deinit();
    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse(options.address, options.port);
    const listener = try address.listen(io, .{ .reuse_address = true, .kernel_backlog = 4096 });
    var app: App = .{ .site = shared.site };
    var server = try Server.init(gpa, io, &app, listener, config);
    defer server.deinit(gpa); // its listener closed by the drain
    var group: std.Io.Group = .init;
    var redirect: Redirect = undefined;
    var redirect_server: Redirect.Server = undefined;
    if (options.https.redirect_port) |port| {
        assert(shared.tls != null); // redirecting to an HTTPS site
        redirect = .{ .host = options.https.https_host.? };
        redirect_server = try redirect.listen(gpa, io, options.address, port, shared.stop);
        try group.concurrent(io, run_redirect, .{&redirect_server});
    }
    try server.run();
    try group.await(io); // the redirect drains too
    if (options.https.redirect_port != null) redirect_server.deinit(gpa);
}
