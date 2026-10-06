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
//! Every file under DIR is read once, at startup, into one table (the
//! TigerStyle way: all memory taken before serving, none after), and the
//! shards serve from it, sharing it read-only. A new site is a restart:
//! fourneau-dragrace's host restarts the service when a deploy lands.
//!
//! Routes: `/` is `index.html`; `/a` is `a`, else `a.html`, else
//! `a/index.html`; nothing else exists, so no request names a path outside
//! the table (no `..`, no symlink games: the table is the whole world).
//! A missing page is `404.html` with status 404, or a plain 404.

const std = @import("std");
const assert = std.debug.assert;
const Evented = @import("zig_io_evented");
const server_module = @import("server.zig");
const http1_response = @import("http1_response.zig");
const http1_head = @import("http1_head.zig");
const tls = @import("tls.zig");
const acme = @import("acme.zig");

const files_max = 4096;
const file_bytes_max = 16 * 1024 * 1024;
const site_bytes_max = 64 * 1024 * 1024;
const shards_max = 256;

const File = struct {
    body: []const u8,
    /// Content-Type, Cache-Control and ETag, made once at load.
    headers: []const http1_response.Header,
    /// The ETag, quoted, as a client sends it back in If-None-Match.
    etag: []const u8,
};

/// The site: every route and its file, built before the first shard starts
/// and never written again.
const Site = struct {
    routes: std.StringHashMapUnmanaged(File) = .empty,
    not_found: ?File = null,
};

const App = struct {
    site: *const Site,

    pub const Response = struct {
        status: u16,
        headers: []const http1_response.Header,
        body: []const u8,
    };

    pub fn handle(app: *App, request: *Server.Request) Response {
        const head = request.head;
        const target = head.path_and_query;
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        const allowed = head.method == .get or head.method == .head;
        if (!allowed) return .{ .status = 405, .headers = &.{}, .body = "" };
        if (app.site.routes.get(path)) |file| {
            // Every file is no-cache: a browser asks again each time, and a
            // copy it already has costs a 304, not the bytes. So a deploy is
            // seen on the next load, with no versioned file names.
            if (fresh(head.headers, file.etag)) {
                return .{ .status = 304, .headers = file.headers, .body = "" };
            }
            return .{ .status = 200, .headers = file.headers, .body = file.body };
        }
        if (app.site.not_found) |file| {
            return .{ .status = 404, .headers = file.headers, .body = file.body };
        }
        return .{ .status = 404, .headers = &.{}, .body = "" };
    }

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const Server = server_module.ServerType(App, .{ .send_then_receive = Evented.sendThenReceive });

/// Plain HTTP beside HTTPS (port 80): every request goes to the same path
/// on `https://host` (301; 308 for methods other than GET and HEAD, which
/// keeps the method and body), so a browser that types the address bare
/// lands on HTTPS. The host is the configured one, never the request's
/// Host header.
const Redirect = struct {
    host: []const u8,

    pub const Response = App.Response;

    pub fn handle(redirect: *Redirect, request: *RedirectServer.Request) Response {
        const head = request.head;
        var memory = std.heap.FixedBufferAllocator.init(request.scratch);
        const allocator = memory.allocator();
        const location = std.fmt.allocPrint(allocator, "https://{s}{s}", .{
            redirect.host,
            head.path_and_query,
        }) catch return .{ .status = 414, .headers = &.{}, .body = "" };
        const headers = allocator.alloc(http1_response.Header, 1) catch
            return .{ .status = 414, .headers = &.{}, .body = "" };
        headers[0] = .{ .name = "Location", .value = location };
        const keeps_method = head.method == .get or head.method == .head;
        return .{ .status = if (keeps_method) 301 else 308, .headers = headers, .body = "" };
    }

    pub fn release(redirect: *Redirect, response: *Response) void {
        _ = redirect;
        response.* = undefined;
    }
};

const RedirectServer = server_module.ServerType(Redirect, .{
    .send_then_receive = Evented.sendThenReceive,
});

/// True when the request's If-None-Match names this ETag (or `*`).
fn fresh(headers: []const http1_head.Header, etag: []const u8) bool {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "if-none-match")) continue;
        var tags = std.mem.tokenizeAny(u8, header.value, ", ");
        for (0..64) |_| {
            const tag = tags.next() orelse break;
            const weakless = if (std.mem.startsWith(u8, tag, "W/")) tag[2..] else tag;
            if (std.mem.eql(u8, weakless, etag) or std.mem.eql(u8, tag, "*")) return true;
        }
    }
    return false;
}

fn content_type(name: []const u8) []const u8 {
    const Kind = struct { extension: []const u8, content_type: []const u8 };
    const kinds = [_]Kind{
        .{ .extension = ".html", .content_type = "text/html; charset=utf-8" },
        .{ .extension = ".css", .content_type = "text/css; charset=utf-8" },
        .{ .extension = ".js", .content_type = "text/javascript; charset=utf-8" },
        .{ .extension = ".json", .content_type = "application/json" },
        .{ .extension = ".svg", .content_type = "image/svg+xml" },
        .{ .extension = ".png", .content_type = "image/png" },
        .{ .extension = ".txt", .content_type = "text/plain; charset=utf-8" },
    };
    for (kinds) |kind| {
        if (std.mem.endsWith(u8, name, kind.extension)) return kind.content_type;
    }
    return "application/octet-stream";
}

/// A file as served: its body and its headers, the ETag a hash of the body.
fn make_file(gpa: std.mem.Allocator, name: []const u8, body: []const u8) !File {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    const etag = try std.fmt.allocPrint(gpa, "\"{x}\"", .{digest[0..8]});
    const headers = try gpa.alloc(http1_response.Header, 4);
    headers[0] = .{ .name = "Content-Type", .value = content_type(name) };
    headers[1] = .{ .name = "Cache-Control", .value = "no-cache" };
    headers[2] = .{ .name = "ETag", .value = etag };
    headers[3] = .{ .name = "X-Content-Type-Options", .value = "nosniff" };
    return .{ .body = body, .headers = headers, .etag = etag };
}

/// Read every file under `root` into `site`, with its routes.
fn load(gpa: std.mem.Allocator, io: std.Io, root: []const u8, site: *Site) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    var site_bytes: u64 = 0;
    var files: u32 = 0;
    for (0..files_max * 8) |_| {
        const entry = (try walker.next(io)) orelse break;
        if (entry.kind != .file) continue;
        // Hidden files are never pages: a deploy's marker, `.git`, an
        // editor's swap file. Serving one is how secrets leak.
        if (is_hidden(entry.path)) continue;
        files += 1;
        if (files > files_max) return error.TooManyFiles;
        const body = try entry.dir.readFileAlloc(io, entry.basename, gpa, .limited(file_bytes_max));
        site_bytes += body.len;
        if (site_bytes > site_bytes_max) return error.SiteTooLarge;
        const file = try make_file(gpa, entry.basename, body);
        try add_routes(gpa, site, entry.path, file);
    } else return error.TooManyEntries;
}

/// Whether any component of a relative path starts with a dot.
fn is_hidden(path: []const u8) bool {
    assert(path.len > 0);
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len > 0 and component[0] == '.') return true;
    }
    return false;
}

test "static: hidden files and directories are not served" {
    try std.testing.expect(is_hidden(".deployed"));
    try std.testing.expect(is_hidden(".git/config"));
    try std.testing.expect(is_hidden("docs/.draft.html"));
    try std.testing.expect(!is_hidden("index.html"));
    try std.testing.expect(!is_hidden("data/runs/a.json"));
}

fn add_routes(gpa: std.mem.Allocator, site: *Site, path: []const u8, file: File) !void {
    const route = try std.fmt.allocPrint(gpa, "/{s}", .{path});
    try site.routes.put(gpa, route, file);
    if (std.mem.eql(u8, path, "404.html")) site.not_found = file;
    if (std.mem.endsWith(u8, route, "/index.html")) {
        const directory = route[0 .. route.len - "index.html".len]; // "/a/"
        try put_alias(gpa, site, directory, file);
        if (directory.len > 1) try put_alias(gpa, site, directory[0 .. directory.len - 1], file);
    } else if (std.mem.endsWith(u8, route, ".html")) {
        try put_alias(gpa, site, route[0 .. route.len - ".html".len], file);
    }
}

/// An alias never displaces a file of that exact name.
fn put_alias(gpa: std.mem.Allocator, site: *Site, route: []const u8, file: File) !void {
    const got = try site.routes.getOrPut(gpa, route);
    if (!got.found_existing) got.value_ptr.* = file;
}

const Options = struct {
    root: ?[]const u8 = null,
    address: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    shards: u32 = 0,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    acme_directory: ?[]const u8 = null,
    acme_identifier: ?[]const u8 = null,
    acme_state: ?[]const u8 = null,
    acme_profile: ?[]const u8 = null,
    acme_http_port: u16 = 80,
    acme_ca: ?[]const u8 = null,
    /// A plain-HTTP port that redirects to HTTPS (80 in production).
    redirect_port: ?u16 = null,
    /// The host the redirect names: the ACME identifier unless given.
    https_host: ?[]const u8 = null,
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
            options.cert = value;
        } else if (std.mem.eql(u8, arg, "--key")) {
            options.key = value;
        } else if (std.mem.eql(u8, arg, "--acme-directory")) {
            options.acme_directory = value;
        } else if (std.mem.eql(u8, arg, "--acme-identifier")) {
            options.acme_identifier = value;
        } else if (std.mem.eql(u8, arg, "--acme-state")) {
            options.acme_state = value;
        } else if (std.mem.eql(u8, arg, "--acme-profile")) {
            options.acme_profile = value;
        } else if (std.mem.eql(u8, arg, "--acme-http-port")) {
            options.acme_http_port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--acme-ca")) {
            options.acme_ca = value;
        } else if (std.mem.eql(u8, arg, "--redirect-port")) {
            options.redirect_port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, arg, "--https-host")) {
            options.https_host = value;
        } else return error.Usage;
    }
    if (options.root == null) return error.Usage;
    // Both or neither: half a certificate is a mistake, not plain HTTP.
    if ((options.cert == null) != (options.key == null)) return error.Usage;
    const acme_given = options.acme_directory != null;
    if (acme_given != (options.acme_identifier != null)) return error.Usage;
    if (acme_given != (options.acme_state != null)) return error.Usage;
    if (acme_given and options.cert != null) return error.Usage; // one source of certificate
    if (options.https_host == null) options.https_host = options.acme_identifier;
    // A redirect needs an HTTPS site and a host to name.
    if (options.redirect_port != null and options.https_host == null) return error.Usage;
    return options;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var options = try parse_options(init);
    const gpa = std.heap.page_allocator;
    // Loading is a startup step: blocking reads on this thread, before any
    // shard exists.
    const io = std.Io.Threaded.global_single_threaded.io();
    var site: Site = .{};
    try load(gpa, io, options.root.?, &site);
    if (site.routes.count() == 0) return error.EmptySite;
    // The certificate, loaded once and shared read-only by every shard.
    var auth: tls.CertKeyPair = undefined;
    var context: tls.Context = undefined;
    if (options.acme_directory != null) try use_acme(gpa, io, &options);
    const https = options.cert != null;
    if (https) {
        const cwd = std.Io.Dir.cwd();
        auth = try tls.CertKeyPair.fromFilePath(gpa, io, cwd, options.cert.?, options.key.?);
        context = .{ .auth = &auth };
    }
    const shared: Shared = .{ .site = &site, .tls = if (https) &context else null };
    if (options.shards == 0) options.shards = cpu_count();
    assert(options.shards <= shards_max);
    var threads: [shards_max]std.Thread = undefined;
    for (threads[1..options.shards]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, run_shard, .{ &shared, options });
    }
    std.debug.print("fourneau-static: {d} routes on {s}://{s}:{d} ({d} shards)\n", .{
        site.routes.count(),
        if (https) "https" else "http",
        options.address,
        options.port,
        options.shards,
    });
    run_shard(&shared, options);
}

/// A fresh certificate in the ACME state directory (obtained now if need
/// be), then served as if given with --cert and --key.
fn use_acme(gpa: std.mem.Allocator, io: std.Io, options: *Options) !void {
    const value = options.acme_identifier.?;
    const identifier: acme.Identifier = if (std.Io.net.IpAddress.parse(value, 0)) |address|
        .{ .ip = address }
    else |_|
        .{ .dns = value };
    const state = options.acme_state.?;
    try acme.ensure(gpa, io, .{
        .directory_url = options.acme_directory.?,
        .identifier = identifier,
        .profile = options.acme_profile,
        .state_dir = state,
        .http_port = options.acme_http_port,
        .ca_bundle_path = options.acme_ca,
    });
    options.cert = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ state, acme.cert_file });
    options.key = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ state, acme.key_file });
}

/// What every shard reads and none writes.
const Shared = struct {
    site: *const Site,
    tls: ?*const tls.Context,
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

fn run_redirect(redirect_server: *RedirectServer) void {
    redirect_server.run() catch |err| std.debug.panic("redirect: {t}", .{err});
}

fn run_shard(shared: *const Shared, options: Options) void {
    run_shard_or_fail(shared, options) catch |err| std.debug.panic("shard: {t}", .{err});
}

fn run_shard_or_fail(shared: *const Shared, options: Options) !void {
    const gpa = std.heap.page_allocator;
    var runtime: Evented = undefined;
    try runtime.init(gpa, .{
        .thread_limit = 0, // this thread only
        .log2_ring_entries = 12, // not the default 8 (experiment 23)
    });
    defer runtime.deinit();
    const io = runtime.io();
    const address = try std.Io.net.IpAddress.parse(options.address, options.port);
    const listener = try address.listen(io, .{ .reuse_address = true, .kernel_backlog = 4096 });
    var app: App = .{ .site = shared.site };
    var server = try Server.init(gpa, io, &app, listener, .{
        .connections_max = @max(64, 1024 / options.shards),
        .tls = shared.tls,
    });
    var group: std.Io.Group = .init;
    var redirect: Redirect = undefined;
    var redirect_server: RedirectServer = undefined;
    if (options.redirect_port) |port| {
        assert(shared.tls != null); // redirecting to an HTTPS site
        redirect = .{ .host = options.https_host.? };
        const plain = try std.Io.net.IpAddress.parse(options.address, port);
        const listen_options: std.Io.net.IpAddress.ListenOptions = .{
            .reuse_address = true,
            .kernel_backlog = 1024,
        };
        const plain_listener = try plain.listen(io, listen_options);
        redirect_server = try RedirectServer.init(gpa, io, &redirect, plain_listener, .{
            .connections_max = 64,
            .scratch_bytes_max = 16 * 1024,
        });
        try group.concurrent(io, run_redirect, .{&redirect_server});
    }
    try server.run();
}

test "static: routes for pages, directories and the 404" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var site: Site = .{};
    const page = try make_file(arena, "a.html", "page");
    const index = try make_file(arena, "index.html", "index");
    const missing = try make_file(arena, "404.html", "missing");
    try add_routes(arena, &site, "index.html", index);
    try add_routes(arena, &site, "about.html", page);
    try add_routes(arena, &site, "docs/index.html", index);
    try add_routes(arena, &site, "404.html", missing);
    try std.testing.expectEqualStrings("index", site.routes.get("/").?.body);
    try std.testing.expectEqualStrings("page", site.routes.get("/about").?.body);
    try std.testing.expectEqualStrings("page", site.routes.get("/about.html").?.body);
    try std.testing.expectEqualStrings("index", site.routes.get("/docs").?.body);
    try std.testing.expectEqualStrings("index", site.routes.get("/docs/").?.body);
    try std.testing.expectEqual(@as(?File, null), site.routes.get("/../etc/passwd"));
    try std.testing.expectEqual(@as(?File, null), site.routes.get("/docs/../about.html"));
    try std.testing.expectEqualStrings("missing", site.not_found.?.body);
    try std.testing.expectEqualStrings("text/css; charset=utf-8", content_type("style.css"));
}

test "static: If-None-Match" {
    const etag = "\"0123456789abcdef\"";
    const matching: []const http1_head.Header = &.{
        .{ .name = "If-None-Match", .value = "W/\"0123456789abcdef\"" },
    };
    const other: []const http1_head.Header = &.{
        .{ .name = "if-none-match", .value = "\"x\", \"y\"" },
    };
    const any: []const http1_head.Header = &.{.{ .name = "IF-NONE-MATCH", .value = "*" }};
    try std.testing.expect(fresh(matching, etag));
    try std.testing.expect(!fresh(other, etag));
    try std.testing.expect(fresh(any, etag));
    try std.testing.expect(!fresh(&.{}, etag));
}
