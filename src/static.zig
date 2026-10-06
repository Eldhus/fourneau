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
const https = @import("https.zig");

const files_max = 4096;
const file_bytes_max = 16 * 1024 * 1024;
const site_bytes_max = 64 * 1024 * 1024;
const shards_max = 256;

/// One file as sent: its bytes and the headers that go with them.
const Variant = struct {
    body: []const u8,
    /// Content-Type, Cache-Control, ETag (and Content-Encoding, Vary), made
    /// once at load.
    headers: []const http1_response.Header,
    /// The ETag, quoted, as a client sends it back in If-None-Match.
    etag: []const u8,
};

/// A file, and its gzip-compressed copy when compressing it paid: made at
/// load, so a request costs no compression (M6).
const File = struct {
    identity: Variant,
    gzip: ?Variant = null,

    /// The copy this request may have: gzip when it says it accepts it.
    fn variant(file: *const File, headers: []const http1_head.Header) *const Variant {
        if (file.gzip) |*compressed| {
            if (accepts_gzip(headers)) return compressed;
        }
        return &file.identity;
    }
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
        if (app.site.routes.getPtr(path)) |file| {
            const sent = file.variant(head.headers);
            // Every file is no-cache: a browser asks again each time, and a
            // copy it already has costs a 304, not the bytes. So a deploy is
            // seen on the next load, with no versioned file names.
            if (fresh(head.headers, sent.etag)) {
                return .{ .status = 304, .headers = sent.headers, .body = "" };
            }
            if (header_value(head.headers, "range")) |range| {
                return partial(request, &file.identity, range);
            }
            return .{ .status = 200, .headers = sent.headers, .body = sent.body };
        }
        if (app.site.not_found) |*file| {
            const sent = file.variant(head.headers);
            return .{ .status = 404, .headers = sent.headers, .body = sent.body };
        }
        return .{ .status = 404, .headers = &.{}, .body = "" };
    }

    /// A Range request (RFC 9110 §14): one byte range of the uncompressed
    /// copy, 206 with Content-Range; an unsatisfiable one, 416; anything
    /// else (several ranges, another unit, an If-Range that no longer
    /// matches) the whole file, which the RFC allows.
    fn partial(request: *Server.Request, file: *const Variant, range: []const u8) Response {
        const whole: Response = .{ .status = 200, .headers = file.headers, .body = file.body };
        if (header_value(request.head.headers, "if-range")) |if_range| {
            if (!std.mem.eql(u8, if_range, file.etag)) return whole;
        }
        const len: u64 = file.body.len;
        var memory = std.heap.FixedBufferAllocator.init(request.scratch);
        const allocator = memory.allocator();
        const headers = allocator.alloc(http1_response.Header, file.headers.len + 1) catch
            return whole;
        @memcpy(headers[0..file.headers.len], file.headers);
        switch (parse_range(range, len)) {
            .whole => return whole,
            .unsatisfiable => {
                const value = std.fmt.allocPrint(allocator, "bytes */{d}", .{len}) catch
                    return whole;
                headers[file.headers.len] = .{ .name = "Content-Range", .value = value };
                return .{ .status = 416, .headers = headers, .body = "" };
            },
            .bytes => |bytes| {
                assert(bytes.first <= bytes.last and bytes.last < len);
                const value = std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{
                    bytes.first, bytes.last, len,
                }) catch return whole;
                headers[file.headers.len] = .{ .name = "Content-Range", .value = value };
                const body = file.body[@intCast(bytes.first)..@intCast(bytes.last + 1)];
                return .{ .status = 206, .headers = headers, .body = body };
            },
        }
    }

    pub fn release(app: *App, response: *Response) void {
        _ = app;
        response.* = undefined;
    }
};

const RangeResult = union(enum) {
    /// Serve the whole file (no usable range).
    whole,
    unsatisfiable,
    bytes: struct { first: u64, last: u64 },
};

/// `bytes=a-b`, `bytes=a-` or `bytes=-n` against a file of `len` bytes.
fn parse_range(value: []const u8, len: u64) RangeResult {
    const prefix = "bytes=";
    if (!std.mem.startsWith(u8, value, prefix)) return .whole;
    const spec = std.mem.trim(u8, value[prefix.len..], " \t");
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return .whole; // several: whole
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return .whole;
    const first_text = spec[0..dash];
    const last_text = spec[dash + 1 ..];
    if (first_text.len == 0) {
        // The last n bytes.
        const n = std.fmt.parseInt(u64, last_text, 10) catch return .whole;
        if (n == 0 or len == 0) return .unsatisfiable;
        return .{ .bytes = .{ .first = len - @min(n, len), .last = len - 1 } };
    }
    const first = std.fmt.parseInt(u64, first_text, 10) catch return .whole;
    if (first >= len) return .unsatisfiable;
    const last = if (last_text.len == 0)
        len - 1
    else
        @min(std.fmt.parseInt(u64, last_text, 10) catch return .whole, len - 1);
    if (last < first) return .whole; // invalid: ignored, as the RFC says
    return .{ .bytes = .{ .first = first, .last = last } };
}

/// The value of the first header with this name, any case.
fn header_value(headers: []const http1_head.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "static: Range, as RFC 9110 §14 reads it" {
    const B = @FieldType(RangeResult, "bytes");
    const cases = [_]struct { value: []const u8, want: RangeResult }{
        .{ .value = "bytes=0-9", .want = .{ .bytes = B{ .first = 0, .last = 9 } } },
        .{ .value = "bytes=90-", .want = .{ .bytes = B{ .first = 90, .last = 99 } } },
        .{ .value = "bytes=-5", .want = .{ .bytes = B{ .first = 95, .last = 99 } } },
        .{ .value = "bytes=-500", .want = .{ .bytes = B{ .first = 0, .last = 99 } } },
        .{ .value = "bytes=50-999", .want = .{ .bytes = B{ .first = 50, .last = 99 } } },
        .{ .value = "bytes=100-", .want = .unsatisfiable },
        .{ .value = "bytes=-0", .want = .unsatisfiable },
        .{ .value = "bytes=0-1,5-6", .want = .whole },
        .{ .value = "items=0-1", .want = .whole },
        .{ .value = "bytes=9-3", .want = .whole },
        .{ .value = "bytes=x-3", .want = .whole },
    };
    for (cases) |case| try std.testing.expectEqual(case.want, parse_range(case.value, 100));
}

const Server = server_module.ServerType(App, .{ .send_then_receive = Evented.sendThenReceive });

/// Port 80 beside HTTPS: redirects (https.zig).
const Redirect = https.RedirectType(.{ .send_then_receive = Evented.sendThenReceive });

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
fn make_file(gpa: std.mem.Allocator, name: []const u8, body: []const u8, secure: bool) !File {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    const compressed = if (compressible(name, body.len)) try gzip(gpa, body) else null;
    // A copy at least a tenth smaller is worth its CPU and memory.
    const worth = if (compressed) |bytes| bytes.len * 10 < body.len * 9 else false;
    const tag = try std.fmt.allocPrint(gpa, "{x}", .{digest[0..8]});
    var file: File = .{ .identity = try make_variant(gpa, name, body, tag, null, worth, secure) };
    if (worth) {
        file.gzip = try make_variant(gpa, name, compressed.?, tag, "gzip", true, secure);
    } else if (compressed) |bytes| gpa.free(bytes);
    return file;
}

/// The headers of one copy. `vary`: the file has another copy, so caches
/// must key on Accept-Encoding.
fn make_variant(
    gpa: std.mem.Allocator,
    name: []const u8,
    body: []const u8,
    tag: []const u8,
    encoding: ?[]const u8,
    vary: bool,
    secure: bool,
) !Variant {
    // Each copy its own ETag, as each has its own bytes.
    const etag = if (encoding) |coding|
        try std.fmt.allocPrint(gpa, "\"{s}-{s}\"", .{ tag, coding })
    else
        try std.fmt.allocPrint(gpa, "\"{s}\"", .{tag});
    var headers: std.ArrayList(http1_response.Header) = .empty;
    try headers.append(gpa, .{ .name = "Content-Type", .value = content_type(name) });
    try headers.append(gpa, .{ .name = "Cache-Control", .value = "no-cache" });
    try headers.append(gpa, .{ .name = "ETag", .value = etag });
    try headers.append(gpa, .{ .name = "X-Content-Type-Options", .value = "nosniff" });
    // Ranges are cut from the uncompressed copy (App.partial).
    if (encoding == null) try headers.append(gpa, .{ .name = "Accept-Ranges", .value = "bytes" });
    if (encoding) |coding| {
        try headers.append(gpa, .{ .name = "Content-Encoding", .value = coding });
    }
    if (vary) try headers.append(gpa, .{ .name = "Vary", .value = "Accept-Encoding" });
    // HTTPS from now on, for a year (browsers ignore it for an IP address:
    // it takes effect when the site has a name).
    if (secure) {
        const policy = "max-age=31536000";
        try headers.append(gpa, .{ .name = "Strict-Transport-Security", .value = policy });
    }
    return .{ .body = body, .headers = try headers.toOwnedSlice(gpa), .etag = etag };
}

/// Text compresses; images and fonts are compressed already. Tiny files are
/// not worth a header.
fn compressible(name: []const u8, len: usize) bool {
    if (len < 256) return false;
    const text_types = [_][]const u8{ ".html", ".css", ".js", ".json", ".svg", ".txt", ".xml" };
    for (text_types) |extension| {
        if (std.mem.endsWith(u8, name, extension)) return true;
    }
    return false;
}

/// gzip at the best level: once, at load.
fn gzip(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    const flate = std.compress.flate;
    var output = try std.Io.Writer.Allocating.initCapacity(gpa, body.len / 2 + 64);
    errdefer output.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const compress = try gpa.create(flate.Compress);
    defer gpa.destroy(compress);
    compress.* = try .init(&output.writer, window, .gzip, .best);
    try compress.writer.writeAll(body);
    try compress.finish();
    return output.toOwnedSlice();
}

/// Whether Accept-Encoding allows gzip: `gzip` (or `*`) listed, and not
/// with q=0 (RFC 9110 §12.5.3).
fn accepts_gzip(headers: []const http1_head.Header) bool {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "accept-encoding")) continue;
        var codings = std.mem.splitScalar(u8, header.value, ',');
        // n bytes split into at most n + 1 codings, then the end.
        for (0..header.value.len + 2) |_| {
            const coding = codings.next() orelse break;
            var parts = std.mem.splitScalar(u8, coding, ';');
            const coding_name = std.mem.trim(u8, parts.first(), " \t");
            const named = std.ascii.eqlIgnoreCase(coding_name, "gzip") or
                std.mem.eql(u8, coding_name, "*");
            if (named) return !refused(parts.rest());
        } else unreachable;
    }
    return false;
}

/// A coding's parameters say q=0 (or 0.0, 0.00, 0.000).
fn refused(parameters: []const u8) bool {
    var params = std.mem.splitScalar(u8, parameters, ';');
    for (0..parameters.len + 2) |_| {
        const param = std.mem.trim(u8, params.next() orelse return false, " \t");
        if (param.len < 2 or !std.ascii.eqlIgnoreCase(param[0..2], "q=")) continue;
        const value = param[2..];
        if (value.len == 0 or value[0] != '0') return false;
        for (value[1..]) |c| {
            if (c != '.' and c != '0') return false;
        }
        return true;
    } else unreachable;
}

test "static: Accept-Encoding, as RFC 9110 reads it" {
    const cases = [_]struct { value: []const u8, gzip: bool }{
        .{ .value = "gzip, deflate, br", .gzip = true },
        .{ .value = "br;q=1.0, gzip;q=0.8", .gzip = true },
        .{ .value = "*", .gzip = true },
        .{ .value = "gzip;q=0", .gzip = false },
        .{ .value = "gzip; q=0.000", .gzip = false },
        .{ .value = "br, deflate", .gzip = false },
        .{ .value = "gzipped", .gzip = false },
        .{ .value = "", .gzip = false },
    };
    for (cases) |case| {
        const headers = [_]http1_head.Header{.{ .name = "Accept-Encoding", .value = case.value }};
        try std.testing.expectEqual(case.gzip, accepts_gzip(&headers));
    }
    try std.testing.expect(!accepts_gzip(&.{}));
}

test "static: a compressible file gets a smaller gzip copy that inflates back" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var page_buffer: std.ArrayList(u8) = .empty;
    for (0..20) |_| {
        const line = "<p>a page that repeats itself, a page that repeats itself</p>\n";
        try page_buffer.appendSlice(arena, line);
    }
    const page = page_buffer.items;
    const file = try make_file(arena, "page.html", page, false);
    const compressed = file.gzip orelse return error.TestExpectedGzip;
    try std.testing.expect(compressed.body.len < page.len / 4);
    var input: std.Io.Reader = .fixed(compressed.body);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    const inflated = try decompress.reader.allocRemaining(arena, .limited(64 * 1024));
    try std.testing.expectEqualStrings(page, inflated);
    try std.testing.expect(!std.mem.eql(u8, file.identity.etag, compressed.etag));
}

/// Read every file under `root` into `site`, with its routes.
fn load(gpa: std.mem.Allocator, io: std.Io, root: []const u8, site: *Site, secure: bool) !void {
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
        const file = try make_file(gpa, entry.basename, body, secure);
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
    var site: Site = .{};
    try load(gpa, io, options.root.?, &site, options.https.enabled());
    if (site.routes.count() == 0) return error.EmptySite;
    // The certificate, loaded once and shared read-only by every shard.
    const shared: Shared = .{ .site = &site, .tls = try https.context(gpa, io, options.https) };
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

fn run_redirect(redirect_server: *Redirect.Server) void {
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
    var redirect_server: Redirect.Server = undefined;
    if (options.https.redirect_port) |port| {
        assert(shared.tls != null); // redirecting to an HTTPS site
        redirect = .{ .host = options.https.https_host.? };
        redirect_server = try redirect.listen(gpa, io, options.address, port);
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
    const page = try make_file(arena, "a.html", "page", false);
    const index = try make_file(arena, "index.html", "index", false);
    const missing = try make_file(arena, "404.html", "missing", false);
    try add_routes(arena, &site, "index.html", index);
    try add_routes(arena, &site, "about.html", page);
    try add_routes(arena, &site, "docs/index.html", index);
    try add_routes(arena, &site, "404.html", missing);
    try std.testing.expectEqualStrings("index", site.routes.get("/").?.identity.body);
    try std.testing.expectEqualStrings("page", site.routes.get("/about").?.identity.body);
    try std.testing.expectEqualStrings("page", site.routes.get("/about.html").?.identity.body);
    try std.testing.expectEqualStrings("index", site.routes.get("/docs").?.identity.body);
    try std.testing.expectEqualStrings("index", site.routes.get("/docs/").?.identity.body);
    try std.testing.expectEqual(@as(?File, null), site.routes.get("/../etc/passwd"));
    try std.testing.expectEqual(@as(?File, null), site.routes.get("/docs/../about.html"));
    try std.testing.expectEqualStrings("missing", site.not_found.?.identity.body);
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
