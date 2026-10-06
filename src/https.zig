//! HTTPS for a program built on fourneau: where its certificate comes from
//! (files, or ACME at startup, acme.zig) and the plain-HTTP server beside
//! it that sends browsers to HTTPS. fourneau-static and roux's host share
//! it, so the two cannot drift.

const std = @import("std");
const assert = std.debug.assert;
const server_module = @import("server.zig");
const http1_response = @import("http1_response.zig");
const tls = @import("tls.zig");
const acme = @import("acme.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Options = struct {
    /// A certificate chain and its key, as PEM files.
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    /// Or a CA to obtain one from at startup (acme.zig).
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

    pub fn enabled(options: Options) bool {
        return options.cert != null or options.acme_directory != null;
    }

    /// Whole or absent: half a certificate, or ACME without its state,
    /// is a mistake, not plain HTTP.
    pub fn check(options: *Options) error{Usage}!void {
        if ((options.cert == null) != (options.key == null)) return error.Usage;
        const acme_given = options.acme_directory != null;
        if (acme_given != (options.acme_identifier != null)) return error.Usage;
        if (acme_given != (options.acme_state != null)) return error.Usage;
        if (acme_given and options.cert != null) return error.Usage; // one source
        if (options.https_host == null) options.https_host = options.acme_identifier;
        // A redirect needs an HTTPS site and a host to name.
        if (options.redirect_port != null and options.https_host == null) return error.Usage;
        if (options.redirect_port != null and !options.enabled()) return error.Usage;
    }
};

/// The TLS context every shard shares read-only, or null for plain HTTP.
/// With ACME, the certificate is obtained first when none is fresh.
/// Allocated once, for the life of the process.
pub fn context(gpa: Allocator, io: Io, options: Options) !?*const tls.Context {
    if (!options.enabled()) return null;
    var cert = options.cert;
    var key = options.key;
    if (options.acme_directory) |directory| {
        const state = options.acme_state.?;
        try acme.ensure(gpa, io, .{
            .directory_url = directory,
            .identifier = identifier_of(options.acme_identifier.?),
            .profile = options.acme_profile,
            .state_dir = state,
            .http_port = options.acme_http_port,
            .ca_bundle_path = options.acme_ca,
        });
        cert = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ state, acme.cert_file });
        key = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ state, acme.key_file });
    }
    const auth = try gpa.create(tls.CertKeyPair);
    auth.* = try tls.CertKeyPair.fromFilePath(gpa, io, Io.Dir.cwd(), cert.?, key.?);
    const shared = try gpa.create(tls.Context);
    shared.* = .{ .auth = auth };
    return shared;
}

/// An IP address when it parses as one, else a DNS name.
fn identifier_of(value: []const u8) acme.Identifier {
    assert(value.len > 0);
    if (std.Io.net.IpAddress.parse(value, 0)) |address| {
        return .{ .ip = address };
    } else |_| return .{ .dns = value };
}

/// Plain HTTP beside HTTPS: every request goes to the same path on
/// `https://host` (301; 308 for methods other than GET and HEAD, which
/// keeps the method and body). The host is the configured one, never the
/// request's Host header.
pub fn RedirectType(comptime server_options: server_module.Options) type {
    return struct {
        const Redirect = @This();
        pub const Server = server_module.ServerType(Redirect, server_options);

        host: []const u8,

        pub const Response = struct {
            status: u16,
            headers: []const http1_response.Header,
            body: []const u8,
        };

        pub fn handle(redirect: *Redirect, request: *Server.Request) Response {
            const head = request.head;
            var memory = std.heap.FixedBufferAllocator.init(request.scratch);
            const allocator = memory.allocator();
            const too_long: Response = .{ .status = 414, .headers = &.{}, .body = "" };
            const location = std.fmt.allocPrint(allocator, "https://{s}{s}", .{
                redirect.host,
                head.path_and_query,
            }) catch return too_long;
            const headers = allocator.alloc(http1_response.Header, 1) catch return too_long;
            headers[0] = .{ .name = "Location", .value = location };
            const keeps_method = head.method == .get or head.method == .head;
            return .{ .status = if (keeps_method) 301 else 308, .headers = headers, .body = "" };
        }

        pub fn release(redirect: *Redirect, response: *Response) void {
            _ = redirect;
            response.* = undefined;
        }

        /// The redirect's server on `port`, beside a shard's HTTPS one:
        /// small (64 connections, 16 KiB of scratch each).
        pub fn listen(
            redirect: *Redirect,
            gpa: Allocator,
            io: Io,
            address: []const u8,
            port: u16,
        ) !Server {
            const plain = try std.Io.net.IpAddress.parse(address, port);
            const listen_options: Io.net.IpAddress.ListenOptions = .{
                .reuse_address = true,
                .kernel_backlog = 1024,
            };
            const listener = try plain.listen(io, listen_options);
            return Server.init(gpa, io, redirect, listener, .{
                .connections_max = 64,
                .scratch_bytes_max = 16 * 1024,
            });
        }
    };
}
