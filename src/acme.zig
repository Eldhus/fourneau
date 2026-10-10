//! ACME (RFC 8555): the server obtains its own certificate (M8).
//!
//! A startup step, blocking, before any shard exists: `ensure` keeps a
//! certificate in the state directory and obtains a new one when it is
//! missing or a third of its life is left. Renewal is a restart: the
//! service is restarted daily, and a restart renews only when due (a
//! short-lived IP certificate lives six days; DESIGN.md, Layers: acme).
//!
//! The challenge is http-01: while an order is validated, a small blocking
//! responder answers `/.well-known/acme-challenge/<token>` on port 80 and
//! nothing else. (DESIGN.md planned tls-alpn-01; http-01 needs no
//! certificate switch inside the TLS handshake, and port 80 is open
//! anyway, to redirect browsers.)
//!
//! State directory: `account.key` (the account's P-256 secret, 0600),
//! `cert.pem` (the chain), `key.pem` (the certificate's key, SEC1, 0600),
//! `directory` (the CA that issued it) and `identifier` (what it is for,
//! `kind:value`): a change of either orders anew.

const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("acme_crypto.zig");
const http1_head = @import("http1_head.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.acme);

pub const Identifier = crypto.Identifier;

pub const Options = struct {
    /// The CA's directory: Let's Encrypt's, its staging, or Pebble's.
    directory_url: []const u8,
    identifier: Identifier,
    /// An ACME profile (Let's Encrypt issues IP certificates only under
    /// "shortlived"); null for the CA's default.
    profile: ?[]const u8 = null,
    state_dir: []const u8,
    /// Where the CA connects for http-01: 80, or Pebble's 5002 in tests.
    http_port: u16 = 80,
    /// A socket already listening there (systemd's, held across restarts:
    /// listen.zig): the responder accepts on a copy of it, never binds,
    /// never shuts it down.
    http_listener: ?std.posix.socket_t = null,
    /// A PEM bundle to trust instead of the system's (Pebble's test root).
    ca_bundle_path: ?[]const u8 = null,
};

pub const cert_file = "cert.pem";
pub const key_file = "key.pem";
const account_file = "account.key";
/// The directory URL of the CA that issued cert.pem.
const directory_file = "directory";
/// What cert.pem is for, as `ip:203.0.113.7` or `dns:example.com`.
const identifier_file = "identifier";

/// Bounds: polls of an authorization or order, and the bytes of any one
/// response from the CA.
const polls_max = 60;
const poll_interval_ms = 1000;
const response_bytes_max = 64 * 1024;

/// A certificate in the state directory with at least a third of its life
/// left; otherwise a new one from the CA.
pub fn ensure(gpa: Allocator, io: Io, options: Options) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try Io.Dir.cwd().createDirPathOpen(io, options.state_dir, .{});
    defer dir.close(io);
    // A certificate from another CA (staging, before production), or for
    // another identifier (an address, before a name: found 2026-10-07,
    // the dragrace site kept serving its IP certificate for its new name),
    // does not count: both are kept beside it.
    var identifier_buffer: [identifier_record_bytes_max]u8 = undefined;
    const identifier = try identifier_record(options.identifier, &identifier_buffer);
    const same = try recorded(arena, io, dir, directory_file, options.directory_url) and
        try recorded(arena, io, dir, identifier_file, identifier);
    const state = if (same) try certificate_state(arena, io, dir) else .missing;
    if (state == .fresh) {
        log.info("certificate in {s} is fresh", .{options.state_dir});
        return;
    }
    log.info("obtaining a certificate for {s} from {s}", .{
        try options.identifier.format_value(try arena.alloc(u8, 256)),
        options.directory_url,
    });
    obtain(arena, io, dir, options) catch |err| switch (state) {
        // A failed renewal (the CA down, a rate limit) must not take a
        // working site down: serve the old certificate while it lasts,
        // and try again at the next restart.
        .valid => log.warn("renewal failed ({t}); serving the current certificate", .{err}),
        .missing, .expired => return err,
        .fresh => unreachable,
    };
}

const CertificateState = enum { missing, expired, valid, fresh };

/// Whether the state file `name` holds exactly `expected`; a missing file
/// (state from before the file existed) holds nothing.
fn recorded(arena: Allocator, io: Io, dir: Io.Dir, name: []const u8, expected: []const u8) !bool {
    assert(expected.len > 0);
    const limit: Io.Limit = .limited(1024);
    const text = dir.readFileAlloc(io, name, arena, limit) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return std.mem.eql(u8, text, expected);
}

const identifier_record_bytes_max = 300;

/// `kind:value`: the kind too, so a name that reads as an address cannot
/// match one.
fn identifier_record(identifier: Identifier, buffer: *[identifier_record_bytes_max]u8) ![]const u8 {
    // format_value returns a name as it is, and writes only an address.
    var value_buffer: [identifier_record_bytes_max - 8]u8 = undefined;
    const value = try identifier.format_value(&value_buffer);
    assert(value.len > 0);
    return std.fmt.bufPrint(buffer, "{s}:{s}", .{ identifier.kind(), value }) catch |err|
        switch (err) {
            error.NoSpaceLeft => error.IdentifierTooLong,
        };
}

/// Fresh: more than a third of its validity left. Valid: not expired.
fn certificate_state(arena: Allocator, io: Io, dir: Io.Dir) !CertificateState {
    const text = dir.readFileAlloc(io, cert_file, arena, .limited(response_bytes_max)) catch |err|
        switch (err) {
            error.FileNotFound => return .missing,
            else => |e| return e,
        };
    const der_bytes = (try first_pem_block(arena, text)) orelse return .missing;
    const certificate: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
    const parsed = certificate.parse() catch return .missing;
    const validity = parsed.validity;
    if (validity.not_after <= validity.not_before) return .missing;
    const now: u64 = @intCast(Io.Clock.real.now(io).toSeconds());
    if (now >= validity.not_after) return .expired;
    const life = validity.not_after - validity.not_before;
    return if (now + life / 3 < validity.not_after) .fresh else .valid;
}

fn first_pem_block(arena: Allocator, text: []const u8) !?[]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const start = (std.mem.indexOf(u8, text, begin) orelse return null) + begin.len;
    const stop = std.mem.indexOfPos(u8, text, start, end) orelse return null;
    var base64 = try arena.alloc(u8, stop - start);
    var used: usize = 0;
    for (text[start..stop]) |c| {
        if (c == '\n' or c == '\r') continue;
        base64[used] = c;
        used += 1;
    }
    const decoder = std.base64.standard.Decoder;
    const der_bytes = try arena.alloc(u8, try decoder.calcSizeForSlice(base64[0..used]));
    try decoder.decode(der_bytes, base64[0..used]);
    return der_bytes;
}

/// One conversation with the CA: its directory, the current nonce, and the
/// account once it exists.
const Client = struct {
    arena: Allocator,
    io: Io,
    http: std.http.Client,
    directory: Directory,
    nonce: []const u8 = "",
    account: crypto.KeyPair,
    kid: ?[]const u8 = null,

    const Directory = struct {
        newNonce: []const u8,
        newAccount: []const u8,
        newOrder: []const u8,
    };

    /// What came back: status, Location, and the body.
    const Reply = struct {
        status: std.http.Status,
        location: ?[]const u8,
        body: []const u8,
    };

    fn init(
        client: *Client,
        arena: Allocator,
        io: Io,
        options: Options,
        account: crypto.KeyPair,
    ) !void {
        client.* = .{
            .arena = arena,
            .io = io,
            .http = .{ .allocator = arena, .io = io },
            .directory = undefined,
            .account = account,
        };
        if (options.ca_bundle_path) |path| {
            // Trust exactly this bundle (a test CA), not the system's.
            const now = Io.Clock.real.now(io);
            try client.http.ca_bundle.addCertsFromFilePath(arena, io, now, Io.Dir.cwd(), path);
            client.http.now = now;
        }
        const reply = try client.exchange(.GET, options.directory_url, null);
        if (reply.status != .ok) return error.AcmeDirectoryUnavailable;
        client.directory = try parse(Directory, arena, reply.body);
    }

    /// A signed POST (or POST-as-GET, with an empty payload). A badNonce
    /// refusal is retried once with the fresh nonce it carries.
    fn post(client: *Client, url: []const u8, payload: []const u8) !Reply {
        for (0..2) |_| {
            if (client.nonce.len == 0) try client.fresh_nonce();
            const signer: crypto.Signer = if (client.kid) |kid| .{ .kid = kid } else .jwk;
            const body = try client.arena.alloc(u8, 4096 + payload.len * 2);
            const nonce = client.nonce;
            const jws = try crypto.sign_request(client.account, signer, nonce, url, payload, body);
            client.nonce = "";
            const reply = try client.exchange(.POST, url, jws);
            const bad_nonce = std.mem.indexOf(u8, reply.body, "badNonce") != null;
            if (reply.status == .bad_request and bad_nonce) continue;
            return reply;
        } else return error.AcmeBadNonce;
    }

    fn fresh_nonce(client: *Client) !void {
        const reply = try client.exchange(.HEAD, client.directory.newNonce, null);
        if (client.nonce.len == 0) {
            log.err("newNonce: {d}", .{@backingInt(reply.status)});
            return error.AcmeNoNonce;
        }
    }

    /// One HTTP request; keeps the Replay-Nonce the reply carries.
    fn exchange(
        client: *Client,
        method: std.http.Method,
        url: []const u8,
        jws: ?[]const u8,
    ) !Reply {
        const uri = try std.Uri.parse(url);
        var request = try client.http.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{ .content_type = .{ .override = "application/jose+json" } },
        });
        defer request.deinit();
        if (jws) |bytes| {
            request.transfer_encoding = .{ .content_length = bytes.len };
            var body = try request.sendBodyUnflushed(&.{});
            try body.writer.writeAll(bytes);
            try body.end();
            try request.connection.?.flush();
        } else try request.sendBodiless();
        var response = try request.receiveHead(&.{});
        var location: ?[]const u8 = null;
        if (response.head.location) |value| location = try client.arena.dupe(u8, value);
        var headers = response.head.iterateHeaders();
        for (0..256) |_| {
            const header = headers.next() orelse break;
            if (std.ascii.eqlIgnoreCase(header.name, "replay-nonce")) {
                client.nonce = try client.arena.dupe(u8, header.value);
            }
        } else return error.AcmeTooManyHeaders;
        const status = response.head.status;
        if (method == .HEAD) return .{ .status = status, .location = location, .body = "" };
        const reader = response.reader(&.{});
        const body = reader.allocRemaining(client.arena, .limited(response_bytes_max)) catch |err|
            switch (err) {
                error.ReadFailed => return response.bodyErr().?,
                else => |e| return e,
            };
        return .{ .status = status, .location = location, .body = body };
    }
};

fn parse(comptime T: type, arena: Allocator, body: []const u8) !T {
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    return std.json.parseFromSliceLeaky(T, arena, body, options) catch |err| {
        log.err("unexpected reply: {s}", .{body[0..@min(body.len, 512)]});
        return err;
    };
}

const Order = struct {
    status: []const u8,
    authorizations: []const []const u8 = &.{},
    finalize: []const u8 = "",
    certificate: ?[]const u8 = null,
};

const Authorization = struct {
    status: []const u8,
    challenges: []const Challenge = &.{},

    const Challenge = struct {
        type: []const u8,
        url: []const u8,
        token: []const u8 = "",
        status: []const u8 = "",
    };
};

fn obtain(arena: Allocator, io: Io, dir: Io.Dir, options: Options) !void {
    const account = try load_or_create_account(arena, io, dir);
    var client: Client = undefined;
    try client.init(arena, io, options, account);
    try register(&client);
    const order_url, var order = try new_order(&client, options);
    // The certificate's own key, new for every certificate.
    const certificate_key = crypto.KeyPair.generate(io);
    var responder: Responder = undefined;
    try responder.start(io, options.http_port, options.http_listener);
    defer responder.stop();
    // One identifier per certificate: one authorization, one answer.
    if (order.authorizations.len != 1) return error.AcmeUnexpectedAuthorizations;
    try authorize(&client, &responder, order.authorizations[0]);
    order = try finalize(&client, order_url, order, certificate_key, options.identifier);
    const chain = try client.post(order.certificate orelse return error.AcmeNoCertificate, "");
    if (chain.status != .ok) return error.AcmeCertificateDownloadFailed;
    var key_buffer: [512]u8 = undefined;
    try write_private(io, dir, key_file, try crypto.private_key_pem(certificate_key, &key_buffer));
    try write_private(io, dir, cert_file, chain.body);
    try write_private(io, dir, directory_file, options.directory_url);
    var identifier_buffer: [identifier_record_bytes_max]u8 = undefined;
    const identifier = try identifier_record(options.identifier, &identifier_buffer);
    try write_private(io, dir, identifier_file, identifier);
    log.info("certificate obtained: {s}/{s}", .{ options.state_dir, cert_file });
}

fn load_or_create_account(arena: Allocator, io: Io, dir: Io.Dir) !crypto.KeyPair {
    const limit: Io.Limit = .limited(64);
    const secret = dir.readFileAlloc(io, account_file, arena, limit) catch |err| switch (err) {
        error.FileNotFound => {
            const key_pair = crypto.KeyPair.generate(io);
            try write_private(io, dir, account_file, &key_pair.secret_key.toBytes());
            return key_pair;
        },
        else => |e| return e,
    };
    if (secret.len != crypto.secret_key_bytes) return error.AcmeAccountKeyCorrupt;
    const secret_key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(
        secret[0..crypto.secret_key_bytes].*,
    );
    return crypto.KeyPair.fromSecretKey(secret_key);
}

/// newAccount: creates the account, or finds it (200) for a known key.
fn register(client: *Client) !void {
    const reply = try client.post(client.directory.newAccount, "{\"termsOfServiceAgreed\":true}");
    switch (reply.status) {
        .ok, .created => {},
        else => {
            log.err("newAccount: {d} {s}", .{ @backingInt(reply.status), reply.body });
            return error.AcmeAccountRefused;
        },
    }
    client.kid = reply.location orelse return error.AcmeNoAccountUrl;
}

fn new_order(client: *Client, options: Options) !struct { []const u8, Order } {
    var value_buffer: [256]u8 = undefined;
    const value = try options.identifier.format_value(&value_buffer);
    const kind = options.identifier.kind();
    const payload = if (options.profile) |profile|
        try std.fmt.allocPrint(client.arena,
            \\{{"identifiers":[{{"type":"{s}","value":"{s}"}}],"profile":"{s}"}}
        , .{ kind, value, profile })
    else
        try std.fmt.allocPrint(client.arena,
            \\{{"identifiers":[{{"type":"{s}","value":"{s}"}}]}}
        , .{ kind, value });
    const reply = try client.post(client.directory.newOrder, payload);
    if (reply.status != .created) {
        log.err("newOrder: {d} {s}", .{ @backingInt(reply.status), reply.body });
        return error.AcmeOrderRefused;
    }
    const url = reply.location orelse return error.AcmeNoOrderUrl;
    return .{ url, try parse(Order, client.arena, reply.body) };
}

/// One authorization: serve its http-01 key authorization, tell the CA to
/// look, and wait until it is valid.
fn authorize(client: *Client, responder: *Responder, url: []const u8) !void {
    var authorization = try parse(Authorization, client.arena, (try client.post(url, "")).body);
    if (std.mem.eql(u8, authorization.status, "valid")) return;
    const challenge = for (authorization.challenges) |challenge| {
        if (std.mem.eql(u8, challenge.type, "http-01")) break challenge;
    } else return error.AcmeNoHttpChallenge;
    var answer_buffer: [256]u8 = undefined;
    const answer = try crypto.key_authorization(challenge.token, client.account, &answer_buffer);
    responder.set(challenge.token, answer);
    _ = try client.post(challenge.url, "{}");
    for (0..polls_max) |_| {
        try client.io.sleep(.fromMilliseconds(poll_interval_ms), .awake);
        authorization = try parse(Authorization, client.arena, (try client.post(url, "")).body);
        if (std.mem.eql(u8, authorization.status, "valid")) return;
        if (std.mem.eql(u8, authorization.status, "invalid")) {
            log.err("authorization invalid: {s}", .{url});
            return error.AcmeAuthorizationInvalid;
        }
    }
    return error.AcmeAuthorizationTimeout;
}

/// Sends the CSR, then waits for the order to hold its certificate.
fn finalize(
    client: *Client,
    order_url: []const u8,
    order_before: Order,
    certificate_key: crypto.KeyPair,
    identifier: Identifier,
) !Order {
    var csr_buffer: [1024]u8 = undefined;
    const request = try crypto.csr(certificate_key, identifier, &csr_buffer);
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const csr_text = try client.arena.alloc(u8, encoder.calcSize(request.len));
    _ = encoder.encode(csr_text, request);
    const payload = try std.fmt.allocPrint(client.arena, "{{\"csr\":\"{s}\"}}", .{csr_text});
    _ = try client.post(order_before.finalize, payload);
    for (0..polls_max) |_| {
        const order = try parse(Order, client.arena, (try client.post(order_url, "")).body);
        if (std.mem.eql(u8, order.status, "valid")) return order;
        if (std.mem.eql(u8, order.status, "invalid")) return error.AcmeOrderInvalid;
        try client.io.sleep(.fromMilliseconds(poll_interval_ms), .awake);
    }
    return error.AcmeOrderTimeout;
}

/// Written whole and then renamed into place, readable by the owner only.
fn write_private(io: Io, dir: Io.Dir, name: []const u8, bytes: []const u8) !void {
    var temporary_name: [64]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&temporary_name, "{s}.new", .{name});
    try dir.writeFile(io, .{
        .sub_path = temporary,
        .data = bytes,
        .flags = .{ .permissions = @fromBackingInt(0o600) },
    });
    try dir.rename(temporary, dir, name, io);
}

/// Answers http-01 while an order is validated: `GET
/// /.well-known/acme-challenge/<token>` gets the key authorization, all
/// else 404. Blocking, on its own thread, for the minute ACME takes; the
/// answer is written once, then published (release) before the CA is told
/// to look, so the thread never reads it half-written.
const Responder = struct {
    thread: std.Thread,
    listener: std.posix.socket_t,
    /// Bound here, so shut down to stop. A copy of systemd's socket is
    /// never shut down (that would shut it for whoever accepts on it next):
    /// the responder polls, and sees `stopping` within a poll's wait.
    owned: bool,
    token: [128]u8 = undefined,
    token_len: u32 = 0,
    answer: [256]u8 = undefined,
    answer_len: u32 = 0,
    published: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),

    const linux = std.os.linux;
    const prefix = "/.well-known/acme-challenge/";
    const connections_max = 1024;
    const poll_wait_ms = 100;
    /// Waits with no connection: two minutes, past ACME's own polling.
    const waits_max = 2 * 60 * 1000 / poll_wait_ms;

    fn start(responder: *Responder, io: Io, port: u16, inherited: ?std.posix.socket_t) !void {
        _ = io;
        responder.* = .{ .thread = undefined, .listener = undefined, .owned = inherited == null };
        if (inherited) |socket| {
            const copied = linux.fcntl(socket, linux.F.DUPFD_CLOEXEC, 3);
            if (linux.errno(copied) != .SUCCESS) return error.AcmeResponderSocket;
            responder.listener = @intCast(copied);
            responder.thread = try std.Thread.spawn(.{}, serve, .{responder});
            return;
        }
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(fd) != .SUCCESS) return error.AcmeResponderSocket;
        responder.listener = @intCast(fd);
        const on: u32 = 1;
        const listener = responder.listener;
        const reuse = linux.SO.REUSEADDR;
        _ = linux.setsockopt(listener, linux.SOL.SOCKET, reuse, std.mem.asBytes(&on), 4);
        var address: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
        const bound = linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
        if (linux.errno(bound) != .SUCCESS) {
            log.err("http-01 responder: cannot bind port {d}", .{port});
            return error.AcmeResponderBind;
        }
        const listening = linux.listen(listener, 64);
        if (linux.errno(listening) != .SUCCESS) return error.AcmeResponderListen;
        responder.thread = try std.Thread.spawn(.{}, serve, .{responder});
    }

    fn set(responder: *Responder, token: []const u8, answer: []const u8) void {
        assert(!responder.published.load(.acquire)); // one answer, once
        assert(token.len <= responder.token.len and answer.len <= responder.answer.len);
        @memcpy(responder.token[0..token.len], token);
        @memcpy(responder.answer[0..answer.len], answer);
        responder.token_len = @intCast(token.len);
        responder.answer_len = @intCast(answer.len);
        responder.published.store(true, .release);
    }

    fn stop(responder: *Responder) void {
        responder.stopping.store(true, .release);
        // Its own socket: shut, which wakes a poll at once. A copy of
        // systemd's: the poll's wait ends it.
        if (responder.owned) _ = linux.shutdown(responder.listener, linux.SHUT.RDWR);
        responder.thread.join();
        _ = linux.close(responder.listener);
    }

    fn serve(responder: *Responder) void {
        var accepted: u32 = 0;
        for (0..connections_max + waits_max) |_| {
            if (responder.stopping.load(.acquire)) return;
            if (accepted == connections_max) return;
            const waiting: linux.pollfd = .{
                .fd = responder.listener,
                .events = linux.POLL.IN,
                .revents = 0,
            };
            var ready = [_]linux.pollfd{waiting};
            const polled = linux.poll(&ready, 1, poll_wait_ms);
            if (linux.errno(polled) != .SUCCESS or polled == 0) continue;
            accepted += 1;
            const fd = linux.accept4(responder.listener, null, null, linux.SOCK.CLOEXEC);
            if (responder.stopping.load(.acquire)) {
                if (linux.errno(fd) == .SUCCESS) _ = linux.close(@intCast(fd));
                return;
            }
            if (linux.errno(fd) != .SUCCESS) continue;
            responder.answer_one(@intCast(fd));
            _ = linux.close(@intCast(fd));
        }
    }

    fn answer_one(responder: *Responder, fd: std.posix.socket_t) void {
        const timeout: linux.timeval = .{ .sec = 5, .usec = 0 };
        const timeout_bytes = std.mem.asBytes(&timeout);
        const option = linux.SO.RCVTIMEO;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, option, timeout_bytes, timeout_bytes.len);
        var buffer: [4096]u8 = undefined;
        var headers: [32]http1_head.Header = undefined;
        var parser = http1_head.Parser.init(.{
            .head_bytes_max = buffer.len,
            .target_bytes_max = 512,
            .headers_max = headers.len,
            .body_bytes_max = 0,
        }, &headers);
        var used: usize = 0;
        const head = for (0..buffer.len) |_| {
            switch (parser.parse(buffer[0..used])) {
                .complete => |parsed| break parsed.head,
                .refusal => return,
                .incomplete => {},
            }
            if (used == buffer.len) return;
            const got = linux.read(fd, buffer[used..].ptr, buffer.len - used);
            if (linux.errno(got) != .SUCCESS or got == 0) return;
            used += got;
        } else return;
        const body = responder.lookup(head.target);
        var response: [512]u8 = undefined;
        const text = std.fmt.bufPrint(&response, "HTTP/1.1 {s}\r\nContent-Type: text/plain\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
            if (body != null) "200 OK" else "404 Not Found",
            if (body) |b| b.len else 0,
            body orelse "",
        }) catch return;
        _ = linux.write(fd, text.ptr, text.len);
    }

    fn lookup(responder: *Responder, target: []const u8) ?[]const u8 {
        if (!responder.published.load(.acquire)) return null;
        if (!std.mem.startsWith(u8, target, prefix)) return null;
        const token = responder.token[0..responder.token_len];
        if (!std.mem.eql(u8, target[prefix.len..], token)) return null;
        return responder.answer[0..responder.answer_len];
    }
};

test "acme: a stored certificate counts only for its CA and its identifier" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [identifier_record_bytes_max]u8 = undefined;
    const ip = try Io.net.IpAddress.parse("203.0.113.7", 0);
    const address = try identifier_record(.{ .ip = ip }, &buffer);
    try std.testing.expectEqualStrings("ip:203.0.113.7", address);
    // State from before the identifier was kept: no file, a new order.
    try std.testing.expect(!try recorded(arena, io, tmp.dir, identifier_file, address));
    try write_private(io, tmp.dir, identifier_file, address);
    try std.testing.expect(try recorded(arena, io, tmp.dir, identifier_file, address));
    var name_buffer: [identifier_record_bytes_max]u8 = undefined;
    const name = try identifier_record(.{ .dns = "site.example.com" }, &name_buffer);
    try std.testing.expectEqualStrings("dns:site.example.com", name);
    try std.testing.expect(!try recorded(arena, io, tmp.dir, identifier_file, name));
    const staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
    try write_private(io, tmp.dir, directory_file, staging);
    const production = "https://acme-v02.api.letsencrypt.org/directory";
    try std.testing.expect(!try recorded(arena, io, tmp.dir, directory_file, production));
}

test "acme: the responder on systemd's socket answers, then leaves it listening" {
    const io = std.testing.io;
    const linux = std.os.linux;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var held = try address.listen(io, .{ .reuse_address = false });
    defer held.deinit(io);
    const port = held.socket.address.getPort();
    var responder: Responder = undefined;
    try responder.start(io, port, held.socket.handle);
    responder.set("token-1", "token-1.thumbprint");
    var answer: [512]u8 = undefined;
    const got = try challenge_get(port, "/.well-known/acme-challenge/token-1", &answer);
    try std.testing.expect(std.mem.endsWith(u8, answer[0..got], "\r\n\r\ntoken-1.thumbprint"));
    responder.stop();
    // Still listening, for the server that comes after: never shut down.
    var accepting: u32 = 0;
    var length: linux.socklen_t = @sizeOf(u32);
    const level = linux.SOL.SOCKET;
    const handle = held.socket.handle;
    _ = linux.getsockopt(handle, level, linux.SO.ACCEPTCONN, @ptrCast(&accepting), &length);
    try std.testing.expectEqual(1, accepting);
}

/// A plain GET on loopback, its response read to the peer's close.
fn challenge_get(port: u16, target: []const u8, buffer: []u8) !usize {
    const linux = std.os.linux;
    const fd: linux.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer _ = linux.close(fd);
    const peer: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const connected = linux.connect(fd, @ptrCast(&peer), @sizeOf(linux.sockaddr.in));
    if (linux.errno(connected) != .SUCCESS) return error.Connect;
    var request: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&request, "GET {s} HTTP/1.1\r\nHost: x\r\n\r\n", .{target});
    if (linux.write(fd, text.ptr, text.len) != text.len) return error.Send;
    var used: usize = 0;
    for (0..buffer.len + 1) |_| {
        const read = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(read) != .SUCCESS) return error.Receive;
        if (read == 0) return used;
        used += read;
    } else return error.TooLong;
}
