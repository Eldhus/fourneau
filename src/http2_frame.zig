//! HTTP/2 frames (RFC 9113 sections 4 and 6), sans-IO: the nine-byte
//! header, each type's payload checked as section 6 says, and the frames
//! a server writes. Every malformed frame is a refusal naming the error
//! the RFC prescribes and whether it ends the stream or the connection;
//! the connection's state machine (http2.zig) decides the rest.

const std = @import("std");
const assert = std.debug.assert;

pub const header_bytes = 9;
/// SETTINGS_MAX_FRAME_SIZE's initial value, the least any peer accepts.
pub const frame_size_default = 1 << 14;
pub const frame_size_max = (1 << 24) - 1;
pub const window_max: u32 = (1 << 31) - 1;

pub const Type = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const flag_end_stream = 0x01;
pub const flag_ack = 0x01;
pub const flag_end_headers = 0x04;
pub const flag_padded = 0x08;
pub const flag_priority = 0x20;

/// Section 7.
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

/// Section 6.5.2.
pub const Setting = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const Header = struct {
    length: u24,
    type: Type,
    flags: u8,
    /// The reserved bit is ignored on receipt (section 4.1).
    stream: u31,
};

pub fn parse_header(bytes: *const [header_bytes]u8) Header {
    return .{
        .length = std.mem.readInt(u24, bytes[0..3], .big),
        .type = @fromBackingInt(bytes[3]),
        .flags = bytes[4],
        .stream = @truncate(std.mem.readInt(u32, bytes[5..9], .big)),
    };
}

pub fn write_header(out: *[header_bytes]u8, header: Header) void {
    std.mem.writeInt(u24, out[0..3], header.length, .big);
    out[3] = @backingInt(header.type);
    out[4] = header.flags;
    std.mem.writeInt(u32, out[5..9], header.stream, .big);
}

/// A frame as received and checked: what it carries.
pub const Frame = union(enum) {
    data: Data,
    headers: Headers,
    /// Deprecated (section 5.3.2): checked, then ignored.
    priority,
    rst_stream: struct { stream: u31, code: ErrorCode },
    settings: struct { ack: bool, entries: []const u8 },
    ping: struct { ack: bool, opaque_data: [8]u8 },
    goaway: struct { last_stream: u31, code: ErrorCode },
    window_update: WindowUpdate,
    continuation: Continuation,
    /// An unknown type: discarded (section 5.5).
    unknown,

    pub const Data = struct {
        stream: u31,
        data: []const u8,
        end_stream: bool,
        /// The whole payload, padding included: what flow control counts.
        flow_length: u32,
    };

    pub const Headers = struct {
        stream: u31,
        fragment: []const u8,
        end_stream: bool,
        end_headers: bool,
    };

    pub const WindowUpdate = struct { stream: u31, increment: u31 };

    pub const Continuation = struct { stream: u31, fragment: []const u8, end_headers: bool };
};

/// What a malformed frame ends, and why.
pub const Refusal = struct {
    code: ErrorCode,
    /// A stream error ends only `stream`; a connection error, everything.
    connection: bool,
    stream: u31,
};

pub const Parsed = union(enum) { frame: Frame, refusal: Refusal };

fn connection_error(code: ErrorCode) Parsed {
    return .{ .refusal = .{ .code = code, .connection = true, .stream = 0 } };
}

fn stream_error(code: ErrorCode, stream: u31) Parsed {
    return .{ .refusal = .{ .code = code, .connection = false, .stream = stream } };
}

/// A frame's payload, checked against section 6, for a server: a
/// PUSH_PROMISE is a client's to receive, never a server's.
pub fn parse(header: Header, payload: []const u8) Parsed {
    assert(payload.len == header.length);
    const stream = header.stream;
    return switch (header.type) {
        .data => parse_data(header, payload),
        .headers => parse_headers(header, payload),
        .priority => {
            if (stream == 0) return connection_error(.protocol_error);
            if (payload.len != 5) return stream_error(.frame_size_error, stream);
            if (dependency(payload) == stream) return stream_error(.protocol_error, stream);
            return .{ .frame = .priority };
        },
        .rst_stream => {
            if (stream == 0) return connection_error(.protocol_error);
            if (payload.len != 4) return connection_error(.frame_size_error);
            const code: ErrorCode = @fromBackingInt(std.mem.readInt(u32, payload[0..4], .big));
            return .{ .frame = .{ .rst_stream = .{ .stream = stream, .code = code } } };
        },
        .settings => parse_settings(header, payload),
        .push_promise => connection_error(.protocol_error),
        .ping => {
            if (stream != 0) return connection_error(.protocol_error);
            if (payload.len != 8) return connection_error(.frame_size_error);
            const ack = header.flags & flag_ack != 0;
            return .{ .frame = .{ .ping = .{ .ack = ack, .opaque_data = payload[0..8].* } } };
        },
        .goaway => {
            if (stream != 0) return connection_error(.protocol_error);
            if (payload.len < 8) return connection_error(.frame_size_error);
            const last: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big));
            const code: ErrorCode = @fromBackingInt(std.mem.readInt(u32, payload[4..8], .big));
            return .{ .frame = .{ .goaway = .{ .last_stream = last, .code = code } } };
        },
        .window_update => parse_window_update(header, payload),
        .continuation => {
            if (stream == 0) return connection_error(.protocol_error);
            const end = header.flags & flag_end_headers != 0;
            const frame: Frame.Continuation = .{
                .stream = stream,
                .fragment = payload,
                .end_headers = end,
            };
            return .{ .frame = .{ .continuation = frame } };
        },
        _ => .{ .frame = .unknown },
    };
}

fn dependency(priority: []const u8) u31 {
    return @truncate(std.mem.readInt(u32, priority[0..4], .big));
}

/// The payload without its padding (sections 6.1, 6.2): null when the
/// padding is as long as the payload or longer.
fn unpad(flags: u8, payload: []const u8) ?[]const u8 {
    if (flags & flag_padded == 0) return payload;
    if (payload.len == 0) return null;
    const pad = payload[0];
    if (pad >= payload.len) return null;
    return payload[1 .. payload.len - pad];
}

fn parse_data(header: Header, payload: []const u8) Parsed {
    if (header.stream == 0) return connection_error(.protocol_error);
    const data = unpad(header.flags, payload) orelse return connection_error(.protocol_error);
    return .{ .frame = .{ .data = .{
        .stream = header.stream,
        .data = data,
        .end_stream = header.flags & flag_end_stream != 0,
        .flow_length = @intCast(payload.len),
    } } };
}

fn parse_headers(header: Header, payload: []const u8) Parsed {
    if (header.stream == 0) return connection_error(.protocol_error);
    var fragment = unpad(header.flags, payload) orelse return connection_error(.protocol_error);
    if (header.flags & flag_priority != 0) {
        if (fragment.len < 5) return connection_error(.frame_size_error);
        if (dependency(fragment) == header.stream) {
            return stream_error(.protocol_error, header.stream);
        }
        fragment = fragment[5..];
    }
    return .{ .frame = .{ .headers = .{
        .stream = header.stream,
        .fragment = fragment,
        .end_stream = header.flags & flag_end_stream != 0,
        .end_headers = header.flags & flag_end_headers != 0,
    } } };
}

fn parse_settings(header: Header, payload: []const u8) Parsed {
    if (header.stream != 0) return connection_error(.protocol_error);
    const ack = header.flags & flag_ack != 0;
    if (ack and payload.len != 0) return connection_error(.frame_size_error);
    if (payload.len % 6 != 0) return connection_error(.frame_size_error);
    // Values a peer may not send at all (section 6.5.2).
    var index: usize = 0;
    while (index < payload.len) : (index += 6) {
        const entry = setting_at(payload, index);
        switch (entry.id) {
            .enable_push => if (entry.value > 1) return connection_error(.protocol_error),
            .initial_window_size => if (entry.value > window_max) {
                return connection_error(.flow_control_error);
            },
            .max_frame_size => {
                if (entry.value < frame_size_default or entry.value > frame_size_max) {
                    return connection_error(.protocol_error);
                }
            },
            else => {},
        }
    }
    return .{ .frame = .{ .settings = .{ .ack = ack, .entries = payload } } };
}

pub const SettingEntry = struct { id: Setting, value: u32 };

pub fn setting_at(entries: []const u8, index: usize) SettingEntry {
    assert(index % 6 == 0 and index + 6 <= entries.len);
    return .{
        .id = @fromBackingInt(std.mem.readInt(u16, entries[index..][0..2], .big)),
        .value = std.mem.readInt(u32, entries[index + 2 ..][0..4], .big),
    };
}

fn parse_window_update(header: Header, payload: []const u8) Parsed {
    if (payload.len != 4) return connection_error(.frame_size_error);
    const increment: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big));
    if (increment == 0) {
        if (header.stream == 0) return connection_error(.protocol_error);
        return stream_error(.protocol_error, header.stream);
    }
    const update: Frame.WindowUpdate = .{ .stream = header.stream, .increment = increment };
    return .{ .frame = .{ .window_update = update } };
}

// --- writing ----------------------------------------------------------------

pub fn write_settings(out: []u8, entries: []const SettingEntry) usize {
    const length = entries.len * 6;
    assert(out.len >= header_bytes + length);
    write_header(out[0..header_bytes], frame_header(.settings, 0, 0, length));
    for (entries, 0..) |entry, index| {
        const at = out[header_bytes + index * 6 ..];
        std.mem.writeInt(u16, at[0..2], @backingInt(entry.id), .big);
        std.mem.writeInt(u32, at[2..6], entry.value, .big);
    }
    return header_bytes + length;
}

pub fn write_settings_ack(out: *[header_bytes]u8) void {
    write_header(out, frame_header(.settings, flag_ack, 0, 0));
}

pub fn write_ping_ack(out: *[header_bytes + 8]u8, opaque_data: [8]u8) void {
    write_header(out[0..header_bytes], frame_header(.ping, flag_ack, 0, 8));
    out[header_bytes..][0..8].* = opaque_data;
}

pub fn write_rst_stream(out: *[header_bytes + 4]u8, stream: u31, code: ErrorCode) void {
    assert(stream != 0);
    write_header(out[0..header_bytes], frame_header(.rst_stream, 0, stream, 4));
    std.mem.writeInt(u32, out[header_bytes..][0..4], @backingInt(code), .big);
}

pub fn write_goaway(out: *[header_bytes + 8]u8, last_stream: u31, code: ErrorCode) void {
    write_header(out[0..header_bytes], frame_header(.goaway, 0, 0, 8));
    std.mem.writeInt(u32, out[header_bytes..][0..4], last_stream, .big);
    std.mem.writeInt(u32, out[header_bytes + 4 ..][0..4], @backingInt(code), .big);
}

pub fn write_window_update(out: *[header_bytes + 4]u8, stream: u31, increment: u31) void {
    assert(increment > 0);
    write_header(out[0..header_bytes], frame_header(.window_update, 0, stream, 4));
    std.mem.writeInt(u32, out[header_bytes..][0..4], increment, .big);
}

pub fn frame_header(kind: Type, flags: u8, stream: u31, length: usize) Header {
    assert(length <= frame_size_max);
    return .{ .length = @intCast(length), .type = kind, .flags = flags, .stream = stream };
}

/// A frame written by one of the writers above, read back as a peer would.
fn reparse(bytes: []const u8) Frame {
    const header = parse_header(bytes[0..header_bytes]);
    assert(bytes.len == header_bytes + header.length);
    return parse(header, bytes[header_bytes..]).frame;
}

test "http2_frame: what the server writes, it would accept" {
    var buffer: [header_bytes + 12]u8 = undefined;
    const entries: []const SettingEntry = &.{
        .{ .id = .max_concurrent_streams, .value = 100 },
        .{ .id = .initial_window_size, .value = window_max },
    };
    const written = write_settings(&buffer, entries);
    const settings = reparse(buffer[0..written]).settings;
    try std.testing.expect(!settings.ack);
    try std.testing.expectEqual(entries[1], setting_at(settings.entries, 6));
    write_settings_ack(buffer[0..header_bytes]);
    try std.testing.expect(reparse(buffer[0..header_bytes]).settings.ack);
    write_ping_ack(buffer[0 .. header_bytes + 8], "fourneau".*);
    const ping = reparse(buffer[0 .. header_bytes + 8]).ping;
    try std.testing.expect(ping.ack);
    try std.testing.expectEqualStrings("fourneau", &ping.opaque_data);
    write_rst_stream(buffer[0 .. header_bytes + 4], 9, .refused_stream);
    const reset = reparse(buffer[0 .. header_bytes + 4]).rst_stream;
    try std.testing.expectEqual(ErrorCode.refused_stream, reset.code);
    write_goaway(buffer[0 .. header_bytes + 8], 7, .enhance_your_calm);
    const goaway = reparse(buffer[0 .. header_bytes + 8]).goaway;
    try std.testing.expectEqual(7, goaway.last_stream);
    write_window_update(buffer[0 .. header_bytes + 4], 0, window_max);
    const update = reparse(buffer[0 .. header_bytes + 4]).window_update;
    try std.testing.expectEqual(window_max, update.increment);
}

test "http2_frame: headers round trip, the reserved bit ignored" {
    var bytes: [header_bytes]u8 = undefined;
    const header: Header = .{ .length = 16_384, .type = .headers, .flags = 0x25, .stream = 7 };
    write_header(&bytes, header);
    try std.testing.expectEqual(header, parse_header(&bytes));
    bytes[5] |= 0x80; // the reserved bit
    try std.testing.expectEqual(header, parse_header(&bytes));
}

fn expect_refusal(header: Header, payload: []const u8, code: ErrorCode, connection: bool) !void {
    switch (parse(header, payload)) {
        .frame => return error.TestExpectedRefusal,
        .refusal => |refusal| {
            try std.testing.expectEqual(code, refusal.code);
            try std.testing.expectEqual(connection, refusal.connection);
        },
    }
}

test "http2_frame: each type's refusals, as section 6 names them" {
    const p = ErrorCode.protocol_error;
    const size = ErrorCode.frame_size_error;
    try expect_refusal(frame_header(.data, 0, 0, 1), "x", p, true);
    try expect_refusal(frame_header(.data, flag_padded, 1, 2), &.{ 2, 0 }, p, true);
    try expect_refusal(frame_header(.data, flag_padded, 1, 0), "", p, true);
    try expect_refusal(frame_header(.headers, 0, 0, 1), "x", p, true);
    try expect_refusal(frame_header(.headers, flag_priority, 3, 5), &.{ 0, 0, 0, 3, 16 }, p, false);
    try expect_refusal(frame_header(.headers, flag_priority, 3, 4), &.{ 0, 0, 0, 1 }, size, true);
    try expect_refusal(frame_header(.priority, 0, 0, 5), &.{ 0, 0, 0, 1, 16 }, p, true);
    try expect_refusal(frame_header(.priority, 0, 1, 4), &.{ 0, 0, 0, 3 }, size, false);
    try expect_refusal(frame_header(.priority, 0, 1, 5), &.{ 0, 0, 0, 1, 16 }, p, false);
    try expect_refusal(frame_header(.rst_stream, 0, 0, 4), &.{ 0, 0, 0, 8 }, p, true);
    try expect_refusal(frame_header(.rst_stream, 0, 1, 3), &.{ 0, 0, 8 }, size, true);
    try expect_refusal(frame_header(.settings, 0, 1, 0), "", p, true);
    try expect_refusal(frame_header(.settings, flag_ack, 0, 6), &.{ 0, 1, 0, 0, 0, 0 }, size, true);
    try expect_refusal(frame_header(.settings, 0, 0, 5), &.{ 0, 1, 0, 0, 0 }, size, true);
    try expect_refusal(frame_header(.settings, 0, 0, 6), &.{ 0, 2, 0, 0, 0, 2 }, p, true);
    const window: ErrorCode = .flow_control_error;
    try expect_refusal(frame_header(.settings, 0, 0, 6), &.{ 0, 4, 0x80, 0, 0, 0 }, window, true);
    try expect_refusal(frame_header(.settings, 0, 0, 6), &.{ 0, 5, 0, 0, 0x3f, 0xff }, p, true);
    try expect_refusal(frame_header(.settings, 0, 0, 6), &.{ 0, 5, 1, 0, 0, 0 }, p, true);
    try expect_refusal(frame_header(.push_promise, 0, 1, 4), &.{ 0, 0, 0, 2 }, p, true);
    const zeros: [8]u8 = @splat(0);
    try expect_refusal(frame_header(.ping, 0, 1, 8), &zeros, p, true);
    try expect_refusal(frame_header(.ping, 0, 0, 7), zeros[0..7], size, true);
    try expect_refusal(frame_header(.goaway, 0, 1, 8), &zeros, p, true);
    try expect_refusal(frame_header(.goaway, 0, 0, 7), zeros[0..7], size, true);
    try expect_refusal(frame_header(.window_update, 0, 0, 4), &.{ 0, 0, 0, 0 }, p, true);
    try expect_refusal(frame_header(.window_update, 0, 1, 4), &.{ 0, 0, 0, 0 }, p, false);
    try expect_refusal(frame_header(.window_update, 0, 1, 3), &.{ 0, 0, 1 }, size, true);
    try expect_refusal(frame_header(.continuation, 0, 0, 1), "x", p, true);
}

test "http2_frame: padding, priority and unknown types are taken apart" {
    const padded = frame_header(.data, flag_padded | flag_end_stream, 1, 6);
    const data = parse(padded, &.{ 2, 'h', 'i', 'x', 0, 0 }).frame.data;
    try std.testing.expectEqualStrings("hix", data.data);
    try std.testing.expectEqual(6, data.flow_length);
    try std.testing.expect(data.end_stream);
    const flags = flag_padded | flag_priority | flag_end_headers;
    const headers = frame_header(.headers, flags, 5, 9);
    const fields = parse(headers, &.{ 1, 0, 0, 0, 3, 16, 0x82, 0x84, 0 }).frame.headers;
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0x84 }, fields.fragment);
    try std.testing.expect(fields.end_headers and !fields.end_stream);
    const unknown: Type = @fromBackingInt(0xfa);
    try std.testing.expect(parse(frame_header(unknown, 0, 9, 1), "?").frame == .unknown);
    // The reserved bit of an increment is ignored.
    const update = parse(frame_header(.window_update, 0, 3, 4), &.{ 0x80, 0, 1, 0 });
    try std.testing.expectEqual(256, update.frame.window_update.increment);
}
