//! HPACK (RFC 7541): HTTP/2's header compression. Sans-IO: a decoder
//! with its dynamic table, and a stateless encoder.
//!
//! The decoder copies every decoded name and value into the caller's
//! buffer: a later field of the same block may evict the table entry an
//! earlier one came from, and the copy is where the header list's limit
//! lives (an HPACK bomb names a large entry over and over: each copy
//! counts against the buffer).
//!
//! The encoder never indexes: no dynamic table to keep in step with the
//! peer, nothing for a peer to probe (section 7.1). Responses use the
//! static table and literals, Huffman-coded when that is shorter.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("prng.zig").Prng;

pub const Header = struct { name: []const u8, value: []const u8 };

/// Appendix A.
pub const static_table = [61]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// An entry's size: its bytes and 32 (section 4.1).
pub fn entry_size(name: []const u8, value: []const u8) u32 {
    return @intCast(name.len + value.len + 32);
}

// --- Huffman (Appendix B) ----------------------------------------------------

/// Each symbol's code length; the code is canonical (checked against the
/// RFC's codes when this table was made), so the lengths define it.
const huffman_lengths = [257]u5{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
};

const end_of_string = 256;
const huffman_length_max = 30;

/// The canonical code: each symbol's code, and for decoding, the symbols
/// by code and each length's first code and where its symbols start.
const Huffman = struct {
    codes: [257]u32,
    symbols: [257]u16,
    /// Per length: the first code, and one past the last.
    first: [huffman_length_max + 2]u32,
    limit: [huffman_length_max + 2]u32,
    offset: [huffman_length_max + 2]u16,
};

const huffman: Huffman = make: {
    @setEvalBranchQuota(200_000);
    var made: Huffman = undefined;
    var counts: [huffman_length_max + 2]u16 = @splat(0);
    for (huffman_lengths) |length| counts[length] += 1;
    var code: u32 = 0;
    var index: u16 = 0;
    for (1..huffman_length_max + 1) |length| {
        made.first[length] = code;
        made.offset[length] = index;
        made.limit[length] = code + counts[length];
        for (huffman_lengths, 0..) |symbol_length, symbol| {
            if (symbol_length != length) continue;
            made.codes[symbol] = code;
            made.symbols[index] = symbol;
            code += 1;
            index += 1;
        }
        code <<= 1;
    }
    assert(index == 257);
    break :make made;
};

/// The bytes Huffman-coded (section 5.2), padded with the EOS code's
/// first bits, into `out`; its length. `out` must hold `huffman_size`.
pub fn huffman_encode(bytes: []const u8, out: []u8) usize {
    var bits: u64 = 0;
    var count: u6 = 0;
    var used: usize = 0;
    for (bytes) |byte| {
        const length = huffman_lengths[byte];
        bits = (bits << length) | huffman.codes[byte];
        count += length;
        for (0..4) |_| {
            if (count < 8) break;
            count -= 8;
            out[used] = @truncate(bits >> count);
            used += 1;
        }
    }
    if (count > 0) {
        const pad: u6 = 8 - count;
        out[used] = @truncate((bits << pad) | ((@as(u64, 1) << pad) - 1));
        used += 1;
    }
    return used;
}

pub fn huffman_size(bytes: []const u8) usize {
    var bits: usize = 0;
    for (bytes) |byte| bits += huffman_lengths[byte];
    return (bits + 7) / 8;
}

pub const Error = error{
    /// Malformed (RFC 9113: a connection error, COMPRESSION_ERROR).
    Compression,
    /// More than the caller's buffer or field count allows.
    HeaderListTooLarge,
};

/// Decodes Huffman-coded `coded` into `out`; the decoded length.
fn huffman_decode(coded: []const u8, out: []u8) Error!usize {
    var bits: u64 = 0;
    var count: u32 = 0; // bits in `bits`, left-aligned in the low 64
    var position: usize = 0;
    var used: usize = 0;
    // Each pass decodes a symbol (5 bits at least) or ends.
    for (0..coded.len * 8 / 5 + 2) |_| {
        for (0..8) |_| {
            if (count > 56 or position == coded.len) break;
            bits |= @as(u64, coded[position]) << @intCast(56 - count);
            count += 8;
            position += 1;
        }
        if (count == 0) return used;
        const symbol = (try next_symbol(bits, count)) orelse {
            // What is left is padding: under 8 bits, all ones (EOS's start).
            if (position != coded.len or count >= 8) return error.Compression;
            const mask = ~@as(u64, 0) << @intCast(64 - count);
            if (bits & mask != mask) return error.Compression;
            return used;
        };
        if (symbol.value == end_of_string) return error.Compression;
        if (used == out.len) return error.HeaderListTooLarge;
        out[used] = @intCast(symbol.value);
        used += 1;
        bits <<= symbol.length;
        count -= symbol.length;
    } else unreachable;
}

const Symbol = struct { value: u16, length: u5 };

/// The symbol whose code starts `bits` (left-aligned, `count` of them
/// valid); null when they are too few to hold a whole code.
fn next_symbol(bits: u64, count: u32) Error!?Symbol {
    for (5..huffman_length_max + 1) |length| {
        if (length > count) return null;
        const code: u32 = @intCast(bits >> @intCast(64 - length));
        if (code < huffman.limit[length]) {
            const index = huffman.offset[length] + (code - huffman.first[length]);
            return .{ .value = huffman.symbols[index], .length = @intCast(length) };
        }
    }
    return error.Compression; // no code: impossible for a complete code
}

// --- integers and strings (section 5) ------------------------------------------

/// The most continuation bytes an integer may take: values to 2^28.
const integer_bytes_max = 4;

pub const Reader = struct {
    bytes: []const u8,
    position: usize = 0,

    fn integer(reader: *Reader, prefix_bits: u4) Error!u32 {
        assert(prefix_bits >= 1 and prefix_bits <= 8);
        if (reader.position == reader.bytes.len) return error.Compression;
        const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
        var value: u32 = reader.bytes[reader.position] & mask;
        reader.position += 1;
        if (value < mask) return value;
        for (0..integer_bytes_max) |index| {
            if (reader.position == reader.bytes.len) return error.Compression;
            const byte = reader.bytes[reader.position];
            reader.position += 1;
            value += @as(u32, byte & 0x7f) << @intCast(index * 7);
            if (byte & 0x80 == 0) return value;
        }
        return error.Compression; // longer than any limit of ours
    }

    /// A string literal, decoded into `out`; its length.
    fn string(reader: *Reader, out: []u8) Error!usize {
        if (reader.position == reader.bytes.len) return error.Compression;
        const coded = reader.bytes[reader.position] & 0x80 != 0;
        const length = try reader.integer(7);
        if (length > reader.bytes.len - reader.position) return error.Compression;
        const data = reader.bytes[reader.position..][0..length];
        reader.position += length;
        if (coded) return huffman_decode(data, out);
        if (data.len > out.len) return error.HeaderListTooLarge;
        @memcpy(out[0..data.len], data);
        return data.len;
    }
};

pub fn write_integer(out: []u8, first_bits: u8, prefix_bits: u4, value: u32) usize {
    const limit: u32 = (@as(u32, 1) << prefix_bits) - 1;
    assert(first_bits & limit == 0);
    if (value < limit) {
        out[0] = first_bits | @as(u8, @intCast(value));
        return 1;
    }
    out[0] = first_bits | @as(u8, @intCast(limit));
    var rest = value - limit;
    var used: usize = 1;
    for (0..5) |_| {
        if (rest < 128) break;
        out[used] = @as(u8, @truncate(rest)) | 0x80;
        used += 1;
        rest >>= 7;
    } else unreachable;
    out[used] = @intCast(rest);
    return used + 1;
}

/// A string literal: Huffman-coded when shorter.
pub fn write_string(out: []u8, bytes: []const u8) usize {
    const coded_size = huffman_size(bytes);
    if (coded_size < bytes.len) {
        const head = write_integer(out, 0x80, 7, @intCast(coded_size));
        const written = huffman_encode(bytes, out[head..]);
        assert(written == coded_size);
        return head + written;
    }
    const head = write_integer(out, 0, 7, @intCast(bytes.len));
    @memcpy(out[head..][0..bytes.len], bytes);
    return head + bytes.len;
}

/// The most bytes `write_string` may take for `length` bytes.
pub fn string_size_max(length: usize) usize {
    return length + 6;
}

// --- the dynamic table (sections 2.3.2, 4) -------------------------------------

/// The newest entries of a size-bounded table: a ring of entries over a
/// byte buffer twice the table's size. The live bytes are always one run
/// (entries are added at its end and evicted from its start), moved to the
/// buffer's start when a new entry would pass its end.
pub const DynamicTable = struct {
    bytes: []u8,
    /// Where the live bytes start and end.
    bytes_start: u32 = 0,
    bytes_end: u32 = 0,
    entries: []Entry,
    /// The oldest entry's place in the ring, and how many there are.
    oldest: u32 = 0,
    count: u32 = 0,
    /// The table's size (section 4.1), its maximum now, and the most the
    /// protocol allows (our SETTINGS_HEADER_TABLE_SIZE).
    size: u32 = 0,
    size_max: u32,
    size_limit: u32,

    const Entry = struct { start: u32, name_length: u32, value_length: u32 };

    pub fn init(gpa: std.mem.Allocator, size_limit: u32) std.mem.Allocator.Error!DynamicTable {
        const bytes = try gpa.alloc(u8, @as(usize, size_limit) * 2);
        errdefer gpa.free(bytes);
        return .{
            .bytes = bytes,
            // An entry takes 32 at least: no more than this many fit.
            .entries = try gpa.alloc(Entry, size_limit / 32 + 1),
            .size_max = size_limit,
            .size_limit = size_limit,
        };
    }

    pub fn deinit(table: *DynamicTable, gpa: std.mem.Allocator) void {
        gpa.free(table.bytes);
        gpa.free(table.entries);
        table.* = undefined;
    }

    /// Entry `index`, 1 the newest.
    fn get(table: *const DynamicTable, index: u32) ?Header {
        if (index == 0 or index > table.count) return null;
        const slot = (table.oldest + table.count - index) % table.entries.len;
        const entry = table.entries[slot];
        const name = table.bytes[entry.start..][0..entry.name_length];
        const value = table.bytes[entry.start + entry.name_length ..][0..entry.value_length];
        return .{ .name = name, .value = value };
    }

    fn evict_oldest(table: *DynamicTable) void {
        assert(table.count > 0);
        const entry = table.entries[table.oldest];
        table.size -= entry.name_length + entry.value_length + 32;
        table.bytes_start = entry.start + entry.name_length + entry.value_length;
        table.oldest = @intCast((table.oldest + 1) % table.entries.len);
        table.count -= 1;
        if (table.count == 0) {
            table.bytes_start = 0;
            table.bytes_end = 0;
        }
    }

    /// Section 4.4: evict until the new entry fits; one larger than the
    /// table empties it and is not added.
    fn add(table: *DynamicTable, name: []const u8, value: []const u8) void {
        const size = entry_size(name, value);
        for (0..table.entries.len + 1) |_| {
            if (table.count == 0 or table.size + size <= table.size_max) break;
            table.evict_oldest();
        } else unreachable;
        if (size > table.size_max) return;
        const length: u32 = @intCast(name.len + value.len);
        if (table.bytes_end + length > table.bytes.len) table.compact();
        assert(table.bytes_end + length <= table.bytes.len);
        @memcpy(table.bytes[table.bytes_end..][0..name.len], name);
        @memcpy(table.bytes[table.bytes_end + name.len ..][0..value.len], value);
        const slot = (table.oldest + table.count) % table.entries.len;
        table.entries[slot] = .{
            .start = table.bytes_end,
            .name_length = @intCast(name.len),
            .value_length = @intCast(value.len),
        };
        table.count += 1;
        table.bytes_end += length;
        table.size += size;
        assert(table.size <= table.size_max);
    }

    /// The live bytes to the buffer's start.
    fn compact(table: *DynamicTable) void {
        const live = table.bytes_end - table.bytes_start;
        const run = table.bytes[table.bytes_start..table.bytes_end];
        std.mem.copyForwards(u8, table.bytes[0..live], run);
        for (0..table.count) |offset| {
            table.entries[(table.oldest + offset) % table.entries.len].start -= table.bytes_start;
        }
        table.bytes_start = 0;
        table.bytes_end = live;
    }

    /// Section 4.3: a new maximum, evicting to it.
    fn set_max(table: *DynamicTable, size_max: u32) void {
        assert(size_max <= table.size_limit);
        table.size_max = size_max;
        for (0..table.entries.len + 1) |_| {
            if (table.size <= size_max) break;
            table.evict_oldest();
        } else unreachable;
    }
};

// --- the decoder (sections 3, 6) ---------------------------------------------

pub const Decoder = struct {
    table: DynamicTable,

    pub fn init(gpa: std.mem.Allocator, table_size: u32) std.mem.Allocator.Error!Decoder {
        return .{ .table = try .init(gpa, table_size) };
    }

    pub fn deinit(decoder: *Decoder, gpa: std.mem.Allocator) void {
        decoder.table.deinit(gpa);
        decoder.* = undefined;
    }

    /// Empty, as a new connection's table starts.
    pub fn reset(decoder: *Decoder) void {
        const table = &decoder.table;
        // Copied first: the new value must not be built in place from itself.
        const empty: DynamicTable = .{
            .bytes = table.bytes,
            .entries = table.entries,
            .size_max = table.size_limit,
            .size_limit = table.size_limit,
        };
        table.* = empty;
        assert(table.count == 0 and table.size == 0);
    }

    /// A header block's fields into `fields`, their names and values copied
    /// into `storage`; the count. Out of either: `HeaderListTooLarge`.
    pub fn decode(
        decoder: *Decoder,
        block: []const u8,
        storage: []u8,
        fields: []Header,
    ) Error!usize {
        var reader: Reader = .{ .bytes = block };
        var count: usize = 0;
        var used: usize = 0;
        // Each pass takes a byte at least.
        for (0..block.len + 1) |_| {
            if (reader.position == block.len) return count;
            const first = block[reader.position];
            if (first & 0xe0 == 0x20) {
                // A size update: only before the block's first field.
                if (count > 0) return error.Compression;
                const size = try reader.integer(5);
                if (size > decoder.table.size_limit) return error.Compression;
                decoder.table.set_max(size);
                continue;
            }
            if (count == fields.len) return error.HeaderListTooLarge;
            fields[count] = try decoder.field(&reader, storage, &used);
            count += 1;
        } else unreachable;
    }

    fn field(decoder: *Decoder, reader: *Reader, storage: []u8, used: *usize) Error!Header {
        const first = reader.bytes[reader.position];
        if (first & 0x80 != 0) {
            const found = try decoder.lookup(try reader.integer(7));
            return copy(storage, used, found.name, found.value);
        }
        const indexing = first & 0xc0 == 0x40;
        const index = try reader.integer(if (indexing) 6 else 4);
        const name_start = used.*;
        if (index == 0) {
            used.* += try reader.string(storage[used.*..]);
        } else {
            const name = (try decoder.lookup(index)).name;
            if (name.len > storage.len - used.*) return error.HeaderListTooLarge;
            @memcpy(storage[used.*..][0..name.len], name);
            used.* += name.len;
        }
        const value_start = used.*;
        used.* += try reader.string(storage[used.*..]);
        const decoded: Header = .{
            .name = storage[name_start..value_start],
            .value = storage[value_start..used.*],
        };
        if (indexing) decoder.table.add(decoded.name, decoded.value);
        return decoded;
    }

    fn lookup(decoder: *const Decoder, index: u32) Error!Header {
        if (index == 0) return error.Compression;
        if (index <= static_table.len) return static_table[index - 1];
        const dynamic_index = index - @as(u32, static_table.len);
        return decoder.table.get(dynamic_index) orelse error.Compression;
    }

    fn copy(storage: []u8, used: *usize, name: []const u8, value: []const u8) Error!Header {
        if (name.len + value.len > storage.len - used.*) return error.HeaderListTooLarge;
        const start = used.*;
        @memcpy(storage[start..][0..name.len], name);
        @memcpy(storage[start + name.len ..][0..value.len], value);
        used.* += name.len + value.len;
        return .{
            .name = storage[start..][0..name.len],
            .value = storage[start + name.len ..][0..value.len],
        };
    }
};

// --- the encoder ---------------------------------------------------------------

/// The most bytes one field may take, encoded.
pub fn field_size_max(name: []const u8, value: []const u8) usize {
    return 1 + string_size_max(name.len) + string_size_max(value.len);
}

/// One field, never indexed into the table (the encoder keeps none): the
/// static table's entry when it has the whole field, its name when it has
/// that, else both literal. `name` must be lowercase (RFC 9113 §8.2.1).
pub fn encode_field(out: []u8, name: []const u8, value: []const u8) usize {
    assert(out.len >= field_size_max(name, value));
    var name_index: u32 = 0;
    for (static_table, 1..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (std.mem.eql(u8, entry.value, value)) {
            return write_integer(out, 0x80, 7, @intCast(index));
        }
        if (name_index == 0) name_index = @intCast(index);
    }
    var used = write_integer(out, 0x00, 4, name_index); // without indexing
    if (name_index == 0) used += write_string(out[used..], name);
    used += write_string(out[used..], value);
    return used;
}

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var bytes: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable;
    return bytes;
}

const Example = struct { block: []const u8, fields: []const Header, table_size: u32 };

fn expect_examples(table_limit: u32, examples: []const Example) !void {
    const gpa = std.testing.allocator;
    var decoder = try Decoder.init(gpa, table_limit);
    defer decoder.deinit(gpa);
    for (examples) |example| {
        var storage: [1024]u8 = undefined;
        var fields: [16]Header = undefined;
        const count = try decoder.decode(example.block, &storage, &fields);
        try std.testing.expectEqual(example.fields.len, count);
        for (example.fields, fields[0..count]) |want, got| {
            try std.testing.expectEqualStrings(want.name, got.name);
            try std.testing.expectEqualStrings(want.value, got.value);
        }
        try std.testing.expectEqual(example.table_size, decoder.table.size);
    }
}

const request_fields = [3][]const Header{
    &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    },
    &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    },
    &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "custom-key", .value = "custom-value" },
    },
};

const response_fields = [3][]const Header{
    &.{
        .{ .name = ":status", .value = "302" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    },
    &.{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    },
    &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{
            .name = "set-cookie",
            .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        },
    },
};

/// Appendix C's header blocks, as its hex dumps give them.
const c3 = [3][]const u8{
    &hex("828684410f7777772e6578616d706c652e636f6d"),
    &hex("828684be58086e6f2d6361636865"),
    &hex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"),
};
const c4 = [3][]const u8{
    &hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
    &hex("828684be5886a8eb10649cbf"),
    &hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"),
};
const c5 = [3][]const u8{
    &hex("4803333032580770726976617465611d4d6f6e2c203231204f63742032303133" ++
        "2032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d70" ++
        "6c652e636f6d"),
    &hex("4803333037c1c0bf"),
    &hex("88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d" ++
        "54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f5049" ++
        "5541585157454f49553b206d61782d6167653d333630303b2076657273696f6e" ++
        "3d31"),
};
const c6 = [3][]const u8{
    &hex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a6" ++
        "2d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"),
    &hex("4883640effc1c0bf"),
    &hex("88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab" ++
        "77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f" ++
        "9587316065c003ed4ee5b1063d5007"),
};

fn appendix(blocks: [3][]const u8, fields: [3][]const Header, sizes: [3]u32) [3]Example {
    var made: [3]Example = undefined;
    for (&made, blocks, fields, sizes) |*example, block, list, size| {
        example.* = .{ .block = block, .fields = list, .table_size = size };
    }
    return made;
}

test "hpack: RFC 7541 C.3 and C.4, requests on one connection" {
    try expect_examples(4096, &appendix(c3, request_fields, .{ 57, 110, 164 }));
    try expect_examples(4096, &appendix(c4, request_fields, .{ 57, 110, 164 }));
}

test "hpack: RFC 7541 C.5 and C.6, responses with evictions" {
    try expect_examples(256, &appendix(c5, response_fields, .{ 222, 222, 215 }));
    try expect_examples(256, &appendix(c6, response_fields, .{ 222, 222, 215 }));
}

test "hpack: integers, as C.1 writes them" {
    var out: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{0x0a}, out[0..write_integer(&out, 0, 5, 10)]);
    const big = write_integer(&out, 0, 5, 1337);
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, out[0..big]);
    try std.testing.expectEqualSlices(u8, &.{0x2a}, out[0..write_integer(&out, 0, 8, 42)]);
    var reader: Reader = .{ .bytes = &.{ 0x1f, 0x9a, 0x0a } };
    try std.testing.expectEqual(1337, try reader.integer(5));
}

test "hpack: Huffman round trips every byte, and the RFC's first string" {
    var bytes: [256]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
    var coded: [1024]u8 = undefined;
    const length = huffman_encode(&bytes, &coded);
    try std.testing.expectEqual(huffman_size(&bytes), length);
    var decoded: [256]u8 = undefined;
    const decoded_length = try huffman_decode(coded[0..length], &decoded);
    try std.testing.expectEqualSlices(u8, &bytes, decoded[0..decoded_length]);
    const www = huffman_encode("www.example.com", &coded);
    try std.testing.expectEqualSlices(u8, &hex("f1e3c2e5f23a6ba0ab90f4ff"), coded[0..www]);
}

test "hpack: what is malformed is refused" {
    const gpa = std.testing.allocator;
    var decoder = try Decoder.init(gpa, 4096);
    defer decoder.deinit(gpa);
    var storage: [64]u8 = undefined;
    var fields: [4]Header = undefined;
    const malformed = [_][]const u8{
        &.{0x80}, // index 0
        &.{0xbe}, // index 62, the dynamic table empty
        &.{ 0x82, 0x3f, 0xe1, 0x1f }, // a size update after a field
        &.{ 0x3f, 0xe2, 0x1f }, // a size update past the limit (4097)
        &.{ 0x04, 0x81, 0x00 }, // Huffman padding of zeros
        &.{ 0x04, 0x84, 0xff, 0xff, 0xff, 0xff }, // 32 ones: EOS inside
        &.{ 0x04, 0x05, 'a', 'b' }, // a string past the block
        &.{ 0x84, 0xff, 0xff, 0xff, 0xff, 0x0f }, // an integer too long
    };
    for (malformed) |block| {
        try std.testing.expectError(error.Compression, decoder.decode(block, &storage, &fields));
    }
    // An HPACK bomb: a large entry, named again and again.
    var big: [80]u8 = undefined;
    big[0] = 0x40;
    big[1] = 0x01;
    big[2] = 'x';
    big[3] = 50;
    @memset(big[4..54], 'y');
    @memset(big[54..], 0xbe); // index 62, over and over
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decode(&big, &storage, &fields));
}

test "hpack: the table under churn holds what a plain model says" {
    const gpa = std.testing.allocator;
    var table = try DynamicTable.init(gpa, 256);
    defer table.deinit(gpa);
    // The model: every entry ever added, newest last, and the table's
    // contents as the newest ones whose sizes fit, as section 4.4 evicts.
    var names: [4000][8]u8 = undefined;
    var values: [4000][40]u8 = undefined;
    var lengths: [4000][2]u8 = undefined;
    var prng = Prng.init(7);
    for (0..4000) |added| {
        const name_length = prng.int_at_most(u8, 1, 8);
        const value_length = prng.int_at_most(u8, 0, 40);
        for (names[added][0..name_length]) |*byte| byte.* = @truncate(prng.next());
        for (values[added][0..value_length]) |*byte| byte.* = @truncate(prng.next());
        lengths[added] = .{ name_length, value_length };
        table.add(names[added][0..name_length], values[added][0..value_length]);
        if (prng.int_less_than(u32, 50) == 0) table.set_max(prng.int_at_most(u32, 0, 256));
        if (prng.int_less_than(u32, 50) == 0) table.set_max(256);
        // Newest first, each entry must be the one added that long ago.
        var size: u32 = 0;
        for (1..table.count + 1) |index| {
            const entry = table.get(@intCast(index)).?;
            const back = added + 1 - index;
            try std.testing.expectEqualSlices(u8, names[back][0..lengths[back][0]], entry.name);
            try std.testing.expectEqualSlices(u8, values[back][0..lengths[back][1]], entry.value);
            size += entry_size(entry.name, entry.value);
        }
        try std.testing.expectEqual(table.size, size);
        try std.testing.expect(table.size <= table.size_max);
    }
}

test "hpack: random and damaged blocks are refused or decoded, never more" {
    const gpa = std.testing.allocator;
    var decoder = try Decoder.init(gpa, 256);
    defer decoder.deinit(gpa);
    var prng = Prng.init(1);
    var block: [64]u8 = undefined;
    var storage: [256]u8 = undefined;
    var fields: [16]Header = undefined;
    const valid = hex("88c16196d07abe941054d444a8200595040b8166e084a62d1bff");
    for (0..20_000) |round| {
        const length = prng.int_at_most(usize, 0, block.len);
        if (round % 2 == 0) {
            for (block[0..length]) |*byte| byte.* = @truncate(prng.next());
        } else {
            // A real block with a byte or two changed.
            @memcpy(block[0..valid.len], &valid);
            block[prng.int_less_than(usize, valid.len)] ^= @truncate(prng.next() | 1);
        }
        const bytes = if (round % 2 == 0) block[0..length] else block[0..valid.len];
        if (decoder.decode(bytes, &storage, &fields)) |count| {
            assert(count <= fields.len);
        } else |err| switch (err) {
            error.Compression, error.HeaderListTooLarge => {},
        }
        try std.testing.expect(decoder.table.size <= decoder.table.size_max);
    }
}

test "hpack: the encoder's fields decode back" {
    const gpa = std.testing.allocator;
    var decoder = try Decoder.init(gpa, 4096);
    defer decoder.deinit(gpa);
    const sent = [_]Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "302" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        .{ .name = "x-custom", .value = "a value nobody has indexed" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    };
    var block: [512]u8 = undefined;
    var used: usize = 0;
    for (sent) |field| used += encode_field(block[used..], field.name, field.value);
    try std.testing.expectEqual(1, encode_field(&block, ":status", "200")); // indexed
    var storage: [512]u8 = undefined;
    var fields: [8]Header = undefined;
    const count = try decoder.decode(block[0..used], &storage, &fields);
    try std.testing.expectEqual(sent.len, count);
    for (sent, fields[0..count]) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
    try std.testing.expectEqual(0, decoder.table.count); // nothing indexed
}
