//! fourneau-brotli: our brotli, file to file, for comparing it with the
//! reference (`brotli`), and a differential check against it.
//!
//!   fourneau-brotli decode IN OUT
//!   fourneau-brotli encode IN OUT
//!   fourneau-brotli check SEEDS     inputs from seeds 0..SEEDS, each
//!                                   encoded by us and decoded by both
//!                                   our decoder and the reference's
//!
//! `zig build brotli-check -- SEEDS` runs the check (the `brotli`
//! command must be on PATH: a test-only tool).

const std = @import("std");
const assert = std.debug.assert;
const brotli_decode = @import("brotli_decode.zig");
const brotli_encode = @import("brotli_encode.zig");
const tables = @import("brotli_tables.zig");
const Prng = @import("prng.zig").Prng;

const bytes_max = 64 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const command = args.next() orelse return error.Usage;
    const first = args.next() orelse return error.Usage;
    if (std.mem.eql(u8, command, "check")) {
        return check(init.gpa, init.io, try std.fmt.parseInt(u32, first, 10));
    }
    const out_path = args.next() orelse return error.Usage;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const input = try cwd.readFileAlloc(io, first, init.gpa, .limited(bytes_max));
    defer init.gpa.free(input);
    if (std.mem.eql(u8, command, "decode")) {
        const output = try init.gpa.alloc(u8, bytes_max);
        defer init.gpa.free(output);
        const decoded = try brotli_decode.decode(init.gpa, input, output);
        try cwd.writeFile(io, .{ .sub_path = out_path, .data = decoded });
    } else if (std.mem.eql(u8, command, "encode")) {
        const encoded = try brotli_encode.encode(init.gpa, input);
        defer init.gpa.free(encoded);
        try cwd.writeFile(io, .{ .sub_path = out_path, .data = encoded });
    } else return error.Usage;
}

const scratch_path = ".zig-cache/brotli-check.br";
const generated_bytes_max = 400 * 1024;

fn check(gpa: std.mem.Allocator, io: std.Io, seeds: u32) !void {
    const input = try gpa.alloc(u8, generated_bytes_max);
    defer gpa.free(input);
    const output = try gpa.alloc(u8, generated_bytes_max + 1);
    defer gpa.free(output);
    var compressed_total: u64 = 0;
    var input_total: u64 = 0;
    for (0..seeds) |seed| {
        const made = generate(seed, input);
        const encoded = try brotli_encode.encode(gpa, made);
        defer gpa.free(encoded);
        const ours = try brotli_decode.decode(gpa, encoded, output);
        if (!std.mem.eql(u8, ours, made)) return fail(seed, "our decoder disagrees");
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = scratch_path, .data = encoded });
        const result = try std.process.run(gpa, io, .{
            .argv = &.{ "brotli", "-d", "-c", scratch_path },
            .stdout_limit = .limited(generated_bytes_max + 1),
        });
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        if (!result.term.success()) return fail(seed, "the reference refuses it");
        if (!std.mem.eql(u8, result.stdout, made)) return fail(seed, "the reference disagrees");
        compressed_total += encoded.len;
        input_total += made.len;
    }
    std.debug.print("{d} seeds: every stream decoded by both ({d} bytes to {d})\n", .{
        seeds, input_total, compressed_total,
    });
}

fn fail(seed: usize, why: []const u8) error{Mismatch} {
    std.debug.print("seed {d}: {s}\n", .{ seed, why });
    return error.Mismatch;
}

/// An input from a seed: random bytes, runs, dictionary words, copies of
/// itself at every distance, or a mixture; small and large.
fn generate(seed: u64, buffer: []u8) []u8 {
    var prng = Prng.init(seed);
    const large = prng.int_less_than(u32, 16) == 0;
    const length = prng.int_at_most(usize, 0, if (large) buffer.len else 6000);
    var used: usize = 0;
    // A piece at a time: each kind fills a stretch.
    for (0..length + 1) |_| {
        if (used >= length) break;
        const piece = @min(length - used, prng.int_at_most(usize, 1, 2000));
        const into = buffer[used..][0..piece];
        switch (prng.int_less_than(u32, 4)) {
            0 => for (into) |*byte| {
                byte.* = @truncate(prng.next());
            },
            1 => runs(&prng, into),
            2 => words(&prng, into),
            3 => if (used > 0) copies(&prng, buffer[0..used], into) else runs(&prng, into),
            else => unreachable,
        }
        used += piece;
    } else unreachable;
    return buffer[0..length];
}

fn runs(prng: *Prng, into: []u8) void {
    var index: usize = 0;
    for (0..into.len) |_| {
        if (index == into.len) break;
        const run = @min(into.len - index, prng.int_at_most(usize, 1, 300));
        @memset(into[index..][0..run], @truncate(prng.int_less_than(u32, 4)));
        index += run;
    }
}

/// Dictionary words, as transforms make them, with spaces and marks:
/// text the dictionary search should find.
fn words(prng: *Prng, into: []u8) void {
    var index: usize = 0;
    for (0..into.len) |_| {
        if (index == into.len) break;
        const length = prng.int_at_most(usize, tables.word_length_min, tables.word_length_max);
        const word = tables.word(length, prng.int_less_than(u32, tables.word_count(length)));
        var buffer: [tables.transformed_bytes_max]u8 = undefined;
        const transform: u8 = @intCast(prng.int_less_than(u32, tables.transforms_count));
        const made = tables.transform_word(word, transform, &buffer);
        const take = @min(into.len - index, made.len);
        @memcpy(into[index..][0..take], made[0..take]);
        index += take;
        if (index < into.len) {
            into[index] = " .,\n"[prng.int_less_than(u32, 4)];
            index += 1;
        }
    }
}

/// Stretches of what came before, from near and far.
fn copies(prng: *Prng, before: []const u8, into: []u8) void {
    var index: usize = 0;
    for (0..into.len) |_| {
        if (index == into.len) break;
        const start = prng.int_less_than(usize, before.len);
        const take = @min(into.len - index, before.len - start, prng.int_at_most(usize, 2, 500));
        @memcpy(into[index..][0..take], before[start..][0..take]);
        index += take;
    }
}
