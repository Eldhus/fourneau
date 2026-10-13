//! Writes `src/curves_p256_base.bin`, the P-256 table `curves.zig` embeds
//! for `p256_scalarmulbase`: `zig build curves-table`. curves.zig's test
//! checks 20 of its entries (one in each end block) against the points std
//! computes; in full, `zig build curves-table` must leave `git diff` clean.

const std = @import("std");
const assert = std.debug.assert;
const curves = @import("curves");

pub fn main(init: std.process.Init) !void {
    const table = try init.gpa.create([curves.p256_table_words]u64);
    defer init.gpa.destroy(table);
    curves.p256_table_build(curves.form(), table);
    const bytes = std.mem.sliceAsBytes(table);
    assert(bytes.len == curves.p256_table_bytes);
    try std.Io.Dir.cwd().writeFile(init.io, .{
        .sub_path = "src/curves_p256_base.bin",
        .data = bytes,
    });
}
