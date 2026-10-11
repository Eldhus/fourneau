//! Writes `src/curves_p256_base.bin`, the P-256 table `curves.zig` embeds
//! for `p256_scalarmulbase`: `zig build curves-table`. Its test checks the
//! file against the table built again, so a stale file fails the suite.

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
