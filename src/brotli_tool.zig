//! fourneau-brotli: our brotli, file to file, for comparing it with the
//! reference (`brotli`) by hand and in `zig build brotli-check`.
//!
//!   fourneau-brotli decode IN OUT

const std = @import("std");
const brotli_decode = @import("brotli_decode.zig");

const bytes_max = 64 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const command = args.next() orelse return error.Usage;
    const in_path = args.next() orelse return error.Usage;
    const out_path = args.next() orelse return error.Usage;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const input = try cwd.readFileAlloc(io, in_path, init.gpa, .limited(bytes_max));
    defer init.gpa.free(input);
    if (std.mem.eql(u8, command, "decode")) {
        const output = try init.gpa.alloc(u8, bytes_max);
        defer init.gpa.free(output);
        const decoded = try brotli_decode.decode(init.gpa, input, output);
        try cwd.writeFile(io, .{ .sub_path = out_path, .data = decoded });
    } else return error.Usage;
}
