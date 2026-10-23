//! One build for the repository: fourneau's modules and its tests.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Tests build Debug by default: every safety check is on, and Zig's own
    // backend compiles the suite in under a second.
    const test_optimize = b.option(
        std.builtin.Optimize,
        "test-optimize",
        "Test build mode (default Debug)",
    ) orelse .debug;
    const filter = b.option([]const u8, "filter", "Run only tests whose name contains this");

    // The kernel the port calls: Linux's (src/kernel.zig).
    const kernel = b.createModule(.{ .root_source_file = b.path("src/kernel.zig") });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
        .filters = if (filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    // The port's fiber switch (its real-ring tests: port_tests.zig).
    tests.root_module.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    tests.root_module.addImport("zig_io_evented", b.createModule(.{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
        .target = target,
        .optimize = test_optimize,
        .imports = &.{.{ .name = "kernel", .module = kernel }},
    }));

    // For the program that embeds fourneau: the server and our port of
    // Evented, in the importer's mode and target.
    _ = b.addModule("fourneau", .{ .root_source_file = b.path("src/fourneau.zig") });
    const exported_port = b.addModule("zig_io_evented", .{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
        .imports = &.{.{ .name = "kernel", .module = kernel }},
    });
    exported_port.addAssemblyFile(b.path("src/context_switch_x86_64.S"));

    const run_tests = b.addRunArtifact(tests);
    run_tests.setCwd(b.path(".")); // tidy reads the source trees
    // ...which the build system cannot see: without this, a change to a file
    // no test imports left the test binary as it was, the cached run was
    // reused, and tidy never looked.
    run_tests.has_side_effects = true;
    const test_step = b.step("test", "Run the tests (-Dfilter=AREA for one area)");
    test_step.dependOn(&run_tests.step);
}
