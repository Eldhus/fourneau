//! One build for the repository: fourneau, its tests and tools.
//!
//!   zig build test                  every fast test, tidy included
//!   zig build test -Dfilter=http1   only tests whose name contains "http1"

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Tests build Debug by default: every safety check is on, and Zig's own
    // backend compiles the suite in under a second where LLVM (ReleaseSafe)
    // takes over twenty (DIARY 2026-10-04). Long simulator sweeps, which
    // run long rather than compile often, build ReleaseSafe.
    const test_optimize = b.option(
        std.builtin.Optimize,
        "test-optimize",
        "Test build mode (default Debug)",
    ) orelse .debug;
    const filter = b.option([]const u8, "filter", "Run only tests whose name contains this");

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = test_optimize,
        }),
        .filters = if (filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    // The simulator's fiber switch (src/sim_io.zig).
    tests.root_module.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    // Programs over the port (fourneau-static) have tests too.
    tests.root_module.addImport("zig_io_evented", b.createModule(.{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
        .target = target,
        .optimize = test_optimize,
    }));
    const optimize = b.standardOptimizeOption(.{});
    // For programs that embed fourneau (fourneau-dragrace's competitors):
    // the server and our port of Evented, in the importer's mode and target.
    _ = b.addModule("fourneau", .{ .root_source_file = b.path("src/fourneau.zig") });
    // The style checker, for repositories built on fourneau (roux's host).
    _ = b.addModule("tidy", .{ .root_source_file = b.path("src/tidy.zig") });
    const exported_port = b.addModule("zig_io_evented", .{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
    });
    exported_port.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    // ThreadSanitizer for fourneau-hello and the port under it (the port
    // tells it about fiber switches).
    const sanitize_thread = b.option(
        bool,
        "sanitize-thread",
        "Build fourneau-hello with ThreadSanitizer",
    ) orelse false;
    // Our vendored std.Io.Evented (io_uring fibers); see vendor/zig-io-evented.
    const zig_io_evented = b.createModule(.{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });
    // Our context switch, which the port and the simulator share.
    zig_io_evented.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    const hello = b.addExecutable(.{
        .name = "fourneau-hello",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hello.zig"),
            .target = target,
            .optimize = optimize,
            .sanitize_thread = sanitize_thread,
            .imports = &.{.{ .name = "zig_io_evented", .module = zig_io_evented }},
        }),
    });
    b.installArtifact(hello);
    const run_hello = b.addRunArtifact(hello);
    run_hello.addPassthruArgs();
    b.step("hello", "Run fourneau-hello (--port P --threads N)").dependOn(&run_hello.step);

    // A directory served from memory: fourneau-dragrace's results site.
    const static = b.addExecutable(.{
        .name = "fourneau-static",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/static.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zig_io_evented", .module = zig_io_evented }},
        }),
    });
    b.installArtifact(static);

    const load = b.addExecutable(.{
        .name = "fourneau-load",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/load.zig"),
            .target = target,
            .optimize = .fast,
        }),
    });
    b.installArtifact(load);

    // The kernel's floor under fourneau, for experiments (experiment 18).
    const floor = b.addExecutable(.{
        .name = "fourneau-floor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/floor.zig"),
            .target = target,
            .optimize = .fast,
        }),
    });
    b.installArtifact(floor);

    // Experiment 3's hybrid: state-machine I/O, handlers inline or on pooled
    // fibers (experiment 3).
    const hybrid = b.addExecutable(.{
        .name = "fourneau-hybrid",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hybrid.zig"),
            .target = target,
            .optimize = .fast,
        }),
    });
    hybrid.root_module.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    b.installArtifact(hybrid);

    const sim = b.addExecutable(.{
        .name = "fourneau-sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sim.zig"),
            .target = target,
            .optimize = .safe,
        }),
    });
    sim.root_module.addAssemblyFile(b.path("src/context_switch_x86_64.S"));
    b.installArtifact(sim);
    const run_sim = b.addRunArtifact(sim);
    run_sim.addPassthruArgs();
    b.step("sim", "Run the simulator (-- --seed N, or -- --seeds COUNT)").dependOn(&run_sim.step);

    const run_tests = b.addRunArtifact(tests);
    run_tests.setCwd(b.path(".")); // tidy reads the source trees
    // ...which the build system cannot see: without this, a change to a file
    // no test imports left the test binary as it was, the cached run was
    // reused, and tidy never looked (2026-10-05: floor.zig went in unchecked).
    run_tests.has_side_effects = true;
    b.step("test", "Run the fast tests (-Dfilter=AREA for one area)").dependOn(&run_tests.step);

}
