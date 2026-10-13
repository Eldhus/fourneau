//! One build for the repository: fourneau, its tests and tools.

const std = @import("std");

/// s2n-bignum's routines under src/curves.zig (vendor/s2n-bignum/README.md).
const curves_assembly = [_][]const u8{
    "vendor/s2n-bignum/x86/curve25519/curve25519_x25519.S",
    "vendor/s2n-bignum/x86/curve25519/curve25519_x25519_alt.S",
    "vendor/s2n-bignum/x86/curve25519/curve25519_x25519base.S",
    "vendor/s2n-bignum/x86/curve25519/curve25519_x25519base_alt.S",
    "vendor/s2n-bignum/x86/p256/p256_scalarmulbase.S",
    "vendor/s2n-bignum/x86/p256/p256_scalarmulbase_alt.S",
    "vendor/s2n-bignum/x86/p256/bignum_tomont_p256.S",
    "vendor/s2n-bignum/x86/p256/bignum_tomont_p256_alt.S",
    "vendor/s2n-bignum/x86/generic/bignum_modinv.S",
};

/// tls.zig and the two modules its patch imports: the handshake's curves
/// (src/curves.zig, on s2n-bignum's assembly) and SHA-256 (src/sha256.zig,
/// std's twice). One `sha256` for both: tls.zig sets its signer's hash
/// from its transcript, so they must be one type.
const TlsModules = struct {
    tls: *std.Build.Module,
    curves: *std.Build.Module,
    sha256: *std.Build.Module,
};

/// `exported`: the modules importers see (`b.addModule`), built in their
/// target and mode; else this build's, in `target` and `optimize`.
fn tls_modules(
    b: *std.Build,
    target: ?std.Build.ResolvedTarget,
    optimize: ?std.builtin.OptimizeMode,
    exported: bool,
) TlsModules {
    const sha256 = module(b, exported, "sha256", .{
        .root_source_file = b.path("src/sha256.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha256.addObject(sha256_shani(b));
    const curves = module(b, exported, "curves", .{
        .root_source_file = b.path("src/curves.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sha256", .module = sha256 }},
    });
    curves.addIncludePath(b.path("vendor/s2n-bignum/include"));
    for (curves_assembly) |file| curves.addAssemblyFile(b.path(file));
    const tls = module(b, exported, "tls", .{
        .root_source_file = b.path("vendor/tls.zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "curves", .module = curves },
            .{ .name = "sha256", .module = sha256 },
        },
    });
    return .{ .tls = tls, .curves = curves, .sha256 = sha256 };
}

fn module(
    b: *std.Build,
    exported: bool,
    name: []const u8,
    options: std.Build.Module.CreateOptions,
) *std.Build.Module {
    return if (exported) b.addModule(name, options) else b.createModule(options);
}

/// std's SHA-256 built for the SHA extensions (src/sha256_shani.zig): its
/// own target whatever the importer's, x86-64-v3 with SHA, as sha256.zig
/// calls it only where `cpuid` finds them. ReleaseSafe in every build:
/// Debug's would be slower than the build's own.
fn sha256_shani(b: *std.Build) *std.Build.Step.Compile {
    return b.addObject(.{
        .name = "sha256_shani",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sha256_shani.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .cpu_model = .{ .explicit = &std.Target.x86.cpu.x86_64_v3 },
                .cpu_features_add = std.Target.x86.featureSet(&.{.sha}),
            }),
            .optimize = .safe,
            .pic = true,
        }),
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Tests build Debug by default: every safety check is on, and Zig's own
    // backend compiles the suite in under a second where LLVM (ReleaseSafe)
    // takes over twenty (measured). Long simulator sweeps, which
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
    // TLS 1.3: the handshake (vendor/tls.zig, ianic/tls.zig), its keys to
    // kTLS; its curves on s2n-bignum (src/curves.zig), its SHA-256 with the
    // CPU's extensions where it has them (src/sha256.zig).
    const test_tls = tls_modules(b, target, test_optimize, false);
    tests.root_module.addImport("tls", test_tls.tls);
    // The curves and SHA-256 are modules of their own (tls.zig imports
    // them), so their tests are artifacts of their own; so are tls.zig's,
    // which check its patch (RFC 8448's key schedule among them).
    const tls_tests = b.addTest(.{
        .root_module = test_tls.tls,
        .filters = if (filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    const curves_tests = b.addTest(.{
        .root_module = test_tls.curves,
        .filters = if (filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    const sha256_tests = b.addTest(.{
        .root_module = test_tls.sha256,
        .filters = if (filter) |f| b.dupeStrings(&.{f}) else &.{},
    });
    // Programs over the port (fourneau-static) have tests too.
    tests.root_module.addImport("zig_io_evented", b.createModule(.{
        .root_source_file = b.path("vendor/zig-io-evented/Uring.zig"),
        .target = target,
        .optimize = test_optimize,
    }));
    // Brotli's static dictionary (vendor/brotli: data the format fixes).
    tests.root_module.addImport("brotli_dictionary", b.createModule(.{
        .root_source_file = b.path("vendor/brotli/dictionary.zig"),
        .target = target,
        .optimize = test_optimize,
    }));
    const optimize = b.standardOptimizeOption(.{});
    // For programs that embed fourneau (roux's host, the dragrace's fourneau-zig):
    // the server and our port of Evented, in the importer's mode and target.
    // The server needs tls.zig, so the module carries it (and tls.zig its
    // curves and SHA-256, with their assembly and object): importers add
    // nothing.
    const exported_tls = tls_modules(b, null, null, true).tls;
    const exported_dictionary = b.addModule("brotli_dictionary", .{
        .root_source_file = b.path("vendor/brotli/dictionary.zig"),
    });
    _ = b.addModule("fourneau", .{
        .root_source_file = b.path("src/fourneau.zig"),
        .imports = &.{
            .{ .name = "tls", .module = exported_tls },
            .{ .name = "brotli_dictionary", .module = exported_dictionary },
        },
    });
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
    const tls = tls_modules(b, target, optimize, false).tls;
    const brotli_dictionary = b.createModule(.{
        .root_source_file = b.path("vendor/brotli/dictionary.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hello = b.addExecutable(.{
        .name = "fourneau-hello",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hello.zig"),
            .target = target,
            .optimize = optimize,
            .sanitize_thread = sanitize_thread,
            .imports = &.{
                .{ .name = "zig_io_evented", .module = zig_io_evented },
                .{ .name = "tls", .module = tls },
            },
        }),
    });
    b.installArtifact(hello);
    const run_hello = b.addRunArtifact(hello);
    run_hello.addPassthruArgs();
    b.step("hello", "Run fourneau-hello (-- --port P --shards N)").dependOn(&run_hello.step);

    // fourneau-static: a directory served from memory (site.zig) over
    // HTTP/1.1, HTTP/2 and HTTPS; an example, h2spec's TLS target, and the
    // static differential's.
    const static = b.addExecutable(.{
        .name = "fourneau-static",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/static.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_io_evented", .module = zig_io_evented },
                .{ .name = "tls", .module = tls },
                .{ .name = "brotli_dictionary", .module = brotli_dictionary },
            },
        }),
    });
    b.installArtifact(static);

    // Our brotli, file to file, against the reference (brotli_tool.zig).
    const brotli_tool = b.addExecutable(.{
        .name = "fourneau-brotli",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/brotli_tool.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "brotli_dictionary", .module = brotli_dictionary }},
        }),
    });
    b.installArtifact(brotli_tool);
    const run_brotli_check = b.addRunArtifact(brotli_tool);
    run_brotli_check.addArg("check");
    run_brotli_check.addPassthruArgs();
    run_brotli_check.has_side_effects = true;
    b.step(
        "brotli-check",
        "Encode inputs from seeds, decode with ours and the reference (-- SEEDS)",
    ).dependOn(&run_brotli_check.step);

    const load = b.addExecutable(.{
        .name = "fourneau-load",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/load.zig"),
            .target = target,
            .optimize = .fast,
        }),
    });
    b.installArtifact(load);

    // The kernel's floor under fourneau, for experiments.
    const floor = b.addExecutable(.{
        .name = "fourneau-floor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/floor.zig"),
            .target = target,
            .optimize = .fast,
        }),
    });
    b.installArtifact(floor);

    // fourneau-hybrid: the state-machine I/O, handlers inline or
    // on pooled fibers.
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
    sim.root_module.addImport("tls", tls); // the server compiles with it; the simulator uses none
    b.installArtifact(sim);
    const run_sim = b.addRunArtifact(sim);
    run_sim.addPassthruArgs();
    b.step("sim", "Run the simulator (-- --seed N, or -- --seeds COUNT)").dependOn(&run_sim.step);

    // Writes src/curves_p256_base.bin, the table curves.zig embeds.
    const table_curves = tls_modules(b, target, .safe, false).curves;
    const curves_table = b.addExecutable(.{
        .name = "fourneau-curves-table",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/curves_table.zig"),
            .target = target,
            .optimize = .safe,
            .imports = &.{.{ .name = "curves", .module = table_curves }},
        }),
    });
    const run_curves_table = b.addRunArtifact(curves_table);
    run_curves_table.setCwd(b.path("."));
    run_curves_table.has_side_effects = true;
    b.step(
        "curves-table",
        "Write src/curves_p256_base.bin, the P-256 table src/curves.zig embeds",
    ).dependOn(&run_curves_table.step);

    const run_curves_tests = b.addRunArtifact(curves_tests);
    const run_sha256_tests = b.addRunArtifact(sha256_tests);
    const run_tls_tests = b.addRunArtifact(tls_tests);
    const run_tests = b.addRunArtifact(tests);
    run_tests.setCwd(b.path(".")); // tidy reads the source trees
    // ...which the build system cannot see: without this, a change to a file
    // no test imports left the test binary as it was, the cached run was
    // reused, and tidy never looked.
    run_tests.has_side_effects = true;
    const test_step = b.step("test", "Run the fast tests (-Dfilter=AREA for one area)");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_curves_tests.step);
    test_step.dependOn(&run_sha256_tests.step);
    test_step.dependOn(&run_tls_tests.step);
}
