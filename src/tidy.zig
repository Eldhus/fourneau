//! Tidy: the style rules a machine can check (TigerStyle, as the eldhus
//! tigerstyle skill gives it), run as a test.
//!
//! Every Zig source file of every tree is parsed with `std.zig.Ast`,
//! so function lengths and declarations come from the real syntax tree,
//! not from guessing at text. A rule enters with its violations fixed, or
//! ratcheted: a table of the old offenders that may only shrink.
//! (Adapted from the owner's DZV, which adapted TigerBeetle's.)

const std = @import("std");
const assert = std.debug.assert;

const Ast = std.zig.Ast;
const Allocator = std.mem.Allocator;

/// A directory of Zig sources with one test root that imports every file.
/// fourneau exports this file as the `tidy` module: roux checks its host's
/// tree with the same rules (`check`).
pub const Tree = struct {
    /// Relative to the repository root, where the test runs.
    dir: []const u8,
    /// Files no other file imports: entry points and the test root.
    roots: []const []const u8,
    /// Files the test root need not import (they cannot build in a test).
    untested: []const []const u8,
    /// Generated files: not ours to format or lint.
    generated: []const []const u8,
    /// Files that implement an interface of `std`'s or an ABI (see
    /// `banned`): indirection is their design. Each says why where listed.
    interfaces: []const []const u8,
};

const trees = [_]Tree{
    .{
        .dir = "src",
        .roots = &.{ "tests.zig", "hello.zig", "load.zig" },
        .untested = &.{ "tests.zig", "hello.zig" },
        .generated = &.{},
        // sim_io.zig: a deterministic std.Io, so a vtable of its own.
        .interfaces = &.{"sim_io.zig"},
    },
};

const columns_max = 100;
/// TigerStyle's limit: a function fits on a screen.
const function_lines_max = 70;
/// A source file larger than this is a mistake (a generated file, a dump).
const file_bytes_max = 1 << 22;
/// Files per tree: a bound for the directory walk.
const files_per_tree_max = 512;

/// Functions over `function_lines_max` lines, with their length when they
/// were entered. A ratchet (TigerBeetle's): no function may grow past the
/// limit or past its entry here; one that shrinks lowers its entry, and
/// leaves the table once it fits.
const long_functions = [_]struct { file: []const u8, name: []const u8, lines: u32 }{};

/// Text that must not appear in the code, and why. Assembled so that this
/// file does not match itself.
/// `indirection`: banned except in files that implement an interface of
/// `std`'s, which is a table of function pointers over opaque userdata by
/// its own design (`std.Io`): each tree lists those files in `interfaces`.
const banned = [_]struct { text: []const u8, why: []const u8, indirection: bool = false }{
    .{ .text = "Self = " ++ "@This()", .why = "give @This() a real name" },
    .{ .text = "== " ++ "error.", .why = "switch on the error" },
    .{ .text = "!= " ++ "error.", .why = "switch on the error" },
    .{ .text = "std.debug." ++ "assert(", .why = "import assert unqualified" },
    .{ .text = "using" ++ "namespace", .why = "name what you use" },
    .{ .text = "FIX" ++ "ME", .why = "fix it before the commit; TODO is for later" },
    .{
        .text = "any" ++ "opaque",
        .why = "no hidden indirection: pass the type",
        .indirection = true,
    },
    .{
        .text = "*const " ++ "fn",
        .why = "no function pointers: a switch, or comptime",
        .indirection = true,
    },
    .{ .text = "std." ++ "Random", .why = "prng.zig: a seed must mean the same forever" },
};

const File = struct {
    tree: *const Tree,
    name: []const u8,
    text: [:0]const u8,
    ast: Ast,
};

test "tidy: the code obeys the rules a machine can check" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const problems = try check(arena_state.allocator(), std.testing.io, &trees);
    try std.testing.expectEqual(@as(u32, 0), problems);
}

/// The trees' problems, each printed; 0 when the code obeys every rule.
pub fn check(arena: Allocator, io: std.Io, tree_list: []const Tree) !u32 {
    assert(tree_list.len > 0);
    assert(tree_list.len <= trees_max);
    var problems: u32 = 0;
    var trees_files: [trees_max][]const File = undefined;
    for (tree_list, trees_files[0..tree_list.len]) |*tree, *files| {
        files.* = try read_files(arena, io, tree);
    }
    // A name used in any of the trees is used.
    const uses = try count_uses(arena, trees_files[0..tree_list.len]);
    for (tree_list, trees_files[0..tree_list.len]) |*tree, files| {
        for (files) |f| {
            if (contains(tree.generated, f.name)) continue;
            problems += check_format(arena, f);
            problems += check_lines(f);
            problems += check_functions(f);
        }
        problems += check_dead(&uses, files);
        problems += check_imports(files);
    }
    return problems;
}

const trees_max = 8;

fn read_files(arena: Allocator, io: std.Io, tree: *const Tree) ![]const File {
    var dir = try std.Io.Dir.cwd().openDir(io, tree.dir, .{ .iterate = true });
    defer dir.close(io);

    var files: std.ArrayList(File) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        assert(files.items.len < files_per_tree_max);
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig")) continue;
        const limit: std.Io.Limit = .limited(file_bytes_max);
        const text = try dir.readFileAllocOptions(io, entry.name, arena, limit, .of(u8), 0);
        try files.append(arena, .{
            .tree = tree,
            .name = try arena.dupe(u8, entry.name),
            .text = text,
            .ast = try Ast.parse(arena, text, .{ .mode = .zig }),
        });
    }
    std.mem.sort(File, files.items, {}, struct {
        fn less(_: void, a: File, b: File) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    assert(files.items.len > 0);
    return files.items;
}

fn problem(f: File, line: usize, comptime fmt: []const u8, args: anytype) u32 {
    std.debug.print("{s}/{s}:{}: " ++ fmt ++ "\n", .{ f.tree.dir, f.name, line } ++ args);
    return 1;
}

/// The file parses and is exactly what `zig fmt` would write.
fn check_format(arena: Allocator, f: File) u32 {
    if (f.ast.errors.len > 0) return problem(f, 0, "does not parse", .{});
    const formatted = f.ast.renderAlloc(arena) catch |err| switch (err) {
        error.OutOfMemory => @panic("tidy: out of memory"),
    };
    if (std.mem.eql(u8, formatted, f.text)) return 0;
    return problem(f, 0, "is not formatted: run zig fmt", .{});
}

/// Line length, banned text and blank lines after defer blocks.
fn check_lines(f: File) u32 {
    var problems: u32 = 0;
    var it = std.mem.splitScalar(u8, f.text, '\n');
    var number: usize = 0;
    var defer_indent: ?usize = null; // inside a multi-line defer block
    var after_defer = false;
    while (it.next()) |line| {
        number += 1;
        const columns = std.unicode.utf8CountCodepoints(line) catch line.len;
        if (columns > columns_max) {
            problems += problem(f, number, "{} columns, over {}", .{ columns, columns_max });
        }
        for (banned) |b| {
            if (b.indirection and contains(f.tree.interfaces, f.name)) continue;
            if (std.mem.indexOf(u8, line, b.text) != null) {
                problems += problem(f, number, "\"{s}\": {s}", .{ b.text, b.why });
            }
        }
        const trimmed = std.mem.trimStart(u8, line, " ");
        const indent = line.len - trimmed.len;
        if (after_defer and trimmed.len > 0 and trimmed[0] != '}') {
            problems += problem(f, number, "a blank line after a defer block", .{});
        }
        after_defer = false;
        if (defer_indent) |d| {
            if (indent == d and std.mem.startsWith(u8, trimmed, "}")) {
                defer_indent = null;
                after_defer = true;
            }
        } else if (std.mem.endsWith(u8, trimmed, "{") and is_defer(trimmed)) {
            defer_indent = indent;
        }
    }
    return problems;
}

fn is_defer(trimmed: []const u8) bool {
    return std.mem.startsWith(u8, trimmed, "defer ") or
        std.mem.startsWith(u8, trimmed, "errdefer ");
}

/// No function grows past `function_lines_max`, or past its ratchet entry.
fn check_functions(f: File) u32 {
    var problems: u32 = 0;
    const ast = &f.ast;
    for (0..ast.nodes.len) |i| {
        const node: Ast.Node.Index = @fromBackingInt(@as(u32, @intCast(i)));
        if (ast.nodeTag(node) != .fn_decl) continue;
        const first = line_of(ast, ast.firstToken(node));
        const lines: u32 = @intCast(line_of(ast, ast.lastToken(node)) - first + 1);
        const name = fn_name(ast, node);
        // A function returning a type is a namespace (`ServerType`), not
        // code to fit on a screen: its functions are checked one by one.
        if (returns_type(ast, node)) continue;
        if (ratchet_entry(f.name, name)) |entry| {
            if (lines > entry) {
                problems += problem(f, first, "fn {s} grew to {} lines; the ratchet says {}", .{
                    name, lines, entry,
                });
            } else if (lines < entry) {
                problems += problem(f, first, "fn {s} shrank to {} lines: lower its entry", .{
                    name, lines,
                });
            }
        } else if (lines > function_lines_max) {
            problems += problem(f, first, "fn {s} is {} lines, over {}", .{
                name, lines, function_lines_max,
            });
        }
    }
    return problems;
}

fn returns_type(ast: *const Ast, node: Ast.Node.Index) bool {
    var buffer: [1]Ast.Node.Index = undefined;
    const proto = ast.fullFnProto(&buffer, node).?;
    const return_type = proto.ast.return_type.unwrap() orelse return false;
    if (ast.nodeTag(return_type) != .identifier) return false;
    return std.mem.eql(u8, ast.tokenSlice(ast.nodeMainToken(return_type)), "type");
}

fn fn_name(ast: *const Ast, node: Ast.Node.Index) []const u8 {
    var buffer: [1]Ast.Node.Index = undefined;
    const proto = ast.fullFnProto(&buffer, node).?;
    return if (proto.name_token) |t| ast.tokenSlice(t) else "(anonymous)";
}

fn ratchet_entry(file: []const u8, name: []const u8) ?u32 {
    for (long_functions) |entry| {
        const match = std.mem.eql(u8, entry.file, file) and std.mem.eql(u8, entry.name, name);
        if (match) return entry.lines;
    }
    return null;
}

/// The 1-based line of a token.
fn line_of(ast: *const Ast, token: Ast.TokenIndex) usize {
    const offset = ast.tokenStart(token);
    return 1 + std.mem.count(u8, ast.source[0..offset], "\n");
}

const Uses = std.StringHashMapUnmanaged(u32);

/// How often each identifier appears, across every tree.
fn count_uses(arena: Allocator, trees_files: []const []const File) !Uses {
    var uses: Uses = .empty;
    for (trees_files) |files| for (files) |f| {
        const ast = &f.ast;
        for (0..ast.tokens.len) |i| {
            const token: Ast.TokenIndex = @intCast(i);
            if (ast.tokenTag(token) != .identifier) continue;
            const got = try uses.getOrPut(arena, ast.tokenSlice(token));
            got.value_ptr.* = if (got.found_existing) got.value_ptr.* + 1 else 1;
        }
    };
    return uses;
}

/// Every function and file-level constant is used somewhere: its name
/// appears as an identifier at least once beyond its declaration.
fn check_dead(uses: *const Uses, files: []const File) u32 {
    var problems: u32 = 0;
    for (files) |f| {
        if (contains(f.tree.generated, f.name)) continue;
        const ast = &f.ast;
        for (0..ast.nodes.len) |i| {
            const node: Ast.Node.Index = @fromBackingInt(@as(u32, @intCast(i)));
            const name_token = declared_name(ast, node) orelse continue;
            const name = ast.tokenSlice(name_token);
            if (std.mem.eql(u8, name, "main")) continue;
            if (is_exported(ast, node)) continue;
            if ((uses.get(name) orelse 0) < 2) {
                problems += problem(f, line_of(ast, name_token), "{s} is never used", .{name});
            }
        }
    }
    return problems;
}

/// An `export fn` is used by the linker, not by Zig code.
fn is_exported(ast: *const Ast, node: Ast.Node.Index) bool {
    const first = ast.firstToken(node);
    return ast.tokenTag(first) == .keyword_export;
}

/// The name a function or a file-level constant declares, if any.
fn declared_name(ast: *const Ast, node: Ast.Node.Index) ?Ast.TokenIndex {
    switch (ast.nodeTag(node)) {
        .fn_decl => {
            var buffer: [1]Ast.Node.Index = undefined;
            return ast.fullFnProto(&buffer, node).?.name_token;
        },
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            const is_root = for (ast.rootDecls()) |d| {
                if (d == node) break true;
            } else false;
            if (!is_root) return null;
            return ast.fullVarDecl(node).?.ast.mut_token + 1;
        },
        else => return null,
    }
}

/// Every file but the roots is imported by another, and the test root
/// imports every file it can build, so no test is silently left out.
fn check_imports(files: []const File) u32 {
    var problems: u32 = 0;
    const tests: ?File = for (files) |f| {
        if (std.mem.eql(u8, f.name, "tests.zig")) break f;
    } else null;
    for (files) |f| {
        var import_buffer: [128]u8 = undefined;
        const import = std.fmt.bufPrint(&import_buffer, "@import(\"{s}\")", .{f.name}) catch
            unreachable; // file names here are short
        if (!contains(f.tree.roots, f.name)) {
            const used = for (files) |g| {
                if (g.name.ptr == f.name.ptr) continue;
                if (std.mem.indexOf(u8, g.text, import) != null) break true;
            } else false;
            if (!used) problems += problem(f, 0, "is imported by no other file", .{});
        }
        const untested = contains(f.tree.untested, f.name);
        const test_root = tests orelse continue; // a tree without one: nothing to check
        if (!untested and std.mem.indexOf(u8, test_root.text, import) == null) {
            problems += problem(f, 0, "is not imported by tests.zig: its tests never run", .{});
        }
    }
    return problems;
}

fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}
