# zig-io-evented

Zig's `std.Io.Evented` for Linux (`lib/std/Io/Uring.zig`): green threads
(fibers) on io_uring with work stealing. Upstream calls it experimental,
and in 0.17.0 it cannot listen, accept, connect, or read and write
streams. We carry it, with those filled in, until upstream can serve;
then this directory is deleted and fourneau uses `std.Io.Evented`. The
interface is `std.Io` either way, so nothing that uses it changes.

How it is kept, the simplest way that works for one file:

1. `Uring.zig` is upstream's file from the Zig release named below, with
   our changes in place, each marked `// fourneau:` and saying why.
2. Our patch is the difference from upstream's file at that tag: fetch it
   (the URL below) and `diff` it against ours.
3. At a new Zig release: take the new upstream file, re-apply the patch,
   fix what the release changed, run the suite, and move the tag named
   below.

Upstream: Zig 0.17.0, `lib/std/Io/Uring.zig`
(https://codeberg.org/ziglang/zig/src/tag/0.17.0/lib/std/Io/Uring.zig).
License: MIT (`LICENSE`, Zig's).
