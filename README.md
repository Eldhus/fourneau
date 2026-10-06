# fourneau

A web server in Zig, meant to face the internet alone: HTTP/1.1, HTTP/2
and TLS 1.3, with certificates it obtains and renews itself. No
dependencies beyond the Zig standard library and what is vendored here;
one static binary.

A *fourneau* is a kitchen's range: the cast-iron stove the kitchen is
built around, which runs all day under a full load and lasts for decades.
It cooks. Say *inferno*, drop the *in*.

It is the engine of [roux](https://github.com/Eldhus/roux), a Roc platform for
hypermedia apps, and it races Go and axum every night in
[fourneau-dragrace](https://github.com/Eldhus/fourneau-dragrace). Part of
[Eldhus](https://github.com/Eldhus).

Status: being built, milestone by milestone; the milestones and where it
stands are in [TODO.md](TODO.md). Today: HTTP/1.1 on io_uring, one shard per
core, on our port of `std.Io.Evented`, tested in a deterministic simulator.

## Build

```sh
zig build test                    # the suite: seconds
zig build test -Dfilter=http1     # one area
zig build sim -- --seeds 1000     # a simulator sweep
zig build                         # fourneau-hello, fourneau-static, ...
```

Zig 0.17.0 (`.zig-version`), Linux 6.1 or later (io_uring).

As a Zig package, it exports the modules `fourneau`, `zig_io_evented` and
`tidy` (roux's build uses all three).

## Working on it

Read first, in order: [DESIGN.md](DESIGN.md) (the contract),
[TESTING.md](TESTING.md), [TODO.md](TODO.md) (where work stands, the
milestones, what we doubt), the last entries of [DIARY.md](DIARY.md). The
style and the notes on Zig, async I/O and benchmarking are the eldhus
skills (`../eldhus-skill`).

- **Try hard to break it.** Every feature gets its refusals tested, its
  limits hit, and a place in the simulator.
- **Keep the loop fast.** `zig build test` stays at seconds; a slow test
  moves behind its own step or a filter.
- **Zig** is the release in `.zig-version`, installed beside others in
  `~/.local/share/zig/`; the `zig` on PATH may be older, so name it:
  `~/.local/share/zig/zig-x86_64-linux-$(cat .zig-version)/zig build test`.
- **roux depends on this repository.** A change to an exported module
  (`fourneau`, `zig_io_evented`, `tidy`) is checked by building roux too
  (`zig build platform` in `../roux`) before it is called done.
- Tooling is Zig; the Go and axum servers it is compared with live in
  fourneau-dragrace.
- **Zig bugs** found here go in the eldhus zig skill
  (`references/upstream.md`) for the owner to report (Zig takes no
  LLM-assisted contributions).
- **Security.** This server faces the internet. Crypto primitives come
  from `std.crypto` and are never written here. Anything that touches
  TLS, certificates or parsing of untrusted input gets its negative space
  tested before it is called done, and its open questions written in
  TODO.md.

## Read

- [DESIGN.md](DESIGN.md): what each part is for and why.
- [TESTING.md](TESTING.md): deterministic simulation, RFC vectors,
  and fuzzing (differential tests against Go and axum are
  fourneau-dragrace's).
- [TODO.md](TODO.md): where work stands, the milestones (Plan), and
  every decision we doubt with the experiment that would settle it.
- [DIARY.md](DIARY.md): what was done and learned, in order.
- [docs/hybrid.md](docs/hybrid.md): the state-machine/fiber hybrid, kept
  for later. [docs/benchmarks/](docs/benchmarks/) and
  [docs/research/](docs/research/): measurements and reading.
- [vendor/zig-io-evented/](vendor/zig-io-evented/): Zig's `Io.Evented`
  with the networking it lacks, and how the port is kept.
- [SECURITY.md](SECURITY.md): how to report a security problem.

## License

MIT (`LICENSE`). `vendor/zig-io-evented/` is Zig's code under Zig's MIT
license (its own `LICENSE`).
