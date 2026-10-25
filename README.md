# fourneau

A web server in Zig, meant to face the internet alone: HTTP/1.1, HTTP/2 and TLS 1.3, with
certificates it obtains itself by ACME. One static binary; no dependencies beyond the Zig standard
library and what is vendored here. Leverages io_uring via `std.Io.Evented`.

*Fourneau*: the cast-iron range a kitchen is built around. Pronounced *ferno*, like *inferno*, without the *in*.

It serves the [dragrace](https://github.com/Eldhus/fourneau-dragrace) site on the internet with
nothing in front.


## Use it

As a Zig package, from a checkout beside yours (no releases yet):

```zig
.dependencies = .{ .fourneau = .{ .path = "../fourneau" } },
```

It exports `fourneau` (the server), `zig_io_evented` and `tidy`.
[roux](https://github.com/Eldhus/roux) is built on it. To try it alone, `fourneau-static` serves a
directory over HTTP/1.1, HTTP/2 and HTTPS:

```sh
zig build -Doptimize=ReleaseSafe
zig-out/bin/fourneau-static --root ./public --port 8080
```

Zig 0.17.0 (`.zig-version`); Linux 6.7 or later; for HTTPS, the kernel's `tls` module.


## The road ahead

- fourneau-static against Go's `FileServer`, tower-http's `ServeDir` and Caddy.
    - Ranges, conditional requests, `Accept-Encoding`.
- More differential cases.
    - Chunked trailers, many small chunks, a body split at every byte.
    - Pipelines past the receive buffer, HTTP/2 over h2c.
- Decide the runtime: Evented, a state-machine hybrid, or a small io_uring layer of our own.
- Idle connections at scale: 10k and 100k and 1M keep-alive or SSE.


## Working on it

```sh
zig build test                  # seconds
zig build sim -- --seeds 1000   # a simulator sweep
```

roux and the dragrace build against this checkout: a change to an exported module is checked by
building them too.


## Security

Report a problem by a private security advisory on GitHub, not an issue.
[SECURITY.md](SECURITY.md) says what a deployment holds.


## License

MIT. Vendored code keeps its own license, beside it in `vendor/`.

Part of [Eldhus](https://github.com/Eldhus).
