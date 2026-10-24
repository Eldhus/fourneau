# fourneau, HTTP/1.1 only

This branch is fourneau cut down to what an HTTP/1.1 application server on plain sockets needs: a
fiber per connection on io_uring (our port of `std.Io.Evented`), shards that share nothing, and
the server's limits, deadlines and eviction. TLS, ACME, HTTP/2, brotli, static files, streamed
responses and the simulator are not here; `master` has them. A chunked request body is refused
(411).

*Fourneau*: the cast-iron range a kitchen is built around. Pronounced *ferno*, like *inferno*, without the *in*.


## Use it

As a Zig package:

```zig
.dependencies = .{ .fourneau = .{ .path = "../fourneau" } },
```

It exports `fourneau` (the server) and `zig_io_evented` (the port, with `park` and `unpark` for
fibers of one thread that hand work to each other).

Zig 0.17.0 (`.zig-version`); Linux 6.7 or later.


## Working on it

```sh
zig build test                  # seconds
```


## Security

Report a problem by a private security advisory on GitHub, not an issue.


## License

MIT. Vendored code keeps its own license, beside it in `vendor/`.

Part of [Eldhus](https://github.com/Eldhus).
