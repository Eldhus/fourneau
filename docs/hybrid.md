# The hybrid, for later

fourneau runs a fiber per connection on our vendored `std.Io.Evented`.
The **hybrid** is the alternative we built, measured and decided not to
adopt yet (owner, 2026-10-05): keep Evented for at least a month, revisit
on 2026-11-05 (TODO, Tickler). This page says what the hybrid is, what
the numbers were, and what would make us switch, in either direction.

## The two shapes

**Fiber per connection (now).** Every connection gets a fiber when it is
accepted and keeps it until it closes. The server is plain blocking-style
code over `std.Io`: read a head, call the handler, write the response,
loop. A handler that waits (a body, a database) just waits; its fiber
yields. Andrew Kelley's design, and the reason `std.Io` exists.

**The hybrid.** The server's own I/O is a state machine driving io_uring
directly: a connection is a few entries in flat arrays (descriptor, bytes
received, bytes to send) and two buffers, and completions move it along.
Handlers still run on fibers, but only while they run: a request takes a
fiber from a small last-in first-out pool when its head is in, and gives it
back when its response is written. Plain code where it pays (handlers),
explicit state where it is cheap (the connection's I/O). Seastar does the
same with `seastar::thread`; TigerBeetle goes further and has no fibers.

`fourneau/src/hybrid.zig` (`fourneau-hybrid`) is the hybrid as an
instrument: the real HTTP parser and response writer, `GET /` only, and
handlers inline or on pooled fibers (`--handler fiber`).

## What was measured

One physical core for the server (cpus 0-1), the loader on the other three,
256 connections, the server charged every non-idle nanosecond including
softirq (docs/benchmarks/2026-10-05-one-core.md).

First round, with fourneau on Evented's default **8-entry ring**:

| | user cycles/request | L1 misses | requests/s, unpipelined | pipelined (8) |
|---|---|---|---|---|
| fiber per connection | 1,957 | 52 | 341k | 1.62M |
| hybrid, pooled fiber | 1,074 | 12 | 378k | 1.97M |
| hybrid, inline | 925 | 10 | 402k | 2.09M |
| raw io_uring floor | 302 | 8 | 391k | 2.57M |

Then the first kernel profile (experiment 23) showed fourneau spending
~3,000 kernel cycles a request more than the hybrid: the 8-entry ring's
queues overflowed with hundreds of connections. With 4,096 entries,
interleaved runs:

| | user ns/request | kernel ns/request | unpipelined | pipelined (8) |
|---|---|---|---|---|
| fiber per connection | ~410 | ~6,000 | even | baseline |
| hybrid, pooled fiber | ~280 | ~6,000 | about +2% | +10-15% |

So the hybrid's real advantage is about 130 ns of user time a request:
cold memory (each connection's stack and fiber header) against one warm
fiber. It is worth little where the kernel dominates (a plain request on
loopback is ~85% kernel) and more where user code does: pipelining, and
HTTP/2's many streams per connection.

## Why keep Evented for now

- **We help Zig test it.** fourneau is a real workload for an
  implementation upstream calls experimental, and it finds things. This
  month: `std.Io.fiber.contextSwitch` miscompiled in ReleaseSafe (the
  message never reaches `rsi`); `net.Stream.read` does not compile; no
  networking at all ([#31723](https://codeberg.org/ziglang/zig/issues/31723));
  ThreadSanitizer needs the fiber annotations; reads and writes as
  RECVMSG/SENDMSG cost 10% against plain RECV/SEND; the fiber header 60
  MiB below its frames halved TLB efficiency; an 8-entry ring overflows
  under any real server load; the request-response turn wants a linked
  send-then-receive that `std.Io` cannot express. Each is an upstream
  report (from the owner: Zig takes no LLM-assisted contributions).
- **The gap is small now.** About +2% unpipelined, inside the noise of
  this laptop.
- **One style.** The whole server reads top to bottom; the hybrid has two
  styles, and the state machine must keep a buffer alive until the kernel
  is done with it, which is where use-after-free bugs live in io_uring
  code. Fibers give that for free: the fiber waits on its own stack.
- **Any `std.Io`.** The server runs on any implementation; the hybrid
  needs its own I/O layer (io_uring and a simulated one) and its own `Io`
  for handler waits.

## Why the hybrid may still win

- **Idle connections.** A parked fiber costs its touched stack pages (with
  right-sized stacks perhaps 8-16 KiB); a parked hybrid connection costs a
  few array entries. At 100k idle keep-alive or SSE connections that is
  a gigabyte against megabytes.
- **HTTP/2.** Many streams on one connection. On Evented it can be done as
  Go does it: the connection's fiber runs the framing loop, each stream's
  handler gets `io.concurrent`, a writer orders frames. That works, but
  every stream is a fiber; the hybrid's pool keeps only running handlers
  warm.
- **User time.** -32% per request measured, +10-15% pipelined.
- **Control.** Our I/O layer would be ~1-2k lines we wrote; the vendored
  port is 6,300 lines of someone else's experimental code that we patch.
  TigerBeetle owns its io_uring layer for the same reason.

## A third path: the hybrid on `std.Io`

One fiber per shard can hold every connection's pending receive in an
`Io.Batch` and wait on all of them (`awaitAsync`), with handlers still on
`io.concurrent`. That is the hybrid's shape expressed through `std.Io`,
so Evented stays in use, and a part of it that is little used. Our port
cannot do it yet: its batch path has `.net_read => @panic("TODO")`.
Implementing networking in Evented's batch support would itself be a
finding for upstream.

## Shards, either way

A shard is one core running a whole server: its own thread, single-threaded
Evented, io_uring ring, listening socket (`SO_REUSEPORT`) and connection
slots, sharing nothing but the app's read-only context. No locks or
atomics; the simulator models a shard exactly; +13% over work stealing
(experiment 1). Both shapes above are per shard.

## When to switch

Move to the hybrid if, at a revisit:

- HTTP/2 (M9) or SSE at scale is next and fibers per stream or per idle
  connection measure badly; or
- the hybrid's lead grows past ~10% unpipelined on the dragrace hardware;
  or
- Evented upstream stalls (no movement on networking or stack sizing) and
  the port becomes a burden.

Stay on Evented, and lean on it harder, if:

- [#157](https://github.com/ziglang/zig/issues/157) (a builtin for a
  function's maximum stack size, accepted in 2016, still open) lands: exact
  stacks pack densely, the locality cost shrinks, idle fibers get cheap;
- networking lands upstream ([#31723](https://codeberg.org/ziglang/zig/issues/31723))
  and our port can shrink toward upstream;
- the batch-based third path measures close to the hybrid.

Keep `fourneau-hybrid` building and in the benchmarks until then: it is the
yardstick for what the fibers cost.
