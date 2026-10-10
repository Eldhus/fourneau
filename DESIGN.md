# Design

The contract this repository is built to. It says what each part is for,
where its boundaries are and why. It changes when experience shows a goal,
an assumption or a boundary was wrong, and the change says what was
learned. How the work is ordered is [TODO.md](TODO.md) (Plan); how it is
tested is [TESTING.md](TESTING.md); how code is written is TigerStyle, as
the eldhus tigerstyle skill gives it.

## What this is

**fourneau**: a web server in Zig. HTTP/1.1, HTTP/2 and TLS 1.3, with its
own certificates from an ACME authority (Let's Encrypt), so that one
process can face the open internet with no proxy in front: what Go's
`net/http` with `autocert`, or axum with rustls, give a Go or Rust
program. It knows nothing of Roc.

Its first user is **roux** (github.com/Eldhus/roux), a Roc platform for
hypermedia apps: roux's host depends on this repository as a Zig package
and links the server into the app's one static executable. Where fourneau
sits, against the stacks it replaces:

| layer | Rust | Go | here |
|---|---|---|---|
| event loop, sockets | tokio | runtime, `net` | fourneau on `std.Io` (our Evented port) |
| HTTP protocol, connections | hyper, h2 | `net/http` server | fourneau |
| TLS, certificates | rustls, rustls-acme | `crypto/tls`, autocert | tls.zig + kTLS, fourneau `acme` |
| static files, compression | tower-http | `FileServer`, middleware | fourneau |
| framework: routing, errors, forms | axum | `ServeMux` | roux (Roc), not here |

The bar is the name's (README): built once, run all day under a full
load, lasting for decades.

## Goals, in order

1. **Safety.** Every input from the network is hostile. Every resource
   has a limit set at startup. Running out is a designed state (a refusal,
   a 503), never growth and never a crash. A bug is caught by an
   assertion and crashes the process before it can corrupt anything.
2. **Performance.** No allocation, no copy and no system call that the
   work does not need. Batch the work and keep the CPU busy. The measure
   is throughput and tail latency at saturation, not a peak number reached
   with unbounded memory.
3. **Developer experience.** One binary to deploy, nothing to configure
   for the common case, and errors that say what to do.

The horizon is twenty years. Protocols (RFC 9110, 9112, 9113, 8446, 8555)
outlive languages and libraries, so the protocol cores are the long-lived
code, and everything that touches a moving target (the Zig standard
library, the Roc ABI) sits behind one small module each.

## Ownership: no dependencies

We own everything that ships. The binary contains our code and the Zig
standard library (pinned: one Zig version, `.zig-version`); an app built
on it (roux) adds its own. Nothing is fetched at build time.

- **Third-party sources are vendored and pinned**, each with a chore to
  update it:
  - **zig-io-evented** (`vendor/zig-io-evented/`): upstream's
    `Io/Uring.zig` at the pinned release, with our changes marked
    `// fourneau:`.
  - **tls.zig** (`vendor/tls.zig/`, ianic/tls.zig, MIT): the TLS 1.3
    server handshake. The owner decided (2026-10-04) not to own a TLS
    protocol implementation; Zig's standard library has only a client,
    and tls.zig is the Zig community's, built on `std.crypto`.
- **Crypto primitives come from `std.crypto`**, through tls.zig and for
  ACME's signatures. Never written here.
- **Record encryption is the kernel's** (kTLS): after the handshake, the
  session keys go to the socket and Linux encrypts and decrypts. fourneau
  only ever sees plaintext.
- **Everything waits through `std.Io`, on our vendored `Io.Evented`.**
  `std.Io` is Zig's design and the right one: anything that blocks or
  introduces nondeterminism goes through an `Io` the program chooses,
  passed like an `Allocator` (TigerBeetle's determinism rule, made a
  language convention; the eldhus async-io skill has the reading of 0.17's
  source). Its event-driven implementation, `Io.Evented` (fibers on
  io_uring, work stealing: Go's model as a library), is "experimental"
  upstream, and in 0.17 it cannot listen, accept or stream. The owner
  chose to go evented anyway (2026-10-04): `vendor/zig-io-evented/` is
  upstream's file plus our patch that fills in the networking
  (the vendor README says how it is kept). When upstream can serve, the
  directory goes and fourneau uses `std.Io.Evented`; nothing else
  changes, since the interface is `std.Io` either way. Zig takes no
  LLM-assisted patches, so the port stays ours until then. Re-checked at
  every Zig release (Tickler).
- **Test-only tools may be anything**: the Go and axum servers
  fourneau-dragrace compares us with,
  `curl`, `openssl`, `h2spec`, Pebble. They never reach the binary.

## fourneau

### Layers

The protocol cores are state machines over bytes: they own no socket, no
clock and no thread, so each is tested alone, exhaustively. Everything
that waits is written as plain blocking-style code over `std.Io`, on
fibers, so the same server runs on any `Io`: our vendored io_uring
`Evented` in production, a deterministic simulator in tests (decided
2026-10-04: "go evented").

```
            ┌──────── a shard per core: one thread, one io_uring, no sharing ─┐
 kernel ◀──▶│ Io.Evented (vendor/zig-io-evented): fibers                      │
 (kTLS:     │                                                                 │
 plaintext) │  accept fiber ──▶ a fiber per connection:                       │
            │     [TLS handshake: tls.zig, then keys to the kernel]           │
            │     http1 | http2 (+hpack) ⇄ requests                           │
            │     static files, compression: answered here                    │
            │     the application (Roc): may block; its effects yield         │
            │  timekeeper fiber: one array of deadlines, scanned each tick    │
            │  acme fiber: certificates                                       │
            └─────────────────────────────────────────────────────────────────┘
```

- **io**: `std.Io`, the program's choice. Production is our vendored port
  of `Io.Evented` (io_uring fibers; upstream's cannot yet accept, connect
  or stream, ours can) until upstream can serve; tests use `sim_io.zig`,
  a deterministic `std.Io`. The server calls nothing else. Each shard's
  ring has 4,096 entries: Evented's default of 8 overflows both queues
  under load, at ~3,000 kernel cycles a request (experiment 23).
- **server** (`server.zig`): a fiber per connection, its memory a stride
  of slabs allocated at startup (receive buffer, header table, response
  head, response scratch). Deadlines are one array of `u32` ticks, set
  without reading the clock; a single timekeeper fiber scans it each tick
  and shuts expired sockets down, so the fiber waiting on one reads 0 and
  closes. Response heads are written without `std.fmt` (status lines
  built at comptime, a digit loop, table-driven header checks, the Date
  refreshed per tick; experiment 7). Pipelined responses are coalesced:
  the send buffer is flushed only before a read that may block
  (experiment 16). A handler may stream instead (server-sent events):
  a chunked head, then a chunk per send, waiting in the same buffer, so
  chunks made together go out together; the handler flushes before it
  waits on anything but its connection. A stream the handler leaves
  without its end (it failed, or the peer left) closes the connection
  without the last chunk: the client sees a response cut short, never a
  complete wrong one. The body is read before a stream starts.
- **http1**: request line, headers, `Content-Length` and chunked bodies,
  keep-alive. It is strict where looseness is how smuggling happens
  (RFC 9112 §6.3, §11.2): both `Content-Length` and `Transfer-Encoding`,
  conflicting lengths, bare CR, obsolete line folding, whitespace before
  a colon are refused, never guessed at.
- **tls** (`tls.zig`, M7): TLS 1.3 only (RFC 8446). The handshake is
  tls.zig's, run on the connection's own fiber (blocking-style code over
  `std.Io` streams, which is what a fiber runs), in memory the connection
  already has: before its first request its scratch holds tls.zig's two
  buffers. Then the keys go to the kernel (kTLS: AES-128-GCM,
  AES-256-GCM, ChaCha20-Poly1305) and the fiber reads and writes
  plaintext through the same io_uring path as HTTP. What the client sent
  behind its Finished (usually its first request) is decrypted in user
  space first, so the kernel's record counter starts after it. ALPN:
  `http/1.1` until HTTP/2 (M9). ECDSA P-256 certificates. No 0-RTT, which
  allows replay; no TLS 1.2, whose surface is most of TLS's history of
  attacks. Every response over TLS says `Strict-Transport-Security:
  max-age=31536000` (no `includeSubDomains`: a server speaks for its own
  host): the server's, like `Date`, so an application cannot drop or
  weaken it; never over plain HTTP. Known costs: the kernel's `tls`
  module must be loaded (an unprivileged server cannot make the kernel
  load it: the site host loads it at boot), checked at startup
  (`tcp_available_ulp`), so a server without it refuses to start rather
  than fail every handshake; a client gone before its keys reach the
  kernel is `PeerClosed` (ENOTCONN), routine. A kTLS socket refuses `MSG_WAITALL`, so HTTPS connections
  flush and then read rather than use the linked send-then-receive
  (experiment 18's +15%); a client's KeyUpdate closes the connection (the
  kernel will not decode it for us); no ML-KEM hybrid until tls.zig's
  server has one.
- **static files and compression** (M6; ETag today): answered in fourneau, never entering
  the application: ETag and Last-Modified, Range, precompressed variants,
  zero-copy sends (which kTLS keeps working over HTTPS). Responses are
  compressed with gzip (`std.compress.flate`) and brotli, whose encoder
  is ours (RFC 7932; the standard library has none). `fourneau-static` is
  a pure-Zig static file server on the same code: an example, and the
  differential target against Go's `FileServer`, tower-http's `ServeDir`
  and Caddy.
- **http2** (planned, M9; RFC 9113, HPACK RFC 7541): the reason is browsers, not
  benchmarks. A page with server-sent event streams (Datastar keeps one
  per tab) runs out of HTTP/1.1's six connections per origin. Priority
  signals are ignored (RFC 9113 §5.3.2 allows it). Every attack in the
  record (rapid reset, CONTINUATION floods, HPACK bombs, ping and
  settings floods, flow-control stalls) is a limit with a counter.
- **acme** (`acme.zig`, `acme_crypto.zig`, `der.zig`; M8; RFC 8555):
  the server obtains its own certificate, at startup, before any shard
  exists, when it has none with a third of its life left; renewal is a
  daily restart that renews only when due (Let's Encrypt's short-lived
  IP certificates live six days). The challenge is http-01, answered by
  a small responder on port 80 while the order is validated, not the
  tls-alpn-01 first planned: tls-alpn-01 needs the TLS server to switch
  certificates inside a handshake, and port 80 is open anyway to redirect
  browsers (owner may revisit). Account and certificate keys are P-256;
  requests are JWS (ES256); the CSR is our DER. State: an account key,
  the chain and the certificate key, written whole and renamed, 0600.

### Resources

The server's memory is allocated at startup from limits in `Config`, as
slabs every connection takes a stride of; nothing is allocated per
request. Limits a deployment has reason to change are configuration; the
rest are constants with a comptime assertion of how they relate.

Fibers are a pool too: our `Evented` reserves room for `fibers_max` of
them at startup, one mapping of address space (8 MiB of stack each over
a guard page, its header at the top beside the first frames so a wake
touches one place; experiment 22). A fiber is carved from it the first
time one more is needed, so an idle server's pool costs no memory, and
recycled after; beyond the pool, a task is refused, never allocated. A
server says what it needs (`Config.fibers_max`: a fiber per slot and the
timekeeper), and a program sums what runs on its `Io`; the simulator's
pool is exactly that, so every seed checks the count. No huge pages,
for the fibers (each touches a few KiB; transparent huge pages made it
2 MiB) or the slabs (they changed nothing; experiment 21).

Time comes from `Io`: `now` and `sleep`. In the simulator, time is ticks
the seed controls. Every timeout (head, idle keep-alive, body, send
progress, TLS handshake, drain) is a deadline in the timekeeper's array.

An application's own memory (Roc's heap, in roux) is not the server's: it
allocates per request and frees when done, through an allocator its host
owns and accounts.

### Threads: shards

A server is one **shard**: one OS thread, its own io_uring, its own
fibers, its own slabs and deadlines, sharing nothing. A machine runs one
shard per core, each listening on the same port with `SO_REUSEPORT`, so
the kernel spreads connections and no fiber ever moves between threads
(experiment 1: shared nothing beat work stealing by ~13%). Nothing in
a shard needs a lock or an atomic; `run` asserts it is never called on two
threads.

**The application runs on its connection's fiber.** An application call
that waits (reading the body, a sleep, an outgoing request) yields the
fiber instead of blocking the thread, so any number of handlers can wait
at once, as in Go. A call that blocks in the kernel (a SQLite query
reading the disk) holds its shard for its microseconds; measured before
anything is done about it.

The simulator runs a shard's fibers on one thread and switches only where
a fiber blocks: it explores every interleaving at yield points, which is
every interleaving a shard has. What does cross threads (an
application's shared context) is ThreadSanitizer's job on the real
server under load, run over fibers (the port tells it of every switch;
experiment 12, TESTING.md).

### fourneau is private

fourneau is roux's engine, with a clean boundary (its own repository, its
own tests, no Roc), not a library with a promised API (decided
2026-10-04; its own repository since 2026-10-06). A public API is a
twenty-year promise, made after the first rewrite if at all.

## Testing, in one paragraph

A protocol layer is tested alone, against its RFC's examples and
exhaustively over small inputs. The server is tested in the simulator:
one seed, many clients, a hostile network, every invariant checked every
tick, and any failure replays from its seed. fourneau-dragrace races it against Go's `net/http` and axum and will
compare their answers to the same requests (planned, `dragrace diff`). Details: [TESTING.md](TESTING.md).
