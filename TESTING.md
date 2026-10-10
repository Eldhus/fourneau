# Testing

How fourneau is tested, beyond the rule every Eldhus repository follows
(the tigerstyle skill: no test may fail by timing or chance; every
source of nondeterminism comes in from outside, fixed by a seed). Here
those sources are the clock, randomness, the network and the order of
completions; a failing run prints its seed and replays from it.

## The flywheel

The speed of the loop from an edit to a verdict is the speed of the whole
project, so the suite is built to be fast and to be cut:

| command | what | budget |
|---|---|---|
| `zig build test` | every unit, exhaustive and RFC-vector test, tidy, a short simulator sweep | seconds |
| `zig build test -Dfilter=http1` | only tests whose name contains `http1` | under a second |
| `zig build sim -- --seed N` | one simulator run, replayed exactly | a second |
| `zig build sim -- --seeds 1000` | a sweep; exits 127 crash, 128 liveness, 129 correctness | minutes |
| `zig build test -Dfilter=fuzz -Dtest-optimize=safe --fuzz=N` | Zig's coverage-guided fuzzer on the parsers, N runs (LLVM builds only: Debug has no coverage instrumentation) | minutes |
| `zig build brotli-check -Doptimize=ReleaseSafe -- 2000` | brotli: inputs from 2,000 seeds (random, runs, dictionary words, copies of themselves, up to 400 KB), encoded by us, decoded by our decoder and the reference `brotli` (on PATH) | minutes |

| `h2spec -h 127.0.0.1 -p PORT -P /echo --strict` against `fourneau-hello` | HTTP/2 conformance, 147 cases (h2spec v2.6.0 built from its tag: `go build ./cmd/h2spec`, its module cache kept out of `~`): 146 every run. The one left: "invalid connection preface", since h2c and HTTP/1.1 share the port, so bytes that are not the preface get HTTP/1.1's 400, which h2spec reads as a frame. `/echo` reads the whole body before answering: against a handler that answers first, two cases race (below) | a second |
| `h2spec ... -t -k --strict` against `fourneau-static --cert --key` | the same over TLS, ALPN choosing h2: 147, or 146. The site answers without reading a body, and a response complete before the client's END_STREAM resets the stream with NO_ERROR (RFC 9113 §8.1; Go does the same), so frames h2spec sends after its HEADERS to provoke an error (a body longer than its content-length, a window past 2^31-1) are discarded when they arrive after the answer: it depends on TCP's segments | a second |

Tests compile Debug by default, fast to build, every assertion on;
`-Dtest-optimize=safe` for an optimised run. Test
names start with their area: `test "http1: chunked: size line overflow"`,
so `-Dfilter` selects an area or a single case.

## Layers, and where each test lives

1. **Protocol cores, alone** (`src/*.zig`, next to the code).
   Each is a state machine over bytes, so it is tested without sockets:
   - **RFC vectors**: chunked and message examples from RFC 9112; HPACK
     (RFC 7541 Appendix C); HTTP/2's refusals as RFC 9113 and h2spec name
     them (`http2.zig`); planned, the TLS 1.3 handshake traces (RFC 8448,
     M7) byte for byte.
   - **Exhaustive over small domains**: every split of a request into two
     reads parses the same as the whole; every byte value in every
     header position is accepted or refused as the grammar says.
   - **Model tests**: a structure next to a naive model, compared on
     every operation (the slot table against an array scan; planned, the
     HPACK table against a list).
   - **Negative space**: every refusal has a test. The edge cases are
     gathered from hyper and axum's test suites and the smuggling
     literature, then each becomes a named test here.
2. **The server in the simulator** (`src/sim.zig` on
   `sim_io.zig`). The real server, unchanged, on a deterministic
   `std.Io`: real fibers on one OS thread, scheduled by the seed, over a
   seeded network that fragments reads, splits writes and delays every
   operation; clients that send valid, invalid and adversarial traffic
   (slowloris, pipelining, idle keep-alives, abandoned and reset
   connections); time in ticks. Each run:
   - checks the server's slot accounting after every tick;
   - checks every response against a model of what the server should
     have said (the simulated app is deterministic, so the model knows);
   - **swarm**: the seed also picks the configuration (slot counts,
     limits, timeouts, window sizes, latencies), so small limits are hit;
   - ends when every client is done and every connection closed, within
     a bound of ticks (128 otherwise: liveness).
   The canary fails on purpose, to prove the sweep catches failures; a
   seed that ever failed becomes a named test. Tested itself by injected
   bugs: 8 of 9 caught (DIARY 2026-10-05).

   **Its limit, stated plainly:** fibers switch only where one blocks, so
   the simulator explores every interleaving at yield points and none
   between two plain statements on two threads. Production is the same
   shape: a server is one shard on one thread (it asserts so), so the
   simulator models a shard exactly. Cross-thread races (the ninth mutant
   was one, from the work-stealing days) cannot happen inside a shard.
   **ThreadSanitizer** checks what is left on the real server under load: `zig build -Dsanitize-thread
   -Doptimize=safe`, then fourneau-hello under fourneau-load; the port
   tells it about every fiber switch. It finds data races (an injected
   unsynchronised counter: reported, with fiber stacks), not logic races
   between correctly synchronised accesses: the ninth mutant is one, and
   only shared nothing removes it.
3. **The server on a real socket** (`src/smoke.zig`, not yet; few and
   fast): io_uring against the kernel through our `Io.Evented`, `curl`,
   `openssl s_client` and
   Zig's own TLS client as outside opinions.
4. **Applications on fourneau** are tested in their own repositories: roux
   runs each platform feature as an example app over a real listener.

## Memory safety: the plan

Zig is not memory safe by proof; it makes classes of bugs rarer and loud
(Andrew Kelley calls safety a spectrum: most of the benefit across many
classes, not a guarantee in one or two). Our layers, each with its test:

| bug | defence | where it is checked |
|---|---|---|
| out of bounds | Zig's bounds checks: tests and the simulator build Debug or Safe; the host ships Safe | every test, the sweep, production |
| use after free, server | none possible on the heap: the server allocates only at startup. The analogue is a reused connection slot; slots are checked by `check_invariants` between simulator steps | simulator |
| leaks, Zig | `std.testing.allocator` in every test (leak report with traces); `std.testing.checkAllAllocationFailures` for code that allocates (startup), so each failing allocation is tried and must not leak | unit tests |
| stack overflow | fiber stacks with guard pages, in the simulator and the port | simulator, production |
| undefined memory | Debug fills it with `0xaa`; assertions on state read where written | tests |
| data races | shared nothing: a shard is one thread; what an application shares across shards is its own (roux: the Roc context and heap). ThreadSanitizer, told about fiber switches (`fourneau-hello`), for the rest | load runs |
| parser bugs | coverage-guided fuzzing (`--fuzz`), the simulator's swarm | fuzz runs, sweep |

## Differential testing: Go and axum

fourneau-dragrace's (planned, `dragrace diff`; its TODO has the plan): the
same seeded requests to fourneau, Go's `net/http` and axum, the servers it
already builds and races, and their answers compared. It is a second
opinion that finds what we did not think to ask, not the source of truth:
the RFCs are.
