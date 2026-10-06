# Diary

What was done, measured and learned, in order. Newest last. Each entry:
what and why, the numbers with their command, what it changes next.

## 2026-10-04: the first day of twenty years

The owner decided to leave the basic-webserver fork behind and build a
server of our own in Zig, facing the internet alone: HTTP/1.1, HTTP/2,
TLS 1.3, ACME. A single-binary deploy, like Go or axum, with no Caddy or
HAProxy in front. The Roc platform (then rocstache, now roux) moves onto it.

**The name.** fourneau: the kitchen range. Cooking, French, and no web
server has the name (a search found a GitHub user and a surname, no
software). The repository is `rocstache-fourneau` (renamed `roux` on
2026-10-05): rocstache, re-rooted on fourneau.

**What was checked before deciding the shape:**
- Zig 0.16's standard library has everything below the protocols:
  `std.os.linux.IoUring`; X25519, ML-KEM-768, P-256 ECDSA signing,
  AES-GCM, ChaCha20-Poly1305, HKDF, SHA-2; X.509 parsing
  (`std.crypto.Certificate`); and the TLS constants. Its TLS is a client
  only, so the server handshake is ours to write. Its HTTP server is
  HTTP/1.1 only and allocates as it pleases, so it is not used.
- `roc glue` with the pinned nightly's `ZigGlue.roc` (extracted from the
  roc repository at f45bfbe, the nightly's commit) generates a Zig ABI
  for the current platform (9.9k lines, in 2.4 s). The host contract is
  small: the host exports `main` and `roc_alloc`, `roc_dealloc`,
  `roc_realloc`, `roc_dbg`, `roc_expect_failed`, `roc_crashed`, and the
  `hosted_*` effects; it calls `roc_init_for_host`,
  `roc_respond_for_host` and the rest. So a Zig host is plain work, not
  research.
- What the apps use of the old platform: `Rocstache` (50 imports),
  `Server` (48), `Env`, `Sqlite`, `Stdout`, `Path`, `UnixTime`, `Sse`,
  `Sleep`, `Url`, `MultipartFormData`. `Http`, `Tcp`, `Cmd`, `File`,
  `Html`, `Attribute`, `OsStr` appear only in examples. They are not
  migrated (DESIGN.md: a module returns when an app needs it).

**Decisions, and why** (DESIGN.md has them in full):
- Our own io layer over io_uring, not `std.Io`: it was redesigned last
  release and will move again; a server needs five operations; and the
  simulator must implement the same interface.
- Protocol layers are state machines over bytes (no sockets, no clock),
  so each is tested alone and the whole server runs in the simulator.
- One thread per core, each a whole server with `SO_REUSEPORT`, and the
  Roc handler called synchronously on the loop thread. No locks. The
  cost (a slow handler stalls its thread's other connections) is written
  down, with the remedy if measurement shows it matters.
- TLS 1.3 only, ECDSA P-256 certificates, no 0-RTT.
- SQLite stays, vendored, the one third-party source. Writing a
  database is not this project; owning the copy is enough.

## 2026-10-04: M0 and M1, the kitchen and HTTP/1.1 alone

**M0.** The repository, its documents, one `build.zig`, tidy (from DZV,
now walking several source trees and skipping generated files), and the
PRNG (from DZV). Tidy caught three problems on its first run.

**The flywheel, measured.** `zig build test` with ReleaseSafe (LLVM)
took 22 s to compile and run a handful of tests; Debug (Zig's own
backend) takes 0.9 s, with every safety check still on. Tests default to
Debug; simulator sweeps, which run long rather than compile often, will
use ReleaseSafe. With all of M1 in, the suite is 1.0 s.

**M1.** Three sans-IO pieces: the request head parser
(`http1_head.zig`), the chunked decoder (`http1_chunked.zig`), and the
response head writer with the date (`http1_response.zig`,
`http_date.zig`). 46 tests.
- Edge cases came from hyper's `role.rs` and `decode.rs` and httparse's
  request tests, read for their ideas, then decided for ourselves.
  Where hyper is lenient we are strict, and those are expected
  differential divergences (to go in `reference/DIVERGENCES.md`):
  equal duplicate `Content-Length` (hyper accepts; we 400),
  `Transfer-Encoding: gzip, chunked` (hyper passes gzip up; we 501),
  `Content-Length` with `Transfer-Encoding` (hyper uses chunked and
  closes after; we 400), whitespace alone after a chunk size (hyper
  accepts; we 400), bare LF line endings (hyper accepts; we 400).
- The property that matters most for a resumable parser is that how the
  bytes arrive cannot change the answer. Every head test parses its
  input whole and in every two-read split; every chunked test whole, in
  every split, a byte at a time, and with one byte of output room at a
  time. All agree.
- Exhaustive mutation: every byte value at every position of a valid
  request (61 × 256) and a valid chunked body: nothing crashes, and every
  accepted result satisfies the invariants (tokens are tokens, values
  have no controls, lengths within limits).
- The date is checked against a day-by-day calendar walk for 600 years.
- All four pieces passed their tests on the first run; the failures
  were in the tests themselves (an extension longer than the test's own
  limit, an empty range). Next time: write the limit next to the case.

**Next (M2):** the io layer (io_uring and simulated), the server with
connection slots, and the simulator. The body-buffer question is open:
a 1 MiB body limit times 1024 connections is 1 GiB, so bodies need a
separate, smaller pool of large buffers (acquired when a body arrives,
503 when none is free), as TigerBeetle's IOPS pools work.

## 2026-10-04: M2, the server real and simulated

**The server** (`server.zig`, `io_linux.zig`, `hello.zig`) worked against
curl on its first run: keep-alive, chunked bodies, pipelining, HEAD, the
smuggling refusal. 324k requests/s on one thread, p99 0.28 ms, 11.5 MB
resident (`oha -z 5s -c 64`, same machine).

**The simulator** (`io_sim.zig`, `sim_client.zig`, `sim.zig`). Every
failure on the way to green was in the model, not the server, and each
taught a rule now written in `sim_client.zig`:
- a connection's entry must outlive the server's close operation, not
  just its submission (io_sim);
- a final response to an earlier pipelined request does not end the
  current request's wait for 100;
- "fast" must mean limited by the window, not by piece size, or a fast
  client with 1-byte pieces is timed out;
- pausing clients still read, or the server's send stalls and is
  (correctly) timed out;
- a bad chunk can be answered 503 before 400, since the server needs a
  body buffer to read it.
One real server gap came from writing the model: a chunked request with
`Expect: 100-continue` never got its 100.

**Measured.** 10,000 seeds: 995k requests, 195k refusals, 7.9k 503s,
126k timeouts, 174k evictions, all answered as the model says, in 41 s.

**Testing the tests.** Eight bugs injected into the server, one at a
time, each against 300 seeds; all eight caught:

| mutant | caught as |
|---|---|
| parser not reset between requests | crash (assertion) |
| request end forgets body bytes taken from the receive buffer | wrong response |
| partial send treated as whole | truncated response |
| eviction of fresh connections | closed without response |
| no 100 for chunked bodies | closed without response (body timeout) |
| HEAD sends its body | unsolicited bytes |
| `Connection: close` ignored | wrong response (close flag) |
| refusal leaks its body buffer | crash (accounting invariant) |

**Next.** The owner asked to stop and think about shape before going
further: the level of abstraction, the feature set and the APIs.

## 2026-10-04: the shape, settled with the owner

The owner stopped the work to ask whether the level of abstraction was
right. basic-webserver was hyper, hyper-util and tokio directly; axum was
never in it. fourneau is that layer (tokio + hyper + rustls + ACME), and
roux is the axum layer, written in Roc. The level is right; FEATURES
now says which rows are which, and DESIGN has the layer table.

Decisions (DESIGN.md has each in full):
- **Workers run Roc.** A Roc effect is a native call that blocks the
  thread running Roc (Roc has no async), so Roc cannot share a thread
  with the network. basic-webserver had this right (a fixed worker pool
  and bounded queue); we keep the model without tokio, channels or locks:
  a fixed ring between loops and workers. Go and axum let any number of
  handlers wait; ours is a bounded resource.
- **Bodies are pulled through effects** (`read_all!(limit)`, file sinks,
  streamed multipart): each route chooses its limit and destination,
  and can refuse before a byte of body is read. This requires the
  workers, which is why the two were one decision.
- **TLS is tls.zig plus the kernel.** The owner does not want to own a
  TLS implementation. Zig's standard library has only a client; ianic's
  tls.zig (MIT, TLS 1.3 server, ALPN, maintained) does the handshake on
  a bounded handshake pool, and the keys go to kTLS, so the loop only
  ever sees plaintext and zero-copy file sends survive HTTPS. Costs
  written down: the kernel's `tls` module, KeyUpdate closes, no ML-KEM
  hybrid until tls.zig's server has one. tls.zig's main branch moved to
  Zig 0.17 yesterday; we take its last 0.16 version (fe60069 or later
  before the 0.17 commit).
- **Static files and compression are fourneau's**; roux declares
  them. gzip from the standard library, brotli from our own encoder.
  `fourneau-static`, a pure-Zig file server, is both an example and the
  differential target against Go, tower-http and Caddy.
- **fourneau is private**: a clean boundary, no promised API.
- **No release gate.** 2027 is exploration. PLAN.md now orders the work
  without a "before deploy" line.

The owner also asked not to go deeper into testing yet: the simulator
stays where M2 left it, and grows only with features.

## 2026-10-04: Zig 0.17.0 and the latest Roc nightly

The owner asked to always use the latest Zig and Roc. Zig 0.17.0 was
released 2026-10-01 (master is 0.18.0-dev); the newest Roc nightly is
2026-10-04-130536d. Both are installed beside the older ones, since the
global `zig` and `roc` serve the owner's other projects.

The migration, all mechanical: `OptimizeMode` became `Optimize` with
short tags (`.debug`, `.safe`); `b.args` became `addPassthruArgs()`;
the `**` operator is gone (`@splat` for filled arrays, a comptime
`stdx.repeat` for strings); `@intFromEnum`/`@enumFromInt` became
`@backingInt`/`@fromBackingInt`, which want the exact backing type
(`Kind` is now `enum(u8)`); `std.meta.Int` became `@Int`;
`std.meta.fields` gave way to `@typeInfo(T).@"struct".field_names`;
`Ast.parse` takes an options struct.

**The seeds survived the compiler.** A 1000-seed sweep gives exactly the
same totals on 0.17 as on 0.16 (99,210 requests, 19,545 refusals, 15,739
evictions...). That is what owning the PRNG bought.

`sync.zig` is deleted: Zig wants synchronisation through `std.Io` so it
works with whatever Io the program chose, and the workers will run Roc's
effects on `Io.Threaded` anyway; the exchange uses `std.Io.Mutex` and
`Condition` on that instance.

## 2026-10-04: could we finish Io.Evented ourselves? An experiment

The owner asked whether completing Zig's io_uring `Io.Evented` was too
much scope, whether it would mean recompiling Zig, or whether we could
port it with the same interface. Measured, in a scratch directory:

- **No recompiling.** The standard library is compiled from source with
  every program, and `std.Io` is a pointer and a table of functions; our
  own implementation is a struct whose `io()` returns one, and every
  library written against `std.Io` uses it unchanged.
- **0.17's own `Io/Uring.zig` does not compile against 0.17's `Io`**
  (it sets two fields the interface dropped and lacks two it gained):
  Zig compiles lazily, so nothing notices until someone uses it. Four
  small fixes made a copy compile outside the standard library.
- **The networking holes**: listen, accept, connect, stream read, stream
  write, send, sendfile, Unix sockets, DNS are all stubs (`NetworkDown`,
  or `@panic("TODO")`); only datagram-style receive works. Listen,
  accept, stream read and stream write took about 170 lines in its own
  style (fill a submission, `yield` the fiber, map the errno).
- **It works**: a fiber-per-connection HTTP server on the port answered
  curl three times out of three (`docs/evented-port/`: the patch
  and the test server).

The verdict for now: the networking is small; the rest is not. Upstream
calls the backend experimental, short of error handling and tests; we
would carry 6,300 lines of someone else's experimental runtime, with
60 MiB fibers allocated on demand (against static allocation), work
stealing (against determinism), and a file that went stale even between
two releases. Zig bans LLM-assisted contributions, so none of this could
go upstream: it would be a fork for as long as we used it. It stays an
experiment for 2027 (Todo), worth running for one question: can a Roc
handler run on a fiber, so effects yield instead of blocking a worker?

## 2026-10-04: evented

The owner chose to switch fourneau to an evented design now: "think
forward", change whatever must change, test and learn at the bleeding
edge until Zig and Roc are stable. The plan, in order:

- E1. Vendor the port: `vendor/zig-io-evented/Uring.zig`, a pristine
  0.17.0 copy in one commit, our patches (compatibility, listen, accept,
  stream read and write) in the next. No subtree: one file, one patch.
- E2. fourneau's connection handling rewritten as blocking-style code on
  fibers, over `std.Io`: the parsers stay (they are sans-IO), the slot
  state machine goes. Bounded: a fixed number of connection fibers, with
  their stacks from a pool sized at startup (pushing the port toward
  static allocation).
- E3. A simulated `Io`: fibers on one thread, every choice from a seed,
  the network as io_sim's byte queues. The simulator's clients and model
  carry over; the seeds must still replay.
- E4. roux on it: Roc handlers run on fibers; a hosted effect
  (a body read, a sleep) yields its fiber instead of blocking a thread.
  The worker pool is dropped. SQLite still blocks: measured, then decided.

## 2026-10-05: evented fourneau, and the first six-core comparison

**E1** vendored `Io.Evented` (pristine commit, then our patch). **E2**
`evented.zig`: a fiber per connection over `std.Io`, memory carved at
startup, deadlines as one array scanned by a timekeeper fiber that shuts
expired sockets down. It passed the same curl checks as the first server
on its first run.

Upstream again: `std.Io.net.Stream.read` does not compile in 0.17 (it
destructures a struct as a tuple). Lazy compilation hides stale code in
the standard library until someone calls it; the evented path is lightly
travelled.

**Measuring the measurer.** oha on two cores topped out near 155k
requests/s while a six-core fourneau sat at 134% CPU: it measured oha.
`fourneau-load` (our io_uring load generator, same style as the server)
reaches the server's limits. Its first version hung when every
connection failed (a wait with no exit); a timeout now always wakes it.

**Nagle.** Pipelined requests ran at 50k requests/s with 41 ms latency:
the evented accept path had lost `TCP_NODELAY`, so each response after
the first waited for the client's delayed ACK. Fixed: 1.0M requests/s.
axum's default `serve` has the same stall (49.7k); with `TCP_NODELAY`,
576k.

**Six cores** (docs/benchmarks/2026-10-05-hello-6-cores.md): capacity at
pipeline 8, fourneau 1,006k, axum 576k, Go 220k, basic-webserver 145k;
CPU per unpipelined request 10.5, 13.5, 29.8, 42.3 µs. Unpipelined, the
two-core loader is the limit for fourneau and axum (~400k): one machine
cannot load six cores of an efficient server with two.

Next: E3, the simulated `Io`, so evented fourneau gets the simulator the
state-machine server had; then E4, Roc on fibers.

## 2026-10-05: E3, a deterministic std.Io, and the subtraction

`sim_io.zig` implements `std.Io` for tests: real fibers on one OS thread,
scheduled by the seed, over byte-queue sockets. Its vtable is
`Io.failing`'s with ~20 operations replaced, so anything unsimulated fails
loudly. The evented server runs on it unchanged.

- **A compiler bug.** Every seed segfaulted in `-O safe` and none in
  Debug or `-O fast`. gdb showed the switch message written to the stack
  but its address never loaded into `rsi`, which `contextSwitch`'s inline
  assembly requires: the safe build miscompiled std's own fiber switch.
  `fiber_switch_x86_64.S` is our own switch, an ordinary C-ABI call
  (callee-saved registers and control words saved on the stack), so
  there is no operand constraint left to miscompile. Results are now the
  same in all three modes (seed 0: 1,172 ticks).
- **A server bug.** Seed 45: a truncated response. The send deadline
  covered the whole response, so a slow, steady reader of 16 KiB
  through a 16-byte window was cut off. It now measures progress.
- **Speed.** 1,000 seeds in 2.6 s (the state-machine simulator: 20 s);
  10,000 seeds, 1.02M requests, in 26 s.
- **Testing the tests.** Nine injected bugs; eight caught (wrong answers,
  truncation, malformed and unsolicited bytes, crashes on invariants,
  and seed 45 again for the old deadline). The ninth, the timekeeper
  shutting down a connection that re-armed between its read and its
  lock, is a race between two threads; the simulator switches only where
  fibers block, so it cannot see it. Stated in TESTING.md;
  ThreadSanitizer is the tool (Todo).
- **A mistake of mine.** I ran the mutants while evented.zig had
  uncommitted changes; the helper's `git checkout` reverted them. All
  were in my context and are restored (the sweep totals match to the
  request), and the helper now refuses to run on a dirty tree. Commit
  before mutating.

**Subtraction.** The state-machine server, its io layers (`io.zig`,
`io_linux.zig`, `io_sim.zig`), its hello and its simulator are deleted;
`evented.zig` is now `server.zig`. Lost on the way and recorded in Todo:
idle eviction under pressure.

## 2026-10-05: the same compiler bug, in production

The simulator's crash was std's `contextSwitch` miscompiled in ReleaseSafe,
so I checked the real server: `fourneau-hello -O safe` crashed at its
first switch (a general protection fault in `mainIdle`). The benchmarks
had run in `-O fast`, which compiles it correctly; production should run
safe, assertions on. Fixed for both at once: `context_switch_x86_64.S`
keeps std's contract (save into `old`, resume `new`, hand over the
message in rsi and as the return value) as an ordinary C-ABI call, and
the port's one call site and the simulator use it. The simulator's sp-only
switch is gone: one switch for everything.

Measured, safe build, six cores, pipeline 8: 908,750 requests/s, zero
errors (fast: 1,006,030), so assertions cost about 10% here. The
simulator's 1000-seed totals are unchanged to the request. One outlier:
the slowest request took ~2 s while p99.9 was 13.8 ms; probably a
connection waiting in the backlog at the start (Todo).

## 2026-10-05: M4 first light, a Roc app on fourneau

A fresh, minimal platform (`roux/platform`: init!, respond!, a
request with its body pulled through one effect, Stdout, Stderr) and the
host in Zig (`roux/host/host.zig`), with glue generated by the
nightly's own `ZigGlue.roc`. `zig build platform` makes libhost.a; `roc
build` links app, host and musl into one static executable (4.8 MB).
`/`, `/echo` (content-length and chunked bodies, read on the request's
fiber), and an error tag mapped to its status all work on the first run.

What it took, besides the host itself:
- Ownership as the glue states it: Roc consumes the arguments of its
  provided functions, so the shared context box is retained per request
  (as basic-webserver's `retain_for_request` did); results are the host's
  to release, after the send.
- `link_libc` for the host (musl's crt1.o starts the program, so musl's
  pthreads must set up thread-local storage for the fibers' threads), and
  a `statx` shim: the musl roc links predates it.
- Zig 0.17's build system has no custom step code any more (configure and
  make run in separate processes): the archive padding fix (Zig issue
  30572) is a tiny program the build runs.
- **16 GB resident** for 256 connections: in safe builds `Allocator.alloc`
  fills new memory with 0xaa, so each fiber's 60 MiB stack was written
  in full. The port allocates fibers raw now: 100 MB, flat.

Measured, six cores (docs/benchmarks/2026-10-05-hello-6-cores.md):
the Roc hello app on fourneau, safe build, 505k-581k requests/s at
pipeline 8 (basic-webserver: 145k), 335k unpipelined (139k), 100 MB.
Open: with the stacks pre-touched (the 16 GB run) it served 721k; THP is
"always"; pre-faulting the top 256 KiB of each stack did not recover it.
Profile at pipeline 8: 24% the connection fiber's own code, 13%
`write_response` (integers through `std.fmt`), 9% `operate`, 5.6%
`findReadyFiber`, ~12% copying requests into Roc strings and releasing
them.

## 2026-10-05: adversarial review; shared nothing; fibers cost cache

The owner asked to be in love with nothing: EXPERIMENTS.md lists fifteen
doubts, each with the experiment that would settle it.

- **This machine** is a 4-core, 8-thread laptop (i7-10510U), and "six
  cores" was six hyperthreads (three physical cores). The same binary
  measured 1.13M and 833k requests/s twenty minutes apart. Wall-clock
  throughput cannot settle a 10-20% question here; `perf stat`
  instructions and cycles per request can.
- **Shared nothing beats work stealing** (experiment 1): six
  single-threaded shards, each with its own listener, against one
  six-thread work-stealing runtime: +13% unpipelined, lower p99, 2,844
  against 3,321 cycles per request. It also removes the cross-thread races
  the simulator cannot see. Its weakness showed too: connections hash
  unevenly across listeners. Settled for shared nothing, with balanced
  accept as the follow-up.
- **Fibers cost cache, not instructions** (experiment 3): the old state
  machine, sharded, took 2,256 cycles per request; sharded fibers 2,815,
  while executing fewer instructions, because they take 2.8x the L1 misses
  (71 against 25): every connection's stack is cold memory. The direction
  this suggests, to be shown to the owner before building: the state
  machine for I/O and HTTP, fibers from a small hot pool only while a Roc
  handler runs.
- **The response writer** (experiment 7) is table-driven now (status
  lines at compile time, a digit loop, byte tables for header checks),
  and the Date is refreshed per tick, not read from the clock per
  response. The simulator's totals are unchanged.

## 2026-10-05: fuzzing the parsers

Zig 0.17 has a coverage-guided fuzzer in its build system
(`std.testing.fuzz`, `zig build test --fuzz=N`). Both parsers have a fuzz
target: any bytes, split at a fuzzer-chosen point; nothing may crash,
every accepted result must be sound, and the split must change nothing.
It needs an LLVM build (`-Dtest-optimize=safe`): in Debug the coverage
file is empty ("pcs_len was zero"). 6,002,409 runs of the chunked decoder
(2,401 unique paths) and 6,000,876 of the head parser (796): no failures.

## 2026-10-05: the host on shards, leaks counted

The roux host now runs one shard per CPU in its affinity mask, as
fourneau-hello's `--shards` does: experiment 1 settled for shared nothing.
That made leak checking cheap. Every Roc allocation of a request is made
and freed on its shard's thread, so a thread-local count needs no atomic,
and whenever a shard has no request in flight its count must equal the
count at start. That is an assertion, on in every build.

The first run crashed on `/echo` with curl: a free on a thread with no
counted allocation. The counter was wrong, not Roc. The glue's
`RocStr.fromSlice` and `RocList.allocate` allocate through the
`RocHost` table, which still pointed at the glue's defaults, while
Roc's compiled code frees through the exported `roc_dealloc`. fourneau-load
sends no headers and short targets, which are inline small strings, so
that path never allocated. Lesson: a load generator sending the minimum
request misses paths; a real client (curl) found it in one request. Both
routes now reach one counted function. Then: 3.1M requests, no leak; an
injected leak (skipping the response's release) crashed on request one.

Connections are split across shards (1024 in all): RSS 106 MB, as before.
Throughput, unchanged: 586k pipelined, 314k unpipelined (6 hyperthreads).

## 2026-10-05: ThreadSanitizer over fibers

TSan keeps a shadow history per thread; a fiber switch swaps the stack
under it, and it lost track and failed under load with no report. Its
runtime has a fiber interface (`__tsan_create_fiber`,
`__tsan_switch_to_fiber`, `__tsan_destroy_fiber`): the port has one switch
site (`yield`), so the patch is small. Each fiber gets a TSan fiber when it
is initialised and loses it when destroyed; each thread's idle context
gets one. Now fourneau-hello under TSan serves 945k requests in work-stealing
mode and 890k sharded with no report, and an injected unsynchronised counter
in the handler is reported at once, with both fibers' stacks.

What TSan cannot do: the ninth mutant (the timekeeper re-checking a deadline
outside its lock) is a logic race between accesses that are each atomic or
locked. No race detector sees it. Shared nothing does away with it, which is
the argument for deleting the work-stealing mode outright.

The Zig 0.17 docs: `std.heap.DebugAllocator` is deprecated for
`SafeAllocator`: thread-safe, never reuses an address, checks writes after
free. The Roc heap can run on it (`-Dhost-heap=checked`).

## 2026-10-05: the loader was the limit, and the kernel is the cost

Asked to chase cache locality, I first measured where the CPU goes. User
against system time per request (from /proc/PID): 84% kernel. And 833k
requests/s at 4.06 µs each is only 3.4 of the server's 6 CPUs: the server
was not saturated. So every six-core comparison so far was partly a
loader benchmark.

Moved the server to one physical core and the loader to the other three,
and charged the server from /proc/stat per CPU. The server's CPUs were
then 100% busy, of which 29% softirq: the network stack, which no
process is charged for. docs/benchmarks/2026-10-05-one-core.md has the
table: fourneau 269k unpipelined on one core (axum 125k, Go 62k), and
89% of fourneau's time is kernel.

Before that, the experiment that the CPU split pointed at: pipelined
responses went out one send each. Coalescing them (flush before any read
that may block) took pipelined CPU per request from 4.0 µs to 1.17 µs, and
throughput from 0.83M to 1.5M on six hyperthreads, 1.31M on one core.
The simulator's swarm covers it, and a mutant without the flush fails.

So the direction: user-space locality is worth at most ~12% now; the
kernel side is the machine. Next experiments are io_uring's: deferred task
running, registered files, multishot receive with provided buffers.

## 2026-10-05: closing in on the kernel's floor

fourneau-floor is the least a server can do for fourneau-load's workload:
raw io_uring, no fibers, a canned response. One core, unpipelined, it
serves ~310k requests/s at ~6.2 µs kernel per request, and its io_uring
options (multishot receive, registered files) barely move it. So the
kernel cost is loopback TCP itself, and the question became what fourneau
asks the kernel that the floor does not.

- Counting submissions, `io_uring_enter` calls and completions per request
  (now in the port; `fourneau-hello --counts on`) gave the same numbers as
  the floor. The difference was the operations: the port's reads and
  writes were RECVMSG and SENDMSG, which import a msghdr and an iovec
  array each. One buffer is now a plain RECV or SEND: kernel time per
  request 7.46 to 6.78 µs, +10%.
- On the floor, linking each send to the next receive and skipping the
  send's success completion gave +15%. std.Io has no ordered pair of
  operations, so `ServerType` takes one at compile time; the port provides
  `sendThenReceive`, the simulator a model of it, and the sweep runs both
  server types. +2-6% in fourneau, with a quarter less user time.
- fourneau is now within about 20% of the linked floor. The rest is ~0.4 µs
  of user time (HTTP parsing and validation, the fiber switch, response
  formatting) and ~0.9 µs of kernel time I cannot see: `perf` here may not
  profile the kernel (perf_event_paranoid=2).

Then shard-only: the server asserts it runs on one thread and lost every
atomic and lock; deadlines are u32 ticks set without reading the clock.
Instructions per request are unchanged; it is a simplification first.

Two mistakes. `git checkout` of a file to undo a one-line probe threw away
uncommitted work in it, the same class as the mutation-script mistake: I
re-applied it from this session. Rule: undo a probe by editing it out, and
commit before any checkout. And a fourneau-hello from a sanity check was
left running for an hour; benchmark scripts kill what they start, my ad
hoc commands now do too. Also: the owner's editor and browser use a core
now and then, so wall-clock comparisons are noisy; instructions per
request are the robust measure for user-space changes.

## 2026-10-05: the research round, and where the TLB misses were

Research, layer by layer (docs/research/2026-10-05-the-edge.md has it):
Zig's Evented is still experimental upstream and has no networking (our
port stays); its devlog names a max-stack-size builtin as what makes
fibers practical. Go has no io_uring (blocked on buffer ownership since
2019); tokio uses it for files only, one global ring behind a mutex.
Axboe's networking guide: DEFER_TASKRUN (done), multishot, provided
buffers, POLL_FIRST. Tried on the floor: POLL_FIRST is 7% slower at
saturation. Postgres 18's AIO is about disk: for SQLite later.

fourneau against the floor: 200x the user-space dTLB misses per request.
Huge pages on the slabs changed nothing. Sampling the addresses of
STLB-missing loads (PEBS, `mem_inst_retired.stlb_miss_loads`) put 98% in
one 15 GiB mapping, the fibers: upstream allocates 60 MiB per fiber with
the header at the bottom and the stack's first frames at the top. The
port now puts the header at the top beside those frames, with a guard
page at the bottom, and 8 MiB stacks: dTLB misses halved, user cycles
down 8-14%. Looking at the addresses, not at the code, found it.

## 2026-10-05: the hybrid, measured

fourneau-hybrid answers experiment 3. Its I/O is a state machine on raw
io_uring (a connection is a few array entries and two buffers; one parser
and one header table per shard, since a head is parsed whole when its bytes
are in), with fourneau's real HTTP parser and response writer. Handlers
run inline or on a fiber from a pool of eight, last in first out.

User cycles per request, unpipelined: fourneau 1,957, hybrid with fibers
1,074, inline 925, the floor 302. A warm fiber costs ~150 cycles a call;
fourneau's fiber per connection costs ~900 more, and it is all cold
memory: L1 misses 52 against 12, dTLB misses 10x. Throughput on one
core +11% unpipelined, +21% pipelined.

This is Kelley's style kept where it pays: a handler is plain code that
may wait (a body, a database) on a fiber, and the fibers it uses are hot
because there are as many as handlers waiting, not as many as connections.
Idle connections hold no stack (experiment 2's tiers for free). The price:
the server's I/O no longer runs on any std.Io; it needs its own I/O layer
with an io_uring and a simulated implementation, and handler fibers need
an Io of ours. That changes DESIGN.md, so it is the owner's call.

## 2026-10-05: the first kernel profile, and an 8-entry ring

The owner opened kernel profiling (perf_event_paranoid=1). Profiling
fourneau, fourneau-hybrid and fourneau-floor under the same load: the
kernel side is a long tail of TCP, the same shape for all three. But per
request fourneau spent ~3,000 kernel cycles more than the hybrid, and a
per-symbol diff named them: kmalloc, kfree, memcg accounting, CQ overflow
flushes, extra io_uring_enter calls. Evented's ring defaults to 8
entries; with 256 connections both queues overflowed constantly. One
option (4,096 entries) removed it: +3-13% on one core.

That changes experiment 3. The hybrid's +11% unpipelined was mostly this
bug, not fibers. With the ring fixed, unpipelined is about even;
pipelined, the hybrid is still +10-15%, from 32% less user time. The
owner had asked for the hybrid rewrite on the earlier numbers, so I
stopped to show them the new ones first.

Also: a reboot cleared /tmp and with it every benchmark script. The
harness belongs in the repo, in Zig (Todo).

## 2026-10-05: rocstache becomes roux

The owner renamed the platform: it is about more than templates (SQLite,
migrations, typed SQL, the CLI), so it should not carry the template
language's name. Picked from four kitchen names: **roux**, the base every
sauce starts from, cooked on the stove (fourneau), said "roo", and it
starts with "ro" like Roc. The repository and its directory are `roux`;
the platform directory is `roux/`; the CLI is `roux` (`new`, `dev`,
`build`); the database tool `roux-db`; the host's address variable
`ROUX_ADDRESS`. **rocstache** now names only the template language:
`*.rocstache` files, the compiler that turns them into typed Roc, its
language server, and the `Rocstache` module (escaping and formatters). The
owner's Zed integration knows it by that name, so it stays. The old
basic-webserver fork at `~/devel/rocstache` keeps its name: it is history.

## 2026-10-06: fourneau gets its own repository

The owner made a GitHub organization for these projects, **Eldhus**
(Icelandic *eldhús*, the kitchen, literally the fire-house), and asked for
one repository per thing: fourneau, roux, rocstache (the grammar and the
editor integration) and a private eldhus-skill holding every note on
style, Zig, Roc and process. This diary began in roux's repository; its
entries before this one are that shared history, kept because they are
fourneau's too (`git filter-repo` kept only fourneau's paths, `src/` was
`fourneau/src/`).

What moved out: the Roc platform and its milestones (M4, M5, part of M6)
to roux; STYLE.md and the async I/O manual (docs/async) to the eldhus
skills, where every repository can use them; FEATURES.md (the comparison
with Go, axum and Caddy) to roux, whose app authors read it. What stayed:
the server, the simulator, the Evented port, the benchmarks, the research,
the experiments. `build.zig` now exports the modules roux needs
(`fourneau`, `zig_io_evented` with its assembly, `tidy` with a `check`
roux calls on its own trees). Suite green, all six executables build,
2,000 simulator seeds green after the split.

## 2026-10-06: the docs harmonized

The owner asked for one official stance per kind of document, kept in the
eldhus skill (`eldhus-way/references/docs.md`), and every repository
brought to it. The first pass here: the README's Build before Read and
sibling links as links; TESTING marks what does not exist yet (`zig build
diff`, `smoke.zig`, `reference.zig`); EXPERIMENTS gained the **moved**
status, 7 says settled, 11 says what it measured; the Zig-bugs note in
TODO became a Todo item. Every CLAUDE.md got the same `## Always` lines.

## 2026-10-06: no CLAUDE.md

The owner wants nothing Claude-specific in the repositories. This
repository's CLAUDE.md is gone: what it said about this repository is now
the README's "Working on it", and what every repository shares is in the
one `~/devel/eldhus/CLAUDE.md` (eldhus-skill's `workspace/CLAUDE.md`,
symlinked), which Claude Code loads for any session started below it.

## 2026-10-06: a cleanup pass

Across Eldhus, at the owner's request. Here: `reference/` and
`docs/evented-port/` deleted (the Go and axum apps are fourneau-dragrace's
competitors, which also take over the planned differential tests; the
port's draft is superseded by `vendor/zig-io-evented`); experiment 20 left
for roux, statuses in the stance's words; the dated docs' H1s lose their
dates; TODO's done hybrid item and its preamble gone, the Zig chore
follows the eldhus-maintenance skill; the name told only in the README;
SQLite patterns out of `.gitignore` (fourneau has no database).

## 2026-10-06: the settled experiments

EXPERIMENTS.md keeps only what is open; a settled entry is a one-line
stub, its conclusion in DESIGN.md (the docs stance, owner 2026-10-06).
Here are the settled entries as they stood, verbatim, numbers and all:

1. **Work stealing, or shared nothing?** (settled 2026-10-05: shared
   nothing. Interleaved medians, 3 rounds: unpipelined 374,791 against
   331,322 requests/s, p99 752 against 848 µs; pipeline 8: 880,638 against
   826,685, but noisier, since connections hash unevenly across shard
   listeners. Cycles per request 2,844 against 3,321. Follow-up: balance at
   accept, handing each new connection to the least-loaded shard.)
   Fibers migrate between threads: the free-slot list and the deadline
   array need locks and atomics, connections lose their cache, and the
   simulator (one thread) cannot see cross-thread races; ThreadSanitizer
   does not understand fibers. The alternative: one single-threaded
   `Evented` per core, each with its own listener (`SO_REUSEPORT`) and its
   own slots, nothing shared. Then the simulator is an exact model of a
   shard. Experiment: both modes in `fourneau-hello`, same benchmark.

7. **Integers through `std.fmt` in response heads.** (settled
   2026-10-05: compile-time status lines, a digit loop, table-driven
   header checks, and the Date refreshed per tick instead of a clock read
   per response.) 13% of the profile is `write_response`. Alternative: digit tables, a cached
   status line, the Date line formatted once per second per thread.

9. **One accept loop for every thread.** (open) With work stealing, every
   connection starts on the accepting thread. Shared nothing (1) answers
   it; otherwise multishot accept per thread.

12. **The simulator cannot see cross-thread races.** (settled 2026-10-05:
    shared nothing makes a shard one thread, which the simulator models
    exactly; ThreadSanitizer now runs over fibers (the port calls its
    fiber API at each switch) and finds an injected data race. The ninth
    mutant, a logic race, is out of TSan's reach; shared nothing removes
    it. Done 2026-10-05: the server is shard-only, asserts it runs on one
    thread, and has no atomics or locks; deadlines are u32 ticks, so no
    request reads the clock. Instructions per request unchanged (an
    atomic is one instruction; its price is cycles).) Answered by
    shared nothing (1), or by ThreadSanitizer told about fiber switches.

14. **No fuzzing.** (settled 2026-10-05: both parsers have fuzz targets,
    any bytes split anywhere; 6M runs each, no failures; DIARY. Next:
    the server's request loop over sim_io, driven by the fuzzer.) Zig has
    a coverage-guided fuzzer in its build system (`zig build test --fuzz`); the parsers are its natural target.

16. **One send per pipelined response.** (settled 2026-10-05: coalesced;
    flush before any read that may block. Pipelined CPU per request 4.0 µs
    to 1.17 µs.)

17. **Benchmarks that measure the loader.** (settled 2026-10-05: the
    server gets one physical core, the loader three, and the server is
    charged from /proc/stat including softirq; docs/benchmarks.)

21. **Huge pages for the slabs.** (settled 2026-10-05: no. madvise
    HUGEPAGE on the receive, send, scratch and header slabs left dTLB
    misses where they were: the slabs were never the TLB's problem.)

22. **Fiber stacks: 60 MiB each, header at the bottom.** (settled
    2026-10-05. PEBS sampling of STLB-missing loads put 98% of them in
    one 15 GiB mapping: 256 fibers x 60 MiB. Each wake touched the
    header at the bottom of the allocation and the frames at the top, 60
    MiB apart. Now: header and result slot at the top, beside the
    closure and the first frames; a guard page at the bottom; 8 MiB
    stacks (256 KiB measured the same). dTLB misses per request -50%,
    user cycles -8-14%. Zig's devlog lists a max-stack-size builtin as
    the follow-up that makes fibers practical: when it lands, size stacks
    exactly.)

23. **Evented's default ring: 8 entries.** (settled 2026-10-05, found by
    the first kernel profile: perf_event_paranoid=1.) With hundreds of
    connections the submission queue filled (an extra io_uring_enter each
    time) and the completion queue overflowed (the kernel allocates an
    overflow entry per completion, then flushes): __kmalloc, kfree, memcg
    hooks, __io_cqring_overflow_flush, ~3,000 kernel cycles per request
    that the hybrid (4,096 entries) never paid. fourneau-hello and the
    host now ask for 4,096. +3-13% on one core. An upstream finding: 8 is
    small for a server, and nothing says the queues overflowed.

## 2026-10-06: PLAN.md and EXPERIMENTS.md fold into TODO.md

The owner: there is no real distinction between experiments, plan and
todo. The milestones are TODO's Plan section, without status (status is
WIP's); each open experiment is a Todo item, "Doubt (experiment N)",
keeping its number, which code and docs cite as "experiment N" (the
settled ones are in this diary's entry before this one). The two files,
as they stood, verbatim:

### PLAN.md

### Plan

The road from an empty repository to a server on the internet with nothing
in front of it, and on from there. Milestones are in order and each ends in
something that proves it. A milestone is planned in detail only when it is
reached: what the last one taught changes the next. Where the work stands
now is in [TODO.md](TODO.md); what was learned on the way is in
[DIARY.md](DIARY.md). roux's milestones (the Roc platform on fourneau: the
host, SQLite, the tools, everything an app needs) are in roux's PLAN.md;
M4 and M5 moved there when fourneau got its own repository (2026-10-06).

There is no release gate. 2027 is for exploring: everything here will
be written, measured, broken and written again. The tests and the notes
are what carry from one version to the next.

#### Done

- **M0. The kitchen**: documents, build, tidy, PRNG, test filter.
- **M1. HTTP/1.1, alone**: request heads, chunked bodies, response heads,
  dates; every arrival split, exhaustive mutation.
- **M2. The server, real and simulated**: slots, ticks, keep-alive,
  pipelining, timeouts, eviction, body pool; io_uring; the simulator
  (10k seeds green, 8 of 8 injected bugs caught).
- **M3. Evented** (2026-10-05): the owner chose evented over a worker pool
  (2026-10-04). Our vendored `Io.Evented` with networking (E1), the server
  as a fiber per connection over `std.Io` (E2), then shard-only, benchmarks
  against axum, Go and basic-webserver, and a deterministic simulated
  `std.Io` (E3) that runs the same server: 10,000 seeds green, 8 of 9
  injected bugs caught (the ninth was a cross-thread race, gone with
  shards). roux's first light ran on it the same day.

#### M6. Static files and compression

- Static files (ETag done, Range, precompressed, zero-copy), and
  `fourneau-static`, the pure-Zig static file server.
- Compression: gzip from the standard library; then our own brotli
  encoder (RFC 7932).
- Graceful shutdown; idle eviction under pressure.

**Proves it:** `fourneau-static` agrees with Go's `FileServer` on what
both offer (fourneau-dragrace's `dragrace diff`).

#### M7. TLS

tls.zig vendored; the handshake on the connection's fiber; keys to kTLS;
ALPN.
**Proves it:** `curl`, `openssl s_client` and Zig's own TLS client
connect; testssl.sh is clean for what we offer; the load test over HTTPS.

#### M8. Certificates: ACME

Account, order, `tls-alpn-01`, certificate storage, renewal on ticks.
**Proves it:** issuance against Pebble, then Let's Encrypt staging.

#### M9. HTTP/2

HPACK, frames, streams, flow control, every attack a limit.
**Proves it:** RFC 7541 vectors; h2spec clean; browsers use it.

#### M10. Deploy

One binary on a public droplet: port 443 with ACME, port 80
redirecting, systemd with `CAP_NET_BIND_SERVICE`, graceful restart.
**Proves it:** `fourneau-static` serving the dragrace site on the
internet, nothing in front; then a roux app (roux's plan).

#### M11. Second opinions

Differential tests, in fourneau-dragrace (`dragrace diff`): fourneau
against Go and axum, `fourneau-static` against Go's `FileServer`,
tower-http's `ServeDir` and Caddy; every divergence fixed or written down
as a decision. Benchmarks are fourneau-dragrace's too. It starts earlier
wherever it helps.

#### Then: the next version

Read the diary, keep the tests, delete what did not pay, write it again.

### EXPERIMENTS.md

### Experiments

What I do not like about what exists, written down adversarially, each
with the experiment that would settle it. The owner's rule (2026-10-05):
be in love with nothing; benchmark, break and replace. Results go to
DIARY.md; a settled experiment leaves a one-line stub here, its
conclusion in DESIGN.md (or deleted with the code it judged) and its full
text and numbers in DIARY.md (2026-10-06: the settled experiments).

Status: **open**, **running**, **settled** (with the date and the verdict),
**moved** (to another repository, with the date). Numbers are never
reused.

#### The architecture

1. **Work stealing, or shared nothing?** (settled 2026-10-05: shared
   nothing, ~13% more requests per second and a shard the simulator models
   exactly; DESIGN, Threads: shards.)
2. **A fiber and ~100 KB per connection, whether it does anything or
   not.** (open) Idle keep-alive and SSE connections pay for buffers and a
   parked stack. Tiered design: an active tier sized by concurrency, a
   parked tier of ~64-byte rows with provided-buffer receives (DIARY,
   2026-10-05 discussion). Experiment: measure memory and throughput at
   10k, 100k idle connections, before and after.
3. **Fibers at all, or the explicit state machine?** (open; hybrid measured
   2026-10-05, evening: fourneau-hybrid, raw io_uring state machine with
   fourneau's real parser and writer, handlers inline or on a pooled
   fiber. Unpipelined, user cycles per request: fiber per connection
   1,957; hybrid with a pooled fiber 1,074; inline 925; the floor 302.
   L1 misses 52 / 12 / 10 / 8. One core: 341k / 378k / 402k / 391k
   requests/s; pipelined 1.62M / 1.97M / 2.09M / 2.57M. A warm fiber per
   handler call costs ~150 cycles; a fiber per connection ~900 more, all
   cold memory. Recommendation to the owner: rebuild the server as the
   hybrid. **Revised the same evening** after experiment 23: most of the
   gap was fourneau's 8-entry ring. With 4,096 entries, interleaved on one
   core: unpipelined about +2% for the hybrid (within noise), pipelined
   +10-15%; user time per request -32% (410 against 280 ns); kernel time
   equal. Decision (owner, 2026-10-05): keep Evented at least a month;
   the hybrid is written up in docs/hybrid.md. Earlier measurement:
   at pipeline 8, sharded state machine 2,256 cycles per request, sharded
   fibers 2,815 (+25%), with *fewer* instructions (3,093 against 3,249) but
   2.8x the L1 misses (71 against 25 per request): each connection's stack is
   cold memory. Next experiment: a hybrid, the state machine for I/O and
   HTTP, fibers from a small hot pool only while a Roc handler runs. Wall
   clock was useless here: the same binary measured 1.13M and 833k twenty
   minutes apart on this laptop.) The state-
   machine server ran 324k requests/s on one core (with oha, which could
   not saturate it); fibers cost a stack, a switch per wait, and an
   experimental runtime we own. Experiment: resurrect the state machine
   from git, per core, against fibers per core, with fourneau-load.
4. **The vendored `Io.Evented`: 6,300 lines we did not write, marked
   experimental, stale between releases.** (open) What do we use of it?
   A smaller runtime of our own (accept, recv, send, timeouts, fibers,
   one ring per thread) might be 1,000 lines we understand completely.
   Experiment: count what is used; prototype if it is small.
5. **Expiry by `shutdown`.** (open; 2026-10-05: deadlines are u32 ticks
   now, half the array, and set without a clock read; `std.Io` also has
   `operateTimeout`, which the port could map to linked timeouts.) The timekeeper scans every deadline
   each tick and wakes a waiting read by shutting the socket down: O(N)
   per tick and a little clever. Alternatives: io_uring linked timeouts
   per operation (the kernel expires them), or a timer wheel.

#### The hot path

6. **Copying every request into Roc strings.**
   (moved to roux, 2026-10-06)
7. **Integers through `std.fmt` in response heads.** (settled
   2026-10-05: heads written without `std.fmt`; DESIGN, Layers.)
8. **The body read through an `ArrayList`, then copied into a Roc list.**
   (moved to roux, 2026-10-06)
9. **One accept loop for every thread.** (settled 2026-10-05 by 1: each
   shard accepts on its own `SO_REUSEPORT` listener.)
10. **io_uring features unused.** (open) Multishot accept and receive,
    provided-buffer rings, registered files and buffers, `SEND_ZC`,
    SQPOLL. Each is an experiment with a number.
11. **The pre-touched-stack mystery.** (open) One build measured 721k
    requests/s against 505k-581k for the others; the cause is not known.

#### Testing

12. **The simulator cannot see cross-thread races.** (settled 2026-10-05:
    a shard is one thread, which the simulator models exactly;
    ThreadSanitizer runs over fibers for the rest; DESIGN, Threads.)
13. **No leak checking of the server.**
    (moved to roux, 2026-10-06)
14. **No fuzzing.** (settled 2026-10-05: both parsers have fuzz targets,
    6M runs each without a failure; TESTING.)
15. **Load-test numbers vary 15% run to run.** (open; partly settled 2026-10-05:
    worse than 15%, and the cause is the machine, a 4-core i7-10510U laptop
    that boosts and throttles. Comparisons now use user-space instructions
    and cycles per request from `perf stat`, interleaved runs and medians.) Pinning, frequency
    scaling, warm-up: a benchmark that cannot tell 10% is not a benchmark.

#### Found while measuring

16. **One send per pipelined response.** (settled 2026-10-05:
    coalesced, 4.0 to 1.17 µs per pipelined request; DESIGN, Layers.)
17. **Benchmarks that measure the loader.** (settled 2026-10-05: the
    method in docs/benchmarks/2026-10-05-one-core.md and the benchmarking
    skill.)
18. **The kernel is 89% of the cost** of an unpipelined request (6.6 of
    7.5 µs). (open) io_uring's levers, each measured on one core:
    `DEFER_TASKRUN`, registered files, multishot receive into provided
    buffers, send and receive linked, fewer `io_uring_enter` calls.
    Results on the floor (one core, unpipelined, interleaved): plain
    RECV/SEND over RECVMSG/SENDMSG +10%; DEFER_TASKRUN +5.5%; linked
    send-then-receive with the send's completion skipped +15%; multishot
    receive and registered files within noise; RECVSEND_POLL_FIRST -7%
    (Axboe recommends it for sockets known empty; at saturation the next
    request has usually arrived).
19. **Request arenas for Roc memory.**
    (moved to roux, 2026-10-06)
20. **What the Roc boundary costs.** (moved to roux, 2026-10-06; its
    largest part, response-head writing with per-byte header validation,
    23%, is ours: experiment 7 and the SIMD Todo.)
21. **Huge pages for the slabs.** (settled 2026-10-05: no effect on dTLB
    misses; DESIGN, Resources.)
22. **Fiber stacks: 60 MiB each, header at the bottom.** (settled
    2026-10-05: 8 MiB stacks, header on top; dTLB misses -50%; DESIGN,
    Resources.)
23. **Evented's default ring: 8 entries.** (settled 2026-10-05: 4,096
    entries, +3-13% on one core; DESIGN, Layers.)

## 2026-10-06: TLS, the handshake on the fiber and the keys to the kernel

M7's core, in the order it went:

- tls.zig (ianic, bd22bcb) is already on Zig 0.17 and has a `Ktls`
  conversion: its server handshake takes a `std.Io` reader and writer, so
  it runs on the connection's fiber unchanged. Vendored whole.
- `src/tls.zig`: a reader and writer over the connection's deadline-armed
  reads and writes, the handshake in the connection's scratch (both
  16 KiB buffers: no new memory), then `TCP_ULP` "tls" and the TX and RX
  keys. A client usually sends its request right behind its Finished, so
  the input buffer may hold an encrypted record the kernel never saw: it
  is decrypted in user space first and becomes the start of `recv`; the
  keys go to the kernel with the receive counter past it.
- First run: `kTLS: NOENT`. The kernel loads the `tls` module for a
  `TCP_ULP` request only with CAP_NET_ADMIN; `modprobe tls` once (the site
  host will load it at boot).
- Second run: the request arrived (78 bytes, through io_uring, decrypted
  by the kernel) and no response left. The linked send-then-receive sends
  with `MSG_WAITALL`, which a kTLS socket refuses (EOPNOTSUPP), and the
  linked receive was cancelled under the fiber. HTTPS connections now
  flush, then read (Todo: a kTLS-safe linked send).
- Then: curl and `openssl s_client` (TLS 1.3, AES-256-GCM) get every
  page; three requests on one connection; an 18 KB response across
  records; TLS 1.2 refused. The suite and a 200-seed sweep pass; roux's
  platform builds (the exported `fourneau` module carries `tls`).

## 2026-10-06: plain HTTP on the HTTPS port; HTTPS under load

Plain HTTP sent to the HTTPS port waited out the head timeout (tls.zig
read `GET ` as a record header and waited for its length). The first
byte of a TLS connection is a handshake record (0x16); anything else now
gets a plain 400, "This port speaks HTTPS: use https://", at once (11 ms).

HTTP against HTTPS, `fourneau-static` ReleaseSafe on one core (taskset 0,
one shard), oha 1.16.0 on cores 2-7, 64 connections, 8 s, a 6-byte page,
interleaved twice:

| | requests/s | p99 |
|---|---|---|
| HTTP | 262,735; 219,922 | 0.52; 0.57 ms |
| HTTPS (kTLS, AES-256-GCM) | 140,699; 121,802 | 0.99; 1.10 ms |

    taskset -c 2-7 oha -z 8s -c 64 --insecure --no-tui URL

HTTPS is about 55% of HTTP here: the kernel encrypts and authenticates
every tiny response, and HTTPS connections lose the linked
send-then-receive (Todo). Laptop numbers, wall clock: the benchmarking
skill's caveats apply.

## 2026-10-06: ACME, the certificate obtained at startup

M8's core, three layers, each tested before the next:

- `der.zig`: the little DER ACME needs, into a fixed buffer; a value that
  does not fit is an error. My hand-computed test length was off by one;
  the encoder was right.
- `acme_crypto.zig`: P-256 keys, the JWK and its thumbprint, JWS (ES256),
  the CSR naming one IP address or DNS name, the key as SEC1 PEM. OpenSSL
  agrees: `req -verify` OK, the SAN is `IP Address:203.0.113.7`, the key
  valid and the CSR's own.
- `acme.zig`: directory, nonces (a badNonce retried once), account, one
  order with one authorization, http-01 answered by a blocking responder
  on its own thread (the answer published once, release/acquire; the
  shards, which exist only after, keep their no-locks rule), finalize,
  the chain; files written whole and renamed, 0600.

Against Pebble (letsencrypt/pebble 1fcb30c, `PEBBLE_VA_NOSLEEP=1`, its
default 5% nonce rejection on), first run: account, order, challenge on
:5002, a two-certificate chain for `IP Address:127.0.0.1`, valid six days
(the shortlived profile), and `curl --cacert` verifies the site through
Pebble's root. A restart finds it fresh and keeps it.

    fourneau-static --root SITE --port 8446 --acme-directory https://localhost:14000/dir \
      --acme-identifier 127.0.0.1 --acme-state STATE --acme-http-port 5002 \
      --acme-ca pebble/test/certs/pebble.minica.pem --acme-profile shortlived

The plan said tls-alpn-01; this is http-01 (DESIGN.md, Layers: acme).
