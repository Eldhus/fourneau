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

## 2026-10-06: port 80 redirects to HTTPS

`fourneau-static --redirect-port 80` runs a second, small server in each
shard (64 connections, 16 KiB of scratch each) beside the HTTPS one: 301
to `https://<host><path?query>` for GET and HEAD, 308 for anything else
(keeping the method and body). The host is the configured one
(`--https-host`, default the ACME identifier), never the request's Host
header. Two shards, Pebble's certificate: GET 301, POST 308, and curl
following the redirect gets 200 with the chain verified.

## 2026-10-06: HTTPS on the internet, nothing in front

The dragrace site host (fourneau-dragrace's `site install-server`) now
runs `fourneau-static --port 443 --redirect-port 80 --acme-*`. Let's
Encrypt staging first: a certificate for `IP Address:174.138.75.219`
from "(STAGING) Baloney Bulgur YE2" in two seconds, the page served, the
redirect 301. Then production: issuer YE2, valid six days, and `curl
https://174.138.75.219/` verifies with the system's trust
(`ssl_verify=0`).

Two robustness fixes on the way: a failed renewal keeps serving the
current certificate while it lasts (else systemd's restarts would order
again and again into a rate limit; the unit also waits 60 s now), and the
CA that issued `cert.pem` is recorded beside it, so moving from staging
to production orders anew instead of keeping the staging certificate.

## 2026-10-06: gzip, compressed once at load

M6's first piece. `fourneau-static` compresses each text file (html, css,
js, json, svg, txt, xml, 256 bytes or more) once, at load, at gzip's best
level, and keeps the copy when it is at least a tenth smaller; a request
whose Accept-Encoding allows gzip (RFC 9110: listed or `*`, not q=0) gets
it, with its own ETag and `Vary: Accept-Encoding`. No compression per
request. The dragrace site: index 3,966 to 1,767 bytes, style.css 8,506
to 2,992, race.js 11,703 to 3,856, latest.json 18,801 to 3,818; curl
`--compressed` gets the page back byte for byte.

The test caught my loop bounds: n bytes split into n + 1 pieces and then
the end, so a split loop needs n + 2 passes; `for ... else unreachable`
said so on the empty header.

## 2026-10-06: idle eviction under pressure

Lost in the move to fibers: a full server stopped accepting, so 1,024 idle
keep-alive connections locked every new client out for up to the idle
timeout (30 s). Now the acceptor accepts first; when no slot is free it
closes the connection idle longest (a separate `idle_since` array of
ticks, scanned once, like the deadlines) and waits for its slot.

The first version flushed before marking a connection idle, so no
response could be cut short; that split the linked send-then-receive in
two on every unpipelined keep-alive request, experiment 18's +15%. Instead
eviction shuts the socket for reading only: a response being sent is sent
whole, then the read returns 0 and the fiber closes. The simulator had
modelled only a full shutdown (`assert(how == .both)` caught it); it now
models the read side too. Suite and a 1000-seed sweep pass.

Measured (fourneau-static, one shard, 1,024 slots, Python clients): 1,024
idle connections, then a new client: served in 1 ms, exactly one idle
connection closed; the next two, after it closed, needed none. (A first
count said 429: my loop spent 51 s reading, past the idle timeout.)

## 2026-10-06: M7's checks: Zig's client, testssl.sh

Zig's own `std.http.Client` fetches https://174.138.75.219/about.html
(200, the chain verified against the system's roots). testssl.sh 3.2 (run
on the site host against its public address: the laptop has no DNS tool
and its Docker daemon is off): TLS 1.3 only, SSLv2 to TLS 1.2 not offered,
trust OK via the SAN, chain of trust OK, a six-day certificate; Heartbleed,
CCS, Ticketbleed, ROBOT, renegotiation, CRIME, POODLE, SWEET32, FREAK,
DROWN, LOGJAM, BEAST, LUCKY13, RC4: not vulnerable. Two notes:

- BREACH, "potentially NOT ok" for gzip: it needs a compressed response
  holding a secret beside attacker-reflected input; a static site has
  neither. Not applicable here; roux apps that compress must think again.
- No Strict-Transport-Security: now sent on an HTTPS site, a year.
  Browsers ignore it for an IP address; it counts once the site has a
  name.

## 2026-10-06: byte ranges

`fourneau-static` answers `Range` (RFC 9110 §14): one range, `a-b`, `a-`
or the last n bytes `-n`, from the uncompressed copy, as 206 with
`Content-Range`; a range past the end, 416 with `bytes */len`; several
ranges, another unit, an invalid range or an `If-Range` that no longer
matches the ETag, the whole file (the RFC allows ignoring Range). Every
uncompressed copy says `Accept-Ranges: bytes`. Curl: `-r 0-14` gets
`<!doctype html>`, `-r -7` the last seven bytes, `-r 99999-` a 416.

## 2026-10-06: streamed responses

For server-sent events: roux's `Sse`, and fourneau-dragrace's new SSE
workload (a Datastar action, ten events, one chunk each). `Request`
gains `stream_start` (a chunked head), `stream_send` (one chunk),
`stream_flush` and `stream_end` (the last chunk); a handler that
streamed returns `streamed_status` (0), and only such a handler does,
asserted both ways. Chunks wait in the send buffer as pipelined
responses do, so events made together leave in one write (hyper does
the same; Go flushes each). A chunk larger than the buffer goes
straight from the handler's memory. A stream left without its end
closes the connection without the last chunk, so the client sees a cut
response, not a whole wrong one. Reading the body after a stream
starts is an assertion: its 100 Continue would be a second head.

The simulator learned streams: `/stream/n/k` (the `/big/n` bytes in k
pieces, some flushed with a 1 ms wait between) and `/abort/n/k` (half
the pieces, then the handler gives up); the clients decode chunks
strictly (lowercase hex, no leading zero, no extensions, no trailers)
and check every chunk's size, and take a cut stream as its response
only when the bytes end exactly at a chunk boundary and the request was
an abort. 2,000 seeds pass (`zig build sim -Doptimize=ReleaseSafe --
--seeds 2000`, 50 s; 16,388 streams cut short among them).

The tests, tested: six bugs injected into the stream path, each swept
over 400 seeds. Five were caught at once (no chunk tail; no last chunk;
a body for HEAD; a size line off by one; a large chunk without its
tail). The sixth was not: a cut stream that kept its connection open.
The client just waited until the idle timeout closed it, and took the
response then. A browser would have waited 30 seconds on a response
that would never finish. The clients now fail when a cut stream's
silence outlasts a few network turns (`cut_short_silence_ticks_max`,
asserted below the idle timeout), and the sixth is caught on seed 0.

## 2026-10-07: a certificate counts only for its identifier

The dragrace site moved from its IP address to a name
(fourneau.y2kbugger.com), and after the restart kept serving its IP
certificate: `acme.ensure` reused any fresh certificate from the same CA,
whatever it was issued for. The state directory now keeps `identifier`
(`ip:203.0.113.7`, `dns:example.com`) beside `directory`, and a stored
certificate counts only when both match; state from before the file
reads as no certificate, so the first restart after this orders anew.
A test covers the record and both refusals; roux builds and tests
against it.

## 2026-10-07: HSTS is the server's; kTLS's faults said rightly

Two findings from the dragrace site's move to a name, fixed at their
layer. HSTS: fourneau-static sent it from its file table, and roux's
own responses never did, so the dragrace site's pages went without it.
The response head writer now writes `Strict-Transport-Security:
max-age=31536000` on every response over TLS (`Head.secure`, from the
connection's kTLS), as it writes `Date`: one policy whatever the
application, refused as an application header, never over plain HTTP
(RFC 6797 §7.2). No includeSubDomains: the site is a name under the
owner's domain, and must not bind the others. The static site's
`secure` plumbing is gone.

kTLS: `kTLS: NOTCONN (is the tls module loadable?)` appeared in the
site's log on clients that hung up right after the handshake (a racer
refusing the certificate, scanners), with the module loaded. Linux
attaches TLS only to an established connection: ENOTCONN is the peer
gone. Now `PeerClosed`, counted as a failed handshake and logged at
debug like the others; any other errno warns with its step (TCP_ULP,
TLS_TX, TLS_RX). Whether the kernel has TLS at all is checked once, at
startup (`/proc/sys/net/ipv4/tcp_available_ulp` lists `tls`), before a
certificate is ordered: a server without it refuses to start, where
before every handshake failed and logged the same warning.

Tests: the head with and without `secure`, an application's own HSTS
refused; the ULP list parsed as words; and on the real kernel, a
loopback pair whose client closed (read sees the FIN: CLOSE_WAIT)
refuses TLS as `PeerClosed`, while an established one takes it (skipped
on a kernel without kTLS). Each test caught its bug injected (NOTCONN
mapped back to a fault; the policy's max-age changed). roux builds and
tests against it.

## 2026-10-09: prng exported

The `fourneau` module exports `prng`, for roux's host: its new test of
the template compiler and VM together makes templates from a seed, and
tidy refuses the standard library's random numbers. `zig build test`
passes.

## 2026-10-09: fibers from a pool

The port allocated a fiber (8 MiB of stack over a guard page) the first
time a task needed one more, without a bound, and recycled it after. Now
`Evented.init` takes `fibers_max` and reserves room for all of them in
one mapping; a fiber is carved from it (the next stride, its guard page
set then) the first time one more is needed, recycled through the free
queues as before, and beyond the pool `concurrent` is refused
(`ConcurrencyUnavailable`; `async` runs inline). The server says what it
needs, `Config.fibers_max()`: a fiber per slot and the timekeeper, since
a slot is given back as its fiber's last act and the port frees a
finished fiber in the switch that leaves it. A program sums what runs on
its `Io` (fourneau-static and roux's host add the redirect's,
`Redirect.fibers_max`). A connection that finds no fiber is counted
(`Stats.fiberless`).

The first version threaded the free list through the fibers and set
every guard page at `init`. Measured (fourneau-hello, 8 shards, 8,192
connections, ReleaseFast): resident memory idle 46-61 MB against 22-27
before (each header written touches its page), and 16,000 mappings at
startup. Carving on first use keeps an idle pool at no memory and one
mapping.

Then, under 4,000 connections, the carved pool held 2.0 GB resident.
Transparent huge pages are `always` on this laptop: inside one large
mapping every 2 MiB region lies within it, so each fiber's first touch
faulted in a huge page. The old per-fiber mappings were not 2 MiB
aligned and mostly escaped it. `MADV_NOHUGEPAGE` on the reservation:
after (three interleaved rounds each, `fourneau-load --connections 4000
--threads 4 --seconds 3`): idle 24-30 MB (before 23-42), loaded 247-258
MB (before 458-480, by chance alignment), requests/s the same within
the laptop's noise (load average 2.4, so no claim). Ubuntu's droplets
default to `madvise` and would not have shown it.

The simulator's pool is now exactly `server.fibers_max() + 1` (the fiber
`run` accepts on), and a sweep fails if any connection found no fiber:
2,000 seeds pass with totals unchanged; one fiber short fails on seed 1.
A test of the port itself (hello.zig): two fibers, a third refused, both
reused, three rounds; it fails when the pool is three. roux's host and
db-floor size their pools the same way; roux builds, its hello serves
2,000 connections.

Found on the way, not fixed: restarting fourneau-hello on the same port
right after 4,000 connections panics with `SystemResources`. io_uring
charges ring memory to `RLIMIT_MEMLOCK` (8 MiB for the user here), and a
killed process's rings are freed late, by a kernel worker, once its
sockets drain; roux's host waits that out (two seconds), fourneau's
programs do not. It is graceful restart's problem (WIP 3.6), where old
and new run at once by design.

A mistake of mine: I first wrote this entry with a shell heredoc, which
the owner's rules forbid (edits go through Edit, so they show as a
diff); the hook refused it. Rule kept: never append to a file from the
shell.

## 2026-10-09: roux's half of the pool, pushed without fourneau's

I edited roux's `host/host.zig` and `host/floor.zig` for the pool and
built roux to check them, meaning to commit them after fourneau's
commit. Meanwhile another session committed in roux with a blanket add
(`333e773 README: v0.2.4`, 22:17) and pushed it, my two files inside.
fourneau `d43d791` is not pushed, so roux main stopped building against
fourneau main (built in scratch worktrees at both origins: `no field or
member function named 'fibers_max'`), and the nightly races both mains.
Prepared, not pushed: roux's branch `race-safe` (`158cfe5`), the two
files back as in `5bb7310`, which builds against fourneau main. The
choice is the owner's (WIP 3). Consequence of my part: an edit left
uncommitted in a repository another session works in is that session's
to sweep. Rule: edit a sibling repository only when ready to commit,
and commit those paths at once.

## 2026-10-09: graceful shutdown

First the simulator learned cancelation (it awaited): a request marks
the fiber, a sleep, accept, read, write or cancelable futex wait
delivers it once, a fiber blocked at one is woken for it, protection
holds it back, recancel re-arms it. Its test cancels a sleep, an accept
and a protected task; it fails when a request does not wake a blocked
fiber. (A first injection, dropping the check after a wake, passed: the
check on entry already delivers it, so that check went.)

Then the drain, read against Go's `Server.Shutdown`, nginx's quit and
hyper's `graceful_shutdown`, which agree: stop accepting, close idle
connections, let requests in flight finish, then close, under a
deadline. The TODO had planned an eventfd per shard with a fiber reading
it; simpler: one flag, set by a signal thread, read by each shard's
timekeeper once a tick (it wakes every tick anyway), so nothing crosses
threads but a bool, and the simulator sets it at a seeded tick. `run`
now accepts on its own fiber and keeps time on its own; at a stop it
cancels the accept loop rather than shutting the listener, because M10's
restart hands the same listening socket to the next process, and a
shutdown would stop that one too. Idle connections are shut for reading,
as eviction does; `write_head` now owns the head's connection fields
(keep-alive, date, HSTS) and closes when draining; `read_head` serves no
next request; at the deadline (`drain_timeout_ms`, 10 s) every open
connection is shut. Waiting for a slot became cancelable: uncancelable,
a full server of streams would hold the timekeeper in `cancel` forever.

The simulator stops half the seeds at a random tick, with a drain
timeout no shorter than a fast client's longest wait (so only slow
clients may be cut); clients then accept a close they did not ask for
and a new connection closed unanswered (accepted as the drain began
with no slot free), and the run must return within its bound. 3,000
seeds pass: 1,473 stopped, 1,110 idle connections closed at a drain's
start, 25 cut at its deadline, 87 shut out (`zig build sim
-Doptimize=ReleaseSafe -- --seeds 3000`, 54 s). Injected: no cancel of
the accept loop (caught, seed 40, liveness), no cut at the deadline
(seed 184, liveness), idle connections left alone (caught by a new
invariant: draining, none waits idle). Not caught: responses without
`Connection: close` during the drain, since clients retry a request on
a closed keep-alive connection, which the simulator cannot tell from the
idle race. It matters (no client retries a POST by itself), so a test on
the real kernel orders events by what it sees, not by sleeping: a
connection half-way through its first request, an idle one answered,
the stop, the idle one's end (the drain began), then the rest of the
first request, whose answer must say `Connection: close`. It catches
that injection, and runs the port's cancelation of a pending accept
(io_uring's async cancel) for real.

`stop.zig`: SIGTERM and SIGINT blocked in every thread, taken by one
(`rt_sigtimedwait`); the first sets the flag, a second exits at once.
fourneau-hello and fourneau-static (its redirect server too) join their
shards and exit 0. Measured (Debug build, 4 shards, 200 connections of
`fourneau-load`): exit 0 in 209-219 ms after SIGTERM, three runs; a
client that stalls half-way through a head holds it to the deadline,
10.2 s; a second SIGINT quits in 9 ms with exit 1.

Found on the way: every HTTPS connection curl closed dumped `unexpected
errno: 5` from the port's stream read (in builds with error tracing;
silent in release). kTLS fails a read with EIO when the next record is
not data and no control buffer asks for its type: curl's close_notify.
It is TLS's end of stream, now read as one; verified by curl, a test is
in the Todo.

## 2026-10-09: the drain, second pass: event streams, the listener, a race

Wiring the drain into roux showed what the first pass missed. `roux dev`
restarts the app with SIGTERM, and the dragrace site's pages keep an
event stream open per tab: a drain waits for requests in flight, and an
event stream never finishes, so every restart would have waited out the
10 s deadline. Changed:

- Event streams end at once. A stream whose head says `Content-Type:
  text/event-stream` is marked `endless`; each tick of a drain shuts
  those (one started during the drain, too), and EventSource reconnects
  by design. Other chunked streams are requests in flight and keep the
  deadline.
- The listener closes at the drain's start, as Go and nginx do: left
  open, new clients queued unanswered until exit, then were reset.
  Closing our descriptor does not close a socket a successor shares.
- At the deadline, `group.cancel` too, for a handler waiting on
  something other than its connection (roux's event streams wait on a
  futex).
- roux's host drains only in production: `roux dev` wants its restart.

The simulator could not see the first: its "streams" end by themselves.
A first check ("an event stream still arriving after the drain") failed
seed 287 wrongly, on a stream the server had ended whose last bytes were
crossing a 16-byte window. So the simulator now has event streams as
they are: `/events/n/k` sends its pieces round after round until a send
fails; the client checks one round against the model and hangs up with
a reset (a page left); during a drain it accepts the stream ended
anywhere, and fails if it outlives two server ticks and a few network
turns. A closed listener refuses connects and resets its backlog, and a
stopped run fails if any client is left queued. 3,000 seeds pass (1,473
stopped: 952 idle closed, 156 event streams ended, 25 cut at deadlines,
900 refused or reset). Injected: no event-stream drain (caught, seed
97); listener left open (caught by the queue check, seed 2; not before
it). The `endless` flag first outlived its stream, which an assertion
caught at once: `stream_end` clears it.

Then, under load, fourneau-hello crashed in one SIGTERM of eleven: EBADF
from shutting an idle connection, after a stall of seconds. The port's
`netShutdown` went through the ring: the timekeeper submitted a
shutdown and yielded until it completed; meanwhile the connection's own
fiber could close the socket, and io_uring does not order unlinked
operations, so the shutdown, punted to a worker, ran after the close.
The race was always there for timeouts and eviction; the drain, shutting
many sockets at once, made it show. A shutdown never blocks, so it is
now the system call (as bind already was): no fiber runs between the
look at a socket and its shutdown, and the timekeeper's scans no longer
yield. Measured, interleaved, 40 SIGTERMs each under 400 connections of
`fourneau-load`: the previous commit crashed 3 times (EBADF, after 2.4-5
s), this one none, stopping in 107-220 ms. The simulator could not have
found it: its shutdown is immediate. A lesson for the port: an
operation used to wake another fiber must not itself go through the
ring.

A note on tools: `git apply` of a patch into a scratch worktree was
refused by the no-shell-edits hook, though the scratchpad is allowed;
the variant was built by editing the real tree and editing it back.

## 2026-10-09: zero-copy sends, measured and not built

What zero-copy could still remove: a body too large for the send buffer
already goes out from the file's memory behind its head (`write_all`),
so the copy left is the kernel's, into socket buffers. Upper bound,
measured: fourneau-static (ReleaseFast, one shard on CPUs 0-1) serving a
48 KiB file to `fourneau-load` (32 connections, CPUs 2-7), 119-125k
requests/s, `perf record -g`: `rep_movs_alternative` (the copy) 22.2%
of the server's samples, `clear_highpages_kasan_tagged` 19.4% (this
Arch kernel zeroes every page it allocates, `init_on_alloc`: the socket
buffers' fresh pages). `SEND_ZC` would hand the file's pages to the
socket and skip both, on a real NIC; on loopback the kernel copies at
delivery anyway, so the laptop cannot measure the gain. (64 KiB failed:
fourneau-load holds a response in 64 KiB, head included.)

Then the doubt: who would use it? kTLS's `tls_sw_sendmsg` refuses every
flag but MORE, DONTWAIT, NOSIGNAL, CMSG_COMPAT, SPLICE_PAGES, EOR and
SENDPAGE_NOPOLICY with `EOPNOTSUPP` (net/tls/tls_sw.c, master), and
io_uring's `SEND_ZC` always adds `MSG_ZEROCOPY` (io_uring/net.c): over
HTTPS it cannot work, and the only zero-copy path, spliced pages, ends
in the kernel's encryption, a pass over the bytes anyway. The owner's
sites are HTTPS with files of 2-4 KB gzipped; the dragrace's races have
no static workload. So it is not built (bespoke, not a product), and
DESIGN's promise of "zero-copy sends, which kTLS keeps working over
HTTPS" was wrong: corrected. Revisit when a site serves large files, or
for a static-file race.

## 2026-10-09: brotli, first the decoder

Is an encoder of our own worth it? Measured on the deployed site's own
files, the reference `brotli -q 11` against `gzip -9`: datastar.js
13,287 to 12,038 bytes (91%), demo.js 83%, favicon.svg 88%, style.css
5,332 to 4,590 (86%), the index page 7,896 to 6,067 (77%), latest.json
74%. A real gain on a first visit, but most of it is brotli's machinery
(the static dictionary, context modeling, optimal parsing): a plain
LZ77-and-Huffman brotli would land near gzip. So the encoder is built in
passes, each kept only when it shrinks these files.

First the oracle: `brotli_tables.zig` (the RFC's tables, each checked
against the CRC-32 the RFC publishes for it: dictionary, transforms,
the three context lookups; all matched the first time) and
`brotli_decode.zig`, strict and plain (a bit at a time, canonical codes
decoded a length at a time, as puff does). The dictionary is vendored
(`vendor/brotli/`, google/brotli's `dictionary.bin`, CRC 0x5136cb04 as
the RFC says), copied in with `cp`: a binary file has no Edit.

Checked against the reference: 13 files (the site's assets, prose, Zig,
100 KB of random bytes, 70 KB of zeros, empty, one byte) at qualities 0,
1, 2, 5, 9 and 11, 78 streams, every one decoded byte for byte by
`fourneau-brotli decode` (a file-to-file tool for these comparisons).
Every byte of style.css's q11 stream flipped (4,590 streams, Debug
build): 4,044 refused, 546 decoded to other bytes (brotli carries no
checksum), no crash. The suite keeps one reference stream (3,000 bytes
of the stylesheet, q11) and flips each of its bytes three ways.

## 2026-10-09: brotli encoder, pass 1: a plain stream

One meta-block, one block type and one prefix code per category, LSB6
context (unused: one literal code), NPOSTFIX and NDIRECT 0; hash-chain
LZ77 (4-byte hash, 1,024 steps, matches from 4 bytes) with one-step lazy
matching; length-limited Huffman codes (the reference's way: raise the
smallest counts until the tree fits) written as simple codes up to four
symbols, else complex with the reference's run-length coding; the
four-distance cache used for any distance it names, the last one implied
in the insert-and-copy symbol where the codes allow; an uncompressed
meta-block when that is smaller.

The decoder caught one bug at once: the fixed code for code-length code
lengths, which the RFC prints "as parsed from the right"; read as binary
numbers, the patterns are already the values to write least significant
bit first, and I had reversed them. The Huffman code, the RFC's
canonical example and every run of 1..119 lengths are tests.

Every stream decodes with the reference `brotli -d` (13 files), and the
sizes are what the doubt predicted, gzip's (ReleaseSafe build): 

| file | bytes | gzip -9 | brotli -q 11 | ours |
|---|---|---|---|---|
| datastar-v1.0.2.js | 34,083 | 13,287 | 12,038 | 13,255 |
| index.html | 37,624 | 7,896 | 6,067 | 7,629 |
| style.css | 15,543 | 5,332 | 4,590 | 5,304 |
| DESIGN.md | 16,852 | 7,418 | 6,257 | 7,344 |
| server.zig | 56,824 | 13,759 | 12,147 | 13,578 |
| latest.json | 1,814 | 866 | 645 | 862 |
| random.bin | 100,000 | 100,049 | 100,005 | 100,005 |

Next: the passes that make brotli brotli, each measured on this table.

## 2026-10-10: brotli encoder, pass 2: optimal parsing

Where do brotli's bytes come from? The reference at each quality on the
same files (index.html): q4 7,841 (where pass 1 is), q5 7,102 (context
modeling, block splitting), q9 7,050, q10 6,301 (optimal parsing), q11
6,067. Two steps matter: q4 to q5, and q9 to q10.

Optimal parsing, as brotli's q10 does it (Zopfli's method): positions
are nodes, edges literals or copies priced in bits by the last parse's
codes, the cheapest path is the next parse; three rounds. A copy's price
depends on its path: the literals before it share its symbol, and its
distance may be the cache's. Each node keeps the literals since the last
command and a shortcut to the last command that moved the cache, which
is rebuilt exactly by walking four such commands back (brotli's
`ComputeDistanceCache`). The command coding moved into
`brotli_command.zig`, so the parser prices exactly what the writer
writes.

Sizes (all decode with the reference): index.html 7,629 to 7,126
(-6.6%), server.zig 13,578 to 13,060 (-3.8%), datastar 13,255 to
12,966, style.css 5,304 to 5,187, DESIGN.md 7,344 to 7,245. Rounds: 1
gives 7,159, 3 gives 7,126, 6 gives 7,125: three.

Two slow paths found by timing (ReleaseFast): 70 KB of zeros took 15 s,
then 2.4 s, and 2 MB of zeros 72 s. First the cache's distances were
compared to the end of the run at every position (quadratic): now
`long_length` (325) ahead. Then, inside a long match every position
still priced ~650 lengths, each finding its codes by a scan: brotli's
skip (no copies start inside a match longer than 325; literals still
reach every node) and lookup tables for the insert and copy codes. 70 KB
of zeros: 5 ms; 2 MB: 53 ms; index.html 39 ms. Sizes unchanged.

Still 13% over the reference's q10 on index.html: its next edge is
context modeling.

## 2026-10-10: brotli encoder, pass 3: literal contexts

Each literal's code chosen by its context (UTF8 mode: the two bytes
before it), 64 contexts clustered greedily (merge the pair whose union
costs least over its parts, while that saves bits; at most 16 codes), a
context map without run-lengths. Contexts depend only on the input, so
the parser prices each literal by its own context's code.

index.html 7,126 to 6,648 (-6.7%), DESIGN.md -3.5%, style.css -3.0%,
datastar -2.7%, server.zig -1.4%. But small files got worse (latest.json
857 to 878, favicon.svg 211 to 214): my estimate of a code's description
(four bits a symbol, twenty for the header) is optimistic, and small
files were split into codes they cannot pay for. Rather than tune an
estimate, the encoder now writes the meta-block both ways (clustered, one
code; and stored) and keeps the smallest: writing is quick beside
parsing. Small files back to 859 and 211. Clustering recomputed every
pair after each merge (random.bin 577 ms): now a table of pair savings,
recomputed for the merged cluster only (85 ms).

Against the reference q10: datastar +2.8%, index.html +5.5%, style.css
+7%, but demo.js +14%, README.md +18%, latest.json +35%: the small files
lack what they cannot find in themselves, the static dictionary.

## 2026-10-10: brotli encoder, pass 4: the static dictionary

A copy whose distance reaches past everything produced names a
dictionary word (section 8): 13,504 words of 4..24 letters through 121
transforms. Two changes to the model first. A word's coded length (its
base length) can differ from what it produces, so a command carries
`out`. And a word never enters the distance cache, even when a short
code names its distance, which can happen near the start, where the
cache's initial 4, 11, 15, 16 reach past what is produced: so coding a
command takes the farthest real distance at its position (`reach`).

Finding words (`brotli_words.zig`): words indexed by their first four
letters, case-folded; at each position each prefix the transforms use
("", " ", " the ", ".com/", ...), then the words matching after it under
each transform of that prefix (as is, capitalized, upper-cased, last
letters omitted; never first letters omitted, whose body does not start
with the word). Cheap tests first (exact or case-folded common lengths),
then the transform made and compared. The parser prices a word as a copy
at distance reach + 1 + id, which does not move the cache.

Sizes (all decode with the reference), now against q10 and q11:

| file | gzip -9 | q10 | q11 | ours |
|---|---|---|---|---|
| datastar-v1.0.2.js | 13,287 | 12,278 | 12,038 | 12,183 |
| demo.js | 1,593 | 1,370 | 1,326 | 1,357 |
| index.html | 7,896 | 6,301 | 6,067 | 6,273 |
| style.css | 5,332 | 4,680 | 4,590 | 4,645 |
| latest.json | 866 | 638 | 645 | 651 |
| DESIGN.md | 7,418 | 6,443 | 6,257 | 6,332 |
| server.zig | 13,759 | 12,431 | 12,147 | 12,267 |
| README.md | 1,837 | 1,532 | 1,486 | 1,516 |
| favicon.svg | 238 | 198 | 209 | 194 |

Smaller than q10 on all but latest.json (+2%), within 0.6-3.4% of q11,
smaller than both on favicon.svg. The index page at 79% of gzip's.
ReleaseFast times: index.html 122 ms, server.zig 256 ms.

What is left of q11's lead is block splitting and distance contexts; at
~1-3% it can wait. Next: serve it.

## 2026-10-10: brotli served, and checked against the reference

`site.zig` makes a brotli copy of each text file beside the gzip one
(kept when a tenth smaller; files up to 1 MiB, past which the parser's
memory is too much at load on a small droplet). Accept-Encoding is now
weighed as RFC 9110 §12.5.3 says (q-values, `*` for unnamed codings,
identity acceptable unless excluded), the client's highest weight wins
and brotli wins a tie; before, the site asked only whether gzip was
acceptable. A doubt checked against the owner's setup: roux serves its
static files through this module, and `roux dev` restarts the app on
every edit; datastar.js alone takes ~74 ms to compress. So loading takes
`LoadOptions`, and roux's host asks for no brotli in development
(roux 519fd86).

fourneau-static on the dragrace site's files, with curl: index.html
37,624 bytes as 6,273 brotli (gzip 7,973), style.css 4,645 (5,351),
datastar 12,183 (13,344), latest.json 651 (854); `br;q=0.5, gzip` gets
gzip, `identity` gets the file; curl's libbrotli (the reference
decoder, as browsers have it) decodes ours byte for byte. The site
loads in 380 ms, compression included (ReleaseFast).

`zig build brotli-check`: inputs from seeds (random bytes, runs,
dictionary words under random transforms, copies of what came before,
mixtures, one in sixteen up to 400 KB), each encoded by us and decoded
by our decoder and the reference `brotli -d`. 2,000 seeds, 34 MB in, 11
MB out: all agree. A word's distance off by one, injected, fails seed 0.

Not a public benchmark tonight: a race of compression compares defaults
(Go's FileServer does not compress; tower-http compresses per response),
so a static-file workload needs the owner's choices; proposed in the
dragrace's TODO. Nothing to teach in the tutor: brotli is invisible to a
roux app.

## 2026-10-10: HTTP/2 planned; HPACK

The plan is docs/http2.md, with the attack record read first: Rapid
Reset (CVE-2023-44487), the CONTINUATION flood (2024), and MadeYouReset
(CVE-2025-8671, August 2025), which makes the server reset streams so
that limits counting only the client's resets miss them. The answer is
in the data: a stream's slot, and its fiber, count against the limit
until its handler returns, whatever the protocol says.

`hpack.zig`, sans-IO. Found while reading RFC 7541: its Huffman code is
canonical (checked against all 257 of its codes), so the table is the
257 lengths and the codes are derived at comptime, nothing transcribed
as hex. The dynamic table is a ring of entries over a byte buffer twice
its size, its live bytes always one run, moved to the start when the end
is reached. The decoder copies every name and value into the caller's
buffer, which is also where the header list's bound lives (an HPACK
bomb's repeated large entry fills it and is refused). The encoder never
indexes: no table to keep in step, nothing for a peer to probe (RFC 7541
§7.1).

Tests: Appendix C's six worked examples (requests with and without
Huffman, responses with a 256-byte table and its evictions) decode to
the RFC's lists and table sizes, first run (one expectation broken by
hand fails, so they run); every byte through Huffman and back, and the
RFC's own coding of "www.example.com"; the table through 4,000 random
additions and resizes against a plain model of what it must hold;
20,000 random and damaged blocks refused or decoded within bounds;
eight malformed blocks refused (index 0, an empty table's index, a size
update after a field or past the limit, bad padding, EOS inside a
string, a string past the block, an integer too long); the bomb.

## 2026-10-10: HTTP/2 frames

`http2_frame.zig`, sans-IO, layer 2 of docs/http2.md: the nine-byte
header, each type's payload checked as RFC 9113 §6 says, and the frames
a server writes (SETTINGS and its ACK, PING ACK, RST_STREAM, GOAWAY,
WINDOW_UPDATE). A malformed frame is not an error value but a
`Refusal`: the code the RFC names and whether it ends one stream or the
connection (a PRIORITY of the wrong length ends its stream; a
RST_STREAM of the wrong length ends everything). What a frame means
for state (an idle stream, a closed one, the windows) is the connection
machine's, the next layer. A PUSH_PROMISE from a client is refused: a
server never receives one.

Tests: every refusal in §6, 27 cases with their code and scope; padding,
a priority block and an unknown type taken apart; each writer's frame
read back by the parser. Learned again: 0.17's `zig fmt` rewrites
`@enumFromInt` to `@fromBackingInt`, and `.{0} ** 8` no longer parses
(`@splat`); the zig skill had both and I wrote from memory anyway.

## 2026-10-10: HTTP/2 connections, the state machine

`http2.zig`, layer 3: bytes in, events out, frames in one send buffer;
the choices and their reasons are in docs/http2.md ("The connection, as
built"). Read before writing: RFC 9113 §5 and §8 again, and h2spec's own
cases (its http2/*.go), to know what it accepts. Its verifiers pass on
a closed connection whatever the GOAWAY says, so the codes matter only
where the RFC says MUST; the frames on closed streams follow Go's
server where the RFC leaves a choice.

Found while designing: a HEADERS frame whose priority names itself is a
stream error, but its block must still be decoded or the HPACK tables
part ways, so the frame layer now flags it instead of refusing it. And a
drain's GOAWAY must name the last stream when it is decided, not when
it is written, or streams ignored in between would be reported taken.

Tests: a GET answered and its HEADERS decoded back; 12 connection errors
and 6 stream errors as h2spec names them; 13 malformed requests reset
and never seen; Rapid Reset (two streams reset by the client, their
handlers still running: the third is REFUSED_STREAM until one returns);
send windows through SETTINGS, WINDOW_UPDATE and a negative window;
receive windows enforced and given back at half; trailers; cookie
crumbs joined; a PING flood cut in its 52nd round of 1,200; a drain;
release's resets; heads refused. Then 500 random conversations
(requests split across CONTINUATION, bodies, resets, settings, garbage
frames, flipped bits) against a server acting at random, the invariants
checked after every call: 85 end open and 415 in a connection error,
none breaks. The tests tested: freeing a stream's entry at the peer's
reset fails the Rapid Reset test.

The first run passed 17 of 19; the two failures were the invariant
check catching windows over 2^31-1 left behind by the error paths
(added, then refused); now checked before they change.

## 2026-10-10: HTTP/2 in the server: h2c, stream fibers, one Request

Layer 4 of docs/http2.md, its choices written there ("The server, as
built"). `fourneau-hello` speaks it on its port beside HTTP/1.1.

Measured and checked:
- A real-kernel test (`hello.zig`): two streams on one connection, a
  GET and a POST whose body is echoed, then a stop: the drain's GOAWAY
  arrives. Passed first run.
- curl 8.22 (`--http2-prior-knowledge`): a GET; three requests on one
  connection; a 300,000-byte upload, more than four stream windows, so
  the window updates flow; HTTP/1.1 on the same port, unchanged.
- h2spec v2.6.0, `--strict`: 143 of 147 at first, in 6.0 s. Three were
  one bug, a lost wake-up: a handler facing a closed window flushed and
  then waited, and a window opened during the flush was never seen, so
  it slept to the send timeout. Fixed by reading the wait word before
  looking at the window, with no wait between. Then 145 of 147 in 2.0 s;
  the two left are one case listed twice, an invalid preface, which on a
  port shared with HTTP/1.1 gets HTTP/1.1's 400 (h2spec reads it as a
  frame). Kept: falling back to HTTP/1.1 is the point of sharing the port.
- The simulator's 200 seeds (HTTP/1.1) still pass; roux builds.

Not yet: ALPN on HTTPS, the simulator speaking HTTP/2, a load test.

## 2026-10-10: HTTP/2 on HTTPS, by ALPN

tls.zig already chose a protocol from the client's list in the server's
order and kept it on the session; the handshake now takes the server's
offer (`tls.Protocols`: `h2` then `http/1.1` when `Config.http2` is set)
and says what was chosen. The certificate's context no longer carries
an ALPN list: what the server speaks is the server's to say.
`fourneau-static` (the site) speaks HTTP/2 now, live at the next deploy.

Checked with a self-signed P-256 certificate: curl negotiates h2 and
gets the page; `--http1.1` still gets HTTP/1.1; a 270 KB file comes back
brotli-compressed (204,039 bytes) and identical once decoded. h2spec
strict over TLS: 147 of 147, in 0.1 s (no fallback to HTTP/1.1 on an
ALPN-chosen connection, so the invalid preface case passes too).

## 2026-10-10: HTTP/2 under load: a leak, a convoy, a drain that hung

oha 1.16 (the dragrace's) on `fourneau-hello`, h2c, the server on CPUs
0-1, oha on 2-7, the desktop busy (VS Code, Brave: correctness here,
not speed). At one stream per connection, 32 connections: 100%, 164k
requests/s. At eight: 6% succeeded.

Measured before guessing: `--counts` now prints the HTTP/2 state each
2 s (connections, streams, refused, slots free, resets, failures, from
each machine as its connection closes). After the load, every
connection closed and 255 of 256 stream slots still taken. A dump of
them (temporary): released by the machine, unmapped, not ended, their
fibers alive. Each had answered, released its stream, then waited to
send behind another fiber, on its own stream's word; the machine gave
its index to a new stream meanwhile, so the sender, waking the
streams it knew, never woke it. Leaked for good, with its fiber. And
the drain then never ended: with every connection closed, the
timekeeper thought it done, never cut, and `run` waited on the stuck
fibers forever (`kill` left four servers sharing the port).

Fixed in three parts: waits for a send are on the connection's word;
a stream is unmapped as it is released; a connection counts its stream
fibers and gives its slot back only after the last (it referred to a
connection a new client could have by then). `run` asserts every stream
slot is back.

Then 7% refused, all from the shard's pool: 1,018 of 1,024 slots held by
finished streams waiting their turn to send, a convoy (each send's end
woke them all, one went on). A finished stream need not wait: its
frames are in the buffer, and the sender sends until none waits. So
two kinds of flush: wait (room, a handler's `stream_flush`) or leave it
to the sender. Then 100% at 1, 8 and 32 streams per connection:
152k, 232k and 320k requests/s (HTTP/1.1, same run: 269k at 64
connections), 96 connections kept, none refused. The pool is now as
many slots as connections unless said: a stream costs what an HTTP/1.1
connection does, and at exactly as many streams as slots a client's
next stream can arrive a moment before the last one's slot is back.

A test now does what oha did (`hello.zig`: four connections keeping 16
streams in flight, 400 requests each, twice the slots needed): it fails
every time with the convoy put back, and passes. h2spec: against a
handler that answers before reading the body, two cases race with TCP's
segments (TESTING.md); against `/echo` it is 146 of 147 every run.

Resident memory after the load: 278 MB, all of one mapping, since oha's
reconnects (45,901) had cycled through all 1,024 connection slots, and
each slot's HTTP/2 machine is ~110 KB (TODO: smaller).

## 2026-10-10: HTTP/2: wake only a fiber that waits

The zig skill knew it (roux's VFS, 2026-10-06): `io.futexWake` is an
`io_uring_enter` even with no waiter. The server's `Signal` woke on
every send's end, and every window update woke each of the connection's
streams. Now it counts its waiters and wakes only when one waits.

`fourneau-hello --counts`, oha 400,000 requests at 32 connections of 8
streams, h2c, the two builds interleaved twice (the desktop at load 2.3,
so the rates are noisy; the counts are not):

| per 100 requests | submissions | enters | requests/s |
|---|---|---|---|
| woken always | 175, 175 | 126, 125 | 324k, 311k |
| woken when one waits | 52, 51 | 2, 3 | 380k, 377k |

## 2026-10-10: a stream's scratch, aligned

The dragrace's local race (branch `http2` there, a workload over h2c)
crashed roux at once: `incorrect alignment` where its host lays its
response headers into `request.scratch`. A stream slot's bytes were
text, scratch, then the body window of 65,535 bytes: an odd stride, so
every other slot's scratch began on an odd address. HTTP/1.1's never
had (its slab, a multiple of 64 KiB). Now each slot is whole pages, its
scratch first; both slabs are page-aligned by type; `scratch_align`
(16) says what an application may count on, asserted for every slot.

The race, one quick round on the laptop (server on 2 CPUs; not a result):
plaintext over h2c at 32 connections of 8 streams, requests/s:

| | HTTP/1.1, 256 connections | h2c, 32 x 8 |
|---|---|---|
| fourneau-zig | 271k, 260k | 303k, 355k |
| roux | 235k | 254k |
| axum | 100k | 84k |
| basic-webserver | 35k | 44k |
| go | 49k | 27k |

## 2026-10-10: graceful restart: systemd holds the socket

The site restarts with `systemctl restart` (a deploy, and daily for its
certificate): stop, then start, and in between the port is closed. The
plan's graceful restart (M10), for the owner's setup: systemd's socket
activation. systemd holds the listening socket across the restart, so a
client connecting while the old process drains and the new one starts
waits in its queue. The drain already closed only its own listener,
"a successor sharing the socket keeps it".

`listen.zig`: `inherited` finds the socket systemd passed by name
(`LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES`; the caller reads them, so
a host on libc can too), `server_from` gives each shard its own copy
(close-on-exec, checked to be listening), and `runtime_init` is roux's
wait for io_uring's locked memory, moved here (a start right after a
stop finds the old rings not yet freed). `fourneau-static` takes `https`
(and `http` for its redirect, `Redirect.server_on`), `fourneau-hello`
takes `http`; without systemd both bind as before.

Measured with transient user units (`systemd-run --user`, nothing
installed): `fourneau-hello`, 2 shards on CPUs 0-1, oha on 4-7 with a
new connection per request (`--disable-keepalive`, 8 at once, 6 s),
three `systemctl --user restart`s in the run (the journal shows four
starts):

| | success | refused | slowest |
|---|---|---|---|
| binds itself | 98.05%, 97.97%, 97.46% | 4,771 (one run counted) | 121 ms |
| socket-activated | 100%, 100%, 100% | 0 | 356-370 ms |

The slowest is a client that waited through a restart in the queue: the
drain (the stop flag is read once a tick, 100 ms) and the start.

Then a trap, found reading acme.zig before writing the site's units: the
http-01 responder binds port 80 itself while ACME validates, which
fails when systemd holds 80, so the daily restart could never renew the
certificate. It takes systemd's socket now (`acme_http_listener`,
`http_listener`), a copy, and it no longer shuts down a socket it did
not bind: shutting a listening socket down stops it listening for every
copy, the redirect after it included. It polls instead, seeing its stop
within 100 ms. A test answers a challenge on a held socket and finds it
still listening after; with the shutdown put back, it fails.
