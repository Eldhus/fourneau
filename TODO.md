# todo

## WIP

1. **Cook: a server that faces the internet alone, for twenty years.**
   (owner, 2026-10-04) The owner's words: no dependencies, we own everything;
   HTTP/2 and HTTPS out of the box; one binary; TigerStyle; write the server
   over and over, taking notes and trying hard to break it; deterministic
   testing against the specs first, differential testing against Go and
   axum through the public interface; serial work, notes after every step;
   fast tests with subsets. Make the base rock hard: adversarial review of
   every decision (the Doubts in Todo), drag races, data-oriented designs at
   every layer (which arrays the server needs, memory locality), all of the
   machine used; fibers as Andrew Kelley designs them, but faster. roux
   (the Roc platform) is built on it.
   - Where it stands (2026-10-06): M0-M3 done (Plan, DIARY). HTTP/1.1 on
     our io_uring port of `std.Io.Evented`, one shard per core, the
     simulator (10k seeds green, injected bugs caught), parsers fuzzed,
     ThreadSanitizer over fibers, the memory-safety plan (TESTING.md). On
     one core: within ~5-10% of fourneau-floor (raw io_uring), the kernel
     ~85% of a request (experiments 18-23: the 8-entry ring, the fiber
     layout, the send path). Split out of roux into this repository
     2026-10-06 (DIARY). Next: idle eviction and the fiber pool (Todo),
     then M6 (static files and compression).

2. **HTTPS and templates, end to end and deployed.** (owner, 2026-10-06)
   "Work through a few more milestones, particularly templating and
   https": M7 (TLS), M8 (ACME), M10 (deploy: the dragrace site on 443),
   with roux's templates and the dragrace's templates workload; then M6
   and M9. Iteratively, TigerStyle, data-oriented, until deployed.
   - Where it stands (2026-10-06): M7's core works: tls.zig vendored,
     the handshake on the connection's fiber, kTLS; `fourneau-static
     --cert --key` serves HTTPS (curl, openssl s_client, keep-alive, an
     18 KB response across records; TLS 1.2 refused; plain HTTP gets a
     400). Load on one core: HTTPS about 55% of HTTP for a 6-byte page
     (DIARY). M8's core works against Pebble: `fourneau-static
     --acme-*` obtains a certificate for an IP address (http-01, the
     short-lived profile) at startup and serves HTTPS with it; a restart
     reuses a fresh one. Next: M10 (port 80 redirecting, the site host on
     443 with Let's Encrypt, staging first), then M7's last checks (Zig's
     TLS client, testssl.sh), then
     M10; templates in roux and the dragrace (their TODOs); M6; M9.

## Plan

The road to a server on the internet with nothing in front of it.
Milestones in order, each ending in what proves it; one is planned in
detail only when it is reached, since what the last one taught changes
the next. No release gate: 2027 is for exploring, and the tests and notes
are what carry from one version to the next. The numbers are shared with
roux (its TODO): M4 and M5 are roux's; M6 and M10 have a half in each.

### Done

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

### M6. Static files and compression

- Static files (ETag, Range, precompressed, zero-copy), and
  `fourneau-static`, the pure-Zig static file server.
- Compression: gzip from the standard library; then our own brotli
  encoder (RFC 7932).
- Graceful shutdown; idle eviction under pressure.

**Proves it:** `fourneau-static` agrees with Go's `FileServer` on what
both offer (fourneau-dragrace's `dragrace diff`).

### M7. TLS

tls.zig vendored; the handshake on the connection's fiber; keys to kTLS;
ALPN.
**Proves it:** `curl`, `openssl s_client` and Zig's own TLS client
connect; testssl.sh is clean for what we offer; the load test over HTTPS.

### M8. Certificates: ACME

Account, order, `tls-alpn-01`, certificate storage, renewal on ticks.
**Proves it:** issuance against Pebble, then Let's Encrypt staging.

### M9. HTTP/2

HPACK, frames, streams, flow control, every attack a limit.
**Proves it:** RFC 7541 vectors; h2spec clean; browsers use it.

### M10. Deploy

One binary on a public droplet: port 443 with ACME, port 80
redirecting, systemd with `CAP_NET_BIND_SERVICE`, graceful restart.
**Proves it:** `fourneau-static` serving the dragrace site on the
internet, nothing in front; then a roux app (roux's plan).

### M11. Second opinions

Differential tests, in fourneau-dragrace (`dragrace diff`): fourneau
against Go and axum, `fourneau-static` against Go's `FileServer`,
tower-http's `ServeDir` and Caddy; every divergence fixed or written down
as a decision. Benchmarks are fourneau-dragrace's too. It starts earlier
wherever it helps.

### Then: the next version

Read the diary, keep the tests, delete what did not pay, write it again.

## Chores

- **Latest Zig**, weekly: a new release (ziglang.org/download)? Install it
  beside the others and follow the eldhus-maintenance skill: it moves the
  pins together (`.zig-version` here and in roux, fourneau-dragrace's
  `versions.json`), refreshes the vendored docs, and says what to run
  (the suite, a 1000-seed sweep whose totals must not change).
  - Last done: 2026-10-04 (0.16.0 to 0.17.0).

- **Vendored sources**, monthly and when a security release appears:
  `vendor/zig-io-evented/` against upstream `Io/Uring.zig` (what upstream
  changed; can a patch go?), and `vendor/tls.zig/` (github.com/ianic/tls.zig;
  its README says how). Run the suite, note what changed in the diary.
  - Last done: 2026-10-04 (the port vendored).

## Todo

- [ ] A ~2 s worst-case request in the safe-build pipelined run (p99.9
  13.8 ms; DIARY 2026-10-05): find where it waited (the accept backlog at
  start-up is the first suspect). (2026-10-05)
- [ ] Idle eviction under pressure, lost in the move to evented: when every
  slot is taken, close the longest-idle keep-alive connection so a new
  client is served (the state-machine server did; the old platform's load
  test showed idle keep-alives holding every slot). (2026-10-05)
- [ ] Fibers from a pool sized at startup in the port (static allocation
  and a bound), not allocated per task; the layout (header on top, guard
  page) is done. (2026-10-05)
- [ ] Parsing with SIMD: line scanning and header validation are a large
  share of user time (DIARY 2026-10-05). (2026-10-05)
- [ ] SQLite-grade branch coverage: 100% branch coverage (MC/DC, as
  SQLite's TH3 reaches it) of the Zig code, perhaps the whole executable.
  Not now: it hardens the code into its shape, so it waits until the API
  and the data layout are settled (owner). (2026-10-05)
- [ ] fourneau-bench in Zig: the benchmark harness (one core
  for the server, charged from /proc/stat with softirq; perf stat per
  request; interleaved A/B rounds) lived in shell scripts in /tmp and a
  reboot took them. In the repository, in Zig, so results can be
  reproduced. (2026-10-05)

- [ ] Balance at accept: hand each new connection to the least-loaded
  shard; `SO_REUSEPORT` hashes connections unevenly, which made
  pipelined runs noisy (experiment 1). (2026-10-05)
- [ ] Fuzz the server's request loop over `sim_io` (the parsers are
  fuzzed; experiment 14). (2026-10-05)

- [ ] Doubt (experiment 2): a fiber and ~100 KB per connection, idle or
  not. Idle keep-alive and SSE connections pay for buffers and a parked
  stack. Tiered design: an active tier sized by concurrency, a parked
  tier of ~64-byte rows with provided-buffer receives. Experiment: memory
  and throughput at 10k and 100k idle connections, before and after.
  (2026-10-05)
- [ ] Doubt (experiment 3): fibers at all, or the explicit state machine?
  Measured (DIARY 2026-10-05, the hybrid): with a 4,096-entry ring the
  hybrid (state-machine I/O, handlers on pooled fibers) is ~2% faster
  unpipelined, 10-15% pipelined, with 32% less user time. Keep Evented at
  least a month (owner, 2026-10-05); `docs/hybrid.md`; decided at the
  Tickler's 2026-11-05. (2026-10-05)
- [ ] Doubt (experiment 4): the vendored `Io.Evented` is 6,300 lines we
  did not write, experimental upstream. Experiment: count what we use;
  if it is small, prototype our own (accept, receive, send, timeouts,
  fibers, a ring per thread: perhaps 1,000 lines). (2026-10-05)
- [ ] Doubt (experiment 5): expiry by `shutdown`. The timekeeper scans
  every deadline each tick (O(N)) and wakes a waiting read by shutting
  the socket down. Alternatives: io_uring linked timeouts per operation
  (`std.Io`'s `operateTimeout`), or a timer wheel. (2026-10-05)
- [ ] Doubt (experiment 10): io_uring features unused: multishot accept
  and receive, provided-buffer rings, registered files and buffers,
  `SEND_ZC`, SQPOLL. Each an experiment with a number. (2026-10-05)
- [ ] Doubt (experiment 11): the pre-touched-stack mystery. One build
  measured 721k requests/s against 505k-581k for the others; the cause is
  not known. (2026-10-05)
- [ ] Doubt (experiment 15): load-test numbers vary run to run, by more
  than 15%: the laptop boosts and throttles. Comparisons use `perf stat`
  instructions and cycles per request, interleaved runs and medians.
  Left: pinning, frequency, warm-up, until a benchmark can tell 10%.
  (2026-10-05)
- [ ] Doubt (experiment 18): the kernel is ~89% of an unpipelined request
  (6.6 of 7.5 µs). Measured on the floor (one core, interleaved): plain
  RECV/SEND +10% over RECVMSG/SENDMSG; `DEFER_TASKRUN` +5.5%; linked
  send-then-receive with its completion skipped +15%; multishot receive
  and registered files within noise; `RECVSEND_POLL_FIRST` -7%. Left:
  fewer `io_uring_enter` calls. (2026-10-05)
- [ ] A kTLS-safe linked send-then-receive: kTLS sends refuse
  `MSG_WAITALL`, so HTTPS connections flush and then read (two
  completions, not one; experiment 18's +15% lost on HTTPS). Without
  WAITALL a short send would let the receive run early; measure whether
  a send-then-poll or a retried send keeps the gain. (2026-10-06)
- [ ] `fourneau-static` names the file that broke a limit at load
  (`StreamTooLong` alone, 2026-10-06, for a 33 MB file in the root).
  (2026-10-06)

## Tickler

### 2026-11-05

- [ ] Evented or the hybrid? (owner, 2026-10-05: keep Evented at least a
  month.) Re-measure fourneau against fourneau-hybrid (and on the dragrace
  droplets), check Zig #157 (stack size) and #31723 (Evented networking),
  and decide with docs/hybrid.md's criteria.

### 2027-01-04

- [ ] `std.Io.Evented` upstream again (and at every Zig release before
  then): can its io_uring backend listen and accept, is it still
  "experimental", how large are fiber stacks, are stackless coroutines in
  the language? If upstream can serve, shrink our port toward it.
  (2026-10-04)

### 2027-04-30

- [ ] Can listeners go back to io_uring's BIND? The port binds with the
  system call because Ubuntu 24.04's kernel (6.8) lacks `IORING_OP_BIND`
  (6.11; zig-io-evented's `netListenIp`). When the dragrace droplets and
  the site host run a kernel of 6.11 or later (Ubuntu 26.04's image),
  decide: drop the patch (one less difference from upstream), or keep it
  (a startup call gains nothing from the ring). (2026-10-06)
