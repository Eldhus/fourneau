# Hello, six hyperthreads: fourneau, axum, Go, basic-webserver

2026-10-05. `GET /` answering `hello\n`, keep-alive, on one laptop (i7-10510U:
4 physical cores, 8 hyperthreads, turbo to 4.9 GHz; Linux 7.2.7): each server
pinned to cpus 0–5, which are three whole physical cores (`taskset -c 0-5`,
six worker threads each), and `fourneau-load` pinned to cpus 6–7, one whole
physical core (two threads, 256 connections, 10 s after a 2 s warm-up).
"CPU used" is the mean busy share of cores 0–5 from `/proc/stat`
(user, system, interrupts: the kernel's TCP work included) over 4 s
mid-run. "CPU µs/request" is cores used × 1 s ÷ requests per second.

| server | unpipelined req/s | server CPU used | CPU µs/request | pipeline 8 req/s | p50 / p99 at pipeline 8 | RSS |
|---|---|---|---|---|---|---|
| **fourneau** (evented, Zig 0.17, our io_uring `Io.Evented`) | 388,893 | 68% | **10.5** | **1,006,030** | 1.5 / **2.6 ms** | 25 MB |
| axum 0.8.9 + `TCP_NODELAY` | 396,760 | 89% | 13.5 | 575,796 | 3.4 / 7.6 ms | 11 MB |
| axum 0.8.9 as `axum::serve` defaults | 400,331 | 88% | 13.2 | 49,735 | 41 / 42 ms | 12 MB |
| Go 1.27.1 `net/http` (`GOMAXPROCS=6`) | 197,400 | 98% | 29.8 | 220,360 | 4.5 / 59 ms | 22 MB |
| basic-webserver (Roc nightly 2026-09-24, hyper + tokio + Roc workers) | 139,033 | 98% | 42.3 | 144,534 | 6.1 / 34 ms | 32 MB |

How to read it:
- **Unpipelined, fourneau and axum are client-bound**: the loader's two
  cores were at 100% while their servers had room (68% and 89%). Their
  requests/s are the loader's ceiling; what differs is the CPU each
  spent: fourneau 10.5 µs a request, axum 13.5. Go and basic-webserver
  saturated their six cores below that ceiling.
- **Pipeline 8 measures capacity**, the way TechEmpower's plaintext test
  does (it pipelines 16): one send carries 8 requests, so the client's
  cost per request falls and the servers saturate (fourneau 99%, axum
  100%). fourneau served 1.75× axum, 4.6× Go, 7.0× basic-webserver.
- **axum's default stalls on pipelining**: `axum::serve` leaves
  `TCP_NODELAY` off, and each pipelined response after the first waits
  for the client's delayed ACK (40 ms). fourneau had the same bug until
  this run found it (50k → 1.0M requests/s).
- basic-webserver pays for its hand-off from tokio to Roc worker threads
  on every request; fourneau's Roc handlers will run on fibers instead
  (DIARY, evented), which is the comparison that will matter once
  roux runs on fourneau.
- Memory: fourneau's 25 MB is mostly its static per-connection buffers
  (4096 connections configured); the fibers' 60 MiB stacks are address
  space, committed only as used.

Not measured yet: TLS, HTTP/2, larger bodies, many more connections,
two machines (the loader saturating at 400k unpipelined is a property
of one 8-core machine), Roc handlers on fourneau.

Reproduce (from the repository root; the Go and axum apps, then in
`reference/`, are now fourneau-dragrace's `competitors/go` and
`competitors/axum`):

    zig build -Doptimize=fast
    (cd ../fourneau-dragrace/competitors/axum && cargo build --release)
    (cd ../fourneau-dragrace/competitors/go && go build .)
    taskset -c 0-5 zig-out/bin/fourneau-hello --port 8103 --threads 6 --connections 4096 &
    taskset -c 6-7 zig-out/bin/fourneau-load --port 8103 --connections 256 --threads 2 --seconds 10 --pipeline 8

The other servers take the port as their first argument
(`AXUM_NODELAY=1` for axum with `TCP_NODELAY`; `GOMAXPROCS=6` for Go).
basic-webserver's app is a five-line `respond!` returning `Server.text`,
built with `roc build --opt=speed` against `~/devel/rocstache`.

## Addendum: a Roc app on fourneau (M4 first light)

The same `hello` in Roc on roux (safe build, host and app
in one static executable), same conditions: 335,256 requests/s
unpipelined (server cores 89% busy), 505k-581k at pipeline 8 across runs
(p99 8.4 ms), 100 MB resident. basic-webserver, the Roc platform it
replaces: 139,033 and 144,534. A run with fiber stacks fully pre-touched
(a bug since fixed, 16 GB resident) served 721k; why the difference is
open (DIARY).

## Correction and caveat (later on 2026-10-05)

"Six cores" above means six hyperthreads: three physical cores of a
laptop that boosts to 4.9 GHz and throttles when warm. The same unchanged
binary later measured 1.13M and 833k requests/s twenty minutes apart, so
the requests/s here are a ranking, not a rate. Comparisons since then
count user-space instructions and cycles per request with `perf stat`
(experiment 15).
