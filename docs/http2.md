# HTTP/2 in fourneau (M9)

RFC 9113 (HTTP/2) and RFC 7541 (HPACK), for browsers: a page with
event streams (Datastar keeps one per tab) runs out of HTTP/1.1's six
connections per origin. Plan written 2026-10-10, before the code; it
changes as the code teaches.

## Shape

Layers, each tested alone before the server sees it, as HTTP/1.1's are:

1. **HPACK** (`hpack.zig`): integers, strings, Huffman (RFC 7541
   Appendix B), the static table, a dynamic table that is a ring of
   bytes with an array of entries, a decoder with every limit, an
   encoder. Tested against the RFC's Appendix C examples.
2. **Frames** (`http2_frame.zig`): the nine-byte header and each frame
   type's payload, parsed and checked (lengths, padding, stream ids),
   written. Sans-IO.
3. **The connection** (`http2.zig`): a state machine over bytes: the
   preface, settings, streams and their states, flow control both ways,
   errors (a stream's or the connection's), GOAWAY. Its input is bytes;
   its output is events for the server (a request's head, body bytes, a
   stream reset) and frames to send. No socket, no clock: tested by
   scripted conversations, every refusal.
4. **The server**: an HTTP/2 connection's fiber reads frames; each
   request runs its handler on a stream fiber; responses are frames
   appended to the connection's send buffer.

## Data

- **Stream slots**, per shard, allocated at startup (`Config.streams_max`)
  as slabs, like connection slots: a stream's head (decoded headers and
  their bytes), its body window, its scratch, its fiber. A connection
  holds at most `SETTINGS_MAX_CONCURRENT_STREAMS` of them; when the
  shard has none free, a new stream is refused (`REFUSED_STREAM`, which
  a client retries). Running out is a designed state.
- **A slot is held until its handler returns**, whatever the protocol
  says: a stream reset by either side (the client's RST_STREAM, or ours
  for a frame it provoked) stays counted against the connection's limit
  until its handler has finished. This is the answer to Rapid Reset
  (CVE-2023-44487) and MadeYouReset (CVE-2025-8671): the work, not the
  protocol state, is what is limited.
- **The body window is the buffer**: the stream window we advertise is
  the slot's body buffer, so DATA can never arrive faster than it is
  read; WINDOW_UPDATE goes out as the handler reads.
- **One send buffer per connection**: every stream's frames go into it
  between waits (fibers on one thread need no lock); whichever fiber
  finds it unflushed flushes it, while others append. A stream out of
  window waits for the peer's WINDOW_UPDATE, with the send timeout.

## Limits, each with a counter

| attack | limit |
|---|---|
| Rapid Reset, MadeYouReset | slots held until handlers return; resets of both directions counted per connection, GOAWAY `ENHANCE_YOUR_CALM` past a rate |
| CONTINUATION Flood (2024) | a header block's bytes bounded (`head_bytes_max`), frames counted |
| HPACK bomb | the decoded header list bounded (`SETTINGS_MAX_HEADER_LIST_SIZE`), the dynamic table at our size |
| PING, SETTINGS, empty-frame floods (CVE-2019-9512, -9515, -9518) | counted per window, GOAWAY past it |
| data dribble, zero window (CVE-2019-9511, -9517) | frames written only as large as the window allows, the send timeout on a stalled window |
| priority (CVE-2019-9513) | ignored (RFC 9113 §5.3.2) |

## Protocol choices

- h2 by ALPN on TLS (browsers); h2c by prior knowledge on plain HTTP
  (benchmarks, curl `--http2-prior-knowledge`). No `Upgrade: h2c`
  (removed by RFC 9113).
- No server push (`SETTINGS_ENABLE_PUSH` honored as 0; never sent).
- Priority signals ignored; streams are served as their handlers go.
- The same `App.handle`: a `Request` is an HTTP/1.1 connection's or an
  HTTP/2 stream's, chosen by a switch, never a function pointer.

## Proved by

RFC 7541's examples; every frame refusal in tests; the simulator's
clients speaking HTTP/2; h2spec clean; curl and a browser; the load
test, against Go and axum (a dragrace workload).
