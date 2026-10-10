# Differential tests: fourneau, Go and axum (M11)

The same requests, byte for byte, to fourneau-zig, Go's net/http and
axum (the dragrace's competitors): `dragrace diff` (fourneau-dragrace,
branch `after-race`, `tools/cmd/dragrace/diff.go`), 59 cases where
HTTP/1.1 parsers are known to differ and where request smuggling lives.
Compared: each response's status, whether the connection was closed,
and the body (an error's body is each stack's own words: its status
only). First run 2026-10-10: 46 cases differed; after the fixes below,
28, each a decision written here.

## Fixed in fourneau

| case | was | now | why |
|---|---|---|---|
| `version-12`: `HTTP/1.2` | 505 | as 1.1 | RFC 9110 §2.5: a later minor version is read as the highest known. Go did. |
| `garbage`: TLS bytes on the plain port | waited for a line end, 10 s | 400 at once | A method is a token: bytes that cannot begin one are refused as they come. |
| `get-with-body`: a GET whose small body the handler ignores, a request pipelined after | answered, then closed: the second lost | both answered | A length-framed body already received is skipped (`skip_buffered_body`); one still on its way, or chunked, still closes. Go and axum skip. |

And in the competitor (the dragrace's fourneau-zig, its routing, not
fourneau): HEAD answered as GET, a query no longer breaks a route
(`Head.path()`, new), 405 with `Allow` for a wrong method.

## Kept: fourneau is stricter, on purpose

| case | fourneau | Go | axum | why |
|---|---|---|---|---|
| `http11-no-host`, `two-hosts`, `host-space` | 400 | 400 | 200 | RFC 9112 §3.2: MUST 400. |
| `cl-and-te`: both framings | 400, closed | 200 by the chunks | 200, closed | §6.1 allows either; refusing is the smuggling-safe one. |
| `cl-twice-same`: `3` twice | 400 | 200 | 200 | RFC 9110 §8.6 allows refusing; one rule for every duplicate is simpler to trust. |
| `te-gzip-chunked` | 501 | 501 | 200, gzip ignored | We decode no coding but chunked: 501 says so. |
| `te-identity`, `te-chunked-gzip` | 501 | 501 | 400 | Same. |
| `te-http10`: chunked in HTTP/1.0 | 400 | 200, no body | 400 | §6.1: MUST treat as faulty framing. |
| `bare-lf`: a head with bare LFs | 400 | 200 | 200 | §2.2 allows LF alone; refusing it is how parsers stop disagreeing about where a line ends (the http1_head.zig header). |
| `obs-fold`: a folded line | 400 | 200 | 400 | §5.2: reject or unfold; we reject. |
| `expect-other` | 417 | 417 | 200 | RFC 9110 §10.1.1. |
| `asterisk-get`: `GET *` | 400 | 400 | 404 | Only OPTIONS takes `*`. |
| `connect` | 501 | 404 | 404 | We are no proxy: CONNECT is not implemented. |
| `version-20`: `HTTP/2.0` on a 1.1 line | 505 | 505 | 400 | |
| `chunked-bad-size`, `chunked-bare-lf` | 400 | 413 | 400 | Go's 413 is its own. |

## Kept: limits and their statuses

| case | fourneau | Go | axum | why |
|---|---|---|---|---|
| `cl-too-large`: 100 MB announced | 413 at once | waits for the body | waits | `body_bytes_max` (1 MiB): refused before a byte of it. |
| `long-target`: 10,000 bytes | 414 | 404 | 404 | `target_bytes_max` (8 KiB). |
| `long-header`: 20,000 bytes | 431 | 200 | 200 | `head_bytes_max` (16 KiB; nginx's per-line default is 8 KiB). |
| `many-headers`: 200 | 431 | 200 | 431 | `headers_max` (64; browsers send ~20). |

## Kept: the application's business

| case | fourneau | Go | axum | why |
|---|---|---|---|---|
| `asterisk`: `OPTIONS *` | 404 | 200 | 404 | The app decides; this one serves no `*`. |
| `dot-segments`: `/./plaintext` | 404 | 307 to the clean path | 404 | No path is rewritten under the app. |
| `percent-path`: `/%70laintext` | 404 | 200 | 404 | No decoding under the app: `/%70` is not `/p` (Head.path's note). |
| `empty-line-first` | 200 | 400 | 200 | §2.2: SHOULD ignore at least one empty line. |
| `expect-continue`, the body already sent | 200 | 100, 200 | 100, 200 | RFC 9110 §10.1.1: no 100 needed once the body is here. |

## Next

Case families to add: chunked trailers with forbidden fields, very many
small chunks, a body split at every byte, pipelines past the receive
buffer, HTTP/2 (h2spec covers the protocol; a differential run over
h2c would cover the semantics). And the static file server against Go's
`FileServer`, tower-http's `ServeDir` and Caddy (ranges, conditional
requests, `Accept-Encoding`), which M11 names.
