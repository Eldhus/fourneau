# tls.zig

Igor Anić's TLS 1.3 (and 1.2) for Zig: github.com/ianic/tls.zig, MIT
(`LICENSE`). fourneau uses its server handshake on the connection's
fiber, then gives the session keys to the kernel (kTLS): `src/tls.zig`.

Vendored whole and unchanged (`src/`), so a new upstream is a copy:

Upstream: commit `bd22bcb` (2026-10-03, "update demo"), which builds on
Zig 0.17.0.

To update (the vendored-sources chore, in TODO.md): copy `src/` and
`LICENSE` from the new commit, name it above, run the suite and the HTTPS
checks (DIARY, 2026-10-06: TLS), note what changed in the DIARY.
