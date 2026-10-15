# tls.zig

Igor Anić's TLS 1.3 (and 1.2) for Zig: github.com/ianic/tls.zig, MIT (`LICENSE`). fourneau uses its
server handshake on the connection's fiber, then gives the session keys to the kernel (kTLS):
`src/tls.zig`.

Vendored whole (`src/`), unchanged but for fourneau's patch, each place marked "fourneau's patch":

- `src/handshake_common.zig` (2026-10-10): X25519 and P-256 ECDSA signing on verified assembly.
    - X25519 (the key pair and the shared secret) and P-256 signing call fourneau's `src/curves.zig`.
    - That runs s2n-bignum's verified assembly (vendor/s2n-bignum); std's took ~310 µs a handshake.
    - The module imports `curves` for it (build.zig).
    - The hybrid group's X25519 (`x25519_ml_kem768`, which fourneau does not offer) stays std's.
- `src/transcript.zig`, `src/handshake_server.zig` (2026-10-11): one transcript hash.
    - A server that asks for no client certificate feeds only its suite's hash to the transcript.
    - That starts once the suite is chosen (`useOnly`), not SHA-256, SHA-384 and SHA-512 all.
    - `hash` asserts no one reads another. 4% of a handshake's instructions.
- `src/transcript.zig`, `src/cipher.zig` (2026-10-11): `Sha256` is fourneau's `src/sha256.zig`.
    - That is std's, with the CPU's SHA extensions where `cpuid` finds them.
    - So the transcript, HKDF and HMAC run on it; the module imports `sha256` (build.zig).
    - `Transcript.hash` hands code that names std's own `Sha256` the same state.
    - That code is the RSA and TLS 1.2 signers.
- `src/transcript.zig`, `src/cipher.zig` (2026-10-11): the TLS 1.3 key schedule hashes less.
    - Without a pre-shared key, the handshake secret's extraction salt is a compile-time constant.
    - That constant is `derived_without_psk`.
    - A secret that derives several labels keys its HMAC once (`KeyedLabels`).
    - Those are the handshake and master secrets, and each traffic secret's key and iv.
    - Checked against std's `hkdfExpandLabel`. 15 SHA-256 compressions of ~130 a handshake.
    - fourneau's `zig build test` runs tls.zig's own tests now.

Upstream: commit `bd22bcb` (2026-10-03, "update demo"), which builds on Zig 0.17.0.

To update: copy `src/` and `LICENSE` from the new commit, put the patch back (grep "fourneau's
patch" in the old copy, the places listed above), name the commit above, run the suite and the
HTTPS checks (curl over HTTP/1.1 and HTTP/2, `openssl s_client -ciphersuites` for each suite
offered).
