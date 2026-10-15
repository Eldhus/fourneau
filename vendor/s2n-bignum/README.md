# s2n-bignum

AWS's big-number and elliptic-curve routines in x86-64 assembly, each with a machine-checked proof
in HOL Light that its instructions compute the mathematical function for every input:
github.com/awslabs/s2n-bignum, Apache-2.0 OR ISC OR MIT-0 (`LICENSE`, `NOTICE`). It is what aws-lc
runs for X25519, so what axum's rustls runs in fourneau-dragrace.

fourneau's TLS handshake uses it through `src/curves.zig`: X25519's key pair and shared secret, and
for ECDSA P-256 signing the multiple of the base point and the inverse of the nonce, rather than
writing our own or keeping std's (~8× slower for a signature).

Vendored: only the routines `src/curves.zig` calls, unchanged, each with its `_alt` form (the same
function without BMI2 and ADX):

- `x86/curve25519/curve25519_x25519{,_alt}.S`: X25519 (the `_byte` entry)
- `x86/curve25519/curve25519_x25519base{,_alt}.S`: X25519 of the base point
- `x86/p256/p256_scalarmulbase{,_alt}.S`: k·P from a table of multiples
- `x86/p256/bignum_tomont_p256{,_alt}.S`: to Montgomery form (the table)
- `x86/generic/bignum_modinv.S`: inverse modulo an odd number (k⁻¹ mod n)
- `include/_internal_s2n_bignum_x86.h`: the macros they include

Upstream: commit `4d1356a` (2026-09-29, "arm/proofs: lift a proof over the BTI landing pad");
s2n-bignum has no release tags.

The proofs cover each routine on its own, for inputs in the ranges its header states. The calls,
the ranges and the P-256 table are ours (`src/curves.zig`): every result there is checked against
Zig std's.

To update: copy these files and `LICENSE`, `NOTICE` from the new commit, name it above, run the
suite (`zig build test`: the curves' tests compare against std) and the HTTPS checks.
