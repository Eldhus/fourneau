# brotli's static dictionary

The 122,784-byte dictionary of RFC 7932 (Appendix A), which every brotli
encoder and decoder shares: `dictionary.bin`, byte for byte google/brotli's
`c/common/dictionary.bin` (commit `a0c7daf`, 2017-10-10), whose CRC-32 is
the RFC's, 0x5136cb04 (`brotli_tables.zig` checks it in a test). SHA-256
`20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70`.

It is data the format fixes, not code: it never changes, so it has no
update chore. `dictionary.zig` makes it a module (a file outside a
module's directory cannot be embedded). google/brotli is MIT; the
dictionary is also published in the RFC itself.
