//! The test root: every file whose tests run (tidy checks none is left out).

test {
    _ = @import("brotli_command.zig");
    _ = @import("brotli_context.zig");
    _ = @import("brotli_decode.zig");
    _ = @import("brotli_encode.zig");
    _ = @import("brotli_huffman.zig");
    _ = @import("brotli_match.zig");
    _ = @import("brotli_optimal.zig");
    _ = @import("brotli_tables.zig");
    _ = @import("brotli_tool.zig");
    _ = @import("http1_chunked.zig");
    _ = @import("hello.zig");
    _ = @import("hybrid.zig");
    _ = @import("http1_head.zig");
    _ = @import("http1_response.zig");
    _ = @import("http_date.zig");
    _ = @import("floor.zig");
    _ = @import("fourneau.zig");
    _ = @import("load.zig");
    _ = @import("prng.zig");
    _ = @import("server.zig");
    _ = @import("sim.zig");
    _ = @import("sim_client.zig");
    _ = @import("sim_io.zig");
    _ = @import("static.zig");
    _ = @import("stdx.zig");
    _ = @import("stop.zig");
    _ = @import("tidy.zig");
    _ = @import("tls.zig");
    _ = @import("der.zig");
    _ = @import("acme_crypto.zig");
    _ = @import("acme.zig");
    _ = @import("https.zig");
    _ = @import("site.zig");
}
