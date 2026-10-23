//! The test root: every file whose tests run (tidy checks none is left out).

test {
    _ = @import("http1_head.zig");
    _ = @import("http1_response.zig");
    _ = @import("http_date.zig");
    _ = @import("fourneau.zig");
    _ = @import("listen.zig");
    _ = @import("port_tests.zig");
    _ = @import("server.zig");
    _ = @import("stdx.zig");
    _ = @import("tidy.zig");
}
