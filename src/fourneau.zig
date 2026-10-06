//! fourneau as a module, for programs that embed it (roux's host).
//! Private: no promise about this surface (DESIGN.md, "fourneau is
//! private").

pub const server = @import("server.zig");
pub const http1_head = @import("http1_head.zig");
pub const http1_response = @import("http1_response.zig");
