//! RFC 7932's static dictionary (README.md).

pub const bytes: *const [122_784]u8 = @embedFile("dictionary.bin");
