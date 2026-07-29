const std = @import("std");

// HPACK static table stub (RFC 7541 Appendix A)
// Full implementation follows in next iteration.

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

test "hpack stub compiles" {
    const field = HeaderField{ .name = ":method", .value = "GET" };
    try std.testing.expectEqualStrings(":method", field.name);
}
