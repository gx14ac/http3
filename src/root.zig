pub const h2 = struct {
    pub const frame = @import("h2/frame.zig");
    pub const hpack = @import("h2/hpack.zig");
};

test {
    _ = h2.frame;
    _ = h2.hpack;
}
