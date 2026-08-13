pub const h2 = struct {
    pub const frame = @import("h2/frame.zig");
    pub const hpack = @import("h2/hpack.zig");
    pub const huffman = @import("h2/huffman.zig");
    pub const stream = @import("h2/stream.zig");
    pub const connection = @import("h2/connection.zig");
    pub const client = @import("h2/client.zig");
    pub const conformance_test = @import("h2/conformance_test.zig");
    pub const fuzz_test = @import("h2/fuzz_test.zig");
};

pub const io = struct {
    pub const tcp = @import("io/tcp.zig");
    pub const TcpTransport = tcp.TcpTransport;
    pub const tls = @import("io/tls.zig");
    pub const TlsTransport = tls.TlsTransport;
};

pub const grpc = @import("grpc/root.zig");
pub const quic = @import("quic/root.zig");

test {
    _ = h2.frame;
    _ = h2.hpack;
    _ = h2.huffman;
    _ = h2.stream;
    _ = h2.connection;
    _ = h2.client;
    _ = h2.conformance_test;
    _ = h2.fuzz_test;
    _ = io.tcp;
    _ = io.tls;
    _ = grpc;
    _ = quic;
}
