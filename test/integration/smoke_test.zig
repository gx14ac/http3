// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const http3 = @import("http3");
const grpc = http3.grpc;
const TcpTransport = http3.io.TcpTransport;
const TlsTransport = http3.io.TlsTransport;
const posix = std.posix;

// Integration test: connect to a real gRPC server via plaintext TCP (h2c).
// Requires the Go test server running on localhost:50051.
// Run with: zig build integration-test

fn connect() !TcpTransport {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051);
    const transport = try TcpTransport.connectAddress(addr);
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(transport.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
    return transport;
}

test "unary echo RPC over TCP" {
    const allocator = std.testing.allocator;
    var transport = connect() catch |err| {
        std.debug.print("SKIP: cannot connect to localhost:50051 ({s})\n", .{@errorName(err)});
        return;
    };
    defer transport.close();

    var ch = grpc.Channel.init(allocator, transport.reader(), transport.writer(), "localhost:50051", .{ .scheme = "http" });
    try ch.handshake();
    defer ch.close();

    var response_buf: [4096]u8 = undefined;
    const result = try ch.unary("/echo.EchoService/Echo", "hello from zig", .{}, &response_buf);

    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("hello from zig", result.data);
}

test "unary echo error RPC over TCP" {
    const allocator = std.testing.allocator;
    var transport = connect() catch |err| {
        std.debug.print("SKIP: cannot connect to localhost:50051 ({s})\n", .{@errorName(err)});
        return;
    };
    defer transport.close();

    var ch = grpc.Channel.init(allocator, transport.reader(), transport.writer(), "localhost:50051", .{ .scheme = "http" });
    try ch.handshake();
    defer ch.close();

    var response_buf: [4096]u8 = undefined;
    const result = try ch.unary("/echo.EchoService/EchoError", "test_error", .{}, &response_buf);

    try std.testing.expectEqual(grpc.Code.internal, result.status.code);
}

test "server streaming RPC over TCP" {
    const allocator = std.testing.allocator;
    var transport = connect() catch |err| {
        std.debug.print("SKIP: cannot connect to localhost:50051 ({s})\n", .{@errorName(err)});
        return;
    };
    defer transport.close();

    var ch = grpc.Channel.init(allocator, transport.reader(), transport.writer(), "localhost:50051", .{ .scheme = "http" });
    try ch.handshake();
    defer ch.close();

    var sh = try ch.serverStream("/echo.EchoService/ServerStream", "hello", .{});
    defer sh.deinit();

    var buf: [256]u8 = undefined;
    var count: usize = 0;

    while (try sh.recv(&buf)) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expect(sh.getStatus().isOk());
}

test "bidi streaming RPC over TCP" {
    const allocator = std.testing.allocator;
    var transport = connect() catch |err| {
        std.debug.print("SKIP: cannot connect to localhost:50051 ({s})\n", .{@errorName(err)});
        return;
    };
    defer transport.close();

    var ch = grpc.Channel.init(allocator, transport.reader(), transport.writer(), "localhost:50051", .{ .scheme = "http" });
    try ch.handshake();
    defer ch.close();

    var sh = try ch.bidiStream("/echo.EchoService/BidiStream", .{});
    defer sh.deinit();

    try sh.send("ping1");

    var buf: [256]u8 = undefined;
    const resp1 = try sh.recv(&buf);
    try std.testing.expect(resp1 != null);
    try std.testing.expectEqualStrings("echo:ping1", resp1.?);

    try sh.send("ping2");
    const resp2 = try sh.recv(&buf);
    try std.testing.expect(resp2 != null);
    try std.testing.expectEqualStrings("echo:ping2", resp2.?);

    try sh.closeSend();
    const resp3 = try sh.recv(&buf);
    try std.testing.expect(resp3 == null);

    try std.testing.expect(sh.getStatus().isOk());
}

test "unary echo RPC over TLS (prior knowledge)" {
    const allocator = std.testing.allocator;

    // Connect to TLS-enabled gRPC server on port 50052
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50052);
    var tcp = TcpTransport.connectAddress(addr) catch |err| {
        std.debug.print("SKIP: cannot connect to localhost:50052 ({s})\n", .{@errorName(err)});
        return;
    };
    defer tcp.close();

    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(tcp.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    // TLS handshake (no CA verification for local testing)
    var tcp_read_buf: [TlsTransport.min_buffer_len]u8 = undefined;
    var tcp_write_buf: [TlsTransport.min_buffer_len]u8 = undefined;
    var tls_read_buf: [TlsTransport.min_buffer_len]u8 = undefined;
    var tls_write_buf: [TlsTransport.min_buffer_len]u8 = undefined;

    var tls: TlsTransport = undefined;
    tls.init(
        tcp.reader(),
        tcp.writer(),
        &tcp_read_buf,
        &tcp_write_buf,
        &tls_read_buf,
        &tls_write_buf,
        .{ .host = "localhost" },
    ) catch |err| {
        std.debug.print("SKIP: TLS handshake failed ({s})\n", .{@errorName(err)});
        return;
    };
    defer tls.close();

    // gRPC over TLS (scheme defaults to "https")
    var ch = grpc.Channel.init(allocator, tls.reader(), tls.writer(), "localhost:50052", .{});
    try ch.handshake();
    defer ch.close();

    var response_buf: [4096]u8 = undefined;
    const result = try ch.unary("/echo.EchoService/Echo", "hello over tls", .{}, &response_buf);

    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("hello over tls", result.data);
}
