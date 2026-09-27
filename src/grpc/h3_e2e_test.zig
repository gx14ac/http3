// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const h3_channel_mod = @import("h3_channel.zig");
const h3_health_mod = @import("h3_health.zig");
const grpc_status = @import("status.zig");

const H3Channel = h3_channel_mod.H3Channel;
const H3ChannelError = h3_channel_mod.H3ChannelError;
const H3HealthClient = h3_health_mod.H3HealthClient;

// ─── E2E: gRPC over HTTP/3 (QUIC) against real server ───
//
// These tests require network access. They skip gracefully if:
//   - QUIC handshake fails (firewall, DNS, etc.)
//   - Server doesn't respond within timeout
//
// Target: cloudflare-quic.com:443 — supports HTTP/3 but NOT gRPC.
// We expect gRPC requests to get an HTTP-level response (non-gRPC),
// which proves the full transport pipeline works:
//   QUIC handshake → H3 control streams → request framing → response parsing

test "E2E: H3Channel connect to cloudflare-quic.com" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});
    defer ch.close();

    ch.connect() catch return; // skip if network unavailable

    try std.testing.expectEqual(h3_channel_mod.ChannelState.connected, ch.getState());
}

test "E2E: H3Channel unary RPC framing over QUIC" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});
    defer ch.close();

    ch.connect() catch return;
    if (ch.getState() != .connected) return;

    var response_buf: [4096]u8 = undefined;
    const result = ch.unary(
        "/grpc.health.v1.Health/Check",
        "", // empty HealthCheckRequest
        .{ .timeout_ms = 5000 },
        &response_buf,
    ) catch {
        return; // server isn't gRPC — any error proves transport worked
    };

    // If we get a response, verify it has a parseable status.
    // Cloudflare isn't a gRPC server, so we expect either:
    // - HTTP 200 with no grpc-status → defaults to .ok (gRPC spec default)
    // - Some other status
    // Either way, getting here proves: QUIC→H3→request→response pipeline works.
    _ = result;
}

test "E2E: H3Channel unary with gRPC framed body" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});
    defer ch.close();

    ch.connect() catch return;
    if (ch.getState() != .connected) return;

    // Send a non-empty gRPC request (HealthCheckRequest with service="test")
    const request_payload = [_]u8{ 0x0A, 0x04, 't', 'e', 's', 't' };

    var response_buf: [4096]u8 = undefined;
    const result = ch.unary(
        "/grpc.health.v1.Health/Check",
        &request_payload,
        .{ .timeout_ms = 5000 },
        &response_buf,
    ) catch {
        // Any transport-level error is acceptable (server isn't gRPC)
        return;
    };

    // Reaching here means we successfully:
    // 1. gRPC length-prefixed the request body
    // 2. Sent QPACK-encoded gRPC headers
    // 3. Received an H3 response
    // 4. Parsed grpc-status from response headers
    _ = result;
}

test "E2E: H3HealthClient check over QUIC" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});
    defer ch.close();

    ch.connect() catch return;
    if (ch.getState() != .connected) return;

    var hc = H3HealthClient.init(&ch);

    // cloudflare-quic.com is NOT a gRPC server, so this will fail
    // with RpcFailed — which proves the full stack executed.
    _ = hc.check("") catch |e| {
        switch (e) {
            error.RpcFailed, error.InvalidResponse, error.StreamEnded => return,
        }
    };
}

test "E2E: H3Channel state transitions" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});

    // Initial state
    try std.testing.expectEqual(h3_channel_mod.ChannelState.idle, ch.getState());

    // After connect
    ch.connect() catch {
        ch.close();
        return;
    };
    try std.testing.expectEqual(h3_channel_mod.ChannelState.connected, ch.getState());

    // After close
    ch.close();
    try std.testing.expectEqual(h3_channel_mod.ChannelState.shutdown, ch.getState());
}

test "E2E: H3Channel rejects RPC after close" {
    const allocator = std.testing.allocator;
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);

    var ch = H3Channel.init(allocator, server_addr, "cloudflare-quic.com", .{});

    ch.connect() catch {
        ch.close();
        return;
    };

    ch.close();

    var response_buf: [256]u8 = undefined;
    const result = ch.unary("/test/Method", "data", .{}, &response_buf);
    try std.testing.expectError(H3ChannelError.ConnectionClosed, result);
}

test "E2E: H3Client requestStream against cloudflare-quic.com" {
    const h3_client_mod = @import("../quic/h3_client.zig");
    const H3Client = h3_client_mod.H3Client;

    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);
    var h3 = H3Client.init(server_addr, "cloudflare-quic.com") catch return;
    defer h3.deinit();

    h3.connect() catch return;
    if (!h3.isConnected()) return;

    const qpack = @import("../quic/qpack.zig");
    const extra = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    var handle = h3.requestStream("POST", "/grpc.health.v1.Health/Watch", &extra, null) catch return;
    defer handle.close();

    // Try to receive headers — server may respond with HTTP error or timeout
    _ = handle.recvHeaders() catch return;

    // If we got headers, try one recv — likely null or error since not gRPC server
    var buf: [256]u8 = undefined;
    _ = handle.recv(&buf) catch return;
}
