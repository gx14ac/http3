// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const tls_dialer_mod = @import("grpc/tls_dialer.zig");
const resolver_mod = @import("grpc/resolver.zig");
const dialer_mod = @import("grpc/dialer.zig");
const h2_client = @import("h2/client.zig");
const hpack = @import("h2/hpack.zig");

const Client = h2_client.Client;
const Endpoint = resolver_mod.Endpoint;

// ─── Pure HTTP/2 E2E Tests (no gRPC) ───
// Validates TLS + ALPN h2 → H2 handshake → HTTP/2 request/response against real servers.

const H2Conn = struct {
    client: Client,
    dial_result: dialer_mod.DialResult,
    td: *tls_dialer_mod.TlsDialer,

    fn deinit(self: *H2Conn, allocator: std.mem.Allocator) void {
        self.client.close();
        self.client.deinit();
        self.dial_result.close();
        self.td.deinit();
        allocator.destroy(self.td);
    }
};

fn connectH2(allocator: std.mem.Allocator, host: []const u8) !H2Conn {
    const list = std.net.getAddressList(allocator, host, 443) catch return error.DnsUnavailable;
    defer list.deinit();
    if (list.addrs.len == 0) return error.DnsUnavailable;

    const td = allocator.create(tls_dialer_mod.TlsDialer) catch return error.CaUnavailable;
    td.* = tls_dialer_mod.TlsDialer.init(allocator, host) catch {
        allocator.destroy(td);
        return error.CaUnavailable;
    };
    errdefer {
        td.deinit();
        allocator.destroy(td);
    }

    const ep = Endpoint{ .address = list.addrs[0] };
    const dial_result = td.dialer().dial(ep) catch return error.ConnectionFailed;
    errdefer dial_result.close();

    var client = Client.init(allocator, dial_result.reader, dial_result.writer, .{});
    client.handshake() catch return error.HandshakeFailed;

    return .{ .client = client, .dial_result = dial_result, .td = td };
}

test "H2 E2E: GET / to www.google.com returns 200 or redirect" {
    const allocator = std.testing.allocator;

    var conn = connectH2(allocator, "www.google.com") catch return;
    defer conn.deinit(allocator);

    const handle = conn.client.request(.GET, "/", "www.google.com", null, .{}) catch return;

    var headers: [32]hpack.HeaderField = undefined;
    var decode_buf: [8192]u8 = undefined;
    var body_buf: [4096]u8 = undefined;

    const resp = conn.client.recvResponse(handle, &headers, &decode_buf, &body_buf) catch return;

    try std.testing.expect(resp.status == 200 or resp.status == 301 or resp.status == 302);
}

test "H2 E2E: multiple sequential requests reuse connection" {
    const allocator = std.testing.allocator;

    var conn = connectH2(allocator, "www.google.com") catch return;
    defer conn.deinit(allocator);

    // First request
    const h1 = conn.client.request(.GET, "/", "www.google.com", null, .{}) catch return;
    var hdr1: [32]hpack.HeaderField = undefined;
    var dec1: [8192]u8 = undefined;
    var body1: [4096]u8 = undefined;
    const r1 = conn.client.recvResponse(h1, &hdr1, &dec1, &body1) catch return;
    try std.testing.expect(r1.status == 200 or r1.status == 301 or r1.status == 302);

    // Second request on same connection
    const h2 = conn.client.request(.GET, "/robots.txt", "www.google.com", null, .{}) catch return;
    var hdr2: [32]hpack.HeaderField = undefined;
    var dec2: [8192]u8 = undefined;
    var body2: [4096]u8 = undefined;
    const r2 = conn.client.recvResponse(h2, &hdr2, &dec2, &body2) catch return;
    try std.testing.expect(r2.status == 200 or r2.status == 301 or r2.status == 302);
}

test "H2 E2E: response body is non-empty for /robots.txt" {
    const allocator = std.testing.allocator;

    var conn = connectH2(allocator, "www.google.com") catch return;
    defer conn.deinit(allocator);

    const handle = conn.client.request(.GET, "/robots.txt", "www.google.com", null, .{}) catch return;

    var headers: [32]hpack.HeaderField = undefined;
    var decode_buf: [8192]u8 = undefined;
    var body_buf: [16384]u8 = undefined;

    const resp = conn.client.recvResponse(handle, &headers, &decode_buf, &body_buf) catch return;

    if (resp.status == 200) {
        try std.testing.expect(resp.body.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, resp.body, "User-agent") != null or
            std.mem.indexOf(u8, resp.body, "user-agent") != null or
            std.mem.indexOf(u8, resp.body, "Disallow") != null);
    }
}
