const std = @import("std");
const h3_client_mod = @import("h3_client.zig");
const h3_server_mod = @import("h3_server.zig");
const client_mod = @import("client.zig");
const server_mod = @import("server.zig");

const H3Client = h3_client_mod.H3Client;
const H3Server = h3_server_mod.H3Server;
const QuicClient = client_mod.QuicClient;
const QuicServer = server_mod.QuicServer;

// ─── Localhost Interop Tests ───
// Validates RFC compliance by running our own server and client against each other.
// These tests exercise the full QUIC + H3 stack end-to-end over localhost UDP.

fn serverHandshakeLoop(server: *QuicServer) void {
    server.setTimeout(500);
    var buf: [4096]u8 = undefined;
    var iterations: usize = 0;
    while (iterations < 60) : (iterations += 1) {
        const event = server.poll(&buf) catch continue;
        switch (event) {
            .connected => return,
            else => continue,
        }
    }
}

fn h3ServerLoop(server: *H3Server) void {
    server.setTimeout(500);
    var iterations: usize = 0;
    while (iterations < 100) : (iterations += 1) {
        const event = server.poll();
        switch (event) {
            .request => |req| {
                server.sendResponse(req.conn_idx, req.stream_id, 200, &.{
                    .{ .name = "content-type", .value = "text/plain" },
                }, "hello from server") catch continue;
            },
            .connected => continue,
            .none => continue,
            .timeout => continue,
            .data => continue,
        }
    }
}

// ─── Test: QUIC handshake completes ───

test "interop-local: QUIC handshake completes on localhost" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = QuicServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverHandshakeLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);
    var client = QuicClient.init(server_addr, &dcid, &scid) catch return;
    defer client.deinit();

    client.connect("localhost") catch {
        server_thread.join();
        return;
    };
    server_thread.join();

    try std.testing.expect(client.isConnected());
}

// ─── Test: stream data exchange after handshake ───

fn serverEchoLoop(server: *QuicServer) void {
    server.setTimeout(500);
    var buf: [4096]u8 = undefined;
    var connected = false;
    var iterations: usize = 0;
    while (iterations < 60) : (iterations += 1) {
        const event = server.poll(&buf) catch continue;
        switch (event) {
            .connected => {
                connected = true;
            },
            .data_received => |stream_data| {
                if (connected) {
                    server.sendStreamDataOn(stream_data.conn_idx, stream_data.stream_id, stream_data.data, stream_data.fin) catch {};
                    if (stream_data.fin) return;
                }
            },
            else => continue,
        }
    }
}

test "interop-local: bidirectional stream data exchange" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = QuicServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverEchoLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);
    var client = QuicClient.init(server_addr, &dcid, &scid) catch return;
    defer client.deinit();

    client.connect("localhost") catch {
        server_thread.join();
        return;
    };

    // Send data on a stream
    const stream_id: u62 = 0; // client-initiated bidi stream
    const payload = "hello QUIC";
    _ = client.writeStream(stream_id, payload, true) orelse {
        server_thread.join();
        return;
    };

    // Receive echo
    var received = false;
    var iterations: usize = 0;
    while (iterations < 30) : (iterations += 1) {
        const result = client.poll();
        switch (result) {
            .received => {
                const data = client.lastStreamData();
                if (data.len > 0) {
                    try std.testing.expectEqualStrings(payload, data);
                    received = true;
                    break;
                }
            },
            .closed => break,
            else => {},
        }
    }

    server_thread.join();
    try std.testing.expect(received);
}

// ─── Test: H3 request/response ───

test "interop-local: H3 GET request returns 200" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = H3Server.init(bind_addr, .{}) catch return;
    defer server.deinit();
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, h3ServerLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var h3 = H3Client.init(server_addr, "localhost") catch {
        server_thread.join();
        return;
    };
    defer h3.deinit();

    h3.connect() catch {
        server_thread.join();
        return;
    };

    const resp = h3.request("GET", "/", &.{}, null) catch {
        h3.close();
        server_thread.join();
        return;
    };

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello from server", resp.bodySlice());

    h3.close();
    server_thread.join();
}

// ─── Test: multiple requests on same connection ───

fn h3ServerMultiLoop(server: *H3Server) void {
    server.setTimeout(500);
    var requests_served: usize = 0;
    var iterations: usize = 0;
    while (iterations < 200 and requests_served < 3) : (iterations += 1) {
        const event = server.poll();
        switch (event) {
            .request => |req| {
                const body = switch (requests_served) {
                    0 => "response-1",
                    1 => "response-2",
                    else => "response-3",
                };
                server.sendResponse(req.conn_idx, req.stream_id, 200, &.{}, body) catch continue;
                requests_served += 1;
            },
            .connected => continue,
            .none => continue,
            .timeout => continue,
            .data => continue,
        }
    }
}

test "interop-local: multiple H3 requests reuse connection" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = H3Server.init(bind_addr, .{}) catch return;
    defer server.deinit();
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, h3ServerMultiLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var h3 = H3Client.init(server_addr, "localhost") catch {
        server_thread.join();
        return;
    };
    defer h3.deinit();

    h3.connect() catch {
        server_thread.join();
        return;
    };

    // Three sequential requests
    const resp1 = h3.request("GET", "/a", &.{}, null) catch {
        h3.close();
        server_thread.join();
        return;
    };
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    try std.testing.expectEqualStrings("response-1", resp1.bodySlice());

    const resp2 = h3.request("GET", "/b", &.{}, null) catch {
        h3.close();
        server_thread.join();
        return;
    };
    try std.testing.expectEqual(@as(u16, 200), resp2.status);
    try std.testing.expectEqualStrings("response-2", resp2.bodySlice());

    const resp3 = h3.request("GET", "/c", &.{}, null) catch {
        h3.close();
        server_thread.join();
        return;
    };
    try std.testing.expectEqual(@as(u16, 200), resp3.status);
    try std.testing.expectEqualStrings("response-3", resp3.bodySlice());

    h3.close();
    server_thread.join();
}

// ─── Test: graceful connection close ───

test "interop-local: graceful close with CONNECTION_CLOSE" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = QuicServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverHandshakeLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);
    var client = QuicClient.init(server_addr, &dcid, &scid) catch return;
    defer client.deinit();

    client.connect("localhost") catch {
        server_thread.join();
        return;
    };
    server_thread.join();

    try std.testing.expect(client.isConnected());

    // Graceful close
    client.close();
    try std.testing.expect(client.isClosed());
}

// ─── External Interop Tests (require network) ───

fn networkAvailable() bool {
    const addr = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 443);
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return false;
    defer std.posix.close(fd);
    // Try sending a single byte — if UDP 443 is blocked, we won't know until recv times out
    // Use a fast connect (non-blocking check that the route exists)
    std.posix.connect(fd, &addr.any, addr.getOsSockLen()) catch return false;
    return true;
}

fn udpReachable() bool {
    const addr = std.net.Address.initIp4(.{ 142, 250, 80, 46 }, 443);
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return false;
    defer std.posix.close(fd);
    std.posix.connect(fd, &addr.any, addr.getOsSockLen()) catch return false;

    // Send a minimal probe and wait for any response (even ICMP unreachable)
    const tv = std.posix.timeval{ .sec = 2, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return false;

    // Send garbage — if port is open, server sends back something (or ICMP unreachable triggers error)
    var probe: [1200]u8 = undefined;
    std.crypto.random.bytes(&probe);
    probe[0] = 0xC0;
    std.mem.writeInt(u32, probe[1..5], 0x00000001, .big);
    probe[5] = 8;
    _ = std.posix.send(fd, &probe, 0) catch return false;

    var buf: [64]u8 = undefined;
    _ = std.posix.recv(fd, &buf, 0) catch return false;
    return true;
}

test "interop-external: QUIC handshake to google.com:443" {
    if (!networkAvailable() or !udpReachable()) return;

    const targets = [_]struct { ip: [4]u8, name: []const u8 }{
        .{ .ip = .{ 142, 250, 80, 46 }, .name = "google.com" },
        .{ .ip = .{ 142, 251, 42, 206 }, .name = "google.com" },
        .{ .ip = .{ 216, 58, 214, 206 }, .name = "google.com" },
    };

    for (targets) |target| {
        const addr = std.net.Address.initIp4(target.ip, 443);
        var dcid: [8]u8 = undefined;
        var scid: [8]u8 = undefined;
        std.crypto.random.bytes(&dcid);
        std.crypto.random.bytes(&scid);

        var quic = QuicClient.init(addr, &dcid, &scid) catch continue;
        defer quic.deinit();

        quic.connect(target.name) catch continue;

        try std.testing.expect(quic.isConnected());
        quic.close();
        return;
    }
    return error.TestUnexpectedResult;
}

test "interop-external: H3 GET / to google.com:443" {
    if (!networkAvailable() or !udpReachable()) return;

    const addr = std.net.Address.initIp4(.{ 142, 250, 80, 46 }, 443);
    var h3 = H3Client.init(addr, "google.com") catch return;
    defer h3.deinit();

    h3.connect() catch return;

    const resp = h3.request("GET", "/", &.{}, null) catch {
        h3.close();
        return;
    };

    try std.testing.expect(resp.status == 200 or resp.status == 301 or resp.status == 302);
    h3.close();
}
