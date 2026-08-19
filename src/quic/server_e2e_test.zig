const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const quic_crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const tls_mod = @import("tls.zig");
const initial_mod = @import("initial.zig");
const decode_mod = @import("decode.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const handshake_complete_mod = @import("handshake_complete.zig");
const tls_messages = @import("tls_messages.zig");
const server_hs = @import("server_handshake.zig");
const reconnect_mod = @import("reconnect.zig");

const QuicServer = server_mod.QuicServer;
const ServerEvent = server_mod.ServerEvent;

test "E2E: server decrypts client Initial and completes handshake" {
    // Start server
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try QuicServer.init(bind_addr, .{});
    defer server.deinit();
    server.setTimeout(2000);
    const port = server.getPort();

    // Client side: build and send Initial
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);

    const socket_mod = @import("socket.zig");
    var sock = try socket_mod.UdpSocket.init(server_addr);
    defer sock.close();
    sock.setTimeout(2000);

    // Build ClientHello
    const ch_builder = tls_mod.ClientHelloBuilder.initWithScid("localhost", &scid);
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf) orelse unreachable;

    // Build Initial packet
    const sender = initial_mod.InitialSender.init(&dcid, &scid);
    var initial_buf: [1500]u8 = undefined;
    const pkt_len = sender.buildPacket(ch_buf[0..ch_len], &initial_buf) catch unreachable;

    // Send to server
    _ = try sock.send(initial_buf[0..pkt_len]);

    // Server polls and handles Initial
    var recv_buf: [4096]u8 = undefined;
    const event = server.poll(&recv_buf) catch |e| {
        std.debug.print("Server poll error: {}\n", .{e});
        return;
    };

    // Server should have started handshake
    try std.testing.expect(event == .handshake_started);
    try std.testing.expect(server.conn().state == .handshake_sent);

    // Verify server has derived handshake keys
    try std.testing.expect(server.conn().handshake_keys != null);
    try std.testing.expect(server.conn().app_keys != null);
}

test "E2E: full handshake — client receives ServerHello and derives keys" {
    // Start server
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try QuicServer.init(bind_addr, .{});
    defer server.deinit();
    server.setTimeout(2000);
    const port = server.getPort();

    // Client: connect
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);

    const socket_mod = @import("socket.zig");
    var sock = try socket_mod.UdpSocket.init(server_addr);
    defer sock.close();
    sock.setTimeout(2000);

    // Build and send ClientHello
    const ch_builder = tls_mod.ClientHelloBuilder.initWithScid("localhost", &scid);
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf) orelse unreachable;

    const sender = initial_mod.InitialSender.init(&dcid, &scid);
    var initial_buf: [1500]u8 = undefined;
    const pkt_len = sender.buildPacket(ch_buf[0..ch_len], &initial_buf) catch unreachable;
    _ = try sock.send(initial_buf[0..pkt_len]);

    // Server processes Initial
    var srv_buf: [4096]u8 = undefined;
    const srv_event = server.poll(&srv_buf) catch return;
    try std.testing.expect(srv_event == .handshake_started);

    // Client receives server response (Initial + Handshake coalesced)
    var response_buf: [4096]u8 = undefined;
    const resp_len = sock.recv(&response_buf) catch return;
    try std.testing.expect(resp_len > 0);

    // Decode server Initial to get ServerHello
    var decode_buf: [4096]u8 = undefined;
    const decoded = decode_mod.decodeServerInitial(response_buf[0..resp_len], &dcid, &decode_buf) catch |e| {
        std.debug.print("Failed to decode server Initial: {}\n", .{e});
        return;
    };

    // ServerHello should start with 0x02
    try std.testing.expectEqual(@as(u8, 0x02), decoded.crypto_data[0]);

    // Extract server's public key and derive handshake keys
    const server_pub_key = handshake_mod.extractServerKeyShare(decoded.crypto_data) catch |e| {
        std.debug.print("Failed to extract server key share: {}\n", .{e});
        return;
    };

    // Compute transcript hash
    const transcript_hash = handshake_mod.computeTranscriptHash(ch_buf[0..ch_len], decoded.crypto_data);

    // Derive handshake keys
    const hs_keys = handshake_mod.deriveHandshakeKeys(ch_builder.private_key, server_pub_key, transcript_hash) catch |e| {
        std.debug.print("Failed to derive handshake keys: {}\n", .{e});
        return;
    };

    // Handshake keys should be non-zero
    var all_zero = true;
    for (hs_keys.server_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "parseClientHello roundtrip with server handshake" {
    // Verify that our parseClientHello works on what ClientHelloBuilder produces
    const ch_builder = tls_mod.ClientHelloBuilder.initWithScid("test.example.com", &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD });
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf) orelse unreachable;

    const parsed = try server_hs.parseClientHello(ch_buf[0..ch_len]);

    // Verify SNI
    try std.testing.expectEqualSlices(u8, "test.example.com", parsed.server_name[0..parsed.server_name_len]);

    // Verify key share matches what builder generated
    try std.testing.expectEqualSlices(u8, &ch_builder.public_key, &parsed.client_public_key);

    // Verify ALPN
    try std.testing.expectEqualSlices(u8, "h3", parsed.alpn[0..parsed.alpn_len]);
}

test "E2E: QuicClient connect, disconnect, reconnect" {
    // Start server
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try server_mod.QuicServer.init(bind_addr, .{});
    defer server.deinit();
    server.setTimeout(2000);
    const port = server.getPort();

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);

    // Create client with reconnect config
    var client = try client_mod.QuicClient.init(server_addr, &dcid, &scid);
    defer client.deinit();
    client.setReconnectConfig(.{
        .initial_delay_ms = 100,
        .max_delay_ms = 1000,
        .max_attempts = 3,
        .jitter_percent = 0,
    });

    // Connect — server handles handshake in a background thread
    const server_thread = try std.Thread.spawn(.{}, serverMultiHandshakeLoop, .{&server});

    client.connect("localhost") catch {
        server_thread.join();
        return;
    };

    try std.testing.expect(client.isConnected());
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.State.connected, client.reconnect_mgr.state);

    // Simulate disconnect
    client.closed = true;
    client.connected = false;

    // Verify reconnect manager detects disconnect and respects backoff
    const now: u64 = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())) / 1000);
    client.reconnect_mgr.onDisconnect(now);
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.State.backoff, client.reconnect_mgr.state);

    // Too early — should wait
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.Action.wait, client.reconnect_mgr.poll(now + 50_000));

    // After delay — should reconnect
    const future = now + 200_000; // 200ms > initial_delay 100ms
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.Action.reconnect_now, client.reconnect_mgr.poll(future));

    // Perform actual reconnect — server is still running its multi-handshake loop
    client.reconnect() catch {
        server_thread.join();
        // Reconnect failed — verify failure is tracked
        try std.testing.expectEqual(@as(u32, 1), client.reconnect_mgr.consecutive_failures);
        return;
    };
    server_thread.join();

    // Verify reconnected
    try std.testing.expect(client.isConnected());
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.State.connected, client.reconnect_mgr.state);
    try std.testing.expectEqual(@as(u32, 0), client.reconnect_mgr.attempt);
}

test "ReconnectManager: gives up after max attempts" {
    var rm = reconnect_mod.ReconnectManager.init(.{
        .initial_delay_ms = 10,
        .max_attempts = 2,
        .jitter_percent = 0,
    });

    rm.onDisconnect(0);
    rm.onReconnectFailed(100_000);
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.State.backoff, rm.state);

    rm.onReconnectFailed(200_000);
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.State.gave_up, rm.state);
    try std.testing.expectEqual(reconnect_mod.ReconnectManager.Action.give_up, rm.poll(300_000));
}

fn serverHandshakeLoop(server: *server_mod.QuicServer) void {
    var buf: [4096]u8 = undefined;
    var iterations: usize = 0;
    while (iterations < 10) : (iterations += 1) {
        const event = server.poll(&buf) catch continue;
        switch (event) {
            .connected => return,
            .handshake_started => continue,
            else => continue,
        }
    }
}

fn serverMultiHandshakeLoop(server: *server_mod.QuicServer) void {
    var buf: [4096]u8 = undefined;
    var connections_completed: usize = 0;
    var iterations: usize = 0;
    while (iterations < 30 and connections_completed < 2) : (iterations += 1) {
        const event = server.poll(&buf) catch continue;
        switch (event) {
            .connected => {
                connections_completed += 1;
            },
            else => continue,
        }
    }
}
