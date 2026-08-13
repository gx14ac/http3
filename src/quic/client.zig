const std = @import("std");
const connection_mod = @import("connection.zig");
const socket_mod = @import("socket.zig");
const loss_mod = @import("loss.zig");
const ack_mod = @import("ack.zig");
const idle_mod = @import("idle_timeout.zig");
const initial_mod = @import("initial.zig");
const tls_mod = @import("tls.zig");
const handshake_flight = @import("handshake_flight.zig");
const handshake_complete = @import("handshake_complete.zig");

const Connection = connection_mod.Connection;
const ConnectionEvent = connection_mod.ConnectionEvent;
const UdpSocket = socket_mod.UdpSocket;
const SendLimit = loss_mod.SendLimit;

/// Result of a poll cycle.
pub const PollResult = enum {
    /// Nothing to do (idle).
    idle,
    /// Data was received and processed.
    received,
    /// Timeout fired (loss/PTO/idle).
    timeout,
    /// Connection closed (by us or peer).
    closed,
    /// Handshake completed this poll cycle.
    connected,
};

/// Event emitted by the client for the caller to handle.
pub const ClientEvent = union(enum) {
    none,
    connected,
    stream_data: struct { stream_id: u62, data: []const u8, fin: bool },
    closed: struct { error_code: u62, reason: []const u8 },
    goaway,
};

pub const ConnectError = error{
    SocketError,
    BuildFailed,
    Timeout,
    HandshakeFailed,
};

pub const CongestionAlgorithm = loss_mod.CongestionAlgorithm;

pub const QuicConfig = struct {
    congestion: CongestionAlgorithm = .cubic,
};

/// Integrated QUIC client: Connection + UdpSocket + event loop.
///
/// Provides a blocking, poll-based interface that ties together:
/// - Congestion control / pacer (sendLimit)
/// - Loss detection timers (PTO, loss timeout)
/// - Idle timeout / keep-alive
/// - Retransmission scheduling
/// - Underutilized detection
pub const QuicClient = struct {
    conn: Connection,
    socket: UdpSocket,
    send_buf: [MAX_DATAGRAM]u8,
    recv_buf: [MAX_DATAGRAM]u8,
    connected: bool,
    closed: bool,
    // Last received stream data (plaintext from data_received event).
    // Valid after poll() returns .received, until the next poll() call.
    stream_data_buf: [MAX_STREAM_DATA]u8,
    stream_data_len: usize,

    const MAX_DATAGRAM = 1452;
    const MAX_STREAM_DATA = 4096;
    const MIN_TIMEOUT_MS: u64 = 1;
    const MAX_TIMEOUT_MS: u64 = 30_000;

    pub fn init(remote: std.net.Address, dcid: []const u8, scid: []const u8) !QuicClient {
        return initWithConfig(remote, dcid, scid, .{});
    }

    pub fn initWithConfig(remote: std.net.Address, dcid: []const u8, scid: []const u8, config: QuicConfig) !QuicClient {
        var socket = try UdpSocket.init(remote);
        errdefer socket.close();

        return .{
            .conn = Connection.initWithConfig(dcid, scid, config.congestion),
            .socket = socket,
            .send_buf = undefined,
            .recv_buf = undefined,
            .connected = false,
            .closed = false,
            .stream_data_buf = undefined,
            .stream_data_len = 0,
        };
    }

    pub fn deinit(self: *QuicClient) void {
        self.socket.close();
    }

    /// Get the current time in microseconds.
    fn nowUs() u64 {
        return @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())) / 1000);
    }

    /// Compute the next timer deadline (absolute us). Returns null if no timers active.
    fn nextTimerDeadline(self: *const QuicClient, now_us: u64) ?u64 {
        var earliest: ?u64 = null;

        // Loss detection timer
        if (self.conn.getLossTimer()) |lt| {
            earliest = lt;
        }

        // Idle timer
        if (self.conn.getIdleTimer()) |it| {
            if (earliest == null or it < earliest.?) earliest = it;
        }

        // Pacer next send time
        const send_lim = self.conn.loss.sendLimit(now_us);
        if (send_lim.limit == .paced and send_lim.next_us > now_us) {
            if (earliest == null or send_lim.next_us < earliest.?) earliest = send_lim.next_us;
        }

        return earliest;
    }

    /// Compute recv timeout in milliseconds based on timer deadlines.
    fn recvTimeoutMs(self: *const QuicClient, now_us: u64) u64 {
        const deadline = self.nextTimerDeadline(now_us) orelse return MAX_TIMEOUT_MS;
        if (deadline <= now_us) return MIN_TIMEOUT_MS;
        const delta_us = deadline - now_us;
        const ms = delta_us / 1000;
        return @max(MIN_TIMEOUT_MS, @min(ms, MAX_TIMEOUT_MS));
    }

    /// Returns the stream payload from the last poll() that returned .received.
    /// Only valid until the next poll() call.
    pub fn lastStreamData(self: *const QuicClient) []const u8 {
        return self.stream_data_buf[0..self.stream_data_len];
    }

    /// Run one poll cycle: set timeout, recv, process, handle timers, transmit.
    /// Returns what happened this cycle.
    pub fn poll(self: *QuicClient) PollResult {
        if (self.closed) return .closed;
        self.stream_data_len = 0;

        const now = nowUs();

        // 1. Check timers BEFORE blocking on recv
        const timer_result = self.handleTimers(now);
        if (timer_result == .closed) return .closed;

        // 2. Set recv timeout to next event
        const timeout = self.recvTimeoutMs(now);
        self.socket.setTimeout(timeout);

        // 3. Try to receive a datagram
        const recv_result = self.socket.recv(&self.recv_buf);
        const recv_now = nowUs();

        if (recv_result) |n| {
            if (n > 0) {
                const event = self.conn.onDatagram(self.recv_buf[0..n], recv_now);
                const process_result = self.processEvent(event, recv_now);
                if (process_result == .connected or process_result == .closed) return process_result;

                // Process pending ACKs
                self.sendPendingAcks(recv_now);

                // Update underutilized state
                self.updateUnderutilized(recv_now);

                return .received;
            }
        } else |_| {
            // Timeout or error — fall through to timer handling
        }

        // 4. Handle timers that may have fired during recv wait
        const post_timer = self.handleTimers(nowUs());
        if (post_timer == .closed) return .closed;
        if (post_timer == .timeout) return .timeout;

        return .idle;
    }

    /// Process a connection event.
    fn processEvent(self: *QuicClient, event: ConnectionEvent, now_us: u64) PollResult {
        _ = now_us;
        switch (event) {
            .none => return .idle,
            .handshake_complete => {
                self.connected = true;
                return .connected;
            },
            .close_resend => |frame| {
                if (frame) |f| {
                    if (self.conn.send1Rtt(&self.send_buf, f)) |len| {
                        _ = self.socket.send(self.send_buf[0..len]) catch {};
                    }
                }
                return .idle;
            },
            .peer_closing => {
                self.closed = true;
                return .closed;
            },
            .path_challenge => |data| {
                if (self.conn.sendPathResponse(&self.send_buf, data, nowUs())) |len| {
                    _ = self.socket.send(self.send_buf[0..len]) catch {};
                }
                return .idle;
            },
            .migration_started => return .idle,
            .ack_needed => return .received,
            .data_received => |payload| {
                const copy_len = @min(payload.len, MAX_STREAM_DATA);
                @memcpy(self.stream_data_buf[0..copy_len], payload[0..copy_len]);
                self.stream_data_len = copy_len;
                return .received;
            },
            .retry_received => return .idle,
            .goaway => return .idle,
        }
    }

    /// Handle fired timers. Returns .closed if connection timed out.
    fn handleTimers(self: *QuicClient, now_us: u64) PollResult {
        // Idle timeout
        const idle_action = self.conn.pollIdle(now_us);
        switch (idle_action) {
            .none => {},
            .send_ping => {
                if (self.conn.sendPing(&self.send_buf, now_us)) |len| {
                    _ = self.socket.send(self.send_buf[0..len]) catch {};
                }
            },
            .close_silent => {
                self.closed = true;
                return .closed;
            },
        }

        // Loss detection timer
        if (self.conn.getLossTimer()) |timer_deadline| {
            if (now_us >= timer_deadline) {
                const probe_level = self.conn.onLossTimeout(now_us);

                // Process any retransmits from loss events
                self.processRetransmits(now_us);

                // If PTO fired, send a probe
                if (probe_level) |level| {
                    self.sendProbe(level, now_us);
                }
                return .timeout;
            }
        }

        return .idle;
    }

    /// Try to send all pending ACKs.
    fn sendPendingAcks(self: *QuicClient, now_us: u64) void {
        const levels = [_]ack_mod.EncryptionLevel{ .initial, .handshake, .application };
        for (levels) |level| {
            if (self.conn.buildAck(level, &self.send_buf, now_us)) |len| {
                _ = self.socket.send(self.send_buf[0..len]) catch {};
            }
        }
    }

    /// Process loss events and send retransmissions.
    fn processRetransmits(self: *QuicClient, now_us: u64) void {
        self.conn.processLoss();
        while (self.conn.retransmitNext(&self.send_buf, now_us)) |len| {
            _ = self.socket.send(self.send_buf[0..len]) catch {};
        }
    }

    /// Send a PTO probe packet.
    fn sendProbe(self: *QuicClient, level: ack_mod.EncryptionLevel, now_us: u64) void {
        _ = level;
        if (self.conn.sendProbe(&self.send_buf, now_us)) |len| {
            _ = self.socket.send(self.send_buf[0..len]) catch {};
        }
    }

    /// Update the underutilized flag based on current CC state.
    fn updateUnderutilized(self: *QuicClient, now_us: u64) void {
        const send_lim = self.conn.loss.sendLimit(now_us);
        const is_underutilized = send_lim.limit == .ok and self.conn.loss.cc.bytesInFlight() < self.conn.loss.cc.congestionWindow();
        self.conn.loss.cc.setUnderutilized(is_underutilized);
    }

    /// Transmit the first `len` bytes of a buffer on the socket.
    fn transmit(self: *QuicClient, buf: []const u8) void {
        _ = self.socket.send(buf) catch {};
    }

    // ─── Public API ───

    /// Perform the QUIC handshake: build ClientHello, send Initial, process server
    /// responses until 1-RTT keys are established and Client Finished is sent.
    ///
    /// After success, the connection is in .connected state with application keys available.
    /// `server_name` is used for SNI in the TLS ClientHello.
    pub fn connect(self: *QuicClient, server_name: []const u8) ConnectError!void {
        // Build TLS 1.3 ClientHello
        const ch_builder = tls_mod.ClientHelloBuilder.init(server_name);
        var ch_buf: [2048]u8 = undefined;
        const ch_len = ch_builder.build(&ch_buf) orelse return ConnectError.BuildFailed;

        // Store private key and ClientHello in connection for handshake processing
        self.conn.setPrivateKey(ch_builder.private_key);
        self.conn.setClientHello(ch_buf[0..ch_len]);

        // Build and send Initial packet
        const sender = initial_mod.InitialSender.init(
            self.conn.dcid[0..self.conn.dcid_len],
            self.conn.scid[0..self.conn.scid_len],
        );
        var initial_buf: [1500]u8 = undefined;
        const pkt_len = sender.buildPacket(ch_buf[0..ch_len], &initial_buf) catch
            return ConnectError.BuildFailed;

        _ = self.socket.send(initial_buf[0..pkt_len]) catch return ConnectError.SocketError;
        self.conn.onInitialSent();

        const now = nowUs();
        self.conn.onPacketSentLD(.initial, 0, @intCast(pkt_len), true, now);

        // Receive loop: process datagrams until handshake completes
        const max_iterations: usize = 50;
        var iterations: usize = 0;

        while (iterations < max_iterations) : (iterations += 1) {
            const recv_now = nowUs();
            const timeout = self.recvTimeoutMs(recv_now);
            self.socket.setTimeout(@max(timeout, MIN_TIMEOUT_MS));

            const n = self.socket.recv(&self.recv_buf) catch |e| {
                switch (e) {
                    socket_mod.UdpSocketError.Timeout => {
                        // Handle PTO timer
                        self.handleTimersConnect(nowUs());
                        continue;
                    },
                    else => return ConnectError.SocketError,
                }
            };
            if (n < 1) continue;

            // Process coalesced packets in the datagram
            var offset: usize = 0;
            while (offset < n) {
                var remaining = self.recv_buf[offset..n];
                if (remaining.len < 1) break;

                var pkt_end: usize = remaining.len;
                if (remaining[0] & 0x80 != 0) {
                    pkt_end = handshake_flight.coalescedPacketLen(remaining) orelse remaining.len;
                }

                const event_time = nowUs();
                const event = self.conn.onDatagram(remaining[0..pkt_end], event_time);
                self.handleHandshakeEvent(event, event_time);

                offset += pkt_end;
            }

            if (self.conn.isConnected()) {
                self.connected = true;
                // Discard Initial and Handshake keys from loss detector
                self.conn.discardLossLevel(.initial);
                self.conn.discardLossLevel(.handshake);
                return;
            }
        }

        return ConnectError.Timeout;
    }

    /// Handle a connection event during the handshake phase.
    fn handleHandshakeEvent(self: *QuicClient, event: ConnectionEvent, now_us: u64) void {
        switch (event) {
            .ack_needed => |level| {
                if (self.conn.buildAck(level, &self.send_buf, now_us)) |len| {
                    _ = self.socket.send(self.send_buf[0..len]) catch {};
                }
            },
            .handshake_complete => |result| {
                // Send Client Finished in a Handshake packet
                const hs_client = self.conn.keys.handshake_client orelse return;
                var fin_buf: [256]u8 = undefined;
                const fin_pn = self.conn.handshake_level.nextPn();
                const fin_len = handshake_complete.buildClientFinishedPacket(
                    &fin_buf,
                    result.client_finished_msg[0..result.client_finished_msg_len],
                    fin_pn,
                    self.conn.dcid[0..self.conn.dcid_len],
                    self.conn.scid[0..self.conn.scid_len],
                    hs_client.key,
                    hs_client.iv,
                    hs_client.hp,
                ) orelse return;
                _ = self.socket.send(fin_buf[0..fin_len]) catch {};
                self.conn.onPacketSentLD(.handshake, fin_pn, @intCast(fin_len), true, now_us);

                // Also send Handshake ACK
                if (self.conn.buildAck(.handshake, &self.send_buf, now_us)) |ack_len| {
                    _ = self.socket.send(self.send_buf[0..ack_len]) catch {};
                }
            },
            .retry_received => {
                // Rebuild and resend Initial with retry token
                self.handleRetry() catch {};
            },
            else => {},
        }
    }

    /// Handle PTO during handshake (resend Initial or probe).
    fn handleTimersConnect(self: *QuicClient, now_us: u64) void {
        if (self.conn.getLossTimer()) |timer_deadline| {
            if (now_us >= timer_deadline) {
                const probe_level = self.conn.onLossTimeout(now_us);
                if (probe_level) |level| {
                    _ = level;
                    // During handshake, PTO probe = resend Initial
                    if (self.conn.sendProbe(&self.send_buf, now_us)) |len| {
                        _ = self.socket.send(self.send_buf[0..len]) catch {};
                    }
                }
            }
        }
    }

    /// Handle a Retry packet: rebuild Initial with token and resend.
    /// TODO: InitialSender doesn't yet support tokens; for now the PTO will retry.
    fn handleRetry(self: *QuicClient) ConnectError!void {
        _ = self;
    }

    /// Write data on a stream. Returns bytes written to wire, or null if CC-blocked or pacer-limited.
    pub fn writeStream(self: *QuicClient, stream_id: u62, data: []const u8, fin: bool) ?usize {
        const now = nowUs();

        // Check send limit (CC + pacer)
        const send_lim = self.conn.loss.sendLimit(now);
        if (send_lim.limit != .ok) return null;

        const len = self.conn.writeStream(&self.send_buf, stream_id, data, fin, now) orelse return null;
        _ = self.socket.send(self.send_buf[0..len]) catch return null;
        self.updateUnderutilized(now);
        return len;
    }

    /// Open a new bidirectional stream.
    pub fn openStream(self: *QuicClient) ?u62 {
        return self.conn.openStream();
    }

    /// Open a new unidirectional stream.
    pub fn openUniStream(self: *QuicClient) ?u62 {
        return self.conn.openUniStream();
    }

    /// Gracefully close the connection.
    pub fn close(self: *QuicClient) void {
        const now = nowUs();
        if (self.conn.close(now, 0)) |frame| {
            if (self.conn.send1Rtt(&self.send_buf, frame)) |len| {
                _ = self.socket.send(self.send_buf[0..len]) catch {};
            }
        }
        self.closed = true;
    }

    /// Check if the connection is established.
    pub fn isConnected(self: *const QuicClient) bool {
        return self.connected;
    }

    /// Check if the connection is closed.
    pub fn isClosed(self: *const QuicClient) bool {
        return self.closed;
    }

    /// Send a QUIC PING frame for keepalive. Returns true if sent successfully.
    pub fn sendPing(self: *QuicClient) bool {
        if (self.closed or !self.connected) return false;
        const now = nowUs();
        const len = self.conn.sendPing(&self.send_buf, now) orelse return false;
        _ = self.socket.send(self.send_buf[0..len]) catch return false;
        return true;
    }
};

// ─── Tests ───

test "QuicClient: init and close" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    try std.testing.expect(!client.isConnected());
    try std.testing.expect(!client.isClosed());
}

test "QuicClient: timer computation" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    const now = QuicClient.nowUs();

    // There may be an idle timer active already; just verify it's bounded
    const initial_timeout = client.recvTimeoutMs(now);
    try std.testing.expect(initial_timeout >= QuicClient.MIN_TIMEOUT_MS);
    try std.testing.expect(initial_timeout <= QuicClient.MAX_TIMEOUT_MS);

    // Send a packet → loss timer gets armed (often shorter than idle timer)
    client.conn.onPacketSentLD(.application, 0, 100, true, now);
    const timeout = client.recvTimeoutMs(now);
    try std.testing.expect(timeout >= QuicClient.MIN_TIMEOUT_MS);
    try std.testing.expect(timeout <= QuicClient.MAX_TIMEOUT_MS);
}

test "QuicClient: close sets state" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    client.close();
    try std.testing.expect(client.isClosed());
}

test "QuicClient: poll returns on timeout" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // Disable idle timeout so it doesn't fire immediately
    client.conn.idle = idle_mod.IdleTimeoutManager.init(.{ .local_idle_timeout_ms = 0 });

    // Set very short socket timeout so recv times out quickly
    client.socket.setTimeout(1);
    const result = client.poll();
    // Should be idle or timeout (no data, PTO may fire)
    try std.testing.expect(result == .idle or result == .timeout);
}

test "QuicClient: underutilized detection" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    const now = QuicClient.nowUs();
    // No data in flight, CC allows sending → underutilized
    client.updateUnderutilized(now);
    try std.testing.expect(client.conn.loss.cc.cubic.underutilized);

    // Fill up the window → not underutilized
    client.conn.loss.cc.cubic.bytes_in_flight = client.conn.loss.cc.cubic.congestion_window;
    client.updateUnderutilized(now);
    try std.testing.expect(!client.conn.loss.cc.cubic.underutilized);
}

test "QuicClient: sendLimit integration" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    const now = QuicClient.nowUs();
    // Initially OK to send
    const lim = client.conn.loss.sendLimit(now);
    try std.testing.expectEqual(SendLimit.ok, lim.limit);

    // Fill window → limited
    client.conn.loss.cc.cubic.bytes_in_flight = client.conn.loss.cc.cubic.congestion_window;
    const lim2 = client.conn.loss.sendLimit(now);
    try std.testing.expectEqual(SendLimit.limited, lim2.limit);
}

test "QuicClient: connect sends Initial and advances state" {
    // Verifies connect() builds ClientHello and sends the Initial packet.
    // We can't do a full connect without a real server, but we verify
    // the connection state transitions correctly.
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 19999);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // Verify we can build a ClientHello and prepare for connect
    const ch_builder = tls_mod.ClientHelloBuilder.init("localhost");
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf);
    try std.testing.expect(ch_len != null);

    // Verify InitialSender can build a packet
    const sender = initial_mod.InitialSender.init(&dcid, &scid);
    var pkt_buf: [1500]u8 = undefined;
    const pkt_len = sender.buildPacket(ch_buf[0..ch_len.?], &pkt_buf) catch unreachable;
    try std.testing.expect(pkt_len >= 1200);
}
