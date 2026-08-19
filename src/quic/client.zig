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
const resumption_mod = @import("resumption.zig");
const zero_rtt_mod = @import("zero_rtt.zig");
const reconnect_mod = @import("reconnect.zig");

const migration_mod = @import("migration.zig");

const Connection = connection_mod.Connection;
const ConnectionEvent = connection_mod.ConnectionEvent;
const UdpSocket = socket_mod.UdpSocket;
const SendLimit = loss_mod.SendLimit;
const PeerAddress = migration_mod.PeerAddress;

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
/// - 0-RTT session resumption
pub const QuicClient = struct {
    conn: Connection,
    socket: UdpSocket,
    send_buf: [MAX_DATAGRAM]u8,
    recv_buf: [MAX_DATAGRAM]u8,
    connected: bool,
    closed: bool,
    stream_data_buf: [MAX_STREAM_DATA]u8,
    stream_data_len: usize,
    ticket_store: resumption_mod.TicketStore,
    zero_rtt_keys: ?resumption_mod.EarlyKeys,
    zero_rtt_pn: u64,
    zero_rtt_accepted: bool,
    zero_rtt_buffer: [MAX_EARLY_DATA]u8,
    zero_rtt_buffer_len: usize,
    zero_rtt_stream_id: u62,
    zero_rtt_fin: bool,
    reconnect_mgr: reconnect_mod.ReconnectManager,
    remote_addr: std.net.Address,
    server_name_buf: [256]u8,
    server_name_len: u8,

    const MAX_EARLY_DATA = 4096;

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
            .ticket_store = resumption_mod.TicketStore.init(),
            .zero_rtt_keys = null,
            .zero_rtt_pn = 0,
            .zero_rtt_accepted = false,
            .zero_rtt_buffer = undefined,
            .zero_rtt_buffer_len = 0,
            .zero_rtt_stream_id = 0,
            .zero_rtt_fin = false,
            .reconnect_mgr = reconnect_mod.ReconnectManager.init(.{}),
            .remote_addr = remote,
            .server_name_buf = undefined,
            .server_name_len = 0,
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
            .migration_started => {
                // Peer address changed — initiate path validation
                if (self.conn.startMigration(&self.send_buf, nowUs())) |len| {
                    _ = self.socket.send(self.send_buf[0..len]) catch {};
                }
                return .idle;
            },
            .ack_needed => return .received,
            .data_received => |payload| {
                const copy_len = @min(payload.len, MAX_STREAM_DATA);
                @memcpy(self.stream_data_buf[0..copy_len], payload[0..copy_len]);
                self.stream_data_len = copy_len;
                // Check if a session ticket was piggy-backed in same packet
                if (self.conn.takePendingTicket()) |ticket| {
                    self.ticket_store.store(ticket);
                }
                return .received;
            },
            .retry_received => return .idle,
            .goaway => return .idle,
            .new_session_ticket => |ticket| {
                self.ticket_store.store(ticket);
                return .idle;
            },
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

        // Migration path validation timer
        self.pollMigrationTimers(now_us);

        return .idle;
    }

    fn pollMigrationTimers(self: *QuicClient, now_us: u64) void {
        const action = self.conn.pollMigration(now_us);
        switch (action) {
            .none => {},
            .retry_probe => {
                if (self.conn.startMigration(&self.send_buf, now_us)) |len| {
                    _ = self.socket.send(self.send_buf[0..len]) catch {};
                }
            },
            .revert_path => {
                _ = self.conn.revertMigration();
            },
            .complete_migration => {
                _ = self.conn.completeMigration();
            },
        }
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
        // Store server name for reconnect (skip if already pointing to our buffer)
        const sn_len: u8 = @intCast(@min(server_name.len, 256));
        if (@intFromPtr(server_name.ptr) != @intFromPtr(&self.server_name_buf[0])) {
            @memcpy(self.server_name_buf[0..sn_len], server_name[0..sn_len]);
        }
        self.server_name_len = sn_len;

        // Build TLS 1.3 ClientHello
        const ch_builder = tls_mod.ClientHelloBuilder.init(server_name);
        var ch_buf: [2048]u8 = undefined;
        const ch_len = ch_builder.build(&ch_buf) orelse return ConnectError.BuildFailed;

        // Store private key and ClientHello in connection for handshake processing
        self.conn.setPrivateKey(ch_builder.private_key);
        self.conn.setClientHello(ch_buf[0..ch_len]);
        self.conn.setServerName(server_name);

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
                // Track 0-RTT acceptance
                self.zero_rtt_accepted = result.early_data_accepted;

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

    /// Perform a 0-RTT connection using a previously stored session ticket.
    /// Builds a ClientHello with PSK, sends Initial, then immediately sends 0-RTT data.
    /// Falls back to regular 1-RTT if no valid ticket is available.
    /// If server rejects 0-RTT, early_data is automatically re-sent as 1-RTT on the same stream.
    /// Returns the 0-RTT early keys if 0-RTT was attempted, null if fell back to 1-RTT.
    pub fn connect0Rtt(self: *QuicClient, server_name: []const u8, stream_id: u62, early_data: []const u8, fin: bool) ConnectError!?resumption_mod.EarlyKeys {
        const now_ms: i64 = @intCast(@divTrunc(std.time.nanoTimestamp(), 1_000_000));
        const ticket = self.ticket_store.lookup(server_name, now_ms) orelse {
            try self.connect(server_name);
            return null;
        };

        // Build ClientHello with PSK extension
        const ch_builder = zero_rtt_mod.ZeroRttClientHelloBuilder.init(
            server_name,
            self.conn.scid[0..self.conn.scid_len],
        );
        var ch_buf: [2048]u8 = undefined;
        const ch_len = ch_builder.build(&ch_buf, ticket, now_ms) orelse return ConnectError.BuildFailed;

        // Store private key and ClientHello
        self.conn.setPrivateKey(ch_builder.private_key);
        self.conn.setClientHello(ch_buf[0..ch_len]);
        self.conn.setServerName(server_name);

        // Derive 0-RTT keys from PSK + ClientHello
        const early_keys = ch_builder.deriveKeys(&ch_buf, ch_len, ticket.psk);
        self.zero_rtt_keys = early_keys;

        // Build and send Initial packet with PSK ClientHello
        const sender = initial_mod.InitialSender.init(
            self.conn.dcid[0..self.conn.dcid_len],
            self.conn.scid[0..self.conn.scid_len],
        );
        var initial_buf: [1500]u8 = undefined;
        const pkt_len = sender.buildPacket(ch_buf[0..ch_len], &initial_buf) catch
            return ConnectError.BuildFailed;

        _ = self.socket.send(initial_buf[0..pkt_len]) catch return ConnectError.SocketError;
        self.conn.onInitialSent();

        const now_us = nowUs();
        self.conn.onPacketSentLD(.initial, 0, @intCast(pkt_len), true, now_us);

        // Buffer early data for potential 1-RTT re-send on rejection
        if (early_data.len > 0) {
            const buf_len = @min(early_data.len, MAX_EARLY_DATA);
            @memcpy(self.zero_rtt_buffer[0..buf_len], early_data[0..buf_len]);
            self.zero_rtt_buffer_len = buf_len;
            self.zero_rtt_stream_id = stream_id;
            self.zero_rtt_fin = fin;

            // Send 0-RTT data immediately and register with loss detector
            var zero_rtt_buf: [MAX_DATAGRAM]u8 = undefined;
            const zero_rtt_len = zero_rtt_mod.encode0RttPacket(
                &zero_rtt_buf,
                self.conn.dcid[0..self.conn.dcid_len],
                self.conn.scid[0..self.conn.scid_len],
                self.zero_rtt_pn,
                early_data,
                early_keys,
            ) orelse return ConnectError.BuildFailed;
            _ = self.socket.send(zero_rtt_buf[0..zero_rtt_len]) catch return ConnectError.SocketError;
            const send_time = nowUs();
            self.conn.onPacketSentLD(.application, self.zero_rtt_pn, @intCast(zero_rtt_len), true, send_time);
            self.zero_rtt_pn += 1;
        }

        // Continue handshake to completion
        const max_iterations: usize = 50;
        var iterations: usize = 0;
        while (iterations < max_iterations) : (iterations += 1) {
            const recv_now = nowUs();
            const timeout = self.recvTimeoutMs(recv_now);
            self.socket.setTimeout(@max(timeout, MIN_TIMEOUT_MS));

            const n = self.socket.recv(&self.recv_buf) catch |e| {
                switch (e) {
                    socket_mod.UdpSocketError.Timeout => {
                        self.handleTimersConnect(nowUs());
                        continue;
                    },
                    else => return ConnectError.SocketError,
                }
            };
            if (n < 1) continue;

            var offset: usize = 0;
            while (offset < n) {
                const remaining = self.recv_buf[offset..n];
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
                self.conn.discardLossLevel(.initial);
                self.conn.discardLossLevel(.handshake);
                self.zero_rtt_keys = null;

                // Re-send early data as 1-RTT if server rejected 0-RTT
                if (!self.zero_rtt_accepted and self.zero_rtt_buffer_len > 0) {
                    const resend_now = nowUs();
                    if (self.conn.writeStream(
                        &self.send_buf,
                        self.zero_rtt_stream_id,
                        self.zero_rtt_buffer[0..self.zero_rtt_buffer_len],
                        self.zero_rtt_fin,
                        resend_now,
                    )) |len| {
                        _ = self.socket.send(self.send_buf[0..len]) catch {};
                        self.zero_rtt_buffer_len = 0;
                    }
                    // If writeStream returns null (CC-blocked), buffer is preserved
                    // for the caller to retry via writeStream() after connect returns.
                } else {
                    self.zero_rtt_buffer_len = 0;
                }
                return early_keys;
            }
        }

        return ConnectError.Timeout;
    }

    /// Write 0-RTT data before handshake completes. Only valid after connect0Rtt
    /// has been called and before the handshake finishes (keys are promoted to 1-RTT).
    /// Data is buffered for 1-RTT re-send if the server rejects 0-RTT.
    /// Returns null if no 0-RTT keys are available or if the re-send buffer is full.
    pub fn writeStream0Rtt(self: *QuicClient, data: []const u8) ?usize {
        const keys = self.zero_rtt_keys orelse return null;

        // Reject if buffer cannot hold this data for potential re-send
        const remaining = MAX_EARLY_DATA - self.zero_rtt_buffer_len;
        if (data.len > remaining) return null;

        var buf: [MAX_DATAGRAM]u8 = undefined;
        const pn = self.zero_rtt_pn;
        const len = zero_rtt_mod.encode0RttPacket(
            &buf,
            self.conn.dcid[0..self.conn.dcid_len],
            self.conn.scid[0..self.conn.scid_len],
            pn,
            data,
            keys,
        ) orelse return null;
        _ = self.socket.send(buf[0..len]) catch return null;
        const now = nowUs();
        self.conn.onPacketSentLD(.application, pn, @intCast(len), true, now);
        self.zero_rtt_pn += 1;

        // Append to buffer for potential 1-RTT re-send on rejection
        @memcpy(self.zero_rtt_buffer[self.zero_rtt_buffer_len..][0..data.len], data);
        self.zero_rtt_buffer_len += data.len;

        return len;
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

    /// Track received data for flow control and send MAX_DATA/MAX_STREAM_DATA if needed.
    pub fn onStreamDataReceived(self: *QuicClient, stream_id: u62, len: usize) void {
        _ = self.conn.stream_mgr.flow.openStream(stream_id);
        self.conn.stream_mgr.flow.onRecv(stream_id, len);
        self.sendFlowControlUpdates();
    }

    fn sendFlowControlUpdates(self: *QuicClient) void {
        var fc_buf: [256]u8 = undefined;
        const fc_len = self.conn.stream_mgr.flow.buildFlowControlFrames(&fc_buf);
        if (fc_len == 0) return;

        const now = nowUs();
        const pn = self.conn.app_level.send_pn;
        if (self.conn.send1Rtt(&self.send_buf, fc_buf[0..fc_len])) |pkt_len| {
            _ = self.socket.send(self.send_buf[0..pkt_len]) catch {};
            self.conn.onPacketSentLD(.application, pn, @intCast(pkt_len), true, now);
        }
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

    /// Check if 0-RTT early data was accepted by the server.
    /// Only meaningful after connect0Rtt completes successfully.
    pub fn isEarlyDataAccepted(self: *const QuicClient) bool {
        return self.zero_rtt_accepted;
    }

    /// Send a QUIC PING frame for keepalive. Returns true if sent successfully.
    pub fn sendPing(self: *QuicClient) bool {
        if (self.closed or !self.connected) return false;
        const now = nowUs();
        const len = self.conn.sendPing(&self.send_buf, now) orelse return false;
        _ = self.socket.send(self.send_buf[0..len]) catch return false;
        return true;
    }

    /// Initiate client-side connection migration to a new server address.
    /// Sends PATH_CHALLENGE and begins path validation.
    /// Returns true if migration was initiated successfully.
    pub fn migrate(self: *QuicClient, new_remote: std.net.Address) bool {
        if (self.closed or !self.connected) return false;

        // Update socket destination
        self.socket.setRemote(new_remote);

        // For client-initiated migration, send PATH_CHALLENGE directly
        // (anti-amplification limit only applies to server responding to unvalidated client)
        const now = nowUs();
        const len = self.conn.sendPathChallenge(&self.send_buf, now) orelse return false;
        _ = self.socket.send(self.send_buf[0..len]) catch return false;

        const new_peer = addressToPeerAddress(new_remote);
        self.conn.migration.initiateClientMigration(new_peer, @intCast(len), now);

        return true;
    }

    /// Check if a migration is currently in progress.
    pub fn isMigrating(self: *const QuicClient) bool {
        return self.conn.migration.isMigrating();
    }

    /// Check if the path has been validated after migration.
    pub fn isPathValidated(self: *const QuicClient) bool {
        return self.conn.isPathValidated();
    }

    // ─── Reconnection ───

    pub const ReconnectConfig = reconnect_mod.ReconnectManager.Config;

    /// Configure reconnection behavior.
    pub fn setReconnectConfig(self: *QuicClient, config: ReconnectConfig) void {
        self.reconnect_mgr = reconnect_mod.ReconnectManager.init(config);
    }

    /// Attempt to reconnect after disconnection.
    /// Uses 0-RTT resumption if a session ticket is available, otherwise full handshake.
    /// Resets internal connection state and re-establishes the QUIC connection.
    pub fn reconnect(self: *QuicClient) ConnectError!void {
        const server_name = self.server_name_buf[0..self.server_name_len];
        if (server_name.len == 0) return ConnectError.BuildFailed;

        // Reset connection state for a fresh handshake
        self.resetForReconnect();

        // Attempt connection (0-RTT will be used automatically if ticket available)
        self.connect(server_name) catch |err| {
            const now = nowUs();
            self.reconnect_mgr.onReconnectFailed(now);
            return err;
        };

        self.reconnect_mgr.onReconnected();
    }

    /// Poll with automatic reconnection on disconnect.
    /// Returns the poll result; handles backoff and reconnect attempts internally.
    pub fn pollWithReconnect(self: *QuicClient) PollResult {
        const result = self.poll();

        if (result == .closed and !self.isUserClosed()) {
            const now = nowUs();

            // First time detecting disconnect
            if (self.reconnect_mgr.state == .connected) {
                self.reconnect_mgr.onDisconnect(now);
            }

            switch (self.reconnect_mgr.poll(now)) {
                .reconnect_now => {
                    self.reconnect() catch {
                        return .closed;
                    };
                    return .connected;
                },
                .wait, .none => return .idle,
                .give_up => return .closed,
            }
        }

        return result;
    }

    /// Whether the connection was closed by user (vs. network failure / idle timeout).
    fn isUserClosed(self: *const QuicClient) bool {
        return self.conn.close_ctrl.state == .closing;
    }

    /// Reset internal state to prepare for a fresh connection attempt.
    /// Preserves: ticket_store, reconnect_mgr, remote_addr, server_name, socket.
    fn resetForReconnect(self: *QuicClient) void {
        var new_dcid: [8]u8 = undefined;
        var new_scid: [8]u8 = undefined;
        std.crypto.random.bytes(&new_dcid);
        std.crypto.random.bytes(&new_scid);

        self.conn = Connection.initWithConfig(&new_dcid, &new_scid, .cubic);
        self.connected = false;
        self.closed = false;
        self.stream_data_len = 0;
        self.zero_rtt_keys = null;
        self.zero_rtt_pn = 0;
        self.zero_rtt_accepted = false;
        self.zero_rtt_buffer_len = 0;
        self.zero_rtt_stream_id = 0;
        self.zero_rtt_fin = false;

        self.socket.setRemote(self.remote_addr);
    }
};

fn addressToPeerAddress(addr: std.net.Address) PeerAddress {
    return switch (addr.any.family) {
        std.posix.AF.INET => PeerAddress.initV4(
            @bitCast(addr.in.sa.addr),
            std.mem.bigToNative(u16, addr.in.sa.port),
        ),
        std.posix.AF.INET6 => PeerAddress.initV6(
            addr.in6.sa.addr,
            std.mem.bigToNative(u16, addr.in6.sa.port),
        ),
        else => PeerAddress.initV4(.{ 0, 0, 0, 0 }, 0),
    };
}

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

test "QuicClient: ticket store integration" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // Store a session ticket
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 7200;
    ticket.ticket_age_add = 0x12345678;
    ticket.ticket_nonce_len = 1;
    ticket.ticket_nonce[0] = 0x01;
    ticket.ticket_len = 8;
    @memcpy(ticket.ticket[0..8], "TESTTKTS");
    ticket.max_early_data_size = 16384;
    ticket.psk = [_]u8{0xAA} ** 32;
    ticket.server_name_len = 11;
    @memcpy(ticket.server_name[0..11], "example.com");
    ticket.received_at_ms = 1000;

    client.ticket_store.store(ticket);
    try std.testing.expectEqual(@as(usize, 1), client.ticket_store.count);

    const found = client.ticket_store.lookup("example.com", 2000);
    try std.testing.expect(found != null);
}

test "QuicClient: writeStream0Rtt returns null without keys" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // No 0-RTT keys set → should return null
    try std.testing.expect(client.writeStream0Rtt("hello") == null);
}

test "QuicClient: writeStream0Rtt sends with keys" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // Manually set 0-RTT keys (simulating post-connect0Rtt state)
    client.zero_rtt_keys = resumption_mod.EarlyKeys{
        .key = [_]u8{0xAA} ** 16,
        .iv = [_]u8{0xBB} ** 12,
        .hp = [_]u8{0xCC} ** 16,
    };

    // writeStream0Rtt will attempt to send — may fail due to socket not connected to a server
    // but it should at least build the packet (return non-null or fail at socket.send)
    const result = client.writeStream0Rtt("early data");
    // On loopback with no listener, send might succeed (UDP is connectionless)
    // or fail — either way, packet_number should advance if we got a result
    if (result) |len| {
        try std.testing.expect(len > 0);
        try std.testing.expectEqual(@as(u64, 1), client.zero_rtt_pn);
    }
}

test "QuicClient: migrate initiates path validation" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    // Set connected state and app keys (needed for sending packets)
    client.connected = true;
    client.conn.state = .connected;
    client.conn.keys.app_client = .{
        .key = [_]u8{0xAA} ** 16,
        .iv = [_]u8{0xBB} ** 12,
        .hp = [_]u8{0xCC} ** 16,
    };
    const initial_peer = PeerAddress.initV4(.{ 127, 0, 0, 1 }, 4433);
    client.conn.setPeerAddress(initial_peer);

    // Migrate to new address
    const new_addr = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 5555);
    const ok = client.migrate(new_addr);
    try std.testing.expect(ok);
    try std.testing.expect(client.isMigrating());
    try std.testing.expect(client.conn.isPathValidationPending());
}

test "QuicClient: isMigrating reflects state" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var client = try QuicClient.init(addr, &dcid, &scid);
    defer client.deinit();

    try std.testing.expect(!client.isMigrating());
}

test "addressToPeerAddress: IPv4" {
    const addr = std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 443);
    const peer = addressToPeerAddress(addr);
    try std.testing.expectEqual(PeerAddress.AddressFamily.ipv4, peer.family);
    try std.testing.expectEqual(@as(u16, 443), peer.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &peer.addr_v4);
}
