const std = @import("std");
const packet_mod = @import("packet.zig");
const quic_crypto = @import("crypto.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const handshake_complete = @import("handshake_complete.zig");
const tls_messages = @import("tls_messages.zig");
const short_header = @import("short_header.zig");
const ack_mod = @import("ack.zig");
const decode_mod = @import("decode.zig");
const conn_close = @import("conn_close.zig");
const loss_mod = @import("loss.zig");
const retransmit_mod = @import("retransmit.zig");
const stream_mod = @import("stream.zig");
const key_update_mod = @import("key_update.zig");
const stream_mgr_mod = @import("stream_manager.zig");
const flow_control_mod = @import("flow_control.zig");
const idle_mod = @import("idle_timeout.zig");
const cid_mod = @import("cid_manager.zig");
const retry_mod = @import("retry.zig");
const migration_mod = @import("migration.zig");

/// Connection states.
pub const ConnState = enum {
    idle,
    initial_sent,
    handshake,
    connected,
    closed,
};

/// Keys for a single encryption level.
pub const LevelKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

/// All keying material for the connection.
pub const KeySet = struct {
    initial_client: LevelKeys,
    initial_server: LevelKeys,
    handshake_client: ?LevelKeys,
    handshake_server: ?LevelKeys,
    app_client: ?LevelKeys,
    app_server: ?LevelKeys,
    handshake_keys: ?handshake_mod.HandshakeKeys,
};

/// Per-level packet number counter and ACK tracker.
pub const LevelState = struct {
    send_pn: u64,
    ack_tracker: ack_mod.AckTracker,

    pub fn init() LevelState {
        return .{
            .send_pn = 0,
            .ack_tracker = ack_mod.AckTracker.init(),
        };
    }

    pub fn nextPn(self: *LevelState) u64 {
        const pn = self.send_pn;
        self.send_pn += 1;
        return pn;
    }
};

/// QUIC Connection Manager.
/// Thin integration layer over existing modules.
pub const Connection = struct {
    state: ConnState,
    dcid: [20]u8,
    dcid_len: usize,
    scid: [20]u8,
    scid_len: usize,
    original_dcid: [20]u8,
    original_dcid_len: usize,
    keys: KeySet,
    initial_level: LevelState,
    handshake_level: LevelState,
    app_level: LevelState,
    crypto_reassembler: handshake_flight.CryptoReassembler,
    transcript: tls_messages.TranscriptHash,
    transcript_snapshot: ?tls_messages.TranscriptHash,
    handshake_crypto_processed: usize,
    client_hello_bytes: [1280]u8,
    client_hello_len: usize,
    server_hello_bytes: [1280]u8,
    server_hello_len: usize,
    x25519_private_key: [32]u8,
    close_ctrl: conn_close.CloseController,
    loss: loss_mod.LossDetector,
    send_buf: retransmit_mod.SendBuffer,
    rtx_queue: retransmit_mod.RetransmitQueue,
    key_mgr: ?key_update_mod.KeyUpdateManager,
    stream_mgr: stream_mgr_mod.StreamManager,
    idle: idle_mod.IdleTimeoutManager,
    cid_mgr: cid_mod.CidManager,
    retry_received: bool,
    retry_token: [512]u8,
    retry_token_len: usize,
    path_challenge_pending: bool,
    path_challenge_data: [8]u8,
    path_challenge_sent_us: u64,
    path_validated: bool,
    migration: migration_mod.MigrationManager,

    /// Legacy init — uses NewReno for backward compatibility with existing tests.
    /// Production code should use QuicClient (which defaults to Cubic via QuicConfig).
    pub fn init(dcid: []const u8, scid: []const u8) Connection {
        return initWithConfig(dcid, scid, .new_reno);
    }

    pub fn initWithConfig(dcid: []const u8, scid: []const u8, cc_algo: loss_mod.CongestionAlgorithm) Connection {
        var conn: Connection = undefined;
        conn.state = .idle;
        conn.dcid_len = @min(dcid.len, 20);
        @memcpy(conn.dcid[0..conn.dcid_len], dcid[0..conn.dcid_len]);
        conn.scid_len = @min(scid.len, 20);
        @memcpy(conn.scid[0..conn.scid_len], scid[0..conn.scid_len]);
        // Preserve original DCID for Initial packet decryption
        conn.original_dcid_len = conn.dcid_len;
        @memcpy(conn.original_dcid[0..conn.original_dcid_len], conn.dcid[0..conn.dcid_len]);

        // Derive Initial keys from DCID
        const initial_keys = quic_crypto.deriveInitialKeys(dcid[0..conn.dcid_len]);
        conn.keys = .{
            .initial_client = .{ .key = initial_keys.client_key, .iv = initial_keys.client_iv, .hp = initial_keys.client_hp },
            .initial_server = .{ .key = initial_keys.server_key, .iv = initial_keys.server_iv, .hp = initial_keys.server_hp },
            .handshake_client = null,
            .handshake_server = null,
            .app_client = null,
            .app_server = null,
            .handshake_keys = null,
        };

        conn.initial_level = LevelState.init();
        conn.handshake_level = LevelState.init();
        conn.app_level = LevelState.init();
        conn.crypto_reassembler = handshake_flight.CryptoReassembler.init();
        conn.transcript = tls_messages.TranscriptHash.init();
        conn.transcript_snapshot = null;
        conn.handshake_crypto_processed = 0;
        conn.client_hello_len = 0;
        conn.server_hello_len = 0;
        conn.x25519_private_key = [_]u8{0} ** 32;
        conn.close_ctrl = conn_close.CloseController.init();
        conn.loss = loss_mod.LossDetector.initWithAlgo(cc_algo, 0);
        conn.send_buf = retransmit_mod.SendBuffer.init();
        conn.rtx_queue = retransmit_mod.RetransmitQueue.init();
        conn.key_mgr = null;
        conn.stream_mgr = stream_mgr_mod.StreamManager.init(false, .{});
        conn.idle = idle_mod.IdleTimeoutManager.init(.{});
        conn.cid_mgr = cid_mod.CidManager.init();
        conn.cid_mgr.setInitialCid(dcid[0..conn.dcid_len]);
        conn.retry_received = false;
        conn.retry_token_len = 0;
        conn.path_challenge_pending = false;
        conn.path_challenge_data = [_]u8{0} ** 8;
        conn.path_challenge_sent_us = 0;
        conn.path_validated = true;
        conn.migration = migration_mod.MigrationManager.init();

        return conn;
    }

    /// Set the client's x25519 private key (needed for handshake key derivation).
    pub fn setPrivateKey(self: *Connection, key: [32]u8) void {
        self.x25519_private_key = key;
    }

    /// Record the ClientHello bytes for transcript.
    pub fn setClientHello(self: *Connection, ch: []const u8) void {
        const len = @min(ch.len, self.client_hello_bytes.len);
        @memcpy(self.client_hello_bytes[0..len], ch[0..len]);
        self.client_hello_len = len;
    }

    /// Mark Initial packet as sent, transition to initial_sent.
    pub fn onInitialSent(self: *Connection) void {
        if (self.state == .idle) {
            self.state = .initial_sent;
        }
    }

    /// Process a received datagram. Dispatches to appropriate handler based on header type.
    /// Returns an action for the caller (e.g., send ACK, handshake complete).
    /// Note: `data` is modified in-place (header protection removal).
    pub fn onDatagram(self: *Connection, data: []u8, recv_time_us: u64) ConnectionEvent {
        if (data.len < 1) return .none;

        // RFC 9000 §10.2.1: In closing state, retransmit CONNECTION_CLOSE on incoming packets
        if (self.close_ctrl.state == .closing) {
            return .{ .close_resend = self.close_ctrl.onPacketReceived() };
        }

        // RFC 9000 §10.2.2: In draining state, discard all packets
        if (self.close_ctrl.state == .draining) {
            return .none;
        }

        if (data[0] & 0x80 != 0) {
            // Long header — determine type
            return self.handleLongHeader(data, recv_time_us);
        } else {
            // Short header (1-RTT)
            return self.handleShortHeader(data, recv_time_us);
        }
    }

    /// Build an ACK packet for the given level. Returns bytes written to buf.
    pub fn buildAck(self: *Connection, level: ack_mod.EncryptionLevel, buf: []u8, now_us: u64) ?usize {
        const tracker = switch (level) {
            .initial => &self.initial_level.ack_tracker,
            .handshake => &self.handshake_level.ack_tracker,
            .application => &self.app_level.ack_tracker,
        };

        if (!tracker.hasPending()) return null;

        const pn = switch (level) {
            .initial => self.initial_level.nextPn(),
            .handshake => self.handshake_level.nextPn(),
            .application => self.app_level.nextPn(),
        };

        var k: [16]u8 = undefined;
        var iv: [12]u8 = undefined;
        var hp: [16]u8 = undefined;

        switch (level) {
            .initial => {
                k = self.keys.initial_client.key;
                iv = self.keys.initial_client.iv;
                hp = self.keys.initial_client.hp;
            },
            .handshake => {
                const hk = self.keys.handshake_client orelse return null;
                k = hk.key;
                iv = hk.iv;
                hp = hk.hp;
            },
            .application => {
                const ak = self.keys.app_client orelse return null;
                k = ak.key;
                iv = ak.iv;
                hp = ak.hp;
            },
        }

        const scid_slice = self.scid[0..self.scid_len];
        const dcid_slice = self.dcid[0..self.dcid_len];

        return ack_mod.buildAckPacket(buf, level, tracker, now_us, pn, dcid_slice, scid_slice, k, iv, hp);
    }

    /// Encode a 1-RTT packet with given payload. Returns bytes written.
    pub fn send1Rtt(self: *Connection, buf: []u8, payload: []const u8) ?usize {
        const pn = self.app_level.nextPn();
        if (self.key_mgr) |*km| {
            const sk = km.sendKeys();
            return short_header.encodeShortHeaderWithPhase(buf, self.dcid[0..self.dcid_len], pn, payload, sk.key, sk.iv, sk.hp, sk.key_phase);
        }
        const ak = self.keys.app_client orelse return null;
        return short_header.encodeShortHeader(buf, self.dcid[0..self.dcid_len], pn, payload, ak.key, ak.iv, ak.hp);
    }

    pub fn isConnected(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Initiate graceful connection close (no_error).
    /// Returns the CONNECTION_CLOSE frame payload to send in a 1-RTT packet.
    pub fn close(self: *Connection, now_us: u64, pto_us: u64) ?[]const u8 {
        if (self.close_ctrl.isClosing() or self.close_ctrl.isClosed()) return null;
        const effective_pto = if (pto_us > 0) pto_us else self.getPto();
        self.close_ctrl.initiateClose(.no_error, 0, "", now_us, effective_pto);
        self.state = .closed;
        return self.close_ctrl.getCloseFrame();
    }

    /// Initiate connection close with a transport error.
    pub fn closeWithError(self: *Connection, err: conn_close.TransportError, frame_type: u62, reason: []const u8, now_us: u64, pto_us: u64) ?[]const u8 {
        if (self.close_ctrl.isClosing() or self.close_ctrl.isClosed()) return null;
        const effective_pto = if (pto_us > 0) pto_us else self.getPto();
        self.close_ctrl.initiateClose(err, frame_type, reason, now_us, effective_pto);
        self.state = .closed;
        return self.close_ctrl.getCloseFrame();
    }

    /// Initiate application-level close (e.g., H3_NO_ERROR).
    pub fn closeApp(self: *Connection, error_code: u62, reason: []const u8, now_us: u64, pto_us: u64) ?[]const u8 {
        if (self.close_ctrl.isClosing() or self.close_ctrl.isClosed()) return null;
        const effective_pto = if (pto_us > 0) pto_us else self.getPto();
        self.close_ctrl.initiateAppClose(error_code, reason, now_us, effective_pto);
        self.state = .closed;
        return self.close_ctrl.getCloseFrame();
    }

    /// Build a 1-RTT packet containing a CONNECTION_CLOSE frame.
    pub fn buildClosePacket(self: *Connection, buf: []u8) ?usize {
        const frame = self.close_ctrl.getCloseFrame() orelse return null;
        return self.send1Rtt(buf, frame);
    }

    /// Check if the drain timer has expired and connection can be freed.
    pub fn checkCloseTimeout(self: *Connection, now_us: u64) void {
        self.close_ctrl.checkTimeout(now_us);
    }

    pub fn isDraining(self: *const Connection) bool {
        return self.close_ctrl.isClosing();
    }

    // ─── Key Update (RFC 9001 §6) ───

    /// Initiate a Key Update. Flips key phase for subsequent sends.
    /// Returns false if key_mgr not yet initialized or update already in flight.
    pub fn initiateKeyUpdate(self: *Connection, now_us: u64) bool {
        const km = &(self.key_mgr orelse return false);
        return km.initiateUpdate(self.app_level.send_pn, now_us, self.getPto());
    }

    /// Get the current key phase (for diagnostics/testing).
    pub fn keyPhase(self: *const Connection) u1 {
        const km = self.key_mgr orelse return 0;
        return km.key_phase;
    }

    /// Get the key generation counter.
    pub fn keyGeneration(self: *const Connection) u32 {
        const km = self.key_mgr orelse return 0;
        return km.generation;
    }

    // ─── Stream Multiplexing ───

    /// Set the peer's transport parameters (for stream/flow control limits).
    pub fn setPeerTransportParams(self: *Connection, params: flow_control_mod.TransportParams) void {
        self.stream_mgr.setPeerParams(params);
        self.idle.setPeerTimeout(params.max_idle_timeout_ms);
    }

    /// Open a new bidirectional stream. Returns stream_id.
    pub fn openStream(self: *Connection) ?u62 {
        return self.stream_mgr.openBidi();
    }

    /// Open a new unidirectional stream. Returns stream_id.
    pub fn openUniStream(self: *Connection) ?u62 {
        return self.stream_mgr.openUni();
    }

    /// Write data on a stream. Encodes and sends a STREAM frame.
    /// Automatically manages offset. Returns bytes written to wire, or null if blocked.
    pub fn writeStream(self: *Connection, buf: []u8, stream_id: u62, data: []const u8, fin: bool, now_us: u64) ?usize {
        const op = self.stream_mgr.write(stream_id, data, fin) orelse return null;
        const len = self.sendStream(buf, op.stream_id, op.offset, op.data, op.fin, now_us);
        if (len == null) {
            self.stream_mgr.rollbackWrite(op);
            return null;
        }
        return len;
    }

    /// Close a stream (send empty FIN frame).
    pub fn finishStream(self: *Connection, buf: []u8, stream_id: u62, now_us: u64) ?usize {
        const op = self.stream_mgr.closeStream(stream_id) orelse return null;
        const len = self.sendStream(buf, op.stream_id, op.offset, op.data, op.fin, now_us);
        if (len == null) {
            self.stream_mgr.rollbackWrite(op);
            return null;
        }
        return len;
    }

    /// Reset a stream (abruptly terminate).
    pub fn resetStreamId(self: *Connection, stream_id: u62) void {
        self.stream_mgr.resetStream(stream_id);
    }

    /// Get number of active streams.
    pub fn activeStreams(self: *const Connection) u32 {
        return self.stream_mgr.activeStreams();
    }

    // ─── Idle Timeout / Keep-alive (RFC 9000 §10.1) ───

    /// Configure idle timeout with explicit parameters.
    /// Call after handshake completes with negotiated values.
    pub fn configureIdleTimeout(self: *Connection, config: idle_mod.IdleTimeoutManager.Config) void {
        self.idle = idle_mod.IdleTimeoutManager.init(config);
    }

    /// Update the peer's idle timeout (from transport parameters).
    pub fn setPeerIdleTimeout(self: *Connection, peer_timeout_ms: u64) void {
        self.idle.setPeerTimeout(peer_timeout_ms);
    }

    /// Poll the idle/keep-alive timer. Returns an action to take.
    /// The caller's event loop should call this regularly.
    pub fn pollIdle(self: *Connection, now_us: u64) idle_mod.IdleTimeoutManager.Action {
        return self.idle.poll(now_us);
    }

    /// Build a PING packet for keep-alive. Returns bytes written to buf.
    pub fn sendPing(self: *Connection, buf: []u8, now_us: u64) ?usize {
        var ping_buf: [1]u8 = undefined;
        _ = idle_mod.IdleTimeoutManager.encodePing(&ping_buf) orelse return null;
        const result = self.sendTracked(buf, &ping_buf, now_us) orelse return null;
        return result.len;
    }

    /// Get the idle timer deadline (absolute microseconds).
    pub fn getIdleTimer(self: *const Connection) ?u64 {
        return self.idle.getTimer();
    }

    /// Check if the connection has expired due to idle timeout.
    pub fn isIdleExpired(self: *const Connection) bool {
        return self.idle.isExpired();
    }

    /// Time remaining before idle timeout fires (microseconds).
    pub fn idleTimeRemaining(self: *const Connection, now_us: u64) u64 {
        return self.idle.timeRemaining(now_us);
    }

    // ─── Connection ID Management (RFC 9000 §5.1) ───

    /// Rotate the DCID to the next available CID (for NAT rebinding / migration).
    /// Also updates the dcid/dcid_len fields used by send paths.
    /// Returns true if rotation succeeded.
    pub fn rotateDcid(self: *Connection) bool {
        if (!self.cid_mgr.rotateCid()) return false;
        self.syncDcidFromManager();
        return true;
    }

    /// Check if there are RETIRE_CONNECTION_ID frames to send.
    pub fn hasRetireCidPending(self: *const Connection) bool {
        return self.cid_mgr.hasRetirePending();
    }

    /// Build a RETIRE_CONNECTION_ID frame packet. Returns bytes written.
    pub fn sendRetireCid(self: *Connection, buf: []u8, now_us: u64) ?usize {
        const seq = self.cid_mgr.dequeueRetire() orelse return null;
        var frame_buf: [16]u8 = undefined;
        const frame_len = cid_mod.encodeRetireConnectionId(&frame_buf, seq) orelse return null;
        const result = self.sendTracked(buf, frame_buf[0..frame_len], now_us) orelse return null;
        return result.len;
    }

    /// Get the number of active CIDs available.
    pub fn activeCidCount(self: *const Connection) u8 {
        return self.cid_mgr.activeCount();
    }

    /// Free retired CID slots (call periodically or after sending all RETIRE frames).
    pub fn gcRetiredCids(self: *Connection) void {
        self.cid_mgr.gcRetired();
    }

    fn syncDcidFromManager(self: *Connection) void {
        if (self.cid_mgr.currentCid()) |cid| {
            const len = @min(cid.len, 20);
            @memcpy(self.dcid[0..len], cid[0..len]);
            self.dcid_len = len;
        }
    }

    // ─── Retry ───

    /// Get the retry token to include in the re-sent Initial packet.
    /// Returns null if no Retry has been received.
    pub fn getRetryToken(self: *const Connection) ?[]const u8 {
        if (!self.retry_received) return null;
        if (self.retry_token_len == 0) return null;
        return self.retry_token[0..self.retry_token_len];
    }

    // ─── Path Validation (RFC 9000 §8.2) ───

    /// Build a PATH_RESPONSE frame in a 1-RTT packet.
    /// Called by the event loop after receiving .path_challenge event.
    pub fn sendPathResponse(self: *Connection, buf: []u8, challenge_data: [8]u8, now_us: u64) ?usize {
        // PATH_RESPONSE = type(0x1b) + data(8)
        var frame: [9]u8 = undefined;
        frame[0] = 0x1b;
        @memcpy(frame[1..9], &challenge_data);
        const result = self.sendTracked(buf, &frame, now_us) orelse return null;
        return result.len;
    }

    /// Initiate path validation by sending a PATH_CHALLENGE.
    /// Returns bytes written to buf.
    pub fn sendPathChallenge(self: *Connection, buf: []u8, now_us: u64) ?usize {
        // Generate random 8-byte challenge data
        var challenge_data: [8]u8 = undefined;
        std.crypto.random.bytes(&challenge_data);

        // PATH_CHALLENGE = type(0x1a) + data(8)
        var frame: [9]u8 = undefined;
        frame[0] = 0x1a;
        @memcpy(frame[1..9], &challenge_data);

        const result = self.sendTracked(buf, &frame, now_us) orelse return null;

        self.path_challenge_pending = true;
        self.path_challenge_data = challenge_data;
        self.path_challenge_sent_us = now_us;
        self.path_validated = false;

        return result.len;
    }

    /// Check if a path validation is currently in progress.
    pub fn isPathValidationPending(self: *const Connection) bool {
        return self.path_challenge_pending;
    }

    /// Check if the current path has been validated.
    pub fn isPathValidated(self: *const Connection) bool {
        return self.path_validated;
    }

    /// Check if path validation has timed out (3 * PTO per RFC 9000 §8.2.4).
    pub fn isPathValidationTimedOut(self: *const Connection, now_us: u64) bool {
        if (!self.path_challenge_pending) return false;
        const timeout = 3 * self.getPto();
        return now_us >= self.path_challenge_sent_us + timeout;
    }

    fn onPathResponse(self: *Connection, response_data: [8]u8) void {
        if (!self.path_challenge_pending) return;
        if (!std.mem.eql(u8, &response_data, &self.path_challenge_data)) return;
        self.path_challenge_pending = false;
        self.path_validated = true;
        if (self.migration.isMigrating()) {
            self.migration.onPathValidated();
        }
    }

    // ─── Connection Migration (RFC 9000 §9) ───

    /// Set the initial peer address (call after handshake with the address used).
    pub fn setPeerAddress(self: *Connection, addr: migration_mod.PeerAddress) void {
        self.migration.setPeerAddress(addr);
    }

    /// Disable active migration (if peer's transport params set disable_active_migration).
    pub fn disableMigration(self: *Connection) void {
        self.migration.disable();
    }

    /// Called by the event loop when a datagram arrives. Detects address changes
    /// and returns a MigrationEvent if migration should be initiated.
    /// The caller is responsible for extracting the source address from the datagram.
    pub fn onDatagramSource(self: *Connection, source: migration_mod.PeerAddress, datagram_size: u64, now_us: u64) ConnectionEvent {
        const event = self.migration.onDatagramReceived(source, datagram_size, now_us);
        return switch (event) {
            .none => .none,
            .address_changed => |info| .{ .migration_started = .{
                .new_addr = info.new_addr,
                .previous_addr = info.previous_addr,
            } },
            .migration_rejected => .none,
        };
    }

    /// Initiate migration path validation: send PATH_CHALLENGE and rotate CID.
    /// Returns bytes written to buf, or null if blocked.
    pub fn startMigration(self: *Connection, buf: []u8, now_us: u64) ?usize {
        if (!self.migration.canSend(50)) return null;

        const len = self.sendPathChallenge(buf, now_us) orelse return null;
        self.migration.onProbeSent(@intCast(len), now_us);
        return len;
    }

    /// Called when PATH_RESPONSE validates the new path after migration.
    /// Rotates CID and transitions migration to complete.
    /// Returns true if migration was successfully completed.
    pub fn completeMigration(self: *Connection) bool {
        if (!self.migration.isNewPathValidated()) {
            if (!self.isPathValidated()) return false;
            self.migration.onPathValidated();
        }

        if (!self.rotateDcid()) return false;
        self.migration.onMigrationComplete();
        return true;
    }

    /// Poll migration state. Returns action to take.
    /// Call from the event loop alongside pollIdle.
    pub fn pollMigration(self: *Connection, now_us: u64) MigrationAction {
        if (!self.migration.isMigrating()) {
            if (self.migration.isNewPathValidated()) {
                return .complete_migration;
            }
            return .none;
        }

        if (self.migration.isProbeTimedOut(now_us, self.getPto())) {
            if (self.migration.isProbingExhausted()) {
                return .revert_path;
            }
            return .retry_probe;
        }

        return .none;
    }

    /// Revert to the previous path (probe failed).
    /// Returns the previous address to send to.
    pub fn revertMigration(self: *Connection) ?migration_mod.PeerAddress {
        self.path_challenge_pending = false;
        self.path_validated = true;
        return self.migration.revertToPreviousPath();
    }

    /// Check if migration is in progress.
    pub fn isMigrationInProgress(self: *const Connection) bool {
        return self.migration.isMigrating();
    }

    /// Check anti-amplification limit during migration.
    pub fn canSendOnNewPath(self: *const Connection, size: u64) bool {
        return self.migration.canSend(size);
    }

    /// Get the current peer address.
    pub fn getPeerAddress(self: *const Connection) ?migration_mod.PeerAddress {
        return self.migration.getPeerAddress();
    }

    /// Get number of completed migrations.
    pub fn migrationCount(self: *const Connection) u32 {
        return self.migration.migration_count;
    }

    pub const MigrationAction = enum {
        none,
        retry_probe,
        revert_path,
        complete_migration,
    };

    // ─── Loss Detection / Congestion Control Integration ───

    /// Notify the loss detector that a packet was sent.
    /// Call AFTER transmitting the packet on the wire.
    pub fn onPacketSentLD(self: *Connection, level: ack_mod.EncryptionLevel, pn: u64, size: u32, ack_eliciting: bool, now_us: u64) void {
        self.loss.onPacketSent(level, pn, size, ack_eliciting, now_us);
    }

    /// Check if sending `size` bytes is allowed by the congestion window.
    pub fn canSendCC(self: *const Connection) bool {
        return self.loss.cc.canSend();
    }

    /// Available send budget (bytes) before congestion window is full.
    pub fn sendBudgetCC(self: *const Connection) u64 {
        return self.loss.sendBudget();
    }

    /// Get the current PTO estimate (microseconds). Used for close timers.
    pub fn getPto(self: *const Connection) u64 {
        return self.loss.rtt.ptoBase(self.loss.max_ack_delay_us);
    }

    /// Get the loss detection timer deadline (absolute microseconds), if set.
    pub fn getLossTimer(self: *const Connection) ?u64 {
        return self.loss.getTimer();
    }

    /// Called when the loss detection timer fires. Returns level for PTO probe, if any.
    pub fn onLossTimeout(self: *Connection, now_us: u64) ?ack_mod.EncryptionLevel {
        return self.loss.onLossDetectionTimeout(now_us);
    }

    /// Discard a crypto level's loss state (e.g., Initial keys discarded after handshake).
    pub fn discardLossLevel(self: *Connection, level: ack_mod.EncryptionLevel) void {
        self.loss.discardLevel(level);
    }

    /// Result of sendTracked: wire bytes written and the PN used.
    pub const SendResult = struct {
        len: usize,
        pn: u64,
    };

    /// Encode a 1-RTT packet, register with loss detector, and return bytes written + PN.
    /// Returns null if CC blocks or no app keys available.
    pub fn sendTracked(self: *Connection, buf: []u8, payload: []const u8, now_us: u64) ?SendResult {
        if (!self.loss.cc.canSend()) return null;

        const actual_pn = self.app_level.nextPn();
        const len = blk: {
            if (self.key_mgr) |*km| {
                const sk = km.sendKeys();
                break :blk short_header.encodeShortHeaderWithPhase(buf, self.dcid[0..self.dcid_len], actual_pn, payload, sk.key, sk.iv, sk.hp, sk.key_phase) orelse return null;
            }
            const ak = self.keys.app_client orelse return null;
            break :blk short_header.encodeShortHeader(buf, self.dcid[0..self.dcid_len], actual_pn, payload, ak.key, ak.iv, ak.hp) orelse return null;
        };
        self.loss.onPacketSent(.application, actual_pn, @intCast(len), true, now_us);
        self.idle.onActivity(now_us);
        return .{ .len = len, .pn = actual_pn };
    }

    // ─── Retransmission ───

    /// Send a STREAM frame with retransmission tracking.
    /// Records the frame in send_buf so it can be retransmitted if lost.
    /// Returns bytes written to buf, or null if CC blocks / no keys.
    pub fn sendStream(self: *Connection, buf: []u8, stream_id: u62, offset: u64, data: []const u8, fin: bool, now_us: u64) ?usize {
        // Encode STREAM frame as payload
        var frame_buf: [1280]u8 = undefined;
        const frame = stream_mod.StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .fin = fin,
        };
        const frame_len = frame.encode(&frame_buf) orelse return null;

        const result = self.sendTracked(buf, frame_buf[0..frame_len], now_us) orelse return null;

        // Record in send buffer for potential retransmission
        _ = self.send_buf.record(result.pn, stream_id, offset, data, fin);

        return result.len;
    }

    /// Process ACK: release acknowledged frames from send buffer.
    /// Iterates all ACK ranges extracted by scanPayload.
    fn processAckForRetransmit(self: *Connection, ranges: []const AckRange) void {
        for (ranges) |r| {
            self.send_buf.onAckRange(r.start, r.end);
        }
    }

    /// Process loss events: move lost frames to retransmit queue.
    fn processLossForRetransmit(self: *Connection, loss_event: *const loss_mod.LossEvent) void {
        if (loss_event.lost_count > 0) {
            self.send_buf.onLoss(loss_event.lost_packets[0..loss_event.lost_count], &self.rtx_queue);
        }
    }

    /// Public: call after onLossTimeout to move any newly-lost frames into the retransmit queue.
    /// The loss detector already ran detectLostPackets; this drains pending loss into rtx_queue.
    pub fn processLoss(self: *Connection) void {
        // Loss detection is handled inside onLossDetectionTimeout/onAckReceived.
        // This is a no-op hook; the retransmit queue is populated by processLossForRetransmit
        // which is called from handleShortHeader after ACK processing.
        // For timeout-driven loss, the caller should use retransmitNext directly.
        _ = self;
    }

    /// Check if there are frames awaiting retransmission.
    pub fn hasRetransmits(self: *const Connection) bool {
        return self.rtx_queue.hasPending();
    }

    /// Retransmit the next lost frame. Encodes into a new packet with a new PN.
    /// Returns bytes written to buf, or null if queue empty / CC blocks / no keys.
    pub fn retransmitNext(self: *Connection, buf: []u8, now_us: u64) ?usize {
        const frame = self.rtx_queue.dequeue() orelse return null;
        return self.sendStream(buf, frame.stream_id, frame.offset, frame.data(), frame.fin, now_us);
    }

    /// Build a PTO probe packet. Uses retransmit queue if available, otherwise PING.
    /// Returns bytes written to buf.
    pub fn sendProbe(self: *Connection, buf: []u8, now_us: u64) ?usize {
        var probe_buf: [64]u8 = undefined;
        const probe_len = retransmit_mod.ProbeGenerator.buildProbe(&self.rtx_queue, &probe_buf) orelse return null;
        const result = self.sendTracked(buf, probe_buf[0..probe_len], now_us) orelse return null;
        return result.len;
    }

    // ─── Internal handlers ───

    fn handleLongHeader(self: *Connection, data: []u8, recv_time_us: u64) ConnectionEvent {
        if (data.len < 5) return .none;
        const ptype: u2 = @intCast((data[0] >> 4) & 0x03);

        return switch (ptype) {
            0 => self.handleInitialPacket(data, recv_time_us),
            2 => self.handleHandshakePacket(data, recv_time_us),
            3 => self.handleRetryPacket(data),
            else => .none,
        };
    }

    fn handleInitialPacket(self: *Connection, data: []u8, recv_time_us: u64) ConnectionEvent {
        // Decode server Initial response (derives keys from original DCID internally)
        var out_buf: [4096]u8 = undefined;
        const decoded = decode_mod.decodeServerInitial(data, self.original_dcid[0..self.original_dcid_len], &out_buf) catch return .none;

        self.initial_level.ack_tracker.recordPacket(decoded.packet_number, recv_time_us);

        // Update DCID to server's SCID (server chooses its own CID)
        if (decoded.scid.len > 0 and decoded.scid.len <= 20) {
            @memcpy(self.dcid[0..decoded.scid.len], decoded.scid);
            self.dcid_len = decoded.scid.len;
            // Re-initialize CID manager with server's chosen CID
            self.cid_mgr = cid_mod.CidManager.init();
            self.cid_mgr.setInitialCid(decoded.scid);
        }

        // Check for ServerHello in CRYPTO frames
        if (decoded.crypto_data.len > 0 and self.state == .initial_sent) {
            // Store ServerHello for transcript
            const sh_len = @min(decoded.crypto_data.len, self.server_hello_bytes.len);
            @memcpy(self.server_hello_bytes[0..sh_len], decoded.crypto_data[0..sh_len]);
            self.server_hello_len = sh_len;

            // Compute transcript hash(CH || SH) and derive handshake keys
            self.transcript.update(self.client_hello_bytes[0..self.client_hello_len]);
            self.transcript.update(self.server_hello_bytes[0..self.server_hello_len]);
            const transcript_ch_sh = self.transcript.current();

            // Extract server's key_share and derive handshake keys
            const server_pub = handshake_mod.extractServerKeyShare(decoded.crypto_data) catch return .none;
            const hs_keys = handshake_mod.deriveHandshakeKeys(self.x25519_private_key, server_pub, transcript_ch_sh) catch return .none;

            self.keys.handshake_keys = hs_keys;
            self.keys.handshake_client = .{ .key = hs_keys.client_key, .iv = hs_keys.client_iv, .hp = hs_keys.client_hp };
            self.keys.handshake_server = .{ .key = hs_keys.server_key, .iv = hs_keys.server_iv, .hp = hs_keys.server_hp };

            self.state = .handshake;
            return .{ .ack_needed = .initial };
        }

        return .{ .ack_needed = .initial };
    }

    fn handleHandshakePacket(self: *Connection, data: []u8, recv_time_us: u64) ConnectionEvent {
        const hs_server = self.keys.handshake_server orelse return .none;

        var out_buf: [4096]u8 = undefined;
        const decoded = handshake_flight.decodeHandshakePacket(
            data,
            hs_server.key,
            hs_server.iv,
            hs_server.hp,
            &out_buf,
        ) orelse return .none;

        self.handshake_level.ack_tracker.recordPacket(decoded.packet_number, recv_time_us);

        // Extract CRYPTO frames into reassembler
        _ = handshake_flight.extractCryptoFrames(decoded.plaintext, &self.crypto_reassembler);

        // Try to complete handshake if we have enough data
        if (self.state == .handshake) {
            const crypto_data = self.crypto_reassembler.getData();
            if (crypto_data.len > self.handshake_crypto_processed) {
                const hs_keys = self.keys.handshake_keys orelse return .{ .ack_needed = .handshake };

                // Use transcript snapshot to avoid double-update on retry
                var trial_transcript = self.transcript;
                const result = handshake_complete.processServerHandshakeFlight(
                    crypto_data,
                    hs_keys,
                    &trial_transcript,
                ) catch return .{ .ack_needed = .handshake };

                // Success — commit transcript and mark processed
                self.transcript = trial_transcript;
                self.handshake_crypto_processed = crypto_data.len;

                // Install 1-RTT keys (including HP)
                self.keys.app_client = .{
                    .key = result.application_keys.client_key,
                    .iv = result.application_keys.client_iv,
                    .hp = result.application_keys.client_hp,
                };
                self.keys.app_server = .{
                    .key = result.application_keys.server_key,
                    .iv = result.application_keys.server_iv,
                    .hp = result.application_keys.server_hp,
                };

                // Initialize Key Update manager with traffic secrets
                self.key_mgr = key_update_mod.KeyUpdateManager.init(
                    result.client_traffic_secret,
                    result.server_traffic_secret,
                    result.application_keys.client_hp,
                    result.application_keys.server_hp,
                );

                // Apply peer's transport parameters
                if (result.peer_transport_params) |peer_tp| {
                    self.setPeerTransportParams(peer_tp.toFlowParams());
                }

                self.state = .connected;
                return .{ .handshake_complete = .{
                    .client_finished_msg = result.client_finished_msg,
                    .client_finished_msg_len = result.client_finished_msg_len,
                } };
            }
        }

        return .{ .ack_needed = .handshake };
    }

    fn handleRetryPacket(self: *Connection, data: []u8) ConnectionEvent {
        // RFC 9000 §17.2.5.2: MUST discard subsequent Retry packets
        if (self.retry_received) return .none;

        // Only accept Retry during initial_sent state
        if (self.state != .initial_sent) return .none;

        const retry = retry_mod.decodeRetryPacket(data) orelse return .none;

        // RFC 9001 §5.8: Validate Retry Integrity Tag
        if (!retry_mod.validateRetryIntegrityTag(data, self.original_dcid[0..self.original_dcid_len])) {
            return .none;
        }

        // RFC 9000 §17.2.5.2: MUST discard if SCID equals current DCID
        if (retry.scid.len == self.dcid_len and std.mem.eql(u8, retry.scid, self.dcid[0..self.dcid_len])) {
            return .none;
        }

        self.retry_received = true;

        // Store retry token (up to 512 bytes)
        const token_len = @min(retry.token.len, self.retry_token.len);
        @memcpy(self.retry_token[0..token_len], retry.token[0..token_len]);
        self.retry_token_len = token_len;

        // Update DCID to Retry's SCID
        const new_dcid_len = @min(retry.scid.len, 20);
        @memcpy(self.dcid[0..new_dcid_len], retry.scid[0..new_dcid_len]);
        self.dcid_len = new_dcid_len;

        // RFC 9001 §5.2: Re-derive Initial keys from new DCID
        const initial_keys = quic_crypto.deriveInitialKeys(self.dcid[0..self.dcid_len]);
        self.keys.initial_client = .{ .key = initial_keys.client_key, .iv = initial_keys.client_iv, .hp = initial_keys.client_hp };
        self.keys.initial_server = .{ .key = initial_keys.server_key, .iv = initial_keys.server_iv, .hp = initial_keys.server_hp };

        // Reset packet number for Initial level
        self.initial_level = LevelState.init();

        // Discard any CRYPTO data received in the first flight
        self.crypto_reassembler = handshake_flight.CryptoReassembler.init();
        self.handshake_crypto_processed = 0;
        self.server_hello_len = 0;

        // Re-initialize CID manager with new DCID
        self.cid_mgr = cid_mod.CidManager.init();
        self.cid_mgr.setInitialCid(self.dcid[0..self.dcid_len]);

        return .retry_received;
    }

    fn handleShortHeader(self: *Connection, data: []u8, recv_time_us: u64) ConnectionEvent {
        var out_buf: [4096]u8 = undefined;

        if (self.key_mgr) |*km| {
            // Key-update-aware decode: HP removal then try decrypt with phase detection
            const hp = km.server_hp;
            const parsed = short_header.removeHpAndParse(data, self.dcid_len, hp) orelse return .none;

            const pt_len = km.tryDecrypt(
                &out_buf,
                data[parsed.ct_start..][0..parsed.ct_len],
                data[parsed.ct_start + parsed.ct_len ..][0..16].*,
                parsed.pn,
                data[0..parsed.ct_start],
                parsed.key_phase,
                recv_time_us,
                self.getPto(),
            ) orelse return .none;

            km.expireOldKeys(recv_time_us);

            self.app_level.ack_tracker.recordPacket(parsed.pn, recv_time_us);
            self.idle.onActivity(recv_time_us);

            const scan_result = scanPayload(out_buf[0..pt_len]);

            if (scan_result.has_ack) {
                const loss_event = self.loss.onAckReceivedRanges(
                    .application,
                    scan_result.ack_largest,
                    scan_result.ack_delay,
                    scan_result.ack_ranges[0..scan_result.ack_range_count],
                    recv_time_us,
                );
                self.processAckForRetransmit(scan_result.ack_ranges[0..scan_result.ack_range_count]);
                self.processLossForRetransmit(&loss_event);

                // RFC 9001 §6: confirm key update only when peer ACKs a PN from the new phase
                _ = km.tryConfirmUpdate(scan_result.ack_largest);
            }

            // Process NEW_CONNECTION_ID frames
            self.processNewCids(&scan_result);

            if (scan_result.close_frame) |close_frame| {
                self.close_ctrl.onPeerClose(recv_time_us, self.getPto());
                self.state = .closed;
                return .{ .peer_closing = close_frame };
            }

            // PATH_CHALLENGE requires immediate PATH_RESPONSE (RFC 9000 §8.2.2)
            if (scan_result.path_challenge_data) |challenge_data| {
                return .{ .path_challenge = challenge_data };
            }

            // PATH_RESPONSE completes our path validation
            if (scan_result.path_response_data) |response_data| {
                self.onPathResponse(response_data);
            }

            return .{ .data_received = out_buf[0..pt_len] };
        }

        // Fallback: no key_mgr (shouldn't happen in normal flow after handshake)
        const app_server = self.keys.app_server orelse return .none;

        const decoded = short_header.decodeShortHeader(
            data,
            self.dcid_len,
            app_server.key,
            app_server.iv,
            app_server.hp,
            &out_buf,
        ) orelse return .none;

        self.app_level.ack_tracker.recordPacket(decoded.packet_number, recv_time_us);
        self.idle.onActivity(recv_time_us);

        // Process frames: feed ACKs to loss detector, detect CONNECTION_CLOSE
        const scan_result = scanPayload(decoded.plaintext);

        if (scan_result.has_ack) {
            const loss_event = self.loss.onAckReceivedRanges(
                .application,
                scan_result.ack_largest,
                scan_result.ack_delay,
                scan_result.ack_ranges[0..scan_result.ack_range_count],
                recv_time_us,
            );
            self.processAckForRetransmit(scan_result.ack_ranges[0..scan_result.ack_range_count]);
            self.processLossForRetransmit(&loss_event);
        }

        // Process NEW_CONNECTION_ID frames
        self.processNewCids(&scan_result);

        if (scan_result.close_frame) |close_frame| {
            self.close_ctrl.onPeerClose(recv_time_us, self.getPto());
            self.state = .closed;
            return .{ .peer_closing = close_frame };
        }

        if (scan_result.path_challenge_data) |challenge_data| {
            return .{ .path_challenge = challenge_data };
        }

        if (scan_result.path_response_data) |response_data| {
            self.onPathResponse(response_data);
        }

        return .{ .data_received = decoded.plaintext };
    }

    fn processNewCids(self: *Connection, scan_result: *const PayloadScanResult) void {
        for (0..scan_result.new_cid_count) |i| {
            _ = self.cid_mgr.onNewConnectionId(scan_result.new_cids[i]);
        }
    }

    pub const AckRange = loss_mod.AckRange;
    const MAX_ACK_RANGES = 16;

    const MAX_NEW_CIDS = 4;

    /// Result of scanning a decrypted payload for ACK and CONNECTION_CLOSE frames.
    const PayloadScanResult = struct {
        has_ack: bool = false,
        ack_largest: u64 = 0,
        ack_first_range: u64 = 0,
        ack_delay: u64 = 0,
        ack_ranges: [MAX_ACK_RANGES]AckRange = [_]AckRange{.{ .start = 0, .end = 0 }} ** MAX_ACK_RANGES,
        ack_range_count: usize = 0,
        close_frame: ?conn_close.ConnectionCloseFrame = null,
        new_cids: [MAX_NEW_CIDS]cid_mod.NewConnectionIdFrame = undefined,
        new_cid_count: usize = 0,
        has_handshake_done: bool = false,
        path_challenge_data: ?[8]u8 = null,
        path_response_data: ?[8]u8 = null,
    };

    /// Scan a decrypted payload, extracting ACK info and CONNECTION_CLOSE.
    fn scanPayload(plaintext: []const u8) PayloadScanResult {
        var result = PayloadScanResult{};
        var pos: usize = 0;

        while (pos < plaintext.len) {
            const ft_byte = plaintext[pos];

            if (ft_byte == 0x1c or ft_byte == 0x1d) {
                const is_app = (ft_byte == 0x1d);
                result.close_frame = conn_close.ConnectionCloseFrame.decode(plaintext[pos + 1 ..], is_app);
                return result;
            }

            switch (ft_byte) {
                0x00 => pos += 1, // PADDING
                0x01 => pos += 1, // PING
                0x02, 0x03 => {
                    // ACK frame — extract all ranges for loss detector + retransmit
                    pos += 1;
                    const largest = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += largest.consumed;
                    const delay = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += delay.consumed;
                    const range_count = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += range_count.consumed;
                    const first_range = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += first_range.consumed;

                    result.has_ack = true;
                    result.ack_largest = largest.value;
                    result.ack_first_range = first_range.value;
                    result.ack_delay = delay.value;

                    // First range: [largest - first_range, largest]
                    const first_start = if (largest.value >= first_range.value) largest.value - first_range.value else 0;
                    result.ack_ranges[0] = .{ .start = first_start, .end = largest.value };
                    result.ack_range_count = 1;

                    // Additional ACK ranges (RFC 9000 §19.3.1)
                    var smallest: u64 = first_start;
                    var i: u64 = 0;
                    while (i < range_count.value) : (i += 1) {
                        const gap = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += gap.consumed;
                        const ack_range = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += ack_range.consumed;

                        if (smallest < gap.value + 2) break;
                        const range_end = smallest - gap.value - 2;
                        const range_start = if (range_end >= ack_range.value) range_end - ack_range.value else 0;

                        if (result.ack_range_count < MAX_ACK_RANGES) {
                            result.ack_ranges[result.ack_range_count] = .{ .start = range_start, .end = range_end };
                            result.ack_range_count += 1;
                        }
                        smallest = range_start;
                    }

                    // ECN counts for type 0x03
                    if (ft_byte == 0x03) {
                        const ect0 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += ect0.consumed;
                        const ect1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += ect1.consumed;
                        const ecn_ce = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += ecn_ce.consumed;
                    }
                },
                0x04 => {
                    // RESET_STREAM: stream_id + app_error_code + final_size
                    pos += 1;
                    const v1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v1.consumed;
                    const v2 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v2.consumed;
                    const v3 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v3.consumed;
                },
                0x05 => {
                    // STOP_SENDING: stream_id + app_error_code
                    pos += 1;
                    const v1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v1.consumed;
                    const v2 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v2.consumed;
                },
                0x06 => {
                    // CRYPTO: offset + length + data
                    pos += 1;
                    const offset = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += offset.consumed;
                    const length = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += length.consumed;
                    pos += @intCast(length.value);
                },
                0x07 => {
                    // NEW_TOKEN: token_length + token
                    pos += 1;
                    const tlen = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += tlen.consumed;
                    pos += @intCast(tlen.value);
                },
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f => {
                    // STREAM: variable fields based on type bits
                    const has_offset = (ft_byte & 0x04) != 0;
                    const has_length = (ft_byte & 0x02) != 0;
                    pos += 1;
                    // stream_id
                    const sid = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += sid.consumed;
                    // offset (if present)
                    if (has_offset) {
                        const off = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += off.consumed;
                    }
                    // length (if present) → skip data; otherwise data extends to end
                    if (has_length) {
                        const slen = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                        pos += slen.consumed;
                        pos += @intCast(slen.value);
                    } else {
                        pos = plaintext.len; // rest of packet is stream data
                    }
                },
                0x10 => {
                    // MAX_DATA: max_data
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v.consumed;
                },
                0x11 => {
                    // MAX_STREAM_DATA: stream_id + max_data
                    pos += 1;
                    const v1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v1.consumed;
                    const v2 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v2.consumed;
                },
                0x12, 0x13 => {
                    // MAX_STREAMS: max_streams
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v.consumed;
                },
                0x14 => {
                    // DATA_BLOCKED: limit
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v.consumed;
                },
                0x15 => {
                    // STREAM_DATA_BLOCKED: stream_id + limit
                    pos += 1;
                    const v1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v1.consumed;
                    const v2 = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v2.consumed;
                },
                0x16, 0x17 => {
                    // STREAMS_BLOCKED: limit
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v.consumed;
                },
                0x18 => {
                    // NEW_CONNECTION_ID: seq + retire_prior_to + cid_len + cid + reset_token
                    pos += 1;
                    if (pos < plaintext.len) {
                        const frame = cid_mod.NewConnectionIdFrame.decode(plaintext[pos..]);
                        if (frame) |f| {
                            if (result.new_cid_count < MAX_NEW_CIDS) {
                                result.new_cids[result.new_cid_count] = f;
                                result.new_cid_count += 1;
                            }
                            pos += f.encodedSize();
                        } else {
                            return result;
                        }
                    }
                },
                0x19 => {
                    // RETIRE_CONNECTION_ID: seq
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return result;
                    pos += v.consumed;
                },
                0x1a => {
                    // PATH_CHALLENGE: 8 bytes data
                    pos += 1;
                    if (pos + 8 > plaintext.len) return result;
                    result.path_challenge_data = plaintext[pos..][0..8].*;
                    pos += 8;
                },
                0x1b => {
                    // PATH_RESPONSE: 8 bytes data
                    pos += 1;
                    if (pos + 8 > plaintext.len) return result;
                    result.path_response_data = plaintext[pos..][0..8].*;
                    pos += 8;
                },
                0x1e => {
                    // HANDSHAKE_DONE
                    pos += 1;
                    result.has_handshake_done = true;
                },
                else => {
                    // Unknown frame type — try to skip using varint-length encoding
                    // RFC 9000 §12.4: frame types use varint, but we already consumed 1 byte.
                    // For truly unknown frames we can't determine length, so stop scanning.
                    return result;
                },
            }
        }
        return result;
    }

    /// Legacy wrapper for tests that only check CONNECTION_CLOSE.
    fn scanForConnectionClose(plaintext: []const u8) ?conn_close.ConnectionCloseFrame {
        return scanPayload(plaintext).close_frame;
    }
};

/// Events returned from onDatagram to inform the caller what to do next.
pub const ConnectionEvent = union(enum) {
    none: void,
    ack_needed: ack_mod.EncryptionLevel,
    handshake_complete: struct {
        client_finished_msg: [36]u8,
        client_finished_msg_len: usize,
    },
    data_received: []const u8,
    /// Peer sent CONNECTION_CLOSE. Connection is now draining.
    peer_closing: conn_close.ConnectionCloseFrame,
    /// We are in closing state; caller should retransmit this frame.
    close_resend: ?[]const u8,
    /// Server sent a Retry. Caller must rebuild ClientHello and resend Initial with token.
    retry_received: void,
    /// Peer sent PATH_CHALLENGE. Caller must send PATH_RESPONSE with this data.
    path_challenge: [8]u8,
    /// Peer address changed. Caller should initiate path validation via startMigration().
    migration_started: struct {
        new_addr: migration_mod.PeerAddress,
        previous_addr: migration_mod.PeerAddress,
    },
    /// Peer sent HTTP/3 GOAWAY. last_stream_id = last stream peer will process.
    goaway: u62,
};

// ─── Tests ───

test "Connection.init: initial keys derived" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const conn = Connection.init(&dcid, &scid);

    try std.testing.expectEqual(ConnState.idle, conn.state);
    try std.testing.expectEqual(@as(usize, 8), conn.dcid_len);
    try std.testing.expectEqual(@as(usize, 4), conn.scid_len);

    // Verify initial keys match known vector
    const expected_client_key = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
    try std.testing.expectEqualSlices(u8, &expected_client_key, &conn.keys.initial_client.key);
}

test "Connection: state transitions" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    var conn = Connection.init(&dcid, &scid);

    try std.testing.expectEqual(ConnState.idle, conn.state);
    conn.onInitialSent();
    try std.testing.expectEqual(ConnState.initial_sent, conn.state);
    try std.testing.expect(!conn.isConnected());
}

test "Connection.setPrivateKey" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    const key = [_]u8{0x42} ** 32;
    conn.setPrivateKey(key);
    try std.testing.expectEqualSlices(u8, &key, &conn.x25519_private_key);
}

test "Connection.setClientHello" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.setClientHello("fake ClientHello");
    try std.testing.expectEqual(@as(usize, 16), conn.client_hello_len);
}

test "Connection: LevelState.nextPn increments" {
    var level = LevelState.init();
    try std.testing.expectEqual(@as(u64, 0), level.nextPn());
    try std.testing.expectEqual(@as(u64, 1), level.nextPn());
    try std.testing.expectEqual(@as(u64, 2), level.nextPn());
}

test "Connection.buildAck: no pending returns null" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    var buf: [256]u8 = undefined;
    try std.testing.expect(conn.buildAck(.initial, &buf, 0) == null);
}

test "Connection.buildAck: pending initial ACK" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.initial_level.ack_tracker.recordPacket(0, 100);

    var buf: [256]u8 = undefined;
    const len = conn.buildAck(.initial, &buf, 200) orelse unreachable;
    try std.testing.expect(len > 0);
    // Used PN 0
    try std.testing.expectEqual(@as(u64, 1), conn.initial_level.send_pn);
}

test "Connection.send1Rtt: no keys returns null" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    var buf: [256]u8 = undefined;
    try std.testing.expect(conn.send1Rtt(&buf, "data") == null);
}

test "Connection.send1Rtt: with keys produces packet" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;
    const len = conn.send1Rtt(&buf, "hello") orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u64, 1), conn.app_level.send_pn);
}

test "Connection.onDatagram: empty returns none" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    var empty: [0]u8 = .{};
    const event = conn.onDatagram(&empty, 0);
    try std.testing.expect(event == .none);
}

test "Connection.onDatagram: short header without keys returns none" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    var data = [_]u8{0x40} ++ [_]u8{0} ** 63; // short header
    const event = conn.onDatagram(&data, 0);
    try std.testing.expect(event == .none);
}

test "Connection.close: transitions to closed" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const frame = conn.close(1_000_000, 100_000);
    try std.testing.expect(frame != null);
    try std.testing.expectEqual(ConnState.closed, conn.state);
    try std.testing.expect(conn.close_ctrl.isClosing());
}

test "Connection.closeWithError: includes error info" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const frame = conn.closeWithError(.flow_control_error, 0x08, "limit exceeded", 1_000_000, 100_000);
    try std.testing.expect(frame != null);
    try std.testing.expectEqual(@as(u8, 0x1c), frame.?[0]); // transport close frame type
}

test "Connection.closeApp: application close" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const frame = conn.closeApp(0x0100, "going away", 1_000_000, 100_000);
    try std.testing.expect(frame != null);
    try std.testing.expectEqual(@as(u8, 0x1d), frame.?[0]); // app close frame type
}

test "Connection: closing state resends close frame on incoming" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    _ = conn.close(1_000_000, 100_000);
    try std.testing.expectEqual(conn_close.CloseState.closing, conn.close_ctrl.state);

    // Receiving any packet in closing state → close_resend event
    var fake_data = [_]u8{0x40} ++ [_]u8{0} ** 31;
    const event = conn.onDatagram(&fake_data, 1_050_000);
    switch (event) {
        .close_resend => |payload| try std.testing.expect(payload != null),
        else => try std.testing.expect(false),
    }
}

test "Connection: draining state discards packets" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.close_ctrl.state = .draining;

    var fake_data = [_]u8{0x40} ++ [_]u8{0} ** 31;
    const event = conn.onDatagram(&fake_data, 1_000_000);
    try std.testing.expect(event == .none);
}

test "Connection.checkCloseTimeout: drain expires" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    _ = conn.close(1_000_000, 100_000);
    // deadline = 1_300_000
    conn.checkCloseTimeout(1_200_000);
    try std.testing.expect(!conn.close_ctrl.isClosed());

    conn.checkCloseTimeout(1_300_000);
    try std.testing.expect(conn.close_ctrl.isClosed());
}

test "Connection.buildClosePacket: requires app keys" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    // No close frame cached → null
    var buf: [256]u8 = undefined;
    try std.testing.expect(conn.buildClosePacket(&buf) == null);

    // With close frame but no app keys → null
    _ = conn.close(1_000_000, 100_000);
    try std.testing.expect(conn.buildClosePacket(&buf) == null);
}

test "Connection.buildClosePacket: with keys produces packet" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    _ = conn.close(1_000_000, 100_000);
    var buf: [256]u8 = undefined;
    const len = conn.buildClosePacket(&buf) orelse unreachable;
    try std.testing.expect(len > 0);
}

test "Connection.close: double call returns null" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const first = conn.close(1_000_000, 100_000);
    try std.testing.expect(first != null);

    // Second call should be no-op
    const second = conn.close(2_000_000, 100_000);
    try std.testing.expect(second == null);
}

test "scanForConnectionClose: detects close after ACK" {
    // Build: ACK frame (type=0x02, largest=5, delay=0, range_count=0, first_range=0)
    //        then CONNECTION_CLOSE (type=0x1c, error=0, frame_type=0, reason_len=0)
    var payload: [16]u8 = undefined;
    var pos: usize = 0;

    // ACK frame
    payload[pos] = 0x02; // type
    pos += 1;
    payload[pos] = 0x05; // largest_acked = 5
    pos += 1;
    payload[pos] = 0x00; // delay = 0
    pos += 1;
    payload[pos] = 0x00; // range_count = 0
    pos += 1;
    payload[pos] = 0x00; // first_ack_range = 0
    pos += 1;

    // CONNECTION_CLOSE frame
    payload[pos] = 0x1c; // type
    pos += 1;
    payload[pos] = 0x00; // error_code = 0
    pos += 1;
    payload[pos] = 0x00; // frame_type = 0
    pos += 1;
    payload[pos] = 0x00; // reason_len = 0
    pos += 1;

    const result = Connection.scanForConnectionClose(payload[0..pos]);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u62, 0), result.?.error_code);
    try std.testing.expect(!result.?.is_application);
}

test "scanForConnectionClose: detects close after PADDING" {
    var payload: [8]u8 = undefined;
    // 3 PADDING bytes + CONNECTION_CLOSE (app, error=0x0100, reason_len=0)
    payload[0] = 0x00; // PADDING
    payload[1] = 0x00; // PADDING
    payload[2] = 0x00; // PADDING
    payload[3] = 0x1d; // CONNECTION_CLOSE (app)
    payload[4] = 0x41; // error_code varint 2-byte: (0x41 & 0x3f)<<8 | 0x00 = 0x0100
    payload[5] = 0x00;
    payload[6] = 0x00; // reason_len = 0

    const result = Connection.scanForConnectionClose(payload[0..7]);
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.is_application);
    try std.testing.expectEqual(@as(u62, 0x0100), result.?.error_code);
}

test "scanForConnectionClose: no close frame returns null" {
    // Just an ACK frame
    var payload: [8]u8 = undefined;
    payload[0] = 0x02;
    payload[1] = 0x03; // largest
    payload[2] = 0x00; // delay
    payload[3] = 0x00; // range_count
    payload[4] = 0x00; // first_range

    const result = Connection.scanForConnectionClose(payload[0..5]);
    try std.testing.expect(result == null);
}

// ─── LossDetector ↔ Connection Integration Tests ───

test "Connection: onPacketSentLD tracks bytes in flight" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    conn.onPacketSentLD(.application, 0, 1200, true, 1_000_000);
    try std.testing.expectEqual(@as(u64, 1200), conn.loss.cc.new_reno.bytes_in_flight);

    conn.onPacketSentLD(.application, 1, 1200, true, 1_001_000);
    try std.testing.expectEqual(@as(u64, 2400), conn.loss.cc.new_reno.bytes_in_flight);
}

test "Connection: canSendCC respects congestion window" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    // Initial cwnd = 12000, bytes_in_flight = 0 → can send (0 + 1200 <= 12000)
    try std.testing.expect(conn.canSendCC());

    // Fill most of the window
    conn.onPacketSentLD(.application, 0, 10800, true, 1_000_000);
    // 10800 + 1200 = 12000 <= 12000 → can still send
    try std.testing.expect(conn.canSendCC());
    try std.testing.expectEqual(@as(u64, 1200), conn.sendBudgetCC());

    // One more byte tips it over
    conn.onPacketSentLD(.application, 1, 1, true, 1_001_000);
    // 10801 + 1200 = 12001 > 12000 → cannot send
    try std.testing.expect(!conn.canSendCC());
}

test "Connection: getPto returns RTT-based estimate" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    // Before any RTT samples: uses initial RTT (333ms) + 4*rttvar(166.5ms) + max_ack_delay(25ms)
    const initial_pto = conn.getPto();
    try std.testing.expect(initial_pto > 0);
    try std.testing.expect(initial_pto < 2_000_000); // should be well under 2s
}

test "Connection: sendTracked registers with loss detector" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;
    const result = conn.sendTracked(&buf, "hello", 1_000_000) orelse unreachable;
    try std.testing.expect(result.len > 0);
    try std.testing.expectEqual(@as(u64, 0), result.pn);
    try std.testing.expect(conn.loss.cc.new_reno.bytes_in_flight > 0);
    try std.testing.expectEqual(@as(u64, 1), conn.app_level.send_pn);
    try std.testing.expect(conn.loss.getTimer() != null);
}

test "Connection: sendTracked respects CC" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    // Fill congestion window
    conn.loss.cc.new_reno.bytes_in_flight = 12000;

    var buf: [256]u8 = undefined;
    // Should be blocked by CC
    try std.testing.expect(conn.sendTracked(&buf, "blocked", 2_000_000) == null);
}

test "Connection: onLossTimeout returns PTO probe level" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    conn.onPacketSentLD(.application, 0, 1200, true, 1_000_000);
    const timer = conn.getLossTimer() orelse unreachable;
    try std.testing.expect(timer > 1_000_000);

    // Simulate timer expiry
    const level = conn.onLossTimeout(timer);
    try std.testing.expect(level != null);
    try std.testing.expectEqual(ack_mod.EncryptionLevel.application, level.?);
    try std.testing.expectEqual(@as(u32, 1), conn.loss.pto_count);
}

test "Connection: discardLossLevel clears initial bytes in flight" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);

    conn.onPacketSentLD(.initial, 0, 1200, true, 1_000_000);
    conn.onPacketSentLD(.initial, 1, 1200, true, 1_001_000);
    try std.testing.expectEqual(@as(u64, 2400), conn.loss.cc.new_reno.bytes_in_flight);

    conn.discardLossLevel(.initial);
    try std.testing.expectEqual(@as(u64, 0), conn.loss.cc.new_reno.bytes_in_flight);
}

test "Connection: close uses real PTO when pto_us=0" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    // Pass 0 → should use getPto() internally
    _ = conn.close(1_000_000, 0);
    const expected_deadline = 1_000_000 + 3 * conn.loss.rtt.ptoBase(conn.loss.max_ack_delay_us);
    try std.testing.expectEqual(expected_deadline, conn.close_ctrl.drain_deadline_us);
}

test "scanPayload: extracts ACK fields" {
    // ACK frame: type=0x02, largest=10, delay=5000, range_count=0, first_range=3
    var payload: [8]u8 = undefined;
    payload[0] = 0x02;
    payload[1] = 0x0a; // largest = 10
    payload[2] = 0x40; // delay = 5000 (2-byte varint: 0x40 | (5000>>8), low byte)
    // 5000 = 0x1388 → 2-byte varint: 0x53, 0x88
    payload[2] = 0x53;
    payload[3] = 0x88;
    payload[4] = 0x00; // range_count = 0
    payload[5] = 0x03; // first_ack_range = 3

    const result = Connection.scanPayload(payload[0..6]);
    try std.testing.expect(result.has_ack);
    try std.testing.expectEqual(@as(u64, 10), result.ack_largest);
    try std.testing.expectEqual(@as(u64, 3), result.ack_first_range);
    try std.testing.expectEqual(@as(u64, 5000), result.ack_delay);
    try std.testing.expect(result.close_frame == null);
    // Verify ack_ranges[0] is populated: [10-3, 10] = [7, 10]
    try std.testing.expectEqual(@as(usize, 1), result.ack_range_count);
    try std.testing.expectEqual(@as(u64, 7), result.ack_ranges[0].start);
    try std.testing.expectEqual(@as(u64, 10), result.ack_ranges[0].end);
}

test "scanPayload: multi-range ACK extracts all ranges" {
    // ACK frame with 2 additional ranges:
    // largest=20, delay=0, range_count=2, first_range=2 → [18,20]
    // gap=1, range=1 → smallest=18, skip gap+2=3 → end=15, range=1 → [14,15]
    // gap=3, range=0 → smallest=14, skip gap+2=5 → end=9, range=0 → [9,9]
    var payload: [16]u8 = undefined;
    payload[0] = 0x02; // ACK type
    payload[1] = 0x14; // largest = 20
    payload[2] = 0x00; // delay = 0
    payload[3] = 0x02; // range_count = 2
    payload[4] = 0x02; // first_range = 2 → [18,20]
    // Range 1: gap=1, ack_range=1 → skip gap+2=3 below 18 → end=15, [14,15]
    payload[5] = 0x01; // gap = 1
    payload[6] = 0x01; // ack_range = 1
    // Range 2: gap=3, ack_range=0 → skip gap+2=5 below 14 → end=9, [9,9]
    payload[7] = 0x03; // gap = 3
    payload[8] = 0x00; // ack_range = 0

    const result = Connection.scanPayload(payload[0..9]);
    try std.testing.expect(result.has_ack);
    try std.testing.expectEqual(@as(u64, 20), result.ack_largest);
    try std.testing.expectEqual(@as(usize, 3), result.ack_range_count);

    // First range: [18, 20]
    try std.testing.expectEqual(@as(u64, 18), result.ack_ranges[0].start);
    try std.testing.expectEqual(@as(u64, 20), result.ack_ranges[0].end);

    // Second range: [14, 15]
    try std.testing.expectEqual(@as(u64, 14), result.ack_ranges[1].start);
    try std.testing.expectEqual(@as(u64, 15), result.ack_ranges[1].end);

    // Third range: [9, 9]
    try std.testing.expectEqual(@as(u64, 9), result.ack_ranges[2].start);
    try std.testing.expectEqual(@as(u64, 9), result.ack_ranges[2].end);
}

test "scanPayload: first range populates ack_ranges[0]" {
    // Single range: largest=5, delay=0, range_count=0, first_range=5 → [0,5]
    var payload: [6]u8 = undefined;
    payload[0] = 0x02;
    payload[1] = 0x05; // largest = 5
    payload[2] = 0x00; // delay = 0
    payload[3] = 0x00; // range_count = 0
    payload[4] = 0x05; // first_range = 5

    const result = Connection.scanPayload(payload[0..5]);
    try std.testing.expect(result.has_ack);
    try std.testing.expectEqual(@as(usize, 1), result.ack_range_count);
    try std.testing.expectEqual(@as(u64, 0), result.ack_ranges[0].start);
    try std.testing.expectEqual(@as(u64, 5), result.ack_ranges[0].end);
}

test "Connection: multi-range ACK releases from send buffer" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;

    // Send 10 STREAM frames (PNs 0..9)
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        _ = conn.sendStream(&buf, 4, i * 3, "xyz", false, 1_000_000 + i * 1000) orelse unreachable;
    }
    try std.testing.expectEqual(@as(usize, 10), conn.send_buf.pending());

    // Simulate multi-range ACK: [8,9], [5,6], [1,2]
    const ranges = [_]Connection.AckRange{
        .{ .start = 8, .end = 9 },
        .{ .start = 5, .end = 6 },
        .{ .start = 1, .end = 2 },
    };
    conn.processAckForRetransmit(&ranges);

    // PNs 1,2,5,6,8,9 released → 4 remaining (0, 3, 4, 7)
    try std.testing.expectEqual(@as(usize, 4), conn.send_buf.pending());
}

// ─── Retransmission Integration Tests ───

test "Connection.sendStream: records in send buffer" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;
    const len = conn.sendStream(&buf, 4, 0, "hello", false, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(usize, 1), conn.send_buf.pending());
    try std.testing.expect(conn.loss.cc.new_reno.bytes_in_flight > 0);
}

test "Connection.hasRetransmits: false initially" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    const conn = Connection.init(&dcid, &scid);
    try std.testing.expect(!conn.hasRetransmits());
}

test "Connection.sendProbe: sends PING when no retransmits" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;
    const len = conn.sendProbe(&buf, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expect(conn.loss.cc.new_reno.bytes_in_flight > 0);
}

test "Connection: sendStream → loss → retransmit cycle" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;

    // Send 4 STREAM frames (PNs 0..3)
    _ = conn.sendStream(&buf, 4, 0, "aaa", false, 1_000_000) orelse unreachable;
    _ = conn.sendStream(&buf, 4, 3, "bbb", false, 1_001_000) orelse unreachable;
    _ = conn.sendStream(&buf, 4, 6, "ccc", false, 1_002_000) orelse unreachable;
    _ = conn.sendStream(&buf, 4, 9, "ddd", true, 1_003_000) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 4), conn.send_buf.pending());

    // Simulate: ACK range [2, 3] — release those from send buffer
    conn.send_buf.onAckRange(2, 3);
    try std.testing.expectEqual(@as(usize, 2), conn.send_buf.pending()); // PNs 0, 1 remain

    // Simulate: PNs 0, 1 declared lost → move to retransmit queue
    const lost = [_]u64{ 0, 1 };
    conn.send_buf.onLoss(&lost, &conn.rtx_queue);
    try std.testing.expectEqual(@as(usize, 0), conn.send_buf.pending());
    try std.testing.expect(conn.hasRetransmits());
    try std.testing.expectEqual(@as(usize, 2), conn.rtx_queue.pending());

    // Retransmit the lost frames
    const rtx_len = conn.retransmitNext(&buf, 2_000_000) orelse unreachable;
    try std.testing.expect(rtx_len > 0);
    try std.testing.expectEqual(@as(usize, 1), conn.rtx_queue.pending());

    const rtx_len2 = conn.retransmitNext(&buf, 2_001_000) orelse unreachable;
    try std.testing.expect(rtx_len2 > 0);
    try std.testing.expect(!conn.hasRetransmits());
}

// ─── Key Update Integration Tests ───

test "Connection: initiateKeyUpdate flips key phase" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    // Install key_mgr with known secrets
    const cs = [_]u8{0xAA} ** 32;
    const ss = [_]u8{0xBB} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;
    conn.key_mgr = key_update_mod.KeyUpdateManager.init(cs, ss, chp, shp);

    try std.testing.expectEqual(@as(u1, 0), conn.keyPhase());
    try std.testing.expectEqual(@as(u32, 0), conn.keyGeneration());

    // send_pn is 0, so first_pn_in_new_phase will be 0
    try std.testing.expect(conn.initiateKeyUpdate(1_000_000));
    try std.testing.expectEqual(@as(u1, 1), conn.keyPhase());
    try std.testing.expectEqual(@as(u32, 1), conn.keyGeneration());

    // Cannot double-update (pending until ACK of PN >= 0)
    try std.testing.expect(!conn.initiateKeyUpdate(1_050_000));

    // Confirm via tryConfirmUpdate (simulating ACK receipt)
    const km = &(conn.key_mgr.?);
    try std.testing.expect(km.tryConfirmUpdate(0)); // ACK for PN 0
    try std.testing.expect(!km.update_pending);

    // Now can initiate again
    try std.testing.expect(conn.initiateKeyUpdate(1_100_000));
    try std.testing.expectEqual(@as(u1, 0), conn.keyPhase());
    try std.testing.expectEqual(@as(u32, 2), conn.keyGeneration());
}

test "Connection: sendTracked uses key_mgr when available" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const cs = [_]u8{0xAA} ** 32;
    const ss = [_]u8{0xBB} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;
    conn.key_mgr = key_update_mod.KeyUpdateManager.init(cs, ss, chp, shp);

    var buf: [256]u8 = undefined;
    const result = conn.sendTracked(&buf, "test payload", 1_000_000) orelse unreachable;
    try std.testing.expect(result.len > 0);
    try std.testing.expectEqual(@as(u64, 0), result.pn);
}

test "Connection: send1Rtt uses key_mgr key_phase" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const cs = [_]u8{0xAA} ** 32;
    const ss = [_]u8{0xBB} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;
    conn.key_mgr = key_update_mod.KeyUpdateManager.init(cs, ss, chp, shp);

    var buf: [256]u8 = undefined;

    // Send with phase 0
    const len1 = conn.send1Rtt(&buf, "hello") orelse unreachable;
    try std.testing.expect(len1 > 0);

    // After key update, send with phase 1
    _ = conn.initiateKeyUpdate(1_000_000);
    const len2 = conn.send1Rtt(&buf, "world") orelse unreachable;
    try std.testing.expect(len2 > 0);
}

test "Connection: key update roundtrip encode/decode" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;

    const cs = [_]u8{0xAA} ** 32;
    const ss = [_]u8{0xBB} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;

    // Sender
    var sender = Connection.init(&dcid, &scid);
    sender.state = .connected;
    sender.key_mgr = key_update_mod.KeyUpdateManager.init(cs, ss, chp, shp);

    // Receiver (swapped roles: server_secret = sender's client_secret)
    var receiver = Connection.init(&scid, &dcid);
    receiver.state = .connected;
    receiver.key_mgr = key_update_mod.KeyUpdateManager.init(ss, cs, shp, chp);
    receiver.dcid_len = dcid.len;
    @memcpy(receiver.dcid[0..dcid.len], &dcid);

    // Sender sends a packet (phase 0)
    var buf: [256]u8 = undefined;
    const send_len = sender.sendTracked(&buf, "phase zero", 1_000_000) orelse unreachable;
    try std.testing.expect(send_len.len > 0);

    // Receiver should be able to decrypt (same phase)
    var recv_data: [256]u8 = undefined;
    @memcpy(recv_data[0..send_len.len], buf[0..send_len.len]);

    // Use the two-phase decode API
    const km = &(receiver.key_mgr.?);
    const parsed = short_header.removeHpAndParse(recv_data[0..send_len.len], receiver.dcid_len, km.server_hp) orelse unreachable;

    var out: [256]u8 = undefined;
    const pt_len = km.tryDecrypt(
        &out,
        recv_data[parsed.ct_start..][0..parsed.ct_len],
        recv_data[parsed.ct_start + parsed.ct_len ..][0..16].*,
        parsed.pn,
        recv_data[0..parsed.ct_start],
        parsed.key_phase,
        1_000_000,
        100_000,
    ) orelse unreachable;
    try std.testing.expectEqualStrings("phase zero", out[0..pt_len]);
}

// ─── Stream Multiplexing Integration Tests ───

test "Connection: openStream and writeStream" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;
    conn.setPeerTransportParams(.{});

    const id = conn.openStream() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), id);
    try std.testing.expectEqual(@as(u32, 1), conn.activeStreams());

    var buf: [256]u8 = undefined;
    const len = conn.writeStream(&buf, id, "hello", false, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(usize, 1), conn.send_buf.pending());
}

test "Connection: writeStream auto-advances offset" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;
    conn.setPeerTransportParams(.{});

    const id = conn.openStream() orelse unreachable;

    var buf: [256]u8 = undefined;
    _ = conn.writeStream(&buf, id, "aaa", false, 1_000_000);
    _ = conn.writeStream(&buf, id, "bbb", false, 1_001_000);
    _ = conn.writeStream(&buf, id, "ccc", true, 1_002_000);

    // Offset should be 9 (3+3+3)
    try std.testing.expectEqual(@as(?u64, 9), conn.stream_mgr.getSendOffset(id));
}

test "Connection: multiple concurrent streams" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;
    conn.setPeerTransportParams(.{});

    const s0 = conn.openStream() orelse unreachable;
    const s1 = conn.openStream() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), s0);
    try std.testing.expectEqual(@as(u62, 4), s1);
    try std.testing.expectEqual(@as(u32, 2), conn.activeStreams());

    var buf: [256]u8 = undefined;
    _ = conn.writeStream(&buf, s0, "req0", false, 1_000_000);
    _ = conn.writeStream(&buf, s1, "req1", false, 1_001_000);

    // Each stream has independent offset
    try std.testing.expectEqual(@as(?u64, 4), conn.stream_mgr.getSendOffset(s0));
    try std.testing.expectEqual(@as(?u64, 4), conn.stream_mgr.getSendOffset(s1));
}

// ─── Retry Integration Tests ───

test "Connection: handleRetryPacket with RFC 9001 A.4 vector" {
    // original DCID from RFC 9001 Appendix A.4
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var conn = Connection.init(&original_dcid, &scid);
    conn.onInitialSent();

    // RFC 9001 A.4 Retry packet
    var retry_pkt = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    const event = conn.onDatagram(&retry_pkt, 1_000_000);
    try std.testing.expect(event == .retry_received);

    // DCID should be updated to Retry's SCID (from the packet: SCID field)
    // In the RFC A.4 vector, DCID len=0, SCID len=8, SCID = f067a5502a4262b5
    try std.testing.expectEqual(@as(usize, 8), conn.dcid_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 }, conn.dcid[0..8]);

    // Token should be stored
    try std.testing.expectEqualSlices(u8, "token", conn.retry_token[0..conn.retry_token_len]);

    // Retry should be marked as received
    try std.testing.expect(conn.retry_received);

    // PN should be reset
    try std.testing.expectEqual(@as(u64, 0), conn.initial_level.send_pn);

    // Initial keys should have been re-derived (different from original)
    const original_keys = quic_crypto.deriveInitialKeys(&original_dcid);
    try std.testing.expect(!std.mem.eql(u8, &conn.keys.initial_client.key, &original_keys.client_key));

    // original_dcid should still be preserved
    try std.testing.expectEqualSlices(u8, &original_dcid, conn.original_dcid[0..conn.original_dcid_len]);
}

test "Connection: second Retry is ignored" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var conn = Connection.init(&original_dcid, &scid);
    conn.onInitialSent();

    var retry_pkt = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    // First Retry accepted
    const event1 = conn.onDatagram(&retry_pkt, 1_000_000);
    try std.testing.expect(event1 == .retry_received);

    // Second Retry ignored
    const event2 = conn.onDatagram(&retry_pkt, 2_000_000);
    try std.testing.expect(event2 == .none);
}

test "Connection: Retry ignored when not in initial_sent state" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var conn = Connection.init(&dcid, &scid);
    // Still in idle state, not initial_sent

    var retry_pkt = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    const event = conn.onDatagram(&retry_pkt, 1_000_000);
    try std.testing.expect(event == .none);
}

test "Connection: getRetryToken returns token after Retry" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var conn = Connection.init(&dcid, &scid);
    conn.onInitialSent();

    // Before retry
    try std.testing.expect(conn.getRetryToken() == null);

    var retry_pkt = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    _ = conn.onDatagram(&retry_pkt, 1_000_000);

    // After retry
    const token = conn.getRetryToken() orelse unreachable;
    try std.testing.expectEqualSlices(u8, "token", token);
}

// ─── PATH_CHALLENGE / PATH_RESPONSE Tests ───

test "Connection: sendPathChallenge initiates validation" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    try std.testing.expect(conn.isPathValidated());
    try std.testing.expect(!conn.isPathValidationPending());

    var buf: [256]u8 = undefined;
    const len = conn.sendPathChallenge(&buf, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expect(conn.isPathValidationPending());
    try std.testing.expect(!conn.isPathValidated());
}

test "Connection: onPathResponse with matching data validates path" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    // Simulate pending challenge
    conn.path_challenge_pending = true;
    conn.path_challenge_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    conn.path_challenge_sent_us = 1_000_000;
    conn.path_validated = false;

    // Matching response
    conn.onPathResponse([_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 });
    try std.testing.expect(!conn.isPathValidationPending());
    try std.testing.expect(conn.isPathValidated());
}

test "Connection: onPathResponse with wrong data does not validate" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    conn.path_challenge_pending = true;
    conn.path_challenge_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
    conn.path_validated = false;

    // Wrong response
    conn.onPathResponse([_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    try std.testing.expect(conn.isPathValidationPending());
    try std.testing.expect(!conn.isPathValidated());
}

test "Connection: isPathValidationTimedOut" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    conn.path_challenge_pending = true;
    conn.path_challenge_sent_us = 1_000_000;

    // PTO default = smoothed_rtt(333ms) + max(4*rttvar, 1ms) + max_ack_delay(25ms)
    // = 333000 + 666000 + 25000 = 1024000 (≈1s)
    // 3*PTO ≈ 3072000
    try std.testing.expect(!conn.isPathValidationTimedOut(2_000_000)); // 1s elapsed — not timed out
    try std.testing.expect(conn.isPathValidationTimedOut(5_000_000)); // 4s elapsed — timed out
}

test "Connection: sendPathResponse encodes frame" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    var buf: [256]u8 = undefined;
    const challenge = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const len = conn.sendPathResponse(&buf, challenge, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
}

test "scanPayload: PATH_CHALLENGE extracted" {
    // PADDING + PATH_CHALLENGE(0x1a) + 8 bytes
    var payload: [10]u8 = undefined;
    payload[0] = 0x00; // PADDING
    payload[1] = 0x1a; // PATH_CHALLENGE
    @memcpy(payload[2..10], &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE });

    const result = Connection.scanPayload(&payload);
    try std.testing.expect(result.path_challenge_data != null);
    try std.testing.expectEqual([_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE }, result.path_challenge_data.?);
    try std.testing.expect(result.path_response_data == null);
}

test "scanPayload: PATH_RESPONSE extracted" {
    var payload: [9]u8 = undefined;
    payload[0] = 0x1b; // PATH_RESPONSE
    @memcpy(payload[1..9], &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });

    const result = Connection.scanPayload(&payload);
    try std.testing.expect(result.path_response_data != null);
    try std.testing.expectEqual([_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, result.path_response_data.?);
    try std.testing.expect(result.path_challenge_data == null);
}

// ─── Connection Migration Integration Tests ───

test "Connection: onDatagramSource detects address change" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    // Same address → no event
    const ev1 = conn.onDatagramSource(addr1, 1200, 1_000_000);
    try std.testing.expect(ev1 == .none);

    // Different address → migration_started
    const ev2 = conn.onDatagramSource(addr2, 1200, 2_000_000);
    switch (ev2) {
        .migration_started => |info| {
            try std.testing.expect(info.new_addr.eql(addr2));
            try std.testing.expect(info.previous_addr.eql(addr1));
        },
        else => try std.testing.expect(false),
    }
    try std.testing.expect(conn.isMigrationInProgress());
}

test "Connection: startMigration sends PATH_CHALLENGE" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    _ = conn.onDatagramSource(addr2, 1200, 1_000_000);

    var buf: [256]u8 = undefined;
    const len = conn.startMigration(&buf, 1_000_000) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expect(conn.isPathValidationPending());
}

test "Connection: full migration lifecycle" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.keys.app_client = .{
        .key = [_]u8{0x11} ** 16,
        .iv = [_]u8{0x22} ** 12,
        .hp = [_]u8{0x33} ** 16,
    };
    conn.state = .connected;

    // Add a second CID so rotation can succeed
    var frame = cid_mod.NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xAA} ** 16,
    };
    @memcpy(frame.cid[0..8], &([_]u8{0x05} ** 8));
    _ = conn.cid_mgr.onNewConnectionId(frame);

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    // 1. Detect address change
    _ = conn.onDatagramSource(addr2, 1200, 1_000_000);
    try std.testing.expect(conn.isMigrationInProgress());

    // 2. Send PATH_CHALLENGE
    var buf: [256]u8 = undefined;
    _ = conn.startMigration(&buf, 1_000_000);

    // 3. Simulate PATH_RESPONSE (matching data)
    conn.onPathResponse(conn.path_challenge_data);
    try std.testing.expect(conn.isPathValidated());
    try std.testing.expect(conn.migration.isNewPathValidated());

    // 4. Complete migration (rotate CID)
    try std.testing.expect(conn.completeMigration());
    try std.testing.expect(!conn.isMigrationInProgress());
    try std.testing.expectEqual(@as(u32, 1), conn.migrationCount());

    // DCID should have rotated to the new one
    try std.testing.expectEqualSlices(u8, &([_]u8{0x05} ** 8), conn.dcid[0..conn.dcid_len]);
}

test "Connection: pollMigration returns retry_probe on timeout" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    _ = conn.onDatagramSource(addr2, 1200, 1_000_000);

    // Not timed out yet
    try std.testing.expectEqual(Connection.MigrationAction.none, conn.pollMigration(1_100_000));

    // After 3*PTO
    const pto = conn.getPto();
    try std.testing.expectEqual(Connection.MigrationAction.retry_probe, conn.pollMigration(1_000_000 + 3 * pto));
}

test "Connection: revertMigration restores previous path" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    _ = conn.onDatagramSource(addr2, 1200, 1_000_000);
    try std.testing.expect(conn.getPeerAddress().?.eql(addr2));

    const reverted = conn.revertMigration() orelse unreachable;
    try std.testing.expect(reverted.eql(addr1));
    try std.testing.expect(conn.getPeerAddress().?.eql(addr1));
    try std.testing.expect(!conn.isMigrationInProgress());
}

test "Connection: canSendOnNewPath respects anti-amplification" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    _ = conn.onDatagramSource(addr2, 1200, 1_000_000);
    // Budget = 1200 * 3 = 3600
    try std.testing.expect(conn.canSendOnNewPath(3600));
    try std.testing.expect(!conn.canSendOnNewPath(3601));
}

test "Connection: disableMigration prevents migration events" {
    const dcid = [_]u8{0x01} ** 8;
    const scid = [_]u8{0x02} ** 4;
    var conn = Connection.init(&dcid, &scid);
    conn.state = .connected;
    conn.disableMigration();

    const addr1 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = migration_mod.PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    conn.setPeerAddress(addr1);

    const ev = conn.onDatagramSource(addr2, 1200, 1_000_000);
    try std.testing.expect(ev == .none);
    try std.testing.expect(!conn.isMigrationInProgress());
}
