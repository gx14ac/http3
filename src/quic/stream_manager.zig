// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const packet_mod = @import("packet.zig");
const stream_mod = @import("stream.zig");
const flow_control = @import("flow_control.zig");

const Stream = stream_mod.Stream;
const StreamState = stream_mod.StreamState;
const StreamType = stream_mod.StreamType;
const StreamAllocator = stream_mod.StreamAllocator;
const StreamFrame = stream_mod.StreamFrame;
const FlowController = flow_control.FlowController;
const TransportParams = flow_control.TransportParams;

const MAX_CONCURRENT_STREAMS = 64;

/// Managed stream entry: state machine + send offset tracking.
const ManagedStream = struct {
    stream: Stream,
    in_use: bool,
};

/// StreamManager: manages the full lifecycle of QUIC streams.
///
/// Responsibilities:
/// - Stream ID allocation (client-initiated bidi/uni)
/// - Per-stream state machine (idle → open → half-closed → closed)
/// - Send offset auto-tracking (no need for caller to pass offset)
/// - Integration with FlowController for per-stream + connection-level limits
/// - MAX_STREAMS frame handling
/// - STREAM_DATA_BLOCKED / STREAMS_BLOCKED signaling
pub const StreamManager = struct {
    streams: [MAX_CONCURRENT_STREAMS]ManagedStream,
    alloc: StreamAllocator,
    flow: FlowController,
    is_server: bool,

    // Peer's max streams limits (updated by MAX_STREAMS frames)
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,

    // Local limits we advertise
    local_max_streams_bidi: u64,
    local_max_streams_uni: u64,

    // Counts of currently active streams (not closed/reset)
    active_bidi: u32,
    active_uni: u32,

    // Blocked state for signaling
    streams_blocked_bidi: bool,
    streams_blocked_uni: bool,

    // Whether we need to send updated MAX_STREAMS to peer
    max_streams_bidi_pending: bool,
    max_streams_uni_pending: bool,

    pub fn init(is_server: bool, local_params: TransportParams) StreamManager {
        var mgr: StreamManager = undefined;
        mgr.is_server = is_server;
        // Allocator starts with 0 — peer must tell us their max via transport params
        mgr.alloc = StreamAllocator.init(is_server, 0, 0);
        mgr.flow = FlowController.init(local_params);
        mgr.peer_max_streams_bidi = 0;
        mgr.peer_max_streams_uni = 0;
        mgr.local_max_streams_bidi = local_params.initial_max_streams_bidi;
        mgr.local_max_streams_uni = local_params.initial_max_streams_uni;
        mgr.active_bidi = 0;
        mgr.active_uni = 0;
        mgr.streams_blocked_bidi = false;
        mgr.streams_blocked_uni = false;
        mgr.max_streams_bidi_pending = false;
        mgr.max_streams_uni_pending = false;
        for (&mgr.streams) |*s| {
            s.in_use = false;
        }
        return mgr;
    }

    /// Set the peer's transport parameters (from EncryptedExtensions/transport_parameters).
    pub fn setPeerParams(self: *StreamManager, peer_params: TransportParams) void {
        self.flow.setPeerParams(peer_params);
        self.peer_max_streams_bidi = peer_params.initial_max_streams_bidi;
        self.peer_max_streams_uni = peer_params.initial_max_streams_uni;
        self.alloc.updateMaxBidi(@intCast(peer_params.initial_max_streams_bidi));
        self.alloc.updateMaxUni(@intCast(peer_params.initial_max_streams_uni));
    }

    /// Open a new bidirectional stream. Returns stream_id or null if limit reached.
    pub fn openBidi(self: *StreamManager) ?u62 {
        const id = self.alloc.allocBidi() orelse {
            self.streams_blocked_bidi = true;
            return null;
        };
        return self.registerStream(id);
    }

    /// Open a new unidirectional stream. Returns stream_id or null if limit reached.
    pub fn openUni(self: *StreamManager) ?u62 {
        const id = self.alloc.allocUni() orelse {
            self.streams_blocked_uni = true;
            return null;
        };
        return self.registerStream(id);
    }

    /// Get a stream's current state.
    pub fn getState(self: *const StreamManager, stream_id: u62) ?StreamState {
        const ms = self.findConst(stream_id) orelse return null;
        return ms.stream.state;
    }

    /// Get the current send offset for a stream.
    pub fn getSendOffset(self: *const StreamManager, stream_id: u62) ?u64 {
        const ms = self.findConst(stream_id) orelse return null;
        return ms.stream.send_offset;
    }

    /// Write data to a stream. Returns a SendOp with stream_id, offset, data slice,
    /// and fin flag for the caller to encode as a STREAM frame.
    /// Advances send_offset. Returns null if stream not found or flow-blocked.
    pub fn write(self: *StreamManager, stream_id: u62, data: []const u8, fin: bool) ?SendOp {
        const ms = self.find(stream_id) orelse return null;

        // Cannot send on closed or half-closed-local streams
        if (ms.stream.state == .half_closed_local or
            ms.stream.state == .closed or
            ms.stream.state == .reset)
        {
            return null;
        }

        // Check flow control (stream + connection level)
        const len = data.len;
        if (len > 0 and !self.flow.canSend(stream_id, @intCast(len))) {
            return null;
        }

        const offset = ms.stream.send_offset;

        // Update flow control
        if (len > 0) {
            self.flow.onSend(stream_id, @intCast(len));
        }
        ms.stream.send_offset += len;

        // Update state on FIN
        if (fin) {
            ms.stream.finishSend();
        }

        return .{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .fin = fin,
        };
    }

    /// Undo a write() that was not committed to wire (e.g., CC blocked sendTracked).
    /// Rolls back send_offset, flow control counters, and state transition.
    pub fn rollbackWrite(self: *StreamManager, op: SendOp) void {
        const ms = self.find(op.stream_id) orelse return;

        // Rollback offset
        ms.stream.send_offset = op.offset;

        // Rollback flow control
        if (op.data.len > 0) {
            const len: u64 = @intCast(op.data.len);
            if (self.flow.conn.send_offset >= len) {
                self.flow.conn.send_offset -= len;
            }
            if (self.flow.getStream(op.stream_id)) |sfc| {
                if (sfc.send_offset >= len) {
                    sfc.send_offset -= len;
                }
            }
        }

        // Rollback state transition from FIN
        if (op.fin) {
            switch (ms.stream.state) {
                .half_closed_local => ms.stream.state = .open,
                .closed => ms.stream.state = .half_closed_remote,
                else => {},
            }
            ms.stream.send_fin = false;
        }
    }

    /// Process a received STREAM frame. Updates recv state and flow control.
    /// Returns the frame data for the application, or null if stream error.
    pub fn onRecvStream(self: *StreamManager, frame: StreamFrame) ?RecvResult {
        // Get or create stream (peer-initiated)
        const ms = self.findOrCreate(frame.stream_id) orelse return null;

        // Cannot receive on half-closed-remote or closed streams
        if (ms.stream.state == .half_closed_remote or
            ms.stream.state == .closed or
            ms.stream.state == .reset)
        {
            return null;
        }

        // Open if idle
        if (ms.stream.state == .idle) {
            ms.stream.state = .open;
        }

        // Update receive offset (simplified: assume in-order delivery)
        const data_end = frame.offset + frame.data.len;
        if (data_end > ms.stream.recv_offset) {
            const new_bytes = data_end - ms.stream.recv_offset;
            self.flow.onRecv(frame.stream_id, new_bytes);
            ms.stream.recv_offset = data_end;
        }

        // Handle FIN
        if (frame.fin) {
            ms.stream.finishRecv();
        }

        // Check if stream is now fully closed
        if (ms.stream.state == .closed) {
            self.releaseStream(frame.stream_id);
        }

        return .{
            .stream_id = frame.stream_id,
            .offset = frame.offset,
            .data = frame.data,
            .fin = frame.fin,
        };
    }

    /// Process a received MAX_STREAM_DATA frame.
    pub fn onMaxStreamData(self: *StreamManager, stream_id: u62, max_data: u64) void {
        if (self.flow.getStream(stream_id)) |sfc| {
            sfc.setPeerMaxStreamData(max_data);
        }
    }

    /// Process a received MAX_STREAMS frame (bidi or uni).
    pub fn onMaxStreams(self: *StreamManager, max: u64, bidi: bool) void {
        if (bidi) {
            if (max > self.peer_max_streams_bidi) {
                self.peer_max_streams_bidi = max;
                self.alloc.updateMaxBidi(@intCast(max));
                self.streams_blocked_bidi = false;
            }
        } else {
            if (max > self.peer_max_streams_uni) {
                self.peer_max_streams_uni = max;
                self.alloc.updateMaxUni(@intCast(max));
                self.streams_blocked_uni = false;
            }
        }
    }

    /// Process a received MAX_DATA frame (connection level).
    pub fn onMaxData(self: *StreamManager, max_data: u64) void {
        self.flow.conn.setPeerMaxData(max_data);
    }

    /// Close a stream (send FIN). Returns SendOp with empty data + fin=true.
    pub fn closeStream(self: *StreamManager, stream_id: u62) ?SendOp {
        return self.write(stream_id, &.{}, true);
    }

    /// Reset a stream (RESET_STREAM). Marks it as reset.
    pub fn resetStream(self: *StreamManager, stream_id: u62) void {
        const ms = self.find(stream_id) orelse return;
        ms.stream.reset();
        self.releaseStream(stream_id);
    }

    /// Check if a MAX_DATA frame should be sent to the peer.
    pub fn shouldSendMaxData(self: *const StreamManager) bool {
        return self.flow.conn.shouldUpdateMaxData();
    }

    /// Generate a MAX_DATA frame. Returns bytes written to buf.
    pub fn buildMaxData(self: *StreamManager, buf: []u8) ?usize {
        return self.flow.conn.buildMaxDataFrame(buf);
    }

    /// Check if a MAX_STREAM_DATA frame should be sent for a stream.
    pub fn shouldSendMaxStreamData(self: *StreamManager, stream_id: u62) bool {
        const sfc = self.flow.getStream(stream_id) orelse return false;
        return sfc.shouldUpdateMaxStreamData();
    }

    /// Generate a MAX_STREAM_DATA frame. Returns bytes written to buf.
    pub fn buildMaxStreamData(self: *StreamManager, stream_id: u62, buf: []u8) ?usize {
        const sfc = self.flow.getStream(stream_id) orelse return null;
        return sfc.buildMaxStreamDataFrame(buf);
    }

    /// Check if STREAMS_BLOCKED should be sent (bidi).
    pub fn isStreamsBidiBlocked(self: *const StreamManager) bool {
        return self.streams_blocked_bidi;
    }

    /// Check if STREAMS_BLOCKED should be sent (uni).
    pub fn isStreamsUniBlocked(self: *const StreamManager) bool {
        return self.streams_blocked_uni;
    }

    /// Check if we should send MAX_STREAMS (bidi) to peer.
    pub fn shouldSendMaxStreamsBidi(self: *const StreamManager) bool {
        return self.max_streams_bidi_pending;
    }

    /// Check if we should send MAX_STREAMS (uni) to peer.
    pub fn shouldSendMaxStreamsUni(self: *const StreamManager) bool {
        return self.max_streams_uni_pending;
    }

    /// Build a MAX_STREAMS frame (bidi) and clear pending flag. Returns bytes written.
    pub fn buildMaxStreamsBidi(self: *StreamManager, buf: []u8) ?usize {
        self.max_streams_bidi_pending = false;
        return encodeMaxStreams(buf, self.local_max_streams_bidi, true);
    }

    /// Build a MAX_STREAMS frame (uni) and clear pending flag. Returns bytes written.
    pub fn buildMaxStreamsUni(self: *StreamManager, buf: []u8) ?usize {
        self.max_streams_uni_pending = false;
        return encodeMaxStreams(buf, self.local_max_streams_uni, false);
    }

    /// Build a STREAMS_BLOCKED frame (bidi). Returns bytes written.
    pub fn buildStreamsBlockedBidi(self: *StreamManager, buf: []u8) ?usize {
        if (!self.streams_blocked_bidi) return null;
        return encodeStreamsBlocked(buf, self.peer_max_streams_bidi, true);
    }

    /// Build a STREAMS_BLOCKED frame (uni). Returns bytes written.
    pub fn buildStreamsBlockedUni(self: *StreamManager, buf: []u8) ?usize {
        if (!self.streams_blocked_uni) return null;
        return encodeStreamsBlocked(buf, self.peer_max_streams_uni, false);
    }

    /// Number of currently active streams.
    pub fn activeStreams(self: *const StreamManager) u32 {
        return self.active_bidi + self.active_uni;
    }

    // ─── Internal ───

    fn registerStream(self: *StreamManager, id: u62) ?u62 {
        for (&self.streams) |*s| {
            if (!s.in_use) {
                const stype: StreamType = @enumFromInt(@as(u2, @intCast(id & 0x03)));
                const is_uni = (stype == .client_uni or stype == .server_uni);

                // Use appropriate initial max based on stream type
                const initial_max = if (is_uni)
                    self.flow.params.initial_max_stream_data_uni
                else
                    self.flow.params.initial_max_stream_data_bidi_local;

                s.stream = Stream.init(id, initial_max);
                s.stream.state = .open;
                s.in_use = true;

                // Register with flow controller
                _ = self.flow.openStream(id);
                if (self.flow.getStream(id)) |sfc| {
                    // Set peer's max_stream_data as our send limit (direct assign)
                    const peer_max = if (is_uni)
                        self.flow.peer_params.initial_max_stream_data_uni
                    else
                        self.flow.peer_params.initial_max_stream_data_bidi_remote;
                    sfc.send_max = peer_max;
                }

                switch (stype) {
                    .client_bidi, .server_bidi => self.active_bidi += 1,
                    .client_uni, .server_uni => self.active_uni += 1,
                }
                return id;
            }
        }
        return null;
    }

    fn releaseStream(self: *StreamManager, stream_id: u62) void {
        for (&self.streams) |*s| {
            if (s.in_use and s.stream.id == stream_id) {
                s.in_use = false;
                self.flow.closeStream(stream_id);

                const stype: StreamType = @enumFromInt(@as(u2, @intCast(stream_id & 0x03)));
                switch (stype) {
                    .client_bidi, .server_bidi => {
                        if (self.active_bidi > 0) self.active_bidi -= 1;
                        // Increment local MAX_STREAMS to allow peer to open new streams
                        self.local_max_streams_bidi += 1;
                        self.max_streams_bidi_pending = true;
                    },
                    .client_uni, .server_uni => {
                        if (self.active_uni > 0) self.active_uni -= 1;
                        self.local_max_streams_uni += 1;
                        self.max_streams_uni_pending = true;
                    },
                }
                return;
            }
        }
    }

    fn find(self: *StreamManager, stream_id: u62) ?*ManagedStream {
        for (&self.streams) |*s| {
            if (s.in_use and s.stream.id == stream_id) return s;
        }
        return null;
    }

    fn findConst(self: *const StreamManager, stream_id: u62) ?*const ManagedStream {
        for (&self.streams) |*s| {
            if (s.in_use and s.stream.id == stream_id) return s;
        }
        return null;
    }

    fn findOrCreate(self: *StreamManager, stream_id: u62) ?*ManagedStream {
        // Existing?
        if (self.find(stream_id)) |ms| return ms;

        // Validate: peer-initiated streams must have the correct initiator bit
        // RFC 9000 §2.1: client-initiated = even low bit, server-initiated = odd low bit
        const initiator_bit: u1 = @intCast(stream_id & 0x01);
        const peer_is_server = !self.is_server;
        const expected_bit: u1 = if (peer_is_server) 1 else 0;
        if (initiator_bit != expected_bit) return null;

        // Create (peer-initiated stream)
        _ = self.registerStream(stream_id) orelse return null;
        return self.find(stream_id);
    }
};

/// Describes a send operation: the caller encodes this as a STREAM frame.
pub const SendOp = struct {
    stream_id: u62,
    offset: u64,
    data: []const u8,
    fin: bool,
};

/// Result of receiving stream data.
pub const RecvResult = struct {
    stream_id: u62,
    offset: u64,
    data: []const u8,
    fin: bool,
};

// ─── Frame encode/decode for MAX_STREAMS / STREAMS_BLOCKED ───

/// Encode MAX_STREAMS frame (RFC 9000 §19.11).
/// Type 0x12 = bidi, 0x13 = uni.
pub fn encodeMaxStreams(buf: []u8, max: u64, bidi: bool) ?usize {
    if (buf.len < 1) return null;
    buf[0] = if (bidi) 0x12 else 0x13;
    const n = packet_mod.encodeVarint(buf[1..], max) orelse return null;
    return 1 + n;
}

/// Decode MAX_STREAMS frame. Returns (max_streams, is_bidi).
pub fn decodeMaxStreams(data: []const u8) ?struct { max: u64, bidi: bool } {
    if (data.len < 2) return null;
    const is_bidi = switch (data[0]) {
        0x12 => true,
        0x13 => false,
        else => return null,
    };
    const v = packet_mod.decodeVarint(data[1..]) orelse return null;
    return .{ .max = v.value, .bidi = is_bidi };
}

/// Encode STREAMS_BLOCKED frame (RFC 9000 §19.14).
/// Type 0x16 = bidi, 0x17 = uni.
pub fn encodeStreamsBlocked(buf: []u8, max: u64, bidi: bool) ?usize {
    if (buf.len < 1) return null;
    buf[0] = if (bidi) 0x16 else 0x17;
    const n = packet_mod.encodeVarint(buf[1..], max) orelse return null;
    return 1 + n;
}

/// Decode STREAMS_BLOCKED frame.
pub fn decodeStreamsBlocked(data: []const u8) ?struct { max: u64, bidi: bool } {
    if (data.len < 2) return null;
    const is_bidi = switch (data[0]) {
        0x16 => true,
        0x17 => false,
        else => return null,
    };
    const v = packet_mod.decodeVarint(data[1..]) orelse return null;
    return .{ .max = v.value, .bidi = is_bidi };
}

/// Encode STREAM_DATA_BLOCKED frame (RFC 9000 §19.13).
/// Type 0x15.
pub fn encodeStreamDataBlocked(buf: []u8, stream_id: u62, max: u64) ?usize {
    if (buf.len < 1) return null;
    buf[0] = 0x15;
    var pos: usize = 1;
    pos += packet_mod.encodeVarint(buf[pos..], stream_id) orelse return null;
    pos += packet_mod.encodeVarint(buf[pos..], max) orelse return null;
    return pos;
}

/// Encode DATA_BLOCKED frame (RFC 9000 §19.12).
/// Type 0x14.
pub fn encodeDataBlocked(buf: []u8, max: u64) ?usize {
    if (buf.len < 1) return null;
    buf[0] = 0x14;
    const n = packet_mod.encodeVarint(buf[1..], max) orelse return null;
    return 1 + n;
}

// ─── Tests ───

test "StreamManager: open bidi stream" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), id);
    try std.testing.expectEqual(StreamState.open, mgr.getState(id).?);
    try std.testing.expectEqual(@as(u32, 1), mgr.active_bidi);
}

test "StreamManager: open uni stream" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openUni() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 2), id);
    try std.testing.expectEqual(StreamState.open, mgr.getState(id).?);
    try std.testing.expectEqual(@as(u32, 1), mgr.active_uni);
}

test "StreamManager: write advances offset" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;

    const op1 = mgr.write(id, "hello", false) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), op1.offset);
    try std.testing.expectEqualStrings("hello", op1.data);
    try std.testing.expect(!op1.fin);

    const op2 = mgr.write(id, " world", true) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 5), op2.offset);
    try std.testing.expect(op2.fin);

    try std.testing.expectEqual(@as(u64, 11), mgr.getSendOffset(id).?);
    try std.testing.expectEqual(StreamState.half_closed_local, mgr.getState(id).?);
}

test "StreamManager: cannot write after FIN" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;
    _ = mgr.write(id, "data", true);

    // Stream is now half_closed_local, cannot write
    try std.testing.expect(mgr.write(id, "more", false) == null);
}

test "StreamManager: receive stream data" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    // Peer opens bidi stream 1 (server-initiated)
    const frame = StreamFrame{ .stream_id = 1, .offset = 0, .data = "response", .fin = false };
    const result = mgr.onRecvStream(frame) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 1), result.stream_id);
    try std.testing.expectEqualStrings("response", result.data);
    try std.testing.expect(!result.fin);

    try std.testing.expectEqual(StreamState.open, mgr.getState(1).?);
}

test "StreamManager: receive FIN closes recv side" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const frame = StreamFrame{ .stream_id = 1, .offset = 0, .data = "done", .fin = true };
    _ = mgr.onRecvStream(frame);

    try std.testing.expectEqual(StreamState.half_closed_remote, mgr.getState(1).?);
}

test "StreamManager: full stream lifecycle" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;
    try std.testing.expectEqual(StreamState.open, mgr.getState(id).?);

    // Send data + FIN
    _ = mgr.write(id, "request", true);
    try std.testing.expectEqual(StreamState.half_closed_local, mgr.getState(id).?);

    // Receive FIN from peer → closed
    const frame = StreamFrame{ .stream_id = id, .offset = 0, .data = "response", .fin = true };
    _ = mgr.onRecvStream(frame);

    // Stream should be released (closed)
    try std.testing.expect(mgr.getState(id) == null);
    try std.testing.expectEqual(@as(u32, 0), mgr.active_bidi);
}

test "StreamManager: multiple concurrent streams" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id0 = mgr.openBidi() orelse unreachable;
    const id1 = mgr.openBidi() orelse unreachable;
    const id2 = mgr.openBidi() orelse unreachable;

    try std.testing.expectEqual(@as(u62, 0), id0);
    try std.testing.expectEqual(@as(u62, 4), id1);
    try std.testing.expectEqual(@as(u62, 8), id2);
    try std.testing.expectEqual(@as(u32, 3), mgr.active_bidi);

    // Write to different streams
    const op0 = mgr.write(id0, "stream0", false) orelse unreachable;
    const op1 = mgr.write(id1, "stream1", false) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), op0.offset);
    try std.testing.expectEqual(@as(u64, 0), op1.offset);

    // Close stream 1
    _ = mgr.write(id1, "", true);
    const fin_frame = StreamFrame{ .stream_id = id1, .offset = 0, .data = "", .fin = true };
    _ = mgr.onRecvStream(fin_frame);
    try std.testing.expectEqual(@as(u32, 2), mgr.active_bidi);
}

test "StreamManager: MAX_STREAMS updates limit" {
    var mgr = StreamManager.init(false, .{});
    // Start with peer allowing only 1 bidi stream
    mgr.setPeerParams(.{ .initial_max_streams_bidi = 1 });

    _ = mgr.openBidi() orelse unreachable;
    try std.testing.expect(mgr.openBidi() == null);
    try std.testing.expect(mgr.isStreamsBidiBlocked());

    // Receive MAX_STREAMS from peer
    mgr.onMaxStreams(3, true);
    try std.testing.expect(!mgr.isStreamsBidiBlocked());

    _ = mgr.openBidi() orelse unreachable;
    _ = mgr.openBidi() orelse unreachable;
    try std.testing.expectEqual(@as(u32, 3), mgr.active_bidi);
}

test "StreamManager: flow control blocks write" {
    var mgr = StreamManager.init(false, .{});
    // Peer allows only 10 bytes per stream
    mgr.setPeerParams(.{ .initial_max_stream_data_bidi_remote = 10 });

    const id = mgr.openBidi() orelse unreachable;

    // Write 10 bytes → succeeds
    const op1 = mgr.write(id, "0123456789", false);
    try std.testing.expect(op1 != null);

    // Write 1 more byte → flow-blocked
    const op2 = mgr.write(id, "x", false);
    try std.testing.expect(op2 == null);
}

test "StreamManager: onMaxStreamData unblocks" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{ .initial_max_stream_data_bidi_remote = 5 });

    const id = mgr.openBidi() orelse unreachable;
    _ = mgr.write(id, "hello", false);
    try std.testing.expect(mgr.write(id, "x", false) == null);

    // Peer sends MAX_STREAM_DATA
    mgr.onMaxStreamData(id, 100);

    const op = mgr.write(id, " world", false);
    try std.testing.expect(op != null);
}

test "StreamManager: resetStream releases" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;
    try std.testing.expectEqual(@as(u32, 1), mgr.active_bidi);

    mgr.resetStream(id);
    try std.testing.expect(mgr.getState(id) == null);
    try std.testing.expectEqual(@as(u32, 0), mgr.active_bidi);
}

test "encodeMaxStreams/decodeMaxStreams roundtrip" {
    var buf: [16]u8 = undefined;
    const len = encodeMaxStreams(&buf, 42, true) orelse unreachable;
    const decoded = decodeMaxStreams(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 42), decoded.max);
    try std.testing.expect(decoded.bidi);

    const len2 = encodeMaxStreams(&buf, 7, false) orelse unreachable;
    const decoded2 = decodeMaxStreams(buf[0..len2]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 7), decoded2.max);
    try std.testing.expect(!decoded2.bidi);
}

test "encodeStreamsBlocked/decodeStreamsBlocked roundtrip" {
    var buf: [16]u8 = undefined;
    const len = encodeStreamsBlocked(&buf, 100, true) orelse unreachable;
    const decoded = decodeStreamsBlocked(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 100), decoded.max);
    try std.testing.expect(decoded.bidi);
}

test "encodeStreamDataBlocked" {
    var buf: [16]u8 = undefined;
    const len = encodeStreamDataBlocked(&buf, 4, 65536) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u8, 0x15), buf[0]);
}

test "encodeDataBlocked" {
    var buf: [16]u8 = undefined;
    const len = encodeDataBlocked(&buf, 1048576) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u8, 0x14), buf[0]);
}

test "StreamManager: rollbackWrite restores state" {
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    const id = mgr.openBidi() orelse unreachable;
    _ = mgr.write(id, "hello", false); // offset now 5

    // Simulate a write that we need to rollback
    const op = mgr.write(id, "world", true) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 5), op.offset);
    try std.testing.expectEqual(stream_mod.StreamState.half_closed_local, mgr.getState(id).?);

    // Rollback
    mgr.rollbackWrite(op);
    try std.testing.expectEqual(@as(?u64, 5), mgr.getSendOffset(id)); // back to 5
    try std.testing.expectEqual(stream_mod.StreamState.open, mgr.getState(id).?); // state restored
}

test "StreamManager: peer-initiated stream ID validated" {
    // Client-side manager: only server-initiated IDs (odd) accepted from peer
    var mgr = StreamManager.init(false, .{});
    mgr.setPeerParams(.{});

    // Server bidi (id=1) — valid
    const frame_ok = StreamFrame{ .stream_id = 1, .offset = 0, .data = "hi", .fin = false };
    try std.testing.expect(mgr.onRecvStream(frame_ok) != null);

    // Client bidi (id=0) — invalid (we are client, peer can't initiate client streams)
    const frame_bad = StreamFrame{ .stream_id = 0, .offset = 0, .data = "x", .fin = false };
    try std.testing.expect(mgr.onRecvStream(frame_bad) == null);
}

test "StreamManager: uni stream uses correct flow limit" {
    var mgr = StreamManager.init(false, .{ .initial_max_stream_data_uni = 50 });
    mgr.setPeerParams(.{ .initial_max_stream_data_uni = 20 });

    const id = mgr.openUni() orelse unreachable;
    // Should be able to write up to 20 bytes (peer's limit)
    const op = mgr.write(id, "12345678901234567890", false); // exactly 20
    try std.testing.expect(op != null);

    // 21st byte should be blocked
    try std.testing.expect(mgr.write(id, "x", false) == null);
}

test "StreamManager: MAX_STREAMS increments on stream close" {
    var mgr = StreamManager.init(false, .{ .initial_max_streams_bidi = 100 });
    mgr.setPeerParams(.{});

    const initial_max = mgr.local_max_streams_bidi;

    const id = mgr.openBidi() orelse unreachable;
    _ = mgr.write(id, "req", true);

    // Simulate peer FIN
    const frame = StreamFrame{ .stream_id = id, .offset = 0, .data = "resp", .fin = true };
    _ = mgr.onRecvStream(frame);

    // Stream closed → local_max_streams_bidi should have incremented
    try std.testing.expectEqual(initial_max + 1, mgr.local_max_streams_bidi);
    try std.testing.expect(mgr.shouldSendMaxStreamsBidi());
}
