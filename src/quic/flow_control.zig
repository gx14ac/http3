const std = @import("std");
const packet_mod = @import("packet.zig");
const stream_mod = @import("stream.zig");

/// Default transport parameter values for a QUIC client.
pub const TransportParams = struct {
    initial_max_data: u64 = 1_048_576, // 1 MB
    initial_max_stream_data_bidi_local: u64 = 262_144, // 256 KB
    initial_max_stream_data_bidi_remote: u64 = 262_144,
    initial_max_stream_data_uni: u64 = 262_144,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    max_idle_timeout_ms: u64 = 30_000, // 30 seconds
};

/// Connection-level flow control state.
pub const ConnectionFlowControl = struct {
    // Receive side: tracking how much data we've consumed
    recv_consumed: u64,
    recv_max_advertised: u64,
    recv_window: u64,

    // Send side: respecting peer's limits
    send_offset: u64,
    send_max: u64,

    pub fn init(params: TransportParams) ConnectionFlowControl {
        return .{
            .recv_consumed = 0,
            .recv_max_advertised = params.initial_max_data,
            .recv_window = params.initial_max_data,
            .send_offset = 0,
            .send_max = 0, // Will be set when peer's transport params are received
        };
    }

    /// Set the peer's advertised max_data (from transport parameters or MAX_DATA frame).
    pub fn setPeerMaxData(self: *ConnectionFlowControl, max: u64) void {
        if (max > self.send_max) {
            self.send_max = max;
        }
    }

    /// Check if we can send `len` bytes at the connection level.
    pub fn canSend(self: *const ConnectionFlowControl, len: u64) bool {
        return self.send_offset + len <= self.send_max;
    }

    /// Record that we sent `len` bytes.
    pub fn onSend(self: *ConnectionFlowControl, len: u64) void {
        self.send_offset += len;
    }

    /// Available send budget (bytes remaining before hitting peer's limit).
    pub fn sendBudget(self: *const ConnectionFlowControl) u64 {
        if (self.send_max <= self.send_offset) return 0;
        return self.send_max - self.send_offset;
    }

    /// Record that we received `len` bytes of stream data.
    pub fn onRecv(self: *ConnectionFlowControl, len: u64) void {
        self.recv_consumed += len;
    }

    /// Check if we should send a MAX_DATA update to the peer.
    /// Triggers when consumed > 50% of the window since last advertised.
    pub fn shouldUpdateMaxData(self: *const ConnectionFlowControl) bool {
        const threshold = self.recv_window / 2;
        return self.recv_consumed + threshold > self.recv_max_advertised;
    }

    /// Generate a new MAX_DATA value and mark as advertised.
    pub fn generateMaxData(self: *ConnectionFlowControl) u64 {
        const new_max = self.recv_consumed + self.recv_window;
        self.recv_max_advertised = new_max;
        return new_max;
    }

    /// Build a MAX_DATA frame into buf. Returns bytes written.
    pub fn buildMaxDataFrame(self: *ConnectionFlowControl, buf: []u8) ?usize {
        const new_max = self.generateMaxData();
        const frame = stream_mod.MaxDataFrame{ .maximum_data = new_max };
        return frame.encode(buf);
    }
};

/// Per-stream flow control state.
pub const StreamFlowControl = struct {
    stream_id: u62,

    // Receive side
    recv_consumed: u64,
    recv_max_advertised: u64,
    recv_window: u64,

    // Send side
    send_offset: u64,
    send_max: u64,

    pub fn init(stream_id: u62, initial_max: u64) StreamFlowControl {
        return .{
            .stream_id = stream_id,
            .recv_consumed = 0,
            .recv_max_advertised = initial_max,
            .recv_window = initial_max,
            .send_offset = 0,
            .send_max = 0,
        };
    }

    /// Set the peer's max_stream_data for this stream.
    pub fn setPeerMaxStreamData(self: *StreamFlowControl, max: u64) void {
        if (max > self.send_max) {
            self.send_max = max;
        }
    }

    pub fn canSend(self: *const StreamFlowControl, len: u64) bool {
        return self.send_offset + len <= self.send_max;
    }

    pub fn onSend(self: *StreamFlowControl, len: u64) void {
        self.send_offset += len;
    }

    pub fn sendBudget(self: *const StreamFlowControl) u64 {
        if (self.send_max <= self.send_offset) return 0;
        return self.send_max - self.send_offset;
    }

    pub fn onRecv(self: *StreamFlowControl, len: u64) void {
        self.recv_consumed += len;
    }

    pub fn shouldUpdateMaxStreamData(self: *const StreamFlowControl) bool {
        const threshold = self.recv_window / 2;
        return self.recv_consumed + threshold > self.recv_max_advertised;
    }

    pub fn generateMaxStreamData(self: *StreamFlowControl) u64 {
        const new_max = self.recv_consumed + self.recv_window;
        self.recv_max_advertised = new_max;
        return new_max;
    }

    pub fn buildMaxStreamDataFrame(self: *StreamFlowControl, buf: []u8) ?usize {
        const new_max = self.generateMaxStreamData();
        const frame = stream_mod.MaxStreamDataFrame{
            .stream_id = self.stream_id,
            .maximum_stream_data = new_max,
        };
        return frame.encode(buf);
    }
};

/// Flow control manager: holds connection-level + per-stream state.
/// Fixed-size array for zero-allocation design.
pub const FlowController = struct {
    conn: ConnectionFlowControl,
    streams: [MAX_STREAMS]?StreamFlowControl,
    params: TransportParams,
    peer_params: TransportParams,

    const MAX_STREAMS = 64;

    pub fn init(local_params: TransportParams) FlowController {
        return .{
            .conn = ConnectionFlowControl.init(local_params),
            .streams = [_]?StreamFlowControl{null} ** MAX_STREAMS,
            .params = local_params,
            .peer_params = .{},
        };
    }

    /// Set the peer's transport parameters (received in EncryptedExtensions).
    pub fn setPeerParams(self: *FlowController, peer_params: TransportParams) void {
        self.conn.setPeerMaxData(peer_params.initial_max_data);
        self.peer_params = peer_params;
    }

    /// Open/register a stream with appropriate initial limits.
    pub fn openStream(self: *FlowController, stream_id: u62) ?*StreamFlowControl {
        const slot = self.findSlot(stream_id);
        if (slot) |s| return s;

        // Find empty slot
        for (&self.streams) |*entry| {
            if (entry.* == null) {
                var sfc = StreamFlowControl.init(stream_id, self.params.initial_max_stream_data_bidi_local);
                sfc.send_max = self.peer_params.initial_max_stream_data_bidi_remote;
                entry.* = sfc;
                return &(entry.*.?);
            }
        }
        return null;
    }

    /// Close/release a stream slot for reuse.
    pub fn closeStream(self: *FlowController, stream_id: u62) void {
        for (&self.streams) |*entry| {
            if (entry.*) |sfc| {
                if (sfc.stream_id == stream_id) {
                    entry.* = null;
                    return;
                }
            }
        }
    }

    /// Get flow control for an existing stream.
    pub fn getStream(self: *FlowController, stream_id: u62) ?*StreamFlowControl {
        return self.findSlot(stream_id);
    }

    /// Check if sending `len` bytes on `stream_id` is allowed (both stream + connection level).
    pub fn canSend(self: *const FlowController, stream_id: u62, len: u64) bool {
        if (!self.conn.canSend(len)) return false;
        const sfc = self.findSlotConst(stream_id) orelse return false;
        return sfc.canSend(len);
    }

    /// Record a send of `len` bytes on `stream_id` (updates both levels).
    pub fn onSend(self: *FlowController, stream_id: u62, len: u64) void {
        self.conn.onSend(len);
        if (self.findSlot(stream_id)) |sfc| {
            sfc.onSend(len);
        }
    }

    /// Record receiving `len` bytes on `stream_id` (updates both levels).
    pub fn onRecv(self: *FlowController, stream_id: u62, len: u64) void {
        self.conn.onRecv(len);
        if (self.findSlot(stream_id)) |sfc| {
            sfc.onRecv(len);
        }
    }

    /// Process a received MAX_DATA frame from the peer.
    pub fn onMaxData(self: *FlowController, max: u64) void {
        self.conn.setPeerMaxData(max);
    }

    /// Process a received MAX_STREAM_DATA frame from the peer.
    pub fn onMaxStreamData(self: *FlowController, stream_id: u62, max: u64) void {
        if (self.findSlot(stream_id)) |sfc| {
            sfc.setPeerMaxStreamData(max);
        }
    }

    /// Minimum send budget across connection and stream levels.
    pub fn sendBudget(self: *const FlowController, stream_id: u62) u64 {
        const conn_budget = self.conn.sendBudget();
        const sfc = self.findSlotConst(stream_id) orelse return 0;
        return @min(conn_budget, sfc.sendBudget());
    }

    /// Build any needed flow control frames (MAX_DATA / MAX_STREAM_DATA).
    /// Returns total bytes written to buf.
    pub fn buildFlowControlFrames(self: *FlowController, buf: []u8) usize {
        var pos: usize = 0;

        // Connection-level MAX_DATA
        if (self.conn.shouldUpdateMaxData()) {
            if (self.conn.buildMaxDataFrame(buf[pos..])) |len| {
                pos += len;
            }
        }

        // Per-stream MAX_STREAM_DATA
        for (&self.streams) |*entry| {
            if (entry.*) |*sfc| {
                if (sfc.shouldUpdateMaxStreamData()) {
                    if (sfc.buildMaxStreamDataFrame(buf[pos..])) |len| {
                        pos += len;
                    }
                }
            }
        }

        return pos;
    }

    fn findSlot(self: *FlowController, stream_id: u62) ?*StreamFlowControl {
        for (&self.streams) |*entry| {
            if (entry.*) |*sfc| {
                if (sfc.stream_id == stream_id) return sfc;
            }
        }
        return null;
    }

    fn findSlotConst(self: *const FlowController, stream_id: u62) ?*const StreamFlowControl {
        for (&self.streams) |*entry| {
            if (entry.*) |*sfc| {
                if (sfc.stream_id == stream_id) return sfc;
            }
        }
        return null;
    }
};

// ─── Tests ───

test "ConnectionFlowControl: send gating" {
    var fc = ConnectionFlowControl.init(.{ .initial_max_data = 1000 });
    fc.setPeerMaxData(500);
    try std.testing.expect(fc.canSend(500));
    try std.testing.expect(!fc.canSend(501));
    try std.testing.expectEqual(@as(u64, 500), fc.sendBudget());

    fc.onSend(300);
    try std.testing.expectEqual(@as(u64, 200), fc.sendBudget());
    try std.testing.expect(!fc.canSend(201));
    try std.testing.expect(fc.canSend(200));
}

test "ConnectionFlowControl: MAX_DATA generation" {
    var fc = ConnectionFlowControl.init(.{ .initial_max_data = 1000 });
    // Initially no update needed
    try std.testing.expect(!fc.shouldUpdateMaxData());

    // Consume >50% of window
    fc.onRecv(600);
    try std.testing.expect(fc.shouldUpdateMaxData());

    // Generate new MAX_DATA
    const new_max = fc.generateMaxData();
    try std.testing.expectEqual(@as(u64, 1600), new_max); // consumed + window

    // After advertising, no longer needs update
    try std.testing.expect(!fc.shouldUpdateMaxData());
}

test "ConnectionFlowControl: buildMaxDataFrame" {
    var fc = ConnectionFlowControl.init(.{ .initial_max_data = 1000 });
    fc.onRecv(600);

    var buf: [16]u8 = undefined;
    const len = fc.buildMaxDataFrame(&buf) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u8, 0x10), buf[0]); // MAX_DATA type
}

test "StreamFlowControl: send gating" {
    var sfc = StreamFlowControl.init(0, 1000);
    sfc.setPeerMaxStreamData(256);
    try std.testing.expect(sfc.canSend(256));
    try std.testing.expect(!sfc.canSend(257));

    sfc.onSend(100);
    try std.testing.expectEqual(@as(u64, 156), sfc.sendBudget());
}

test "StreamFlowControl: MAX_STREAM_DATA generation" {
    var sfc = StreamFlowControl.init(4, 1000);
    sfc.onRecv(600);
    try std.testing.expect(sfc.shouldUpdateMaxStreamData());

    var buf: [16]u8 = undefined;
    const len = sfc.buildMaxStreamDataFrame(&buf) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u8, 0x11), buf[0]); // MAX_STREAM_DATA type
}

test "FlowController: init and open stream" {
    var fc = FlowController.init(.{});
    const sfc = fc.openStream(0) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), sfc.stream_id);

    // Opening same stream returns same slot
    const sfc2 = fc.openStream(0) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), sfc2.stream_id);
}

test "FlowController: canSend checks both levels" {
    var fc = FlowController.init(.{ .initial_max_data = 1000 });
    fc.setPeerParams(.{ .initial_max_data = 500, .initial_max_stream_data_bidi_remote = 200 });

    _ = fc.openStream(0) orelse unreachable;

    // Stream limit is tighter (200 < 500)
    try std.testing.expect(fc.canSend(0, 200));
    try std.testing.expect(!fc.canSend(0, 201));
    try std.testing.expectEqual(@as(u64, 200), fc.sendBudget(0));
}

test "FlowController: onSend updates both levels" {
    var fc = FlowController.init(.{ .initial_max_data = 1000 });
    fc.setPeerParams(.{ .initial_max_data = 1000 });

    const sfc = fc.openStream(4) orelse unreachable;
    sfc.setPeerMaxStreamData(1000);

    fc.onSend(4, 300);
    try std.testing.expectEqual(@as(u64, 700), fc.conn.sendBudget());
    try std.testing.expectEqual(@as(u64, 700), fc.sendBudget(4));
}

test "FlowController: onRecv and flow control updates" {
    var fc = FlowController.init(.{ .initial_max_data = 1000, .initial_max_stream_data_bidi_local = 1000 });
    _ = fc.openStream(0);

    fc.onRecv(0, 600);
    try std.testing.expect(fc.conn.shouldUpdateMaxData());
}

test "FlowController: onMaxData from peer" {
    var fc = FlowController.init(.{});
    try std.testing.expectEqual(@as(u64, 0), fc.conn.sendBudget());
    fc.onMaxData(5000);
    try std.testing.expectEqual(@as(u64, 5000), fc.conn.sendBudget());
}

test "FlowController: onMaxStreamData from peer" {
    var fc = FlowController.init(.{});
    fc.setPeerParams(.{ .initial_max_stream_data_bidi_remote = 0 });
    const sfc = fc.openStream(0) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), sfc.sendBudget());
    fc.onMaxStreamData(0, 2000);
    try std.testing.expectEqual(@as(u64, 2000), sfc.sendBudget());
}

test "FlowController: buildFlowControlFrames" {
    var fc = FlowController.init(.{ .initial_max_data = 1000, .initial_max_stream_data_bidi_local = 500 });
    _ = fc.openStream(0);

    fc.onRecv(0, 600); // Triggers both conn and stream updates

    var buf: [64]u8 = undefined;
    const len = fc.buildFlowControlFrames(&buf);
    try std.testing.expect(len > 0);
    // Should contain at least MAX_DATA (0x10)
    try std.testing.expectEqual(@as(u8, 0x10), buf[0]);
}

test "FlowController: unknown stream returns false/0" {
    const fc = FlowController.init(.{});
    try std.testing.expect(!fc.canSend(99, 1));
    try std.testing.expectEqual(@as(u64, 0), fc.sendBudget(99));
}

test "FlowController: setPeerParams updates conn max" {
    var fc = FlowController.init(.{});
    try std.testing.expectEqual(@as(u64, 0), fc.conn.sendBudget());
    fc.setPeerParams(.{ .initial_max_data = 65536 });
    try std.testing.expectEqual(@as(u64, 65536), fc.conn.sendBudget());
}

test "FlowController: setPeerParams initializes stream send_max on openStream" {
    var fc = FlowController.init(.{});
    fc.setPeerParams(.{ .initial_max_data = 100000, .initial_max_stream_data_bidi_remote = 32768 });

    const sfc = fc.openStream(4) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 32768), sfc.send_max);
    try std.testing.expect(sfc.canSend(32768));
    try std.testing.expect(!sfc.canSend(32769));
}

test "FlowController: closeStream frees slot for reuse" {
    var fc = FlowController.init(.{});
    fc.setPeerParams(.{ .initial_max_data = 100000, .initial_max_stream_data_bidi_remote = 1000 });

    // Open a stream
    const sfc = fc.openStream(0) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), sfc.stream_id);

    // Close it
    fc.closeStream(0);

    // Slot is freed — getStream returns null
    try std.testing.expect(fc.getStream(0) == null);

    // Can reuse the slot with a new stream
    const sfc2 = fc.openStream(4) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 4), sfc2.stream_id);
    try std.testing.expectEqual(@as(u64, 1000), sfc2.send_max);
}
