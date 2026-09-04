const std = @import("std");
const frame = @import("frame.zig");

/// Stream states per RFC 9113 §5.1
pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Reason a stream was closed
pub const CloseReason = enum {
    normal,
    reset_local,
    reset_remote,
    refused,
};

/// Per-stream flow control window (RFC 9113 §6.9.1)
pub const FlowWindow = struct {
    size: i32,

    pub fn init(initial_size: u32) FlowWindow {
        return .{ .size = @intCast(initial_size) };
    }

    pub fn consume(self: *FlowWindow, amount: u32) error{FlowControlError}!void {
        const current = @atomicLoad(i32, &self.size, .acquire);
        const new = current - @as(i32, @intCast(amount));
        if (new < 0) return error.FlowControlError;
        _ = @atomicRmw(i32, &self.size, .Sub, @as(i32, @intCast(amount)), .release);
    }

    pub fn credit(self: *FlowWindow, increment: u31) error{FlowControlError}!void {
        const current = @atomicLoad(i32, &self.size, .acquire);
        const new = @as(i64, current) + @as(i64, increment);
        if (new > 0x7FFFFFFF) return error.FlowControlError;
        _ = @atomicRmw(i32, &self.size, .Add, @as(i32, increment), .release);
    }

    pub fn available(self: FlowWindow) u32 {
        if (self.size <= 0) return 0;
        return @intCast(self.size);
    }

    pub fn updateInitialSize(self: *FlowWindow, old_initial: u32, new_initial: u32) error{FlowControlError}!void {
        const delta = @as(i64, new_initial) - @as(i64, old_initial);
        const current = @atomicLoad(i32, &self.size, .acquire);
        const new = @as(i64, current) + delta;
        if (new > 0x7FFFFFFF or new < -0x80000000) return error.FlowControlError;
        const delta_i32: i32 = @intCast(delta);
        _ = @atomicRmw(i32, &self.size, .Add, delta_i32, .release);
    }
};

/// Single HTTP/2 stream
pub const Stream = struct {
    id: u31,
    state: State,
    send_window: FlowWindow,
    recv_window: FlowWindow,
    recv_window_consumed: u32,
    close_reason: ?CloseReason,

    pub fn init(id: u31, initial_send_window: u32, initial_recv_window: u32) Stream {
        return .{
            .id = id,
            .state = .idle,
            .send_window = FlowWindow.init(initial_send_window),
            .recv_window = FlowWindow.init(initial_recv_window),
            .recv_window_consumed = 0,
            .close_reason = null,
        };
    }

    pub fn sendHeaders(self: *Stream, end_stream: bool) Error!void {
        switch (self.state) {
            .idle => {
                self.state = if (end_stream) .half_closed_local else .open;
            },
            .reserved_local => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                } else {
                    self.state = .half_closed_remote;
                }
            },
            .open => {
                if (end_stream) self.state = .half_closed_local;
            },
            .half_closed_remote => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                }
            },
            else => return Error.StreamClosed,
        }
    }

    pub fn recvHeaders(self: *Stream, end_stream: bool) Error!void {
        switch (self.state) {
            .idle => {
                self.state = if (end_stream) .half_closed_remote else .open;
            },
            .reserved_remote => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                } else {
                    self.state = .half_closed_local;
                }
            },
            .open => {
                if (end_stream) self.state = .half_closed_remote;
            },
            .half_closed_local => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                }
            },
            else => return Error.StreamClosed,
        }
    }

    pub fn sendData(self: *Stream, length: u32, end_stream: bool) Error!void {
        switch (self.state) {
            .open, .half_closed_remote => {},
            else => return Error.StreamClosed,
        }
        self.send_window.consume(length) catch return Error.FlowControlError;
        switch (self.state) {
            .open => {
                if (end_stream) self.state = .half_closed_local;
            },
            .half_closed_remote => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                }
            },
            else => unreachable,
        }
    }

    pub fn recvData(self: *Stream, length: u32, end_stream: bool) Error!void {
        switch (self.state) {
            .open, .half_closed_local => {},
            else => return Error.StreamClosed,
        }
        self.recv_window.consume(length) catch return Error.FlowControlError;
        self.recv_window_consumed += length;
        switch (self.state) {
            .open => {
                if (end_stream) self.state = .half_closed_remote;
            },
            .half_closed_local => {
                if (end_stream) {
                    self.state = .closed;
                    self.close_reason = .normal;
                }
            },
            else => unreachable,
        }
    }

    pub fn sendReset(self: *Stream, _: frame.ErrorCode) void {
        self.state = .closed;
        self.close_reason = .reset_local;
    }

    pub fn recvReset(self: *Stream) void {
        self.state = .closed;
        self.close_reason = .reset_remote;
    }

    pub fn recvWindowUpdate(self: *Stream, increment: u31) Error!void {
        if (self.state == .idle) return Error.ProtocolError;
        if (self.state == .closed) return Error.StreamClosed;
        self.send_window.credit(increment) catch return Error.FlowControlError;
    }

    /// Returns WINDOW_UPDATE increment if threshold exceeded, 0 otherwise.
    pub fn shouldSendWindowUpdate(self: Stream, threshold: u32) u31 {
        if (self.recv_window_consumed >= threshold) {
            return @intCast(self.recv_window_consumed);
        }
        return 0;
    }

    pub fn ackWindowUpdate(self: *Stream) void {
        const consumed = self.recv_window_consumed;
        self.recv_window.size += @intCast(consumed);
        self.recv_window_consumed = 0;
    }

    pub fn isClosed(self: Stream) bool {
        return self.state == .closed;
    }

    pub const Error = error{
        StreamClosed,
        FlowControlError,
        ProtocolError,
    };
};

/// Connection-level flow control
pub const ConnectionFlowControl = struct {
    send_window: FlowWindow,
    recv_window: FlowWindow,
    recv_window_consumed: u32,
    auto_update_threshold: u32,

    pub fn init(initial_window_size: u32) ConnectionFlowControl {
        return .{
            .send_window = FlowWindow.init(initial_window_size),
            .recv_window = FlowWindow.init(initial_window_size),
            .recv_window_consumed = 0,
            .auto_update_threshold = initial_window_size / 2,
        };
    }

    pub fn consumeSend(self: *ConnectionFlowControl, amount: u32) error{FlowControlError}!void {
        return self.send_window.consume(amount);
    }

    pub fn consumeRecv(self: *ConnectionFlowControl, amount: u32) error{FlowControlError}!void {
        self.recv_window.consume(amount) catch return error.FlowControlError;
        self.recv_window_consumed += amount;
    }

    pub fn creditSend(self: *ConnectionFlowControl, increment: u31) error{FlowControlError}!void {
        return self.send_window.credit(increment);
    }

    pub fn shouldSendWindowUpdate(self: ConnectionFlowControl) u31 {
        if (self.recv_window_consumed >= self.auto_update_threshold) {
            return @intCast(self.recv_window_consumed);
        }
        return 0;
    }

    pub fn ackWindowUpdate(self: *ConnectionFlowControl) void {
        const consumed = self.recv_window_consumed;
        self.recv_window.size += @intCast(consumed);
        self.recv_window_consumed = 0;
    }

    pub fn availableSend(self: ConnectionFlowControl) u32 {
        return self.send_window.available();
    }
};

/// Manages all active streams on a connection.
/// Uses a slot array with an id→slot index for O(1) lookup by stream ID.
pub const StreamMap = struct {
    streams: [max_streams]?Stream,
    id_to_slot: [max_streams]u16,
    id_count: usize,
    count: u32,
    max_concurrent: u32,
    next_stream_id: u31,

    const max_streams = 256;
    const empty_slot: u16 = std.math.maxInt(u16);

    pub fn init(max_concurrent: u32) StreamMap {
        return .{
            .streams = .{null} ** max_streams,
            .id_to_slot = .{empty_slot} ** max_streams,
            .id_count = 0,
            .count = 0,
            .max_concurrent = max_concurrent,
            .next_stream_id = 1,
        };
    }

    pub fn openStream(self: *StreamMap, initial_send_window: u32, initial_recv_window: u32) Error!*Stream {
        if (self.count >= self.max_concurrent) return Error.MaxConcurrentStreams;
        if (self.count >= max_streams) return Error.MaxConcurrentStreams;

        const id = self.next_stream_id;
        if (id == 0) return Error.StreamIdExhausted;

        const slot = self.findFreeSlot() orelse return Error.MaxConcurrentStreams;
        self.streams[slot] = Stream.init(id, initial_send_window, initial_recv_window);
        self.count += 1;

        // Index: map id → slot for O(1) lookup
        if (self.id_count < max_streams) {
            self.id_to_slot[self.id_count] = @intCast(slot);
            self.id_count += 1;
        }

        const next = @as(u32, id) + 2;
        self.next_stream_id = if (next <= 0x7FFFFFFF) @intCast(next) else 0;

        return &(self.streams[slot].?);
    }

    pub fn get(self: *StreamMap, id: u31) ?*Stream {
        // Fast path: check indexed slots first (covers all streams opened via openStream)
        for (self.id_to_slot[0..self.id_count]) |slot_idx| {
            if (slot_idx == empty_slot) continue;
            if (self.streams[slot_idx]) |*s| {
                if (s.id == id) return s;
            }
        }
        return null;
    }

    pub fn removeClosedStreams(self: *StreamMap) void {
        for (&self.streams) |*slot| {
            if (slot.*) |s| {
                if (s.state == .closed) {
                    slot.* = null;
                    self.count -= 1;
                }
            }
        }
        // Rebuild index
        self.id_count = 0;
        for (self.streams, 0..) |slot, i| {
            if (slot != null) {
                self.id_to_slot[self.id_count] = @intCast(i);
                self.id_count += 1;
            }
        }
    }

    pub fn activeCount(self: StreamMap) u32 {
        return self.count;
    }

    pub fn updateInitialWindowSize(self: *StreamMap, old_size: u32, new_size: u32) error{FlowControlError}!void {
        for (self.id_to_slot[0..self.id_count]) |slot_idx| {
            if (slot_idx == empty_slot) continue;
            if (self.streams[slot_idx]) |*s| {
                if (s.state != .closed) {
                    s.send_window.updateInitialSize(old_size, new_size) catch return error.FlowControlError;
                }
            }
        }
    }

    fn findFreeSlot(self: *StreamMap) ?usize {
        for (self.streams, 0..) |slot, i| {
            if (slot == null) return i;
        }
        return null;
    }

    pub const Error = error{
        MaxConcurrentStreams,
        StreamIdExhausted,
    };
};

// ─── Tests ───

test "stream lifecycle: idle → open → half_closed_local → closed" {
    var s = Stream.init(1, 65535, 65535);
    try std.testing.expectEqual(State.idle, s.state);

    try s.sendHeaders(false);
    try std.testing.expectEqual(State.open, s.state);

    try s.sendData(100, true);
    try std.testing.expectEqual(State.half_closed_local, s.state);

    try s.recvHeaders(true);
    try std.testing.expectEqual(State.closed, s.state);
    try std.testing.expectEqual(CloseReason.normal, s.close_reason.?);
}

test "stream lifecycle: idle → open → half_closed_remote → closed" {
    var s = Stream.init(1, 65535, 65535);

    try s.recvHeaders(false);
    try std.testing.expectEqual(State.open, s.state);

    try s.recvData(50, true);
    try std.testing.expectEqual(State.half_closed_remote, s.state);

    try s.sendHeaders(true);
    try std.testing.expectEqual(State.closed, s.state);
}

test "stream RST_STREAM" {
    var s = Stream.init(1, 65535, 65535);
    try s.sendHeaders(false);

    s.sendReset(.cancel);
    try std.testing.expectEqual(State.closed, s.state);
    try std.testing.expectEqual(CloseReason.reset_local, s.close_reason.?);
}

test "stream recv RST_STREAM" {
    var s = Stream.init(1, 65535, 65535);
    try s.sendHeaders(false);

    s.recvReset();
    try std.testing.expectEqual(State.closed, s.state);
    try std.testing.expectEqual(CloseReason.reset_remote, s.close_reason.?);
}

test "stream rejects send on closed" {
    var s = Stream.init(1, 65535, 65535);
    s.state = .closed;

    try std.testing.expectError(Stream.Error.StreamClosed, s.sendHeaders(false));
    try std.testing.expectError(Stream.Error.StreamClosed, s.sendData(0, false));
}

test "FlowWindow basic operations" {
    var w = FlowWindow.init(65535);
    try std.testing.expectEqual(@as(u32, 65535), w.available());

    try w.consume(1000);
    try std.testing.expectEqual(@as(u32, 64535), w.available());

    try w.credit(500);
    try std.testing.expectEqual(@as(u32, 65035), w.available());
}

test "FlowWindow rejects over-consumption" {
    var w = FlowWindow.init(100);
    try std.testing.expectError(error.FlowControlError, w.consume(101));
}

test "FlowWindow rejects overflow on credit" {
    var w = FlowWindow.init(0x7FFFFFFF);
    try std.testing.expectError(error.FlowControlError, w.credit(1));
}

test "FlowWindow updateInitialSize" {
    var w = FlowWindow.init(65535);
    try w.consume(1000);
    try std.testing.expectEqual(@as(u32, 64535), w.available());

    try w.updateInitialSize(65535, 131072);
    try std.testing.expectEqual(@as(u32, 130072), w.available());
}

test "ConnectionFlowControl auto window update" {
    var cfc = ConnectionFlowControl.init(65535);
    try std.testing.expectEqual(@as(u31, 0), cfc.shouldSendWindowUpdate());

    try cfc.consumeRecv(40000);
    try std.testing.expect(cfc.shouldSendWindowUpdate() > 0);

    cfc.ackWindowUpdate();
    try std.testing.expectEqual(@as(u31, 0), cfc.shouldSendWindowUpdate());
    try std.testing.expectEqual(@as(u32, 65535), cfc.recv_window.available());
}

test "StreamMap open and get" {
    var sm = StreamMap.init(100);
    const s = try sm.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 1), s.id);
    try std.testing.expectEqual(State.idle, s.state);
    try std.testing.expectEqual(@as(u32, 1), sm.activeCount());

    // Transition to open via sendHeaders (RFC 9113 §5.1)
    try s.sendHeaders(false);
    try std.testing.expectEqual(State.open, s.state);

    const found = sm.get(1).?;
    try std.testing.expectEqual(@as(u31, 1), found.id);
}

test "StreamMap max concurrent streams" {
    var sm = StreamMap.init(2);
    _ = try sm.openStream(65535, 65535);
    _ = try sm.openStream(65535, 65535);
    try std.testing.expectError(StreamMap.Error.MaxConcurrentStreams, sm.openStream(65535, 65535));
}

test "StreamMap removeClosedStreams" {
    var sm = StreamMap.init(100);
    const s = try sm.openStream(65535, 65535);
    s.sendReset(.cancel);
    try std.testing.expectEqual(@as(u32, 1), sm.activeCount());

    sm.removeClosedStreams();
    try std.testing.expectEqual(@as(u32, 0), sm.activeCount());
}

test "StreamMap stream IDs are odd and incrementing" {
    var sm = StreamMap.init(100);
    const s1 = try sm.openStream(65535, 65535);
    const s2 = try sm.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 1), s1.id);
    try std.testing.expectEqual(@as(u31, 3), s2.id);
}

test "StreamMap updateInitialWindowSize" {
    var sm = StreamMap.init(100);
    const s = try sm.openStream(65535, 65535);
    try s.send_window.consume(1000);

    try sm.updateInitialWindowSize(65535, 131072);
    try std.testing.expectEqual(@as(u32, 130072), s.send_window.available());
}

test "stream WINDOW_UPDATE on idle is protocol error" {
    var s = Stream.init(1, 65535, 65535);
    try std.testing.expectError(Stream.Error.ProtocolError, s.recvWindowUpdate(100));
}

test "stream shouldSendWindowUpdate threshold" {
    var s = Stream.init(1, 65535, 65535);
    s.state = .open;
    try s.recvData(30000, false);

    const threshold: u32 = 32768;
    try std.testing.expectEqual(@as(u31, 0), s.shouldSendWindowUpdate(threshold));

    try s.recvData(5000, false);
    try std.testing.expect(s.shouldSendWindowUpdate(threshold) > 0);

    s.ackWindowUpdate();
    try std.testing.expectEqual(@as(u31, 0), s.shouldSendWindowUpdate(threshold));
    try std.testing.expectEqual(@as(u32, 65535), s.recv_window.available());
}
