const std = @import("std");
const packet_mod = @import("packet.zig");

/// QUIC transport error codes (RFC 9000 §20.1).
pub const TransportError = enum(u62) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
};

/// CONNECTION_CLOSE frame (RFC 9000 §19.19).
/// Type 0x1c: transport error, includes frame_type field.
/// Type 0x1d: application error, no frame_type field.
pub const ConnectionCloseFrame = struct {
    is_application: bool,
    error_code: u62,
    frame_type: u62, // only for transport errors (type 0x1c)
    reason: []const u8,

    /// Encode a CONNECTION_CLOSE frame into buf. Returns bytes written.
    pub fn encode(self: *const ConnectionCloseFrame, buf: []u8) ?usize {
        var pos: usize = 0;

        // Frame type
        const frame_type_val: u64 = if (self.is_application) 0x1d else 0x1c;
        const ft_len = packet_mod.encodeVarint(buf[pos..], frame_type_val) orelse return null;
        pos += ft_len;

        // Error Code
        const ec_len = packet_mod.encodeVarint(buf[pos..], self.error_code) orelse return null;
        pos += ec_len;

        // Frame Type (only for transport errors)
        if (!self.is_application) {
            const fft_len = packet_mod.encodeVarint(buf[pos..], self.frame_type) orelse return null;
            pos += fft_len;
        }

        // Reason Phrase Length + Reason Phrase
        const rp_len = packet_mod.encodeVarint(buf[pos..], @intCast(self.reason.len)) orelse return null;
        pos += rp_len;

        if (pos + self.reason.len > buf.len) return null;
        @memcpy(buf[pos..][0..self.reason.len], self.reason);
        pos += self.reason.len;

        return pos;
    }

    /// Decode a CONNECTION_CLOSE frame. `data` starts AFTER the frame type byte(s).
    /// `is_application` indicates whether this is type 0x1d (true) or 0x1c (false).
    pub fn decode(data: []const u8, is_application: bool) ?ConnectionCloseFrame {
        var pos: usize = 0;

        // Error Code
        const ec = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += ec.consumed;

        // Frame Type (only for 0x1c)
        var frame_type: u62 = 0;
        if (!is_application) {
            const ft = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += ft.consumed;
            frame_type = @intCast(ft.value);
        }

        // Reason Phrase Length
        const rp_len_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += rp_len_v.consumed;
        const rp_len: usize = @intCast(rp_len_v.value);

        if (pos + rp_len > data.len) return null;
        const reason = data[pos..][0..rp_len];

        return .{
            .is_application = is_application,
            .error_code = @intCast(ec.value),
            .frame_type = frame_type,
            .reason = reason,
        };
    }
};

/// Connection close state machine (RFC 9000 §10).
/// States: open → closing → draining → (timer expiry) → closed
pub const CloseState = enum {
    open,
    closing, // We initiated close; resend CONNECTION_CLOSE on incoming packets
    draining, // Peer initiated close; silent, wait for drain timeout
    closed, // Drain timer expired; connection can be freed
};

/// Connection Close controller.
/// Manages the close/drain lifecycle and caches the CONNECTION_CLOSE frame for retransmission.
pub const CloseController = struct {
    state: CloseState,
    close_frame_buf: [128]u8,
    close_frame_len: usize,
    drain_deadline_us: u64, // when to transition to closed

    pub fn init() CloseController {
        return .{
            .state = .open,
            .close_frame_buf = undefined,
            .close_frame_len = 0,
            .drain_deadline_us = 0,
        };
    }

    /// Initiate connection close (we send CONNECTION_CLOSE).
    /// `pto_us` is the current PTO estimate, used to set drain timer = 3 * PTO.
    pub fn initiateClose(
        self: *CloseController,
        error_code: TransportError,
        frame_type: u62,
        reason: []const u8,
        now_us: u64,
        pto_us: u64,
    ) void {
        if (self.state != .open) return;

        const frame = ConnectionCloseFrame{
            .is_application = false,
            .error_code = @intFromEnum(error_code),
            .frame_type = frame_type,
            .reason = reason,
        };
        self.close_frame_len = frame.encode(&self.close_frame_buf) orelse 0;
        self.state = .closing;
        self.drain_deadline_us = now_us + 3 * pto_us;
    }

    /// Initiate application-level close (H3 GOAWAY, gRPC errors, etc.)
    pub fn initiateAppClose(
        self: *CloseController,
        error_code: u62,
        reason: []const u8,
        now_us: u64,
        pto_us: u64,
    ) void {
        if (self.state != .open) return;

        const frame = ConnectionCloseFrame{
            .is_application = true,
            .error_code = error_code,
            .frame_type = 0,
            .reason = reason,
        };
        self.close_frame_len = frame.encode(&self.close_frame_buf) orelse 0;
        self.state = .closing;
        self.drain_deadline_us = now_us + 3 * pto_us;
    }

    /// Called when we receive a CONNECTION_CLOSE from the peer.
    /// Transitions to draining state (no more packets sent).
    pub fn onPeerClose(self: *CloseController, now_us: u64, pto_us: u64) void {
        switch (self.state) {
            .open => {
                self.state = .draining;
                self.drain_deadline_us = now_us + 3 * pto_us;
            },
            .closing => {
                // Already closing, switch to draining (peer acknowledged)
                self.state = .draining;
            },
            .draining, .closed => {},
        }
    }

    /// Called when a packet is received while in closing state.
    /// Returns the cached CONNECTION_CLOSE frame to retransmit (RFC 9000 §10.2.1).
    pub fn onPacketReceived(self: *const CloseController) ?[]const u8 {
        if (self.state == .closing and self.close_frame_len > 0) {
            return self.close_frame_buf[0..self.close_frame_len];
        }
        return null;
    }

    /// Check if the drain timer has expired. Call periodically.
    pub fn checkTimeout(self: *CloseController, now_us: u64) void {
        switch (self.state) {
            .closing, .draining => {
                if (now_us >= self.drain_deadline_us) {
                    self.state = .closed;
                }
            },
            .open, .closed => {},
        }
    }

    pub fn isClosed(self: *const CloseController) bool {
        return self.state == .closed;
    }

    pub fn isClosing(self: *const CloseController) bool {
        return self.state == .closing or self.state == .draining;
    }

    /// Get the cached close frame payload (for building into a packet).
    pub fn getCloseFrame(self: *const CloseController) ?[]const u8 {
        if (self.close_frame_len > 0) {
            return self.close_frame_buf[0..self.close_frame_len];
        }
        return null;
    }
};

// ─── Tests ───

test "ConnectionCloseFrame: encode transport error" {
    const frame = ConnectionCloseFrame{
        .is_application = false,
        .error_code = @intFromEnum(TransportError.flow_control_error),
        .frame_type = 0x08, // STREAM frame
        .reason = "flow control exceeded",
    };

    var buf: [128]u8 = undefined;
    const len = frame.encode(&buf) orelse unreachable;
    try std.testing.expect(len > 0);

    // First byte should be 0x1c (varint)
    try std.testing.expectEqual(@as(u8, 0x1c), buf[0]);
}

test "ConnectionCloseFrame: encode application error" {
    const frame = ConnectionCloseFrame{
        .is_application = true,
        .error_code = 0x0100, // H3_NO_ERROR
        .frame_type = 0,
        .reason = "",
    };

    var buf: [128]u8 = undefined;
    const len = frame.encode(&buf) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expectEqual(@as(u8, 0x1d), buf[0]);
}

test "ConnectionCloseFrame: encode/decode roundtrip (transport)" {
    const original = ConnectionCloseFrame{
        .is_application = false,
        .error_code = @intFromEnum(TransportError.protocol_violation),
        .frame_type = 0x06, // CRYPTO frame
        .reason = "bad cert",
    };

    var buf: [128]u8 = undefined;
    const len = original.encode(&buf) orelse unreachable;

    // Skip the frame type varint (0x1c = 1 byte)
    const decoded = ConnectionCloseFrame.decode(buf[1..len], false) orelse unreachable;
    try std.testing.expectEqual(original.error_code, decoded.error_code);
    try std.testing.expectEqual(original.frame_type, decoded.frame_type);
    try std.testing.expectEqualSlices(u8, original.reason, decoded.reason);
    try std.testing.expect(!decoded.is_application);
}

test "ConnectionCloseFrame: encode/decode roundtrip (application)" {
    const original = ConnectionCloseFrame{
        .is_application = true,
        .error_code = 0x0107, // H3_EXCESSIVE_LOAD
        .frame_type = 0,
        .reason = "too many requests",
    };

    var buf: [128]u8 = undefined;
    const len = original.encode(&buf) orelse unreachable;

    // Skip frame type varint (0x1d = 1 byte)
    const decoded = ConnectionCloseFrame.decode(buf[1..len], true) orelse unreachable;
    try std.testing.expectEqual(original.error_code, decoded.error_code);
    try std.testing.expectEqualSlices(u8, original.reason, decoded.reason);
    try std.testing.expect(decoded.is_application);
}

test "ConnectionCloseFrame: decode no_error with empty reason" {
    const frame = ConnectionCloseFrame{
        .is_application = false,
        .error_code = 0,
        .frame_type = 0,
        .reason = "",
    };

    var buf: [32]u8 = undefined;
    const len = frame.encode(&buf) orelse unreachable;

    const decoded = ConnectionCloseFrame.decode(buf[1..len], false) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), decoded.error_code);
    try std.testing.expectEqual(@as(u62, 0), decoded.frame_type);
    try std.testing.expectEqual(@as(usize, 0), decoded.reason.len);
}

test "CloseController: init is open" {
    const cc = CloseController.init();
    try std.testing.expectEqual(CloseState.open, cc.state);
    try std.testing.expect(!cc.isClosed());
    try std.testing.expect(!cc.isClosing());
}

test "CloseController: initiateClose transitions to closing" {
    var cc = CloseController.init();
    cc.initiateClose(.no_error, 0, "", 1_000_000, 100_000);

    try std.testing.expectEqual(CloseState.closing, cc.state);
    try std.testing.expect(cc.isClosing());
    try std.testing.expect(!cc.isClosed());
    try std.testing.expectEqual(@as(u64, 1_300_000), cc.drain_deadline_us); // now + 3*pto
    try std.testing.expect(cc.close_frame_len > 0);
}

test "CloseController: initiateAppClose transitions to closing" {
    var cc = CloseController.init();
    cc.initiateAppClose(0x0100, "going away", 2_000_000, 200_000);

    try std.testing.expectEqual(CloseState.closing, cc.state);
    try std.testing.expectEqual(@as(u64, 2_600_000), cc.drain_deadline_us);
    try std.testing.expect(cc.getCloseFrame() != null);
}

test "CloseController: onPacketReceived in closing returns cached frame" {
    var cc = CloseController.init();
    cc.initiateClose(.internal_error, 0, "oops", 1_000_000, 100_000);

    const frame_data = cc.onPacketReceived() orelse unreachable;
    try std.testing.expect(frame_data.len > 0);
    try std.testing.expectEqual(@as(u8, 0x1c), frame_data[0]);
}

test "CloseController: onPacketReceived in open returns null" {
    const cc = CloseController.init();
    try std.testing.expect(cc.onPacketReceived() == null);
}

test "CloseController: onPeerClose transitions to draining" {
    var cc = CloseController.init();
    cc.onPeerClose(1_000_000, 100_000);

    try std.testing.expectEqual(CloseState.draining, cc.state);
    try std.testing.expect(cc.isClosing());
    try std.testing.expectEqual(@as(u64, 1_300_000), cc.drain_deadline_us);
}

test "CloseController: closing → draining on peer close" {
    var cc = CloseController.init();
    cc.initiateClose(.no_error, 0, "", 1_000_000, 100_000);
    try std.testing.expectEqual(CloseState.closing, cc.state);

    cc.onPeerClose(1_050_000, 100_000);
    try std.testing.expectEqual(CloseState.draining, cc.state);
}

test "CloseController: checkTimeout transitions to closed" {
    var cc = CloseController.init();
    cc.initiateClose(.no_error, 0, "", 1_000_000, 100_000);
    // deadline = 1_300_000

    cc.checkTimeout(1_200_000);
    try std.testing.expectEqual(CloseState.closing, cc.state);

    cc.checkTimeout(1_300_000);
    try std.testing.expectEqual(CloseState.closed, cc.state);
    try std.testing.expect(cc.isClosed());
    try std.testing.expect(!cc.isClosing());
}

test "CloseController: draining timeout to closed" {
    var cc = CloseController.init();
    cc.onPeerClose(1_000_000, 200_000);
    // deadline = 1_600_000

    cc.checkTimeout(1_500_000);
    try std.testing.expectEqual(CloseState.draining, cc.state);

    cc.checkTimeout(1_600_000);
    try std.testing.expectEqual(CloseState.closed, cc.state);
}

test "CloseController: double initiate is no-op" {
    var cc = CloseController.init();
    cc.initiateClose(.no_error, 0, "", 1_000_000, 100_000);
    const first_deadline = cc.drain_deadline_us;
    const first_len = cc.close_frame_len;

    // Second call should be ignored
    cc.initiateClose(.internal_error, 0, "second", 2_000_000, 200_000);
    try std.testing.expectEqual(first_deadline, cc.drain_deadline_us);
    try std.testing.expectEqual(first_len, cc.close_frame_len);
}

test "CloseController: no retransmit in draining" {
    var cc = CloseController.init();
    cc.onPeerClose(1_000_000, 100_000);
    try std.testing.expect(cc.onPacketReceived() == null);
}
