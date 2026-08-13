const std = @import("std");
const packet_mod = @import("packet.zig");
const stream_mod = @import("stream.zig");
const loss_mod = @import("loss.zig");
const ack_mod = @import("ack.zig");

/// A buffered STREAM frame awaiting acknowledgment.
/// Retains the payload data so it can be retransmitted if lost.
const SendEntry = struct {
    pn: u64,
    stream_id: u62,
    offset: u64,
    data_buf: [MAX_FRAME_DATA]u8,
    data_len: usize,
    fin: bool,
    in_use: bool,
};

const MAX_FRAME_DATA = 1200;
const MAX_SEND_ENTRIES = 128;

/// Send buffer: holds STREAM frame payloads keyed by packet number.
/// When a PN is ACK'd, its entry is released. When declared lost, it's
/// moved to the retransmit queue.
pub const SendBuffer = struct {
    entries: [MAX_SEND_ENTRIES]SendEntry,
    count: usize,

    pub fn init() SendBuffer {
        var sb: SendBuffer = undefined;
        sb.count = 0;
        for (&sb.entries) |*e| {
            e.in_use = false;
        }
        return sb;
    }

    /// Record a sent STREAM frame. Returns false if buffer is full.
    pub fn record(self: *SendBuffer, pn: u64, stream_id: u62, offset: u64, data: []const u8, fin: bool) bool {
        const slot = self.findFreeSlot() orelse return false;
        const len = @min(data.len, MAX_FRAME_DATA);
        @memcpy(slot.data_buf[0..len], data[0..len]);
        slot.pn = pn;
        slot.stream_id = stream_id;
        slot.offset = offset;
        slot.data_len = len;
        slot.fin = fin;
        slot.in_use = true;
        self.count += 1;
        return true;
    }

    /// Release entries for acknowledged packet numbers.
    pub fn onAck(self: *SendBuffer, acked_pns: []const u64) void {
        for (acked_pns) |pn| {
            self.releaseByPn(pn);
        }
    }

    /// Release a single PN (called when we know it was ACK'd).
    pub fn onAckPn(self: *SendBuffer, pn: u64) void {
        self.releaseByPn(pn);
    }

    /// Release all entries for a range [from, to] inclusive.
    pub fn onAckRange(self: *SendBuffer, from: u64, to: u64) void {
        for (&self.entries) |*e| {
            if (e.in_use and e.pn >= from and e.pn <= to) {
                e.in_use = false;
                if (self.count > 0) self.count -= 1;
            }
        }
    }

    /// Collect lost frames into the retransmit queue.
    /// Called after LossDetector reports lost PNs.
    pub fn onLoss(self: *SendBuffer, lost_pns: []const u64, rtx_queue: *RetransmitQueue) void {
        for (lost_pns) |pn| {
            for (&self.entries) |*e| {
                if (e.in_use and e.pn == pn) {
                    _ = rtx_queue.enqueue(e.stream_id, e.offset, e.data_buf[0..e.data_len], e.fin);
                    e.in_use = false;
                    if (self.count > 0) self.count -= 1;
                    break;
                }
            }
        }
    }

    /// Number of buffered entries.
    pub fn pending(self: *const SendBuffer) usize {
        return self.count;
    }

    fn releaseByPn(self: *SendBuffer, pn: u64) void {
        for (&self.entries) |*e| {
            if (e.in_use and e.pn == pn) {
                e.in_use = false;
                if (self.count > 0) self.count -= 1;
                return;
            }
        }
    }

    fn findFreeSlot(self: *SendBuffer) ?*SendEntry {
        for (&self.entries) |*e| {
            if (!e.in_use) return e;
        }
        return null;
    }
};

/// A frame waiting to be retransmitted.
pub const RetransmitEntry = struct {
    stream_id: u62,
    offset: u64,
    data_buf: [MAX_FRAME_DATA]u8,
    data_len: usize,
    fin: bool,
    in_use: bool,
};

const MAX_RTX_QUEUE = 64;

/// Queue of STREAM frames awaiting retransmission.
pub const RetransmitQueue = struct {
    entries: [MAX_RTX_QUEUE]RetransmitEntry,
    count: usize,

    pub fn init() RetransmitQueue {
        var q: RetransmitQueue = undefined;
        q.count = 0;
        for (&q.entries) |*e| {
            e.in_use = false;
        }
        return q;
    }

    /// Add a frame to the retransmit queue. Returns false if full.
    pub fn enqueue(self: *RetransmitQueue, stream_id: u62, offset: u64, data: []const u8, fin: bool) bool {
        for (&self.entries) |*e| {
            if (!e.in_use) {
                const len = @min(data.len, MAX_FRAME_DATA);
                @memcpy(e.data_buf[0..len], data[0..len]);
                e.stream_id = stream_id;
                e.offset = offset;
                e.data_len = len;
                e.fin = fin;
                e.in_use = true;
                self.count += 1;
                return true;
            }
        }
        return false;
    }

    /// Dequeue the next frame to retransmit. Returns null if empty.
    /// The returned RetransmitFrame owns a copy of the data (safe after slot reuse).
    pub fn dequeue(self: *RetransmitQueue) ?RetransmitFrame {
        for (&self.entries) |*e| {
            if (e.in_use) {
                var frame: RetransmitFrame = undefined;
                frame.stream_id = e.stream_id;
                frame.offset = e.offset;
                frame.data_len = e.data_len;
                @memcpy(frame.data_buf[0..e.data_len], e.data_buf[0..e.data_len]);
                frame.fin = e.fin;
                e.in_use = false;
                if (self.count > 0) self.count -= 1;
                return frame;
            }
        }
        return null;
    }

    /// Check if there are frames pending retransmission.
    pub fn hasPending(self: *const RetransmitQueue) bool {
        return self.count > 0;
    }

    /// Number of pending retransmissions.
    pub fn pending(self: *const RetransmitQueue) usize {
        return self.count;
    }
};

/// A dequeued frame ready for retransmission. Owns a copy of the data.
pub const RetransmitFrame = struct {
    stream_id: u62,
    offset: u64,
    data_buf: [MAX_FRAME_DATA]u8,
    data_len: usize,
    fin: bool,

    pub fn data(self: *const RetransmitFrame) []const u8 {
        return self.data_buf[0..self.data_len];
    }

    /// Encode as a STREAM frame into buf. Returns bytes written.
    pub fn encode(self: *const RetransmitFrame, buf: []u8) ?usize {
        const frame = stream_mod.StreamFrame{
            .stream_id = self.stream_id,
            .offset = self.offset,
            .data = self.data_buf[0..self.data_len],
            .fin = self.fin,
        };
        return frame.encode(buf);
    }
};

/// PTO probe generator.
/// When PTO fires without detected loss, we send a probe packet to elicit ACKs.
pub const ProbeGenerator = struct {
    /// Generate a PING frame (0x01) for PTO probe. Returns 1 byte written.
    pub fn buildPingFrame(buf: []u8) ?usize {
        if (buf.len < 1) return null;
        buf[0] = 0x01; // PING frame
        return 1;
    }

    /// Generate a probe packet from retransmit queue if available,
    /// otherwise generate a PING.
    pub fn buildProbe(rtx_queue: *RetransmitQueue, buf: []u8) ?usize {
        if (rtx_queue.dequeue()) |frame| {
            return frame.encode(buf);
        }
        return buildPingFrame(buf);
    }
};

// ─── Tests ───

test "SendBuffer: record and release on ACK" {
    var sb = SendBuffer.init();
    try std.testing.expectEqual(@as(usize, 0), sb.pending());

    const ok = sb.record(0, 4, 0, "hello world", false);
    try std.testing.expect(ok);
    try std.testing.expectEqual(@as(usize, 1), sb.pending());

    sb.onAckPn(0);
    try std.testing.expectEqual(@as(usize, 0), sb.pending());
}

test "SendBuffer: record multiple, release range" {
    var sb = SendBuffer.init();
    _ = sb.record(0, 4, 0, "data0", false);
    _ = sb.record(1, 4, 5, "data1", false);
    _ = sb.record(2, 4, 10, "data2", false);
    _ = sb.record(3, 4, 15, "data3", true);
    try std.testing.expectEqual(@as(usize, 4), sb.pending());

    sb.onAckRange(0, 2);
    try std.testing.expectEqual(@as(usize, 1), sb.pending());
}

test "SendBuffer: loss moves to retransmit queue" {
    var sb = SendBuffer.init();
    var rtx = RetransmitQueue.init();

    _ = sb.record(0, 4, 0, "hello", false);
    _ = sb.record(1, 4, 5, "world", true);
    try std.testing.expectEqual(@as(usize, 2), sb.pending());

    const lost = [_]u64{0};
    sb.onLoss(&lost, &rtx);

    try std.testing.expectEqual(@as(usize, 1), sb.pending()); // PN 1 still buffered
    try std.testing.expectEqual(@as(usize, 1), rtx.pending());
}

test "SendBuffer: full buffer returns false" {
    var sb = SendBuffer.init();
    var i: u64 = 0;
    while (i < MAX_SEND_ENTRIES) : (i += 1) {
        try std.testing.expect(sb.record(i, 4, i * 10, "x", false));
    }
    try std.testing.expect(!sb.record(MAX_SEND_ENTRIES, 4, 0, "overflow", false));
}

test "RetransmitQueue: enqueue and dequeue" {
    var rtx = RetransmitQueue.init();
    try std.testing.expect(!rtx.hasPending());

    _ = rtx.enqueue(4, 0, "hello", false);
    _ = rtx.enqueue(4, 5, "world", true);
    try std.testing.expectEqual(@as(usize, 2), rtx.pending());

    const frame1 = rtx.dequeue() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 4), frame1.stream_id);
    try std.testing.expectEqual(@as(u64, 0), frame1.offset);
    try std.testing.expectEqualSlices(u8, "hello", frame1.data());
    try std.testing.expect(!frame1.fin);

    const frame2 = rtx.dequeue() orelse unreachable;
    try std.testing.expect(frame2.fin);
    try std.testing.expectEqual(@as(u64, 5), frame2.offset);

    try std.testing.expect(rtx.dequeue() == null);
    try std.testing.expect(!rtx.hasPending());
}

test "RetransmitQueue: full queue returns false" {
    var rtx = RetransmitQueue.init();
    var i: usize = 0;
    while (i < MAX_RTX_QUEUE) : (i += 1) {
        try std.testing.expect(rtx.enqueue(4, @intCast(i * 10), "x", false));
    }
    try std.testing.expect(!rtx.enqueue(4, 999, "overflow", false));
}

test "RetransmitFrame: encode produces valid STREAM frame" {
    var rtx = RetransmitQueue.init();
    _ = rtx.enqueue(4, 100, "retransmit me", true);

    const frame = rtx.dequeue() orelse unreachable;
    var buf: [64]u8 = undefined;
    const len = frame.encode(&buf) orelse unreachable;
    try std.testing.expect(len > 0);

    // Verify it decodes as a STREAM frame
    const decoded = stream_mod.StreamFrame.decode(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 4), decoded.frame.stream_id);
    try std.testing.expectEqual(@as(u64, 100), decoded.frame.offset);
    try std.testing.expectEqualSlices(u8, "retransmit me", decoded.frame.data);
    try std.testing.expect(decoded.frame.fin);
}

test "ProbeGenerator: buildPingFrame" {
    var buf: [4]u8 = undefined;
    const len = ProbeGenerator.buildPingFrame(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "ProbeGenerator: buildProbe uses rtx queue first" {
    var rtx = RetransmitQueue.init();
    _ = rtx.enqueue(0, 0, "probe data", false);

    var buf: [64]u8 = undefined;
    const len = ProbeGenerator.buildProbe(&rtx, &buf) orelse unreachable;
    try std.testing.expect(len > 1); // STREAM frame, not just PING

    // Queue should now be empty
    try std.testing.expect(!rtx.hasPending());
}

test "ProbeGenerator: buildProbe falls back to PING" {
    var rtx = RetransmitQueue.init();
    var buf: [4]u8 = undefined;
    const len = ProbeGenerator.buildProbe(&rtx, &buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "SendBuffer + RetransmitQueue: full cycle" {
    var sb = SendBuffer.init();
    var rtx = RetransmitQueue.init();

    // Send 5 packets
    _ = sb.record(0, 4, 0, "aaa", false);
    _ = sb.record(1, 4, 3, "bbb", false);
    _ = sb.record(2, 4, 6, "ccc", false);
    _ = sb.record(3, 4, 9, "ddd", false);
    _ = sb.record(4, 4, 12, "eee", true);

    // ACK packets 2,3,4
    sb.onAckRange(2, 4);
    try std.testing.expectEqual(@as(usize, 2), sb.pending()); // 0, 1 remain

    // Packets 0, 1 declared lost
    const lost = [_]u64{ 0, 1 };
    sb.onLoss(&lost, &rtx);
    try std.testing.expectEqual(@as(usize, 0), sb.pending());
    try std.testing.expectEqual(@as(usize, 2), rtx.pending());

    // Retransmit both
    const f1 = rtx.dequeue() orelse unreachable;
    try std.testing.expectEqualSlices(u8, "aaa", f1.data());
    const f2 = rtx.dequeue() orelse unreachable;
    try std.testing.expectEqualSlices(u8, "bbb", f2.data());
    try std.testing.expect(!rtx.hasPending());
}

test "SendBuffer: onAck with slice" {
    var sb = SendBuffer.init();
    _ = sb.record(10, 0, 0, "x", false);
    _ = sb.record(11, 0, 1, "y", false);
    _ = sb.record(12, 0, 2, "z", false);

    const acked = [_]u64{ 10, 12 };
    sb.onAck(&acked);
    try std.testing.expectEqual(@as(usize, 1), sb.pending()); // only PN 11 remains
}

test "SendBuffer: release non-existent PN is no-op" {
    var sb = SendBuffer.init();
    _ = sb.record(5, 0, 0, "data", false);
    sb.onAckPn(99); // doesn't exist
    try std.testing.expectEqual(@as(usize, 1), sb.pending());
}
