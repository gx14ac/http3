const std = @import("std");
const packet_mod = @import("packet.zig");
const ecn_mod = @import("ecn.zig");

/// Tracks received packet numbers and generates ACK frames.
/// Maintains up to MAX_RANGES contiguous ranges of received PNs.
pub const AckTracker = struct {
    ranges: [MAX_RANGES]PnRange,
    range_count: usize,
    largest_recv_time: u64,
    largest_pn: ?u64,

    const MAX_RANGES = 32;

    pub const PnRange = struct {
        start: u64,
        end: u64, // inclusive
    };

    pub fn init() AckTracker {
        return .{
            .ranges = undefined,
            .range_count = 0,
            .largest_recv_time = 0,
            .largest_pn = null,
        };
    }

    /// Record a received packet number.
    /// `recv_time_us` is the receive timestamp in microseconds (for ack_delay).
    pub fn recordPacket(self: *AckTracker, pn: u64, recv_time_us: u64) void {
        if (self.largest_pn == null or pn > self.largest_pn.?) {
            self.largest_pn = pn;
            self.largest_recv_time = recv_time_us;
        }
        self.insertPn(pn);
    }

    /// Returns the largest acknowledged PN, or null if empty.
    pub fn largestAcked(self: *const AckTracker) ?u64 {
        return self.largest_pn;
    }

    /// Returns true if there are packets to acknowledge.
    pub fn hasPending(self: *const AckTracker) bool {
        return self.range_count > 0;
    }

    /// Build an ACK frame into buf.
    /// `now_us` is the current time in microseconds.
    /// Returns bytes written.
    pub fn buildAckFrame(self: *const AckTracker, buf: []u8, now_us: u64) ?usize {
        if (self.range_count == 0) return null;

        // Sort ranges descending by end (largest first)
        var sorted: [MAX_RANGES]PnRange = undefined;
        @memcpy(sorted[0..self.range_count], self.ranges[0..self.range_count]);
        sortRangesDesc(sorted[0..self.range_count]);

        var pos: usize = 0;

        // Frame type: 0x02 (ACK without ECN)
        if (buf.len < 1) return null;
        buf[pos] = 0x02;
        pos += 1;

        // Largest Acknowledged
        const largest = sorted[0].end;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(largest)) orelse return null;

        // ACK Delay: microseconds / 2^ack_delay_exponent. Must match server's
        // ack_delay_exponent transport parameter (default=3, RFC 9000 §18.2).
        const delay_us = if (now_us > self.largest_recv_time) now_us - self.largest_recv_time else 0;
        const ack_delay = delay_us / 8;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(ack_delay)) orelse return null;

        // ACK Range Count (number of gap+range pairs after the first range)
        const range_count: usize = if (self.range_count > 0) self.range_count - 1 else 0;
        pos += packet_mod.encodeVarint(buf[pos..], range_count) orelse return null;

        // First ACK Range (largest - smallest in first contiguous range)
        const first_range = sorted[0].end - sorted[0].start;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(first_range)) orelse return null;

        // Additional ranges: gap + ack_range pairs
        var i: usize = 1;
        while (i < self.range_count) : (i += 1) {
            // RFC 9000 §19.3.1: gap = previous_smallest - current_largest - 2
            const prev_start = sorted[i - 1].start;
            const curr_end = sorted[i].end;
            if (prev_start <= curr_end + 1) break;
            const gap = prev_start - curr_end - 2;
            pos += packet_mod.encodeVarint(buf[pos..], @intCast(gap)) orelse return null;

            // ACK Range = end - start of this range
            const ack_range = sorted[i].end - sorted[i].start;
            pos += packet_mod.encodeVarint(buf[pos..], @intCast(ack_range)) orelse return null;
        }

        return pos;
    }

    /// Build an ACK_ECN frame (type 0x03) into buf.
    /// Like buildAckFrame but appends ECN counts at the end.
    pub fn buildAckEcnFrame(self: *const AckTracker, buf: []u8, now_us: u64, ecn_counts: ecn_mod.EcnCounts) ?usize {
        if (self.range_count == 0) return null;

        var sorted: [MAX_RANGES]PnRange = undefined;
        @memcpy(sorted[0..self.range_count], self.ranges[0..self.range_count]);
        sortRangesDesc(sorted[0..self.range_count]);

        var pos: usize = 0;

        // Frame type: 0x03 (ACK with ECN)
        if (buf.len < 1) return null;
        buf[pos] = 0x03;
        pos += 1;

        // Largest Acknowledged
        const largest = sorted[0].end;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(largest)) orelse return null;

        // ACK Delay
        const delay_us = if (now_us > self.largest_recv_time) now_us - self.largest_recv_time else 0;
        const ack_delay = delay_us / 8;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(ack_delay)) orelse return null;

        // ACK Range Count
        const range_count: usize = if (self.range_count > 0) self.range_count - 1 else 0;
        pos += packet_mod.encodeVarint(buf[pos..], range_count) orelse return null;

        // First ACK Range
        const first_range = sorted[0].end - sorted[0].start;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(first_range)) orelse return null;

        // Additional ranges
        var i: usize = 1;
        while (i < self.range_count) : (i += 1) {
            const prev_start = sorted[i - 1].start;
            const curr_end = sorted[i].end;
            if (prev_start <= curr_end + 1) break;
            const gap = prev_start - curr_end - 2;
            pos += packet_mod.encodeVarint(buf[pos..], @intCast(gap)) orelse return null;
            const ack_range = sorted[i].end - sorted[i].start;
            pos += packet_mod.encodeVarint(buf[pos..], @intCast(ack_range)) orelse return null;
        }

        // ECN counts (RFC 9000 §19.3.2)
        pos += packet_mod.encodeVarint(buf[pos..], ecn_counts.ect0) orelse return null;
        pos += packet_mod.encodeVarint(buf[pos..], ecn_counts.ect1) orelse return null;
        pos += packet_mod.encodeVarint(buf[pos..], ecn_counts.ce) orelse return null;

        return pos;
    }

    // TODO: On ACK loss, peer will retransmit. Need "ACK of ACK" tracking
    // to only remove ranges the peer has confirmed (RFC 9000 §13.2.3).
    pub fn clear(self: *AckTracker) void {
        self.range_count = 0;
        self.largest_pn = null;
    }

    fn insertPn(self: *AckTracker, pn: u64) void {
        // Try to extend an existing range
        for (self.ranges[0..self.range_count]) |*r| {
            if (pn >= r.start and pn <= r.end) return; // already tracked
            if (pn == r.end + 1) {
                r.end = pn;
                self.mergeAdjacentRanges();
                return;
            }
            if (pn + 1 == r.start) {
                r.start = pn;
                self.mergeAdjacentRanges();
                return;
            }
        }

        // New isolated PN — create new range
        if (self.range_count < MAX_RANGES) {
            self.ranges[self.range_count] = .{ .start = pn, .end = pn };
            self.range_count += 1;
        } else {
            // Drop smallest range to make room
            var min_idx: usize = 0;
            var min_start: u64 = self.ranges[0].start;
            for (1..self.range_count) |idx| {
                if (self.ranges[idx].start < min_start) {
                    min_start = self.ranges[idx].start;
                    min_idx = idx;
                }
            }
            self.ranges[min_idx] = .{ .start = pn, .end = pn };
        }
    }

    fn mergeAdjacentRanges(self: *AckTracker) void {
        if (self.range_count < 2) return;

        var merged = true;
        while (merged) {
            merged = false;
            var i: usize = 0;
            while (i < self.range_count) : (i += 1) {
                var j: usize = i + 1;
                while (j < self.range_count) {
                    if (self.ranges[i].end + 1 >= self.ranges[j].start and
                        self.ranges[j].end + 1 >= self.ranges[i].start)
                    {
                        // Merge j into i
                        self.ranges[i].start = @min(self.ranges[i].start, self.ranges[j].start);
                        self.ranges[i].end = @max(self.ranges[i].end, self.ranges[j].end);
                        // Remove j
                        self.range_count -= 1;
                        if (j < self.range_count) {
                            self.ranges[j] = self.ranges[self.range_count];
                        }
                        merged = true;
                    } else {
                        j += 1;
                    }
                }
            }
        }
    }

    fn sortRangesDesc(ranges: []PnRange) void {
        // Simple insertion sort (MAX_RANGES is small)
        for (1..ranges.len) |i| {
            const key = ranges[i];
            var j: usize = i;
            while (j > 0 and ranges[j - 1].end < key.end) {
                ranges[j] = ranges[j - 1];
                j -= 1;
            }
            ranges[j] = key;
        }
    }
};

/// Build an ACK-only packet at the given encryption level.
/// For Initial/Handshake (long header) or 1-RTT (short header).
pub const EncryptionLevel = enum {
    initial,
    handshake,
    application,
};

/// Wraps an ACK frame in an appropriate QUIC packet.
/// Returns bytes written, or null if buf too small.
pub fn buildAckPacket(
    buf: []u8,
    level: EncryptionLevel,
    tracker: *const AckTracker,
    now_us: u64,
    packet_number: u64,
    dcid: []const u8,
    scid: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    // Build ACK frame payload
    var ack_frame: [128]u8 = undefined;
    const ack_len = tracker.buildAckFrame(&ack_frame, now_us) orelse return null;

    switch (level) {
        .initial => return buildLongHeaderAckPacket(buf, 0, ack_frame[0..ack_len], packet_number, dcid, scid, key, iv, hp),
        .handshake => return buildLongHeaderAckPacket(buf, 2, ack_frame[0..ack_len], packet_number, dcid, scid, key, iv, hp),
        .application => return buildShortHeaderAckPacket(buf, ack_frame[0..ack_len], packet_number, dcid, key, iv, hp),
    }
}

fn buildLongHeaderAckPacket(
    buf: []u8,
    pkt_type: u2,
    ack_payload: []const u8,
    packet_number: u64,
    dcid: []const u8,
    scid: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    const quic_crypto = @import("crypto.zig");

    var pos: usize = 0;
    const pn_len: u8 = if (packet_number < 256) 0 else if (packet_number < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;

    // First byte: long header
    const type_bits: u8 = @as(u8, pkt_type) << 4;
    buf[pos] = 0xC0 | type_bits | pn_len;
    pos += 1;

    // Version
    std.mem.writeInt(u32, buf[pos..][0..4], packet_mod.QUIC_VERSION_1, .big);
    pos += 4;

    // DCID
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    // SCID
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos..][0..scid.len], scid);
    pos += scid.len;

    // Token (Initial only)
    if (pkt_type == 0) {
        buf[pos] = 0; // token_length = 0
        pos += 1;
    }

    // Length: pn_bytes + payload + 16 (AEAD tag)
    const length_val: usize = @as(usize, pn_bytes) + ack_payload.len + 16;
    pos += packet_mod.encodeVarint(buf[pos..], length_val) orelse return null;

    // Packet number
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((packet_number >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // Encrypt
    const aad = buf[0..pos];
    var ciphertext: [128]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(ciphertext[0..ack_payload.len], &tag, ack_payload, key, iv, packet_number, aad);

    @memcpy(buf[pos..][0..ack_payload.len], ciphertext[0..ack_payload.len]);
    pos += ack_payload.len;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    // Header protection
    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, hp);

    return pos;
}

fn buildShortHeaderAckPacket(
    buf: []u8,
    ack_payload: []const u8,
    packet_number: u64,
    dcid: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    const short_header = @import("short_header.zig");
    return short_header.encodeShortHeader(buf, dcid, packet_number, ack_payload, key, iv, hp);
}

// ─── Tests ───

test "AckTracker: single packet" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 1000);
    try std.testing.expect(tracker.hasPending());
    try std.testing.expectEqual(@as(?u64, 0), tracker.largestAcked());
}

test "AckTracker: sequential packets merge into one range" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    tracker.recordPacket(2, 300);
    tracker.recordPacket(3, 400);
    try std.testing.expectEqual(@as(usize, 1), tracker.range_count);
    try std.testing.expectEqual(@as(u64, 0), tracker.ranges[0].start);
    try std.testing.expectEqual(@as(u64, 3), tracker.ranges[0].end);
}

test "AckTracker: gap creates multiple ranges" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    // skip 2
    tracker.recordPacket(3, 400);
    tracker.recordPacket(4, 500);
    try std.testing.expectEqual(@as(usize, 2), tracker.range_count);
}

test "AckTracker: filling gap merges ranges" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(2, 200);
    try std.testing.expectEqual(@as(usize, 2), tracker.range_count);
    tracker.recordPacket(1, 300);
    try std.testing.expectEqual(@as(usize, 1), tracker.range_count);
    try std.testing.expectEqual(@as(u64, 0), tracker.ranges[0].start);
    try std.testing.expectEqual(@as(u64, 2), tracker.ranges[0].end);
}

test "AckTracker: duplicate PN ignored" {
    var tracker = AckTracker.init();
    tracker.recordPacket(5, 100);
    tracker.recordPacket(5, 200);
    try std.testing.expectEqual(@as(usize, 1), tracker.range_count);
}

test "AckTracker: out-of-order arrivals" {
    var tracker = AckTracker.init();
    tracker.recordPacket(5, 100);
    tracker.recordPacket(3, 200);
    tracker.recordPacket(4, 300);
    // Should merge into one range [3,5]
    try std.testing.expectEqual(@as(usize, 1), tracker.range_count);
    try std.testing.expectEqual(@as(u64, 3), tracker.ranges[0].start);
    try std.testing.expectEqual(@as(u64, 5), tracker.ranges[0].end);
}

test "AckTracker.buildAckFrame: single contiguous range" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    tracker.recordPacket(2, 300);

    var buf: [64]u8 = undefined;
    const len = tracker.buildAckFrame(&buf, 500) orelse unreachable;
    try std.testing.expect(len > 0);

    // Parse the generated frame
    try std.testing.expectEqual(@as(u8, 0x02), buf[0]); // ACK frame type
    var pos: usize = 1;
    const largest = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 2), largest.value); // largest acked = 2
    pos += largest.consumed;
    const delay = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    pos += delay.consumed;
    const range_count = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), range_count.value); // no additional ranges
    pos += range_count.consumed;
    const first_range = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 2), first_range.value); // first range = 2-0 = 2
}

test "AckTracker.buildAckFrame: multiple ranges" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    // gap at 2
    tracker.recordPacket(3, 300);
    tracker.recordPacket(4, 400);

    var buf: [64]u8 = undefined;
    const len = tracker.buildAckFrame(&buf, 500) orelse unreachable;
    try std.testing.expect(len > 0);

    // Parse
    try std.testing.expectEqual(@as(u8, 0x02), buf[0]);
    var pos: usize = 1;
    const largest = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 4), largest.value);
    pos += largest.consumed;
    pos += (packet_mod.decodeVarint(buf[pos..]) orelse unreachable).consumed; // delay
    const range_count = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 1), range_count.value); // one additional range
    pos += range_count.consumed;
    const first_range = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 1), first_range.value); // [3,4] → 4-3=1
}

test "AckTracker.buildAckFrame: empty returns null" {
    const tracker = AckTracker.init();
    var buf: [64]u8 = undefined;
    try std.testing.expect(tracker.buildAckFrame(&buf, 0) == null);
}

test "AckTracker: clear" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    try std.testing.expect(tracker.hasPending());
    tracker.clear();
    try std.testing.expect(!tracker.hasPending());
}

test "AckTracker: largest_recv_time updated on new largest" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    try std.testing.expectEqual(@as(u64, 100), tracker.largest_recv_time);
    tracker.recordPacket(5, 500);
    try std.testing.expectEqual(@as(u64, 500), tracker.largest_recv_time);
    // Earlier PN doesn't update time
    tracker.recordPacket(2, 999);
    try std.testing.expectEqual(@as(u64, 500), tracker.largest_recv_time);
}

test "buildAckPacket: initial level" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;

    var buf: [256]u8 = undefined;
    const len = buildAckPacket(&buf, .initial, &tracker, 300, 0, &dcid, &scid, key, iv, hp) orelse unreachable;

    // Should produce a long-header Initial packet
    try std.testing.expect(len > 20);
    // Form bit should be set (after HP, first byte is masked but form bit preserved)
    try std.testing.expect(buf[0] & 0x80 != 0);
}

test "buildAckPacket: application level" {
    var tracker = AckTracker.init();
    tracker.recordPacket(10, 1000);

    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const key = [_]u8{0x44} ** 16;
    const iv = [_]u8{0x55} ** 12;
    const hp = [_]u8{0x66} ** 16;

    var buf: [256]u8 = undefined;
    const len = buildAckPacket(&buf, .application, &tracker, 2000, 5, &dcid, "", key, iv, hp) orelse unreachable;

    // Should produce a short-header packet (form bit = 0)
    try std.testing.expect(len > 0);
}

test "AckTracker.buildAckEcnFrame: includes ECN counts" {
    var tracker = AckTracker.init();
    tracker.recordPacket(0, 100);
    tracker.recordPacket(1, 200);
    tracker.recordPacket(2, 300);

    const counts = ecn_mod.EcnCounts{ .ect0 = 42, .ect1 = 3, .ce = 1 };
    var buf: [128]u8 = undefined;
    const len = tracker.buildAckEcnFrame(&buf, 500, counts) orelse unreachable;
    try std.testing.expect(len > 0);

    // Frame type should be 0x03 (ACK_ECN)
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);

    // Parse: skip type, largest, delay, range_count, first_range → then ECN counts
    var pos: usize = 1;
    pos += (packet_mod.decodeVarint(buf[pos..]) orelse unreachable).consumed; // largest
    pos += (packet_mod.decodeVarint(buf[pos..]) orelse unreachable).consumed; // delay
    const rc = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    pos += rc.consumed; // range_count
    pos += (packet_mod.decodeVarint(buf[pos..]) orelse unreachable).consumed; // first_range

    // No additional ranges (range_count=0), so ECN counts follow directly
    try std.testing.expectEqual(@as(u64, 0), rc.value);

    const ect0 = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    pos += ect0.consumed;
    const ect1 = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    pos += ect1.consumed;
    const ce = packet_mod.decodeVarint(buf[pos..]) orelse unreachable;
    pos += ce.consumed;

    try std.testing.expectEqual(@as(u64, 42), ect0.value);
    try std.testing.expectEqual(@as(u64, 3), ect1.value);
    try std.testing.expectEqual(@as(u64, 1), ce.value);
    try std.testing.expectEqual(len, pos);
}
