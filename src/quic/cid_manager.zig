// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const packet_mod = @import("packet.zig");

/// RFC 9000 §5.1: Connection ID Management
///
/// Each endpoint issues Connection IDs to its peer via NEW_CONNECTION_ID.
/// The peer uses these CIDs in the DCID field of packets it sends.
/// When a CID is no longer needed, RETIRE_CONNECTION_ID retires it.
///
/// Key invariants:
/// - Active CID set is bounded (active_connection_id_limit transport param, min 2)
/// - retire_prior_to advances monotonically — all CIDs with seq < retire_prior_to must be retired
/// - Sequence numbers are monotonically increasing per issuer

/// A single Connection ID entry in our table.
pub const CidEntry = struct {
    seq: u64,
    cid: [20]u8,
    cid_len: u8,
    stateless_reset_token: [16]u8,
    retired: bool,
};

/// Manages the set of peer-issued Connection IDs we can use as DCID.
pub const CidManager = struct {
    /// CID table — fixed slots.
    entries: [MAX_CIDS]?CidEntry,
    /// Number of active (non-retired) entries.
    active_count: u8,
    /// Current active CID index (into entries).
    current_idx: u8,
    /// Highest retire_prior_to we've seen.
    retire_prior_to: u64,
    /// Highest sequence number received.
    max_seq_received: u64,
    /// Sequence numbers pending RETIRE_CONNECTION_ID to send.
    retire_pending: [MAX_CIDS]u64,
    retire_pending_count: u8,

    const MAX_CIDS = 8;

    pub fn init() CidManager {
        return .{
            .entries = [_]?CidEntry{null} ** MAX_CIDS,
            .active_count = 0,
            .current_idx = 0,
            .retire_prior_to = 0,
            .max_seq_received = 0,
            .retire_pending = [_]u64{0} ** MAX_CIDS,
            .retire_pending_count = 0,
        };
    }

    /// Set the initial DCID (sequence 0, no reset token yet).
    /// Called during connection setup with the server's chosen CID.
    pub fn setInitialCid(self: *CidManager, cid: []const u8) void {
        const len: u8 = @intCast(@min(cid.len, 20));
        var entry = CidEntry{
            .seq = 0,
            .cid = [_]u8{0} ** 20,
            .cid_len = len,
            .stateless_reset_token = [_]u8{0} ** 16,
            .retired = false,
        };
        @memcpy(entry.cid[0..len], cid[0..len]);
        self.entries[0] = entry;
        self.active_count = 1;
        self.current_idx = 0;
    }

    /// Process a received NEW_CONNECTION_ID frame.
    /// Returns error info if the frame is invalid (caller should close connection).
    pub fn onNewConnectionId(self: *CidManager, frame: NewConnectionIdFrame) CidResult {
        // RFC 9000 §19.15: retire_prior_to must not exceed sequence
        if (frame.retire_prior_to > frame.sequence) {
            return .{ .err = .protocol_violation };
        }

        // Update retire_prior_to (monotonically increasing)
        if (frame.retire_prior_to > self.retire_prior_to) {
            self.retireBelow(frame.retire_prior_to);
            self.retire_prior_to = frame.retire_prior_to;
        }

        // Track max sequence
        if (frame.sequence > self.max_seq_received) {
            self.max_seq_received = frame.sequence;
        }

        // If this CID's seq is below retire_prior_to, retire it immediately
        if (frame.sequence < self.retire_prior_to) {
            self.queueRetire(frame.sequence);
            return .ok;
        }

        // Check if already stored (duplicate)
        for (&self.entries) |*slot| {
            if (slot.*) |entry| {
                if (entry.seq == frame.sequence) return .ok;
            }
        }

        // Store in an empty slot
        const len: u8 = @intCast(@min(frame.cid_len, 20));
        var entry = CidEntry{
            .seq = frame.sequence,
            .cid = [_]u8{0} ** 20,
            .cid_len = len,
            .stateless_reset_token = frame.stateless_reset_token,
            .retired = false,
        };
        @memcpy(entry.cid[0..len], frame.cid[0..len]);

        for (&self.entries) |*slot| {
            if (slot.* == null) {
                slot.* = entry;
                self.active_count += 1;
                return .ok;
            }
        }

        // Table full — this can happen if peer sends too many without proper retire_prior_to
        return .{ .err = .connection_id_limit };
    }

    /// Get the current active DCID.
    pub fn currentCid(self: *const CidManager) ?[]const u8 {
        if (self.getActiveEntry()) |entry| {
            return entry.cid[0..entry.cid_len];
        }
        return null;
    }

    /// Get the current CID length.
    pub fn currentCidLen(self: *const CidManager) u8 {
        if (self.getActiveEntry()) |entry| {
            return entry.cid_len;
        }
        return 0;
    }

    fn getActiveEntry(self: *const CidManager) ?*const CidEntry {
        for (&self.entries, 0..) |*slot, idx| {
            if (idx == self.current_idx) {
                if (slot.*) |*entry| {
                    if (!entry.retired) return entry;
                }
                break;
            }
        }
        // Fallback: find any active
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                if (!entry.retired) return entry;
            }
        }
        return null;
    }

    /// Rotate to the next available CID (e.g., for NAT rebinding or migration).
    /// Retires the old CID and switches to the next one.
    /// Returns true if rotation succeeded (a new CID was available).
    pub fn rotateCid(self: *CidManager) bool {
        const old_idx = self.current_idx;
        const old_entry = self.entries[old_idx] orelse return false;
        if (old_entry.retired) return false;

        // Find next active entry
        var found: ?u8 = null;
        for (0..MAX_CIDS) |offset| {
            const idx: u8 = @intCast((old_idx + 1 + offset) % MAX_CIDS);
            if (self.entries[idx]) |entry| {
                if (!entry.retired and entry.seq != old_entry.seq) {
                    found = idx;
                    break;
                }
            }
        }

        const new_idx = found orelse return false;

        // Retire old
        self.entries[old_idx].?.retired = true;
        self.active_count -= 1;
        self.queueRetire(old_entry.seq);

        self.current_idx = new_idx;
        return true;
    }

    /// Check if there are RETIRE_CONNECTION_ID frames to send.
    pub fn hasRetirePending(self: *const CidManager) bool {
        return self.retire_pending_count > 0;
    }

    /// Dequeue a pending retire sequence number. Returns null if none pending.
    pub fn dequeueRetire(self: *CidManager) ?u64 {
        if (self.retire_pending_count == 0) return null;
        const seq = self.retire_pending[0];
        // Shift remaining
        var i: u8 = 0;
        while (i < self.retire_pending_count - 1) : (i += 1) {
            self.retire_pending[i] = self.retire_pending[i + 1];
        }
        self.retire_pending_count -= 1;
        return seq;
    }

    /// Get number of active (non-retired) CIDs.
    pub fn activeCount(self: *const CidManager) u8 {
        return self.active_count;
    }

    // ─── Internal ───

    fn retireBelow(self: *CidManager, prior_to: u64) void {
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                if (!entry.retired and entry.seq < prior_to) {
                    entry.retired = true;
                    if (self.active_count > 0) self.active_count -= 1;
                    self.queueRetire(entry.seq);
                }
            }
        }
        // If current was retired, move to first active
        if (self.entries[self.current_idx]) |entry| {
            if (entry.retired) {
                self.advanceCurrentIdx();
            }
        }
    }

    fn advanceCurrentIdx(self: *CidManager) void {
        for (0..MAX_CIDS) |offset| {
            const idx: u8 = @intCast((self.current_idx + 1 + offset) % MAX_CIDS);
            if (self.entries[idx]) |entry| {
                if (!entry.retired) {
                    self.current_idx = idx;
                    return;
                }
            }
        }
    }

    fn queueRetire(self: *CidManager, seq: u64) void {
        if (self.retire_pending_count >= MAX_CIDS) return;
        self.retire_pending[self.retire_pending_count] = seq;
        self.retire_pending_count += 1;
    }

    /// Clean up retired entries (free slots for new CIDs).
    pub fn gcRetired(self: *CidManager) void {
        for (&self.entries) |*slot| {
            if (slot.*) |entry| {
                if (entry.retired) {
                    slot.* = null;
                }
            }
        }
    }

    pub const CidResult = union(enum) {
        ok: void,
        err: CidError,
    };

    pub const CidError = enum {
        protocol_violation,
        connection_id_limit,
    };
};

/// NEW_CONNECTION_ID frame (RFC 9000 §19.15).
pub const NewConnectionIdFrame = struct {
    sequence: u64,
    retire_prior_to: u64,
    cid_len: u8,
    cid: [20]u8,
    stateless_reset_token: [16]u8,

    /// Decode from payload bytes (after frame type byte).
    pub fn decode(data: []const u8) ?NewConnectionIdFrame {
        var pos: usize = 0;

        const seq = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += seq.consumed;

        const rpt = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += rpt.consumed;

        if (pos >= data.len) return null;
        const cid_len = data[pos];
        pos += 1;

        if (cid_len > 20) return null;
        if (pos + cid_len + 16 > data.len) return null;

        var frame = NewConnectionIdFrame{
            .sequence = seq.value,
            .retire_prior_to = rpt.value,
            .cid_len = cid_len,
            .cid = [_]u8{0} ** 20,
            .stateless_reset_token = undefined,
        };

        @memcpy(frame.cid[0..cid_len], data[pos..][0..cid_len]);
        pos += cid_len;

        @memcpy(&frame.stateless_reset_token, data[pos..][0..16]);

        return frame;
    }

    /// Total encoded size (excluding frame type byte).
    pub fn encodedSize(self: *const NewConnectionIdFrame) usize {
        return packet_mod.varintSize(self.sequence) +
            packet_mod.varintSize(self.retire_prior_to) +
            1 + self.cid_len + 16;
    }
};

/// Encode a RETIRE_CONNECTION_ID frame (RFC 9000 §19.16).
/// Returns bytes written, or null if buffer too small.
pub fn encodeRetireConnectionId(buf: []u8, seq: u64) ?usize {
    const seq_size = packet_mod.varintSize(seq);
    const total = 1 + seq_size;
    if (buf.len < total) return null;

    buf[0] = 0x19; // RETIRE_CONNECTION_ID frame type
    _ = packet_mod.encodeVarint(buf[1..], seq);
    return total;
}

/// Decode a RETIRE_CONNECTION_ID frame (after frame type byte).
pub fn decodeRetireConnectionId(data: []const u8) ?u64 {
    const v = packet_mod.decodeVarint(data) orelse return null;
    return v.value;
}

/// Calculate varint-encoded frame skip size.
/// Used for unknown frame types that carry a length prefix.
pub fn skipVarintFrame(data: []const u8) ?usize {
    const v = packet_mod.decodeVarint(data) orelse return null;
    return v.consumed + @as(usize, @intCast(v.value));
}

// ─── Tests ───

test "CidManager: init and setInitialCid" {
    var mgr = CidManager.init();
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    mgr.setInitialCid(&cid);

    try std.testing.expectEqual(@as(u8, 1), mgr.activeCount());
    const current = mgr.currentCid() orelse unreachable;
    try std.testing.expectEqualSlices(u8, &cid, current);
}

test "CidManager: onNewConnectionId adds entry" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    var frame = NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xAA} ** 16,
    };
    @memcpy(frame.cid[0..8], &([_]u8{0x02} ** 8));

    const result = mgr.onNewConnectionId(frame);
    try std.testing.expect(result == .ok);
    try std.testing.expectEqual(@as(u8, 2), mgr.activeCount());
}

test "CidManager: retire_prior_to retires old CIDs" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    // Add seq 1
    var frame1 = NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xBB} ** 16,
    };
    @memcpy(frame1.cid[0..8], &([_]u8{0x02} ** 8));
    _ = mgr.onNewConnectionId(frame1);

    // Add seq 2 with retire_prior_to = 1 (retires seq 0)
    var frame2 = NewConnectionIdFrame{
        .sequence = 2,
        .retire_prior_to = 1,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xCC} ** 16,
    };
    @memcpy(frame2.cid[0..8], &([_]u8{0x03} ** 8));
    _ = mgr.onNewConnectionId(frame2);

    // seq 0 should be retired
    try std.testing.expectEqual(@as(u8, 2), mgr.activeCount()); // seq 1, seq 2
    try std.testing.expect(mgr.hasRetirePending());

    const retired_seq = mgr.dequeueRetire() orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), retired_seq);
}

test "CidManager: rotateCid switches and retires old" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    // Add seq 1
    var frame = NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xDD} ** 16,
    };
    @memcpy(frame.cid[0..8], &([_]u8{0x02} ** 8));
    _ = mgr.onNewConnectionId(frame);

    // Rotate from seq 0 to seq 1
    try std.testing.expect(mgr.rotateCid());

    // Now using seq 1
    const current = mgr.currentCid() orelse unreachable;
    try std.testing.expectEqualSlices(u8, &([_]u8{0x02} ** 8), current);

    // seq 0 retired
    try std.testing.expectEqual(@as(u8, 1), mgr.activeCount());
    try std.testing.expect(mgr.hasRetirePending());
}

test "CidManager: rotateCid fails with only one CID" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);
    try std.testing.expect(!mgr.rotateCid());
}

test "CidManager: retire_prior_to > sequence is protocol violation" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    const frame = NewConnectionIdFrame{
        .sequence = 2,
        .retire_prior_to = 3, // invalid: retire_prior_to > sequence
        .cid_len = 8,
        .cid = [_]u8{0x02} ** 20,
        .stateless_reset_token = [_]u8{0} ** 16,
    };
    const result = mgr.onNewConnectionId(frame);
    try std.testing.expect(result == .err);
    try std.testing.expectEqual(CidManager.CidError.protocol_violation, result.err);
}

test "CidManager: duplicate sequence is ignored" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    var frame = NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xEE} ** 16,
    };
    @memcpy(frame.cid[0..8], &([_]u8{0x02} ** 8));

    _ = mgr.onNewConnectionId(frame);
    _ = mgr.onNewConnectionId(frame); // duplicate
    try std.testing.expectEqual(@as(u8, 2), mgr.activeCount()); // still 2
}

test "CidManager: gcRetired frees slots" {
    var mgr = CidManager.init();
    mgr.setInitialCid(&[_]u8{0x01} ** 8);

    var frame = NewConnectionIdFrame{
        .sequence = 1,
        .retire_prior_to = 1, // retires seq 0
        .cid_len = 8,
        .cid = [_]u8{0} ** 20,
        .stateless_reset_token = [_]u8{0xFF} ** 16,
    };
    @memcpy(frame.cid[0..8], &([_]u8{0x02} ** 8));
    _ = mgr.onNewConnectionId(frame);

    // slot 0 is retired but still occupies the entry
    try std.testing.expect(mgr.entries[0] != null);

    mgr.gcRetired();

    // Now slot 0 is freed
    try std.testing.expect(mgr.entries[0] == null);
}

test "NewConnectionIdFrame: decode" {
    // Encode manually: seq=3, retire_prior_to=1, cid_len=4, cid=0x01020304, token=0xAA*16
    var data: [64]u8 = undefined;
    var pos: usize = 0;

    pos += packet_mod.encodeVarint(data[pos..], 3) orelse unreachable; // sequence
    pos += packet_mod.encodeVarint(data[pos..], 1) orelse unreachable; // retire_prior_to
    data[pos] = 4; // cid_len
    pos += 1;
    data[pos] = 0x01;
    data[pos + 1] = 0x02;
    data[pos + 2] = 0x03;
    data[pos + 3] = 0x04;
    pos += 4;
    @memset(data[pos..][0..16], 0xAA); // token
    pos += 16;

    const frame = NewConnectionIdFrame.decode(data[0..pos]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 3), frame.sequence);
    try std.testing.expectEqual(@as(u64, 1), frame.retire_prior_to);
    try std.testing.expectEqual(@as(u8, 4), frame.cid_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, frame.cid[0..4]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAA} ** 16), &frame.stateless_reset_token);
}

test "encodeRetireConnectionId/decodeRetireConnectionId roundtrip" {
    var buf: [16]u8 = undefined;
    const len = encodeRetireConnectionId(&buf, 42) orelse unreachable;
    try std.testing.expectEqual(@as(u8, 0x19), buf[0]);

    const seq = decodeRetireConnectionId(buf[1..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 42), seq);
}

test "encodeRetireConnectionId: large sequence" {
    var buf: [16]u8 = undefined;
    const len = encodeRetireConnectionId(&buf, 16384) orelse unreachable;
    try std.testing.expect(len > 2); // varint encoding > 1 byte

    const seq = decodeRetireConnectionId(buf[1..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 16384), seq);
}
