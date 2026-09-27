// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const posix = std.posix;

// ─── ECN codepoint values (2-bit field in IP TOS byte) ───

pub const EcnCodepoint = enum(u2) {
    not_ect = 0b00,
    ect_1 = 0b01,
    ect_0 = 0b10,
    ce = 0b11,

    pub fn fromTos(tos: u8) EcnCodepoint {
        return @enumFromInt(@as(u2, @truncate(tos)));
    }
};

// ─── Platform-specific socket option constants ───

const IP_TOS: u32 = 3;
const IP_RECVTOS: u32 = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 27,
    .linux => 13,
    else => 13,
};
const IPPROTO_IP: u32 = 0;
const IPPROTO_IPV6: u32 = 41;
const IPV6_TCLASS: u32 = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 36,
    .linux => 67,
    else => 67,
};
const IPV6_RECVTCLASS: u32 = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 35,
    .linux => 66,
    else => 66,
};

// ─── ECN socket configuration ───

pub const EcnSocketError = error{
    SetTosFailure,
    SetRecvTosFailure,
};

/// Enable ECN marking on outgoing packets (sets ECT(0) in TOS byte).
/// Also enables receiving ECN info via cmsg on incoming packets.
pub fn enableEcn(fd: posix.socket_t, family: u32) EcnSocketError!void {
    if (family == posix.AF.INET) {
        const tos_val: u32 = @intFromEnum(EcnCodepoint.ect_0) & 0x03;
        posix.setsockopt(fd, IPPROTO_IP, IP_TOS, std.mem.asBytes(&tos_val)) catch
            return EcnSocketError.SetTosFailure;
        const enable: u32 = 1;
        posix.setsockopt(fd, IPPROTO_IP, IP_RECVTOS, std.mem.asBytes(&enable)) catch
            return EcnSocketError.SetRecvTosFailure;
    } else if (family == posix.AF.INET6) {
        const tclass_val: u32 = @intFromEnum(EcnCodepoint.ect_0) & 0x03;
        posix.setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, std.mem.asBytes(&tclass_val)) catch
            return EcnSocketError.SetTosFailure;
        const enable: u32 = 1;
        posix.setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, std.mem.asBytes(&enable)) catch
            return EcnSocketError.SetRecvTosFailure;
    }
}

// ─── Receive with ECN info via recvmsg ───

pub const RecvResult = struct {
    bytes_read: usize,
    ecn: EcnCodepoint,
};

const CmsgLenType = switch (@import("builtin").os.tag) {
    .linux => usize,
    else => u32,
};

const CmsgHdr = extern struct {
    len: CmsgLenType,
    level: i32,
    type: i32,
};

const CMSG_ALIGN = @sizeOf(usize);

fn cmsgAlign(len: usize) usize {
    return (len + CMSG_ALIGN - 1) & ~@as(usize, CMSG_ALIGN - 1);
}

/// Receive a datagram and extract ECN codepoint from ancillary data.
/// Falls back to .not_ect if cmsg parsing fails or ECN info is absent.
pub fn recvWithEcn(fd: posix.socket_t, buf: []u8) !RecvResult {
    var iov = [1]posix.iovec{.{
        .base = buf.ptr,
        .len = buf.len,
    }};

    var cmsg_buf: [256]u8 align(@alignOf(CmsgHdr)) = undefined;

    var msg = std.c.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = @intCast(cmsg_buf.len),
        .flags = 0,
    };

    const rc = std.c.recvmsg(fd, &msg, 0);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        return switch (err) {
            .AGAIN, .WOULDBLOCK => error.WouldBlock,
            else => error.RecvFailed,
        };
    }

    const ecn = parseTosFromCmsg(&cmsg_buf, @intCast(msg.controllen));
    return .{
        .bytes_read = @intCast(rc),
        .ecn = ecn,
    };
}

fn parseTosFromCmsg(buf: [*]const u8, controllen: usize) EcnCodepoint {
    var offset: usize = 0;
    while (offset + @sizeOf(CmsgHdr) <= controllen) {
        const hdr: *const CmsgHdr = @ptrCast(@alignCast(buf + offset));
        if (hdr.len < @sizeOf(CmsgHdr)) break;

        const data_offset = offset + cmsgAlign(@sizeOf(CmsgHdr));
        const is_ip_tos = (hdr.level == @as(i32, @intCast(IPPROTO_IP)) and
            hdr.type == @as(i32, @intCast(IP_RECVTOS)));
        const is_ipv6_tclass = (hdr.level == @as(i32, @intCast(IPPROTO_IPV6)) and
            hdr.type == @as(i32, @intCast(IPV6_RECVTCLASS)));

        if (is_ip_tos or is_ipv6_tclass) {
            if (data_offset < controllen) {
                const tos = buf[data_offset];
                return EcnCodepoint.fromTos(tos);
            }
        }

        const aligned_len = cmsgAlign(hdr.len);
        offset += aligned_len;
    }
    return .not_ect;
}

// ─── ECN counters (per-path, reported in ACK_ECN) ───

pub const EcnCounts = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,

    pub fn increment(self: *EcnCounts, ecn: EcnCodepoint) void {
        switch (ecn) {
            .ect_0 => self.ect0 += 1,
            .ect_1 => self.ect1 += 1,
            .ce => self.ce += 1,
            .not_ect => {},
        }
    }

    pub fn total(self: *const EcnCounts) u64 {
        return self.ect0 + self.ect1 + self.ce;
    }
};

// ─── ECN Validator (RFC 9000 §13.4.2) ───
//
// Validates that the path supports ECN by checking:
// 1. Sent ECT(0) packets are reflected as ECT(0) or CE in ACKs
// 2. ECN counts from peer don't decrease
// 3. ECN counts increase by at least the number of newly acked packets

pub const ValidationState = enum {
    testing,
    capable,
    failed,
};

pub const EcnValidator = struct {
    state: ValidationState = .testing,
    /// Packets sent with ECT(0) marking during testing phase
    testing_packets_sent: u64 = 0,
    /// How many testing packets have been acked
    testing_packets_acked: u64 = 0,
    /// Last received ECN counts from peer's ACK_ECN
    peer_counts: EcnCounts = .{},
    /// Local receive-side counts (what we report in our ACK_ECN)
    local_counts: EcnCounts = .{},

    const TESTING_THRESHOLD: u64 = 10;

    /// Called when we send a packet with ECT marking.
    pub fn onPacketSent(self: *EcnValidator) void {
        if (self.state == .testing) {
            self.testing_packets_sent += 1;
        }
    }

    /// Called when we receive a packet and read its ECN codepoint.
    pub fn onPacketReceived(self: *EcnValidator, ecn: EcnCodepoint) void {
        self.local_counts.increment(ecn);
    }

    /// Called when peer sends ACK_ECN with updated counts.
    /// `newly_acked` is the number of packets acknowledged in this ACK.
    /// Returns true if CE was detected (congestion signal).
    pub fn onAckEcn(self: *EcnValidator, peer_counts: EcnCounts, newly_acked: u64) bool {
        if (self.state == .failed) return false;

        // Counts must not decrease (RFC 9000 §13.4.2.1)
        if (peer_counts.ect0 < self.peer_counts.ect0 or
            peer_counts.ect1 < self.peer_counts.ect1 or
            peer_counts.ce < self.peer_counts.ce)
        {
            self.state = .failed;
            return false;
        }

        // Total increase must account for newly acked ECT-marked packets
        const total_increase = (peer_counts.ect0 + peer_counts.ect1 + peer_counts.ce) -
            (self.peer_counts.ect0 + self.peer_counts.ect1 + self.peer_counts.ce);

        if (total_increase < newly_acked and self.state == .testing) {
            // Path may be stripping ECN marks — marks lost
            self.state = .failed;
            self.peer_counts = peer_counts;
            return false;
        }

        const ce_delta = peer_counts.ce - self.peer_counts.ce;
        self.peer_counts = peer_counts;

        if (self.state == .testing) {
            self.testing_packets_acked += newly_acked;
            if (self.testing_packets_acked >= TESTING_THRESHOLD) {
                self.state = .capable;
            }
        }

        return ce_delta > 0;
    }

    /// Whether to mark outgoing packets with ECT(0).
    pub fn shouldMark(self: *const EcnValidator) bool {
        return self.state != .failed;
    }

    /// The ECN codepoint to use for outgoing packets.
    pub fn markingCodepoint(self: *const EcnValidator) EcnCodepoint {
        if (self.state == .failed) return .not_ect;
        return .ect_0;
    }
};

// ─── Tests ───

test "EcnCodepoint: fromTos extracts 2 LSBs" {
    try std.testing.expectEqual(EcnCodepoint.not_ect, EcnCodepoint.fromTos(0x00));
    try std.testing.expectEqual(EcnCodepoint.ect_1, EcnCodepoint.fromTos(0x01));
    try std.testing.expectEqual(EcnCodepoint.ect_0, EcnCodepoint.fromTos(0x02));
    try std.testing.expectEqual(EcnCodepoint.ce, EcnCodepoint.fromTos(0x03));
    // Upper bits don't affect ECN
    try std.testing.expectEqual(EcnCodepoint.ect_0, EcnCodepoint.fromTos(0xFE));
    try std.testing.expectEqual(EcnCodepoint.ce, EcnCodepoint.fromTos(0xFF));
}

test "EcnCounts: increment and total" {
    var counts = EcnCounts{};
    counts.increment(.ect_0);
    counts.increment(.ect_0);
    counts.increment(.ce);
    counts.increment(.not_ect);
    try std.testing.expectEqual(@as(u64, 2), counts.ect0);
    try std.testing.expectEqual(@as(u64, 0), counts.ect1);
    try std.testing.expectEqual(@as(u64, 1), counts.ce);
    try std.testing.expectEqual(@as(u64, 3), counts.total());
}

test "EcnValidator: transitions testing → capable after threshold" {
    var v = EcnValidator{};
    try std.testing.expectEqual(ValidationState.testing, v.state);

    // Simulate sending 10 packets and peer acking them with correct counts
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        v.onPacketSent();
    }

    // Peer acks all 10 with ECT(0) reflected
    const ce_detected = v.onAckEcn(.{ .ect0 = 10, .ect1 = 0, .ce = 0 }, 10);
    try std.testing.expect(!ce_detected);
    try std.testing.expectEqual(ValidationState.capable, v.state);
}

test "EcnValidator: detects CE signal" {
    var v = EcnValidator{ .state = .capable };
    v.peer_counts = .{ .ect0 = 10, .ect1 = 0, .ce = 0 };

    // Peer reports CE increase
    const ce_detected = v.onAckEcn(.{ .ect0 = 14, .ect1 = 0, .ce = 1 }, 5);
    try std.testing.expect(ce_detected);
}

test "EcnValidator: fails on decreasing counts" {
    var v = EcnValidator{ .state = .capable };
    v.peer_counts = .{ .ect0 = 10, .ect1 = 0, .ce = 2 };

    // ECT(0) count decreased — invalid
    const ce = v.onAckEcn(.{ .ect0 = 9, .ect1 = 0, .ce = 2 }, 1);
    try std.testing.expect(!ce);
    try std.testing.expectEqual(ValidationState.failed, v.state);
    try std.testing.expect(!v.shouldMark());
}

test "EcnValidator: fails when marks are stripped (testing)" {
    var v = EcnValidator{};
    v.onPacketSent();
    v.onPacketSent();
    v.onPacketSent();

    // We sent 3 ECT-marked packets but peer only reports 1 total ECN count
    const ce = v.onAckEcn(.{ .ect0 = 1, .ect1 = 0, .ce = 0 }, 3);
    try std.testing.expect(!ce);
    try std.testing.expectEqual(ValidationState.failed, v.state);
}

test "EcnValidator: shouldMark returns correct codepoint" {
    var v = EcnValidator{};
    try std.testing.expectEqual(EcnCodepoint.ect_0, v.markingCodepoint());

    v.state = .failed;
    try std.testing.expectEqual(EcnCodepoint.not_ect, v.markingCodepoint());
}

test "parseTosFromCmsg: empty buffer returns not_ect" {
    const buf = [_]u8{0} ** 256;
    const result = parseTosFromCmsg(&buf, 0);
    try std.testing.expectEqual(EcnCodepoint.not_ect, result);
}
