// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// RFC 9000 §9: Connection Migration
///
/// When a peer's address changes (detected by receiving a datagram from
/// a different source address), the endpoint must:
/// 1. Validate the new path via PATH_CHALLENGE/RESPONSE
/// 2. Limit data sent to the unvalidated address (anti-amplification)
/// 3. Rotate to a new Connection ID (prevent linkability)
///
/// Migration states:
///   stable   — path validated, normal operation
///   probing  — PATH_CHALLENGE sent, awaiting response
///   validated — new path confirmed, CID rotated

pub const PeerAddress = struct {
    family: AddressFamily,
    port: u16,
    addr_v4: [4]u8,
    addr_v6: [16]u8,

    pub const AddressFamily = enum { ipv4, ipv6 };

    pub fn initV4(addr: [4]u8, port: u16) PeerAddress {
        return .{
            .family = .ipv4,
            .port = port,
            .addr_v4 = addr,
            .addr_v6 = [_]u8{0} ** 16,
        };
    }

    pub fn initV6(addr: [16]u8, port: u16) PeerAddress {
        return .{
            .family = .ipv6,
            .port = port,
            .addr_v4 = [_]u8{0} ** 4,
            .addr_v6 = addr,
        };
    }

    pub fn eql(self: PeerAddress, other: PeerAddress) bool {
        if (self.family != other.family) return false;
        if (self.port != other.port) return false;
        return switch (self.family) {
            .ipv4 => std.mem.eql(u8, &self.addr_v4, &other.addr_v4),
            .ipv6 => std.mem.eql(u8, &self.addr_v6, &other.addr_v6),
        };
    }
};

pub const MigrationState = enum {
    stable,
    probing,
    validated,
};

/// Manages connection migration state (RFC 9000 §9).
pub const MigrationManager = struct {
    state: MigrationState,
    current_peer: ?PeerAddress,
    previous_peer: ?PeerAddress,
    amplification_budget: u64,
    bytes_received_on_new_path: u64,
    bytes_sent_on_new_path: u64,
    migration_count: u32,
    probe_start_us: u64,
    probe_attempts: u8,
    disabled: bool,

    const AMPLIFICATION_FACTOR: u64 = 3;
    const MAX_PROBE_ATTEMPTS: u8 = 3;

    pub fn init() MigrationManager {
        return .{
            .state = .stable,
            .current_peer = null,
            .previous_peer = null,
            .amplification_budget = 0,
            .bytes_received_on_new_path = 0,
            .bytes_sent_on_new_path = 0,
            .migration_count = 0,
            .probe_start_us = 0,
            .probe_attempts = 0,
            .disabled = false,
        };
    }

    /// Set the initial peer address (after handshake).
    pub fn setPeerAddress(self: *MigrationManager, addr: PeerAddress) void {
        self.current_peer = addr;
        self.state = .stable;
    }

    /// Disable migration (e.g., if disable_active_migration transport param is set).
    pub fn disable(self: *MigrationManager) void {
        self.disabled = true;
    }

    /// Check whether a received datagram's source address differs from current peer.
    /// If so, returns a MigrationEvent describing what happened.
    pub fn onDatagramReceived(self: *MigrationManager, source: PeerAddress, datagram_size: u64, now_us: u64) MigrationEvent {
        const current = self.current_peer orelse {
            self.current_peer = source;
            return .none;
        };

        if (current.eql(source)) {
            if (self.state == .probing) {
                self.bytes_received_on_new_path += datagram_size;
                self.amplification_budget = self.bytes_received_on_new_path * AMPLIFICATION_FACTOR;
            }
            return .none;
        }

        if (self.disabled) return .migration_rejected;

        // RFC 9000 §9.3.3: Don't trigger a new migration if we're already probing
        // and the datagram came from the previous path (prevents oscillation).
        if (self.state == .probing) {
            if (self.previous_peer) |prev| {
                if (prev.eql(source)) return .none;
            }
        }

        // Address changed — initiate migration
        self.previous_peer = self.current_peer;
        self.current_peer = source;
        self.state = .probing;
        self.bytes_received_on_new_path = datagram_size;
        self.bytes_sent_on_new_path = 0;
        self.amplification_budget = datagram_size * AMPLIFICATION_FACTOR;
        self.probe_start_us = now_us;
        self.probe_attempts = 0;

        return .{ .address_changed = .{
            .new_addr = source,
            .previous_addr = self.previous_peer.?,
        } };
    }

    /// Client-initiated migration: transition to probing state for a new peer.
    /// Anti-amplification does not apply to client-initiated paths (client sends first).
    pub fn initiateClientMigration(self: *MigrationManager, new_peer: PeerAddress, bytes_sent: u64, now_us: u64) void {
        self.previous_peer = self.current_peer;
        self.current_peer = new_peer;
        self.state = .probing;
        self.probe_start_us = now_us;
        self.probe_attempts = 1;
        self.bytes_sent_on_new_path = bytes_sent;
        self.bytes_received_on_new_path = 0;
        self.amplification_budget = 0;
    }

    /// Called when PATH_CHALLENGE is sent on the new path.
    pub fn onProbeSent(self: *MigrationManager, bytes_sent: u64, now_us: u64) void {
        self.probe_attempts += 1;
        self.bytes_sent_on_new_path += bytes_sent;
        self.probe_start_us = now_us;
    }

    /// Called when PATH_RESPONSE validates the new path.
    pub fn onPathValidated(self: *MigrationManager) void {
        self.state = .validated;
        self.migration_count += 1;
        self.amplification_budget = 0;
    }

    /// Promote from validated to stable (after CID rotation is complete).
    pub fn onMigrationComplete(self: *MigrationManager) void {
        self.state = .stable;
        self.previous_peer = null;
    }

    /// RFC 9000 §9.3: Check anti-amplification limit.
    /// Returns true if `size` bytes can be sent on the unvalidated path.
    pub fn canSend(self: *const MigrationManager, size: u64) bool {
        if (self.state != .probing) return true;
        return self.bytes_sent_on_new_path + size <= self.amplification_budget;
    }

    /// Record bytes sent on the new (unvalidated) path.
    pub fn onBytesSent(self: *MigrationManager, size: u64) void {
        if (self.state == .probing) {
            self.bytes_sent_on_new_path += size;
        }
    }

    /// Check if probing has exceeded max attempts.
    pub fn isProbingExhausted(self: *const MigrationManager) bool {
        return self.probe_attempts >= MAX_PROBE_ATTEMPTS;
    }

    /// Check if probe has timed out (3 * PTO).
    pub fn isProbeTimedOut(self: *const MigrationManager, now_us: u64, pto_us: u64) bool {
        if (self.state != .probing) return false;
        return now_us >= self.probe_start_us + 3 * pto_us;
    }

    /// Revert to previous path (probe failed).
    pub fn revertToPreviousPath(self: *MigrationManager) ?PeerAddress {
        const prev = self.previous_peer orelse return null;
        self.current_peer = prev;
        self.previous_peer = null;
        self.state = .stable;
        self.amplification_budget = 0;
        self.bytes_received_on_new_path = 0;
        self.bytes_sent_on_new_path = 0;
        return prev;
    }

    /// Get the current peer address.
    pub fn getPeerAddress(self: *const MigrationManager) ?PeerAddress {
        return self.current_peer;
    }

    /// Check if migration is in progress.
    pub fn isMigrating(self: *const MigrationManager) bool {
        return self.state == .probing;
    }

    /// Check if the path has been validated after migration.
    pub fn isNewPathValidated(self: *const MigrationManager) bool {
        return self.state == .validated;
    }
};

pub const MigrationEvent = union(enum) {
    none: void,
    address_changed: struct {
        new_addr: PeerAddress,
        previous_addr: PeerAddress,
    },
    migration_rejected: void,
};

// ─── Tests ───

test "MigrationManager: init state" {
    const mgr = MigrationManager.init();
    try std.testing.expectEqual(MigrationState.stable, mgr.state);
    try std.testing.expect(mgr.current_peer == null);
    try std.testing.expect(!mgr.isMigrating());
}

test "MigrationManager: setPeerAddress" {
    var mgr = MigrationManager.init();
    const addr = PeerAddress.initV4(.{ 192, 168, 1, 1 }, 4433);
    mgr.setPeerAddress(addr);

    try std.testing.expect(mgr.current_peer != null);
    try std.testing.expect(mgr.current_peer.?.eql(addr));
    try std.testing.expectEqual(MigrationState.stable, mgr.state);
}

test "MigrationManager: same address is no-op" {
    var mgr = MigrationManager.init();
    const addr = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    mgr.setPeerAddress(addr);

    const event = mgr.onDatagramReceived(addr, 1200, 1_000_000);
    try std.testing.expect(event == .none);
    try std.testing.expect(!mgr.isMigrating());
}

test "MigrationManager: address change triggers migration" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    const event = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    switch (event) {
        .address_changed => |info| {
            try std.testing.expect(info.new_addr.eql(addr2));
            try std.testing.expect(info.previous_addr.eql(addr1));
        },
        else => try std.testing.expect(false),
    }
    try std.testing.expect(mgr.isMigrating());
    try std.testing.expectEqual(MigrationState.probing, mgr.state);
}

test "MigrationManager: port change is migration" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 8443);
    mgr.setPeerAddress(addr1);

    const event = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expect(event == .address_changed);
}

test "MigrationManager: disabled rejects migration" {
    var mgr = MigrationManager.init();
    mgr.disable();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    const event = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expect(event == .migration_rejected);
    try std.testing.expect(!mgr.isMigrating());
}

test "MigrationManager: anti-amplification limit" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    // Budget = 1200 * 3 = 3600
    try std.testing.expect(mgr.canSend(3600));
    try std.testing.expect(!mgr.canSend(3601));

    mgr.onBytesSent(2000);
    try std.testing.expect(mgr.canSend(1600));
    try std.testing.expect(!mgr.canSend(1601));
}

test "MigrationManager: canSend always true when stable" {
    var mgr = MigrationManager.init();
    const addr = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    mgr.setPeerAddress(addr);

    try std.testing.expect(mgr.canSend(999_999));
}

test "MigrationManager: path validation lifecycle" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expectEqual(MigrationState.probing, mgr.state);

    mgr.onProbeSent(50, 1_000_000);
    try std.testing.expectEqual(@as(u8, 1), mgr.probe_attempts);

    mgr.onPathValidated();
    try std.testing.expectEqual(MigrationState.validated, mgr.state);
    try std.testing.expect(mgr.isNewPathValidated());
    try std.testing.expectEqual(@as(u32, 1), mgr.migration_count);

    mgr.onMigrationComplete();
    try std.testing.expectEqual(MigrationState.stable, mgr.state);
    try std.testing.expect(mgr.current_peer.?.eql(addr2));
    try std.testing.expect(mgr.previous_peer == null);
}

test "MigrationManager: probe timeout detection" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);

    const pto: u64 = 100_000; // 100ms
    try std.testing.expect(!mgr.isProbeTimedOut(1_200_000, pto)); // 200ms < 3*PTO
    try std.testing.expect(mgr.isProbeTimedOut(1_300_000, pto)); // 300ms = 3*PTO
}

test "MigrationManager: revert to previous path" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expect(mgr.current_peer.?.eql(addr2));

    const reverted = mgr.revertToPreviousPath() orelse unreachable;
    try std.testing.expect(reverted.eql(addr1));
    try std.testing.expect(mgr.current_peer.?.eql(addr1));
    try std.testing.expectEqual(MigrationState.stable, mgr.state);
}

test "MigrationManager: probe exhaustion" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);

    try std.testing.expect(!mgr.isProbingExhausted());
    mgr.onProbeSent(50, 1_100_000);
    mgr.onProbeSent(50, 1_200_000);
    try std.testing.expect(!mgr.isProbingExhausted());
    mgr.onProbeSent(50, 1_300_000);
    try std.testing.expect(mgr.isProbingExhausted());
}

test "MigrationManager: IPv6 address change" {
    var mgr = MigrationManager.init();
    var a1 = [_]u8{0} ** 16;
    a1[15] = 1;
    var a2 = [_]u8{0} ** 16;
    a2[15] = 2;
    const addr1 = PeerAddress.initV6(a1, 443);
    const addr2 = PeerAddress.initV6(a2, 443);
    mgr.setPeerAddress(addr1);

    const event = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expect(event == .address_changed);
}

test "MigrationManager: first datagram sets peer (no migration)" {
    var mgr = MigrationManager.init();
    const addr = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);

    const event = mgr.onDatagramReceived(addr, 1200, 1_000_000);
    try std.testing.expect(event == .none);
    try std.testing.expect(mgr.current_peer.?.eql(addr));
}

test "MigrationManager: amplification budget grows with received data" {
    var mgr = MigrationManager.init();
    const addr1 = PeerAddress.initV4(.{ 10, 0, 0, 1 }, 443);
    const addr2 = PeerAddress.initV4(.{ 10, 0, 0, 2 }, 443);
    mgr.setPeerAddress(addr1);

    // First datagram from new address → budget = 1200*3 = 3600
    _ = mgr.onDatagramReceived(addr2, 1200, 1_000_000);
    try std.testing.expectEqual(@as(u64, 3600), mgr.amplification_budget);

    // Second datagram from same (new) address → budget = (1200+500)*3 = 5100
    _ = mgr.onDatagramReceived(addr2, 500, 1_001_000);
    try std.testing.expectEqual(@as(u64, 5100), mgr.amplification_budget);
}

test "PeerAddress: equality" {
    const a = PeerAddress.initV4(.{ 1, 2, 3, 4 }, 443);
    const b = PeerAddress.initV4(.{ 1, 2, 3, 4 }, 443);
    const c = PeerAddress.initV4(.{ 1, 2, 3, 5 }, 443);
    const d = PeerAddress.initV4(.{ 1, 2, 3, 4 }, 444);

    try std.testing.expect(a.eql(b));
    try std.testing.expect(!a.eql(c));
    try std.testing.expect(!a.eql(d));
}

test "PeerAddress: v4 vs v6 never equal" {
    const v4 = PeerAddress.initV4(.{ 0, 0, 0, 1 }, 443);
    var v6_addr = [_]u8{0} ** 16;
    v6_addr[15] = 1;
    const v6 = PeerAddress.initV6(v6_addr, 443);
    try std.testing.expect(!v4.eql(v6));
}
