// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const packet_mod = @import("packet.zig");

/// RFC 9000 §10.1: Idle Timeout
///
/// Each endpoint advertises a max_idle_timeout transport parameter.
/// The effective idle timeout is min(local, peer), or the single advertised
/// value if only one side specifies it. A value of 0 means "no timeout".
///
/// The idle timer resets on every ack-eliciting packet sent or received.
/// When it expires, the connection is silently closed (no CONNECTION_CLOSE).
///
/// Keep-alive: PING frames sent before the idle timeout fires to prevent
/// silent closure. Interval is configurable (default = effective_timeout / 2).
pub const IdleTimeoutManager = struct {
    /// Effective idle timeout in microseconds (0 = disabled).
    effective_timeout_us: u64,

    /// Keep-alive interval in microseconds (0 = disabled).
    keepalive_interval_us: u64,

    /// Last time an ack-eliciting packet was sent or received (microseconds).
    last_activity_us: u64,

    /// Last time a PING was sent for keep-alive.
    last_ping_sent_us: u64,

    /// Whether keep-alive is enabled.
    keepalive_enabled: bool,

    /// Whether the idle timer has expired (connection should be silently closed).
    expired: bool,

    pub fn init(config: Config) IdleTimeoutManager {
        const effective = computeEffectiveTimeout(config.local_idle_timeout_ms, config.peer_idle_timeout_ms);
        const effective_us = effective * 1000;
        const keepalive_us = if (config.keepalive_interval_ms > 0)
            config.keepalive_interval_ms * 1000
        else if (effective_us > 0)
            effective_us / 2
        else
            0;

        return .{
            .effective_timeout_us = effective_us,
            .keepalive_interval_us = keepalive_us,
            .last_activity_us = config.now_us,
            .last_ping_sent_us = 0,
            .keepalive_enabled = config.keepalive_enabled and effective_us > 0,
            .expired = false,
        };
    }

    /// Record that an ack-eliciting packet was sent or received.
    /// Resets the idle timer.
    pub fn onActivity(self: *IdleTimeoutManager, now_us: u64) void {
        self.last_activity_us = now_us;
    }

    /// Check timers. Returns an action the caller should take.
    /// Call this on every event loop tick.
    pub fn poll(self: *IdleTimeoutManager, now_us: u64) Action {
        if (self.expired) return .none;
        if (self.effective_timeout_us == 0) return .none;

        // Check idle timeout expiry
        if (now_us >= self.last_activity_us + self.effective_timeout_us) {
            self.expired = true;
            return .close_silent;
        }

        // Check keep-alive
        if (self.keepalive_enabled and self.keepalive_interval_us > 0) {
            const since_activity = now_us - self.last_activity_us;
            if (since_activity >= self.keepalive_interval_us) {
                // Only send if we haven't already sent a PING since last activity
                if (self.last_ping_sent_us <= self.last_activity_us) {
                    self.last_ping_sent_us = now_us;
                    return .send_ping;
                }
            }
        }

        return .none;
    }

    /// Get the deadline (absolute microseconds) for the next timer event.
    /// Returns null if no timer is active.
    pub fn getTimer(self: *const IdleTimeoutManager) ?u64 {
        if (self.expired) return null;
        if (self.effective_timeout_us == 0) return null;

        if (self.keepalive_enabled and self.keepalive_interval_us > 0) {
            // Next event is either keep-alive or idle expiry, whichever is sooner
            const keepalive_deadline = self.last_activity_us + self.keepalive_interval_us;
            const idle_deadline = self.last_activity_us + self.effective_timeout_us;
            return @min(keepalive_deadline, idle_deadline);
        }

        return self.last_activity_us + self.effective_timeout_us;
    }

    /// Time remaining before idle timeout fires (microseconds).
    /// Returns 0 if already expired.
    pub fn timeRemaining(self: *const IdleTimeoutManager, now_us: u64) u64 {
        if (self.expired or self.effective_timeout_us == 0) return 0;
        const deadline = self.last_activity_us + self.effective_timeout_us;
        if (now_us >= deadline) return 0;
        return deadline - now_us;
    }

    /// Update peer's max_idle_timeout after receiving transport parameters.
    /// Recomputes effective timeout.
    pub fn setPeerTimeout(self: *IdleTimeoutManager, peer_timeout_ms: u64) void {
        const local_ms = self.effective_timeout_us / 1000;
        const effective = computeEffectiveTimeout(local_ms, peer_timeout_ms);
        self.effective_timeout_us = effective * 1000;
        if (self.effective_timeout_us > 0 and self.keepalive_enabled) {
            self.keepalive_interval_us = self.effective_timeout_us / 2;
        }
    }

    /// Encode a PING frame (type 0x01, zero length).
    /// RFC 9000 §19.2: PING frames are ack-eliciting.
    pub fn encodePing(buf: []u8) ?usize {
        if (buf.len < 1) return null;
        buf[0] = 0x01;
        return 1;
    }

    /// Check if we are expired.
    pub fn isExpired(self: *const IdleTimeoutManager) bool {
        return self.expired;
    }

    pub const Action = enum {
        none,
        send_ping,
        close_silent,
    };

    pub const Config = struct {
        /// Local max_idle_timeout (milliseconds). 0 = no timeout preference.
        local_idle_timeout_ms: u64 = 30_000,
        /// Peer's max_idle_timeout (milliseconds). 0 = no timeout preference.
        peer_idle_timeout_ms: u64 = 0,
        /// Whether to send PING frames to keep the connection alive.
        keepalive_enabled: bool = true,
        /// Explicit keep-alive interval (milliseconds). 0 = auto (effective_timeout / 2).
        keepalive_interval_ms: u64 = 0,
        /// Current time for initializing last_activity.
        now_us: u64 = 0,
    };
};

/// RFC 9000 §10.1: effective idle timeout computation.
/// If both are non-zero → min. If one is zero → the other. If both zero → 0 (disabled).
fn computeEffectiveTimeout(local_ms: u64, peer_ms: u64) u64 {
    if (local_ms == 0 and peer_ms == 0) return 0;
    if (local_ms == 0) return peer_ms;
    if (peer_ms == 0) return local_ms;
    return @min(local_ms, peer_ms);
}

// ─── Tests ───

test "IdleTimeoutManager: init with defaults" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .now_us = 1_000_000,
    });
    try std.testing.expectEqual(@as(u64, 30_000_000), mgr.effective_timeout_us);
    try std.testing.expectEqual(@as(u64, 15_000_000), mgr.keepalive_interval_us);
    try std.testing.expect(mgr.keepalive_enabled);
    try std.testing.expect(!mgr.expired);
}

test "IdleTimeoutManager: effective timeout is min(local, peer)" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .peer_idle_timeout_ms = 20_000,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 20_000_000), mgr.effective_timeout_us);
    try std.testing.expectEqual(@as(u64, 10_000_000), mgr.keepalive_interval_us);
}

test "IdleTimeoutManager: zero local uses peer's value" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 0,
        .peer_idle_timeout_ms = 60_000,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 60_000_000), mgr.effective_timeout_us);
}

test "IdleTimeoutManager: both zero disables timeout" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 0,
        .peer_idle_timeout_ms = 0,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 0), mgr.effective_timeout_us);
    try std.testing.expect(!mgr.keepalive_enabled);
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(999_999_999));
}

test "IdleTimeoutManager: idle timeout fires after effective_timeout" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 10_000,
        .keepalive_enabled = false,
        .now_us = 1_000_000,
    });

    // Before timeout
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(5_000_000));
    try std.testing.expect(!mgr.expired);

    // At timeout boundary
    try std.testing.expectEqual(IdleTimeoutManager.Action.close_silent, mgr.poll(11_000_000));
    try std.testing.expect(mgr.expired);
}

test "IdleTimeoutManager: onActivity resets timer" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 10_000,
        .keepalive_enabled = false,
        .now_us = 0,
    });

    // Activity at 5s — resets deadline to 15s
    mgr.onActivity(5_000_000);
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(12_000_000));
    try std.testing.expect(!mgr.expired);

    // Now expires at 15s
    try std.testing.expectEqual(IdleTimeoutManager.Action.close_silent, mgr.poll(15_000_000));
    try std.testing.expect(mgr.expired);
}

test "IdleTimeoutManager: keep-alive sends PING before timeout" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .keepalive_enabled = true,
        .now_us = 0,
    });
    // keepalive_interval = 15s (half of 30s)

    // Before keep-alive interval
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(10_000_000));

    // At keep-alive interval → send PING
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(15_000_000));

    // Second poll should not send another PING (already sent since last activity)
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(16_000_000));
}

test "IdleTimeoutManager: PING response resets timer, prevents expiry" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .keepalive_enabled = true,
        .now_us = 0,
    });

    // PING sent at 15s
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(15_000_000));

    // Peer ACKs the PING (ack-eliciting receive) at 15.1s → resets activity
    mgr.onActivity(15_100_000);

    // Next keep-alive at 15.1s + 15s = 30.1s
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(29_000_000));
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(30_100_000));
}

test "IdleTimeoutManager: explicit keepalive_interval_ms" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 90_000,
        .keepalive_enabled = true,
        .keepalive_interval_ms = 30_000,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 30_000_000), mgr.keepalive_interval_us);

    // PING at 30s, not 45s
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(25_000_000));
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(30_000_000));
}

test "IdleTimeoutManager: getTimer returns correct deadline" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .keepalive_enabled = true,
        .now_us = 1_000_000,
    });

    // With keep-alive: deadline is keepalive_interval from last_activity
    const timer = mgr.getTimer() orelse unreachable;
    try std.testing.expectEqual(@as(u64, 16_000_000), timer); // 1M + 15M
}

test "IdleTimeoutManager: getTimer without keepalive" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .keepalive_enabled = false,
        .now_us = 0,
    });
    const timer = mgr.getTimer() orelse unreachable;
    try std.testing.expectEqual(@as(u64, 30_000_000), timer);
}

test "IdleTimeoutManager: timeRemaining" {
    const mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 30_000,
        .keepalive_enabled = false,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 20_000_000), mgr.timeRemaining(10_000_000));
    try std.testing.expectEqual(@as(u64, 0), mgr.timeRemaining(30_000_000));
    try std.testing.expectEqual(@as(u64, 0), mgr.timeRemaining(40_000_000));
}

test "IdleTimeoutManager: setPeerTimeout updates effective" {
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 60_000,
        .now_us = 0,
    });
    try std.testing.expectEqual(@as(u64, 60_000_000), mgr.effective_timeout_us);

    mgr.setPeerTimeout(30_000);
    try std.testing.expectEqual(@as(u64, 30_000_000), mgr.effective_timeout_us);
    try std.testing.expectEqual(@as(u64, 15_000_000), mgr.keepalive_interval_us);
}

test "IdleTimeoutManager: encodePing" {
    var buf: [4]u8 = undefined;
    const len = IdleTimeoutManager.encodePing(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "IdleTimeoutManager: encodePing buffer too small" {
    var buf: [0]u8 = .{};
    try std.testing.expect(IdleTimeoutManager.encodePing(&buf) == null);
}

test "IdleTimeoutManager: ALB 90s scenario" {
    // Simulate ALB with 90s idle timeout, keep-alive at 30s
    var mgr = IdleTimeoutManager.init(.{
        .local_idle_timeout_ms = 90_000,
        .peer_idle_timeout_ms = 90_000,
        .keepalive_enabled = true,
        .keepalive_interval_ms = 30_000,
        .now_us = 0,
    });

    // First PING at 30s
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(30_000_000));

    // Peer responds, activity at 30.05s
    mgr.onActivity(30_050_000);

    // No action until 60.05s
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(55_000_000));

    // Second PING at 60.05s
    try std.testing.expectEqual(IdleTimeoutManager.Action.send_ping, mgr.poll(60_050_000));

    // Peer responds
    mgr.onActivity(60_100_000);

    // Connection stays alive — no timeout at what would have been 90s from start
    try std.testing.expectEqual(IdleTimeoutManager.Action.none, mgr.poll(90_000_000));
    try std.testing.expect(!mgr.expired);
}
