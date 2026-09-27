// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// Reconnection state machine with exponential backoff.
///
/// Tracks disconnection events and schedules reconnect attempts with
/// configurable backoff (initial_delay_ms * 2^attempt), capped at max_delay_ms.
/// Supports jitter to prevent thundering herd on mass reconnect.
pub const ReconnectManager = struct {
    state: State,
    attempt: u32,
    last_disconnect_us: u64,
    next_attempt_us: u64,
    config: Config,
    consecutive_failures: u32,

    pub const State = enum {
        connected,
        disconnected,
        reconnecting,
        backoff,
        gave_up,
    };

    pub const Config = struct {
        initial_delay_ms: u64 = 1_000,
        max_delay_ms: u64 = 60_000,
        max_attempts: u32 = 0, // 0 = unlimited
        jitter_percent: u8 = 25,
    };

    pub const Action = enum {
        none,
        reconnect_now,
        wait,
        give_up,
    };

    pub fn init(config: Config) ReconnectManager {
        return .{
            .state = .connected,
            .attempt = 0,
            .last_disconnect_us = 0,
            .next_attempt_us = 0,
            .config = config,
            .consecutive_failures = 0,
        };
    }

    /// Signal that the connection was lost.
    pub fn onDisconnect(self: *ReconnectManager, now_us: u64) void {
        if (self.state == .gave_up) return;
        self.state = .backoff;
        self.last_disconnect_us = now_us;
        self.scheduleNext(now_us);
    }

    /// Signal that a reconnect attempt failed.
    pub fn onReconnectFailed(self: *ReconnectManager, now_us: u64) void {
        self.consecutive_failures += 1;
        self.attempt += 1;

        if (self.config.max_attempts > 0 and self.attempt >= self.config.max_attempts) {
            self.state = .gave_up;
            return;
        }

        self.state = .backoff;
        self.scheduleNext(now_us);
    }

    /// Signal that reconnection succeeded.
    pub fn onReconnected(self: *ReconnectManager) void {
        self.state = .connected;
        self.attempt = 0;
        self.consecutive_failures = 0;
        self.next_attempt_us = 0;
    }

    /// Poll for the next action.
    pub fn poll(self: *ReconnectManager, now_us: u64) Action {
        switch (self.state) {
            .connected => return .none,
            .reconnecting => return .none,
            .gave_up => return .give_up,
            .disconnected => return .reconnect_now,
            .backoff => {
                if (now_us >= self.next_attempt_us) {
                    self.state = .reconnecting;
                    return .reconnect_now;
                }
                return .wait;
            },
        }
    }

    /// Time remaining until the next reconnect attempt (microseconds).
    pub fn timeUntilNext(self: *const ReconnectManager, now_us: u64) ?u64 {
        if (self.state != .backoff) return null;
        if (now_us >= self.next_attempt_us) return 0;
        return self.next_attempt_us - now_us;
    }

    /// Current backoff delay in milliseconds for the next attempt.
    pub fn currentDelayMs(self: *const ReconnectManager) u64 {
        return self.computeDelay();
    }

    /// Reset to initial state (e.g., after user-initiated close).
    pub fn reset(self: *ReconnectManager) void {
        self.state = .connected;
        self.attempt = 0;
        self.consecutive_failures = 0;
        self.next_attempt_us = 0;
        self.last_disconnect_us = 0;
    }

    fn scheduleNext(self: *ReconnectManager, now_us: u64) void {
        const delay_ms = self.computeDelay();
        self.next_attempt_us = now_us + delay_ms * 1000;
    }

    fn computeDelay(self: *const ReconnectManager) u64 {
        const base = self.config.initial_delay_ms;
        const shift: u6 = @intCast(@min(self.attempt, 20));
        const exponential = base << shift;
        const capped = @min(exponential, self.config.max_delay_ms);

        if (self.config.jitter_percent == 0) return capped;

        // Deterministic jitter based on attempt count (no random needed)
        const jitter_range = capped * self.config.jitter_percent / 100;
        const jitter_offset = (self.attempt * 7 + 13) % (@as(u32, @intCast(@min(jitter_range, std.math.maxInt(u32)))) + 1);
        return capped -| jitter_range / 2 +| jitter_offset;
    }
};

// ─── Tests ───

test "ReconnectManager: initial state" {
    var rm = ReconnectManager.init(.{});
    try std.testing.expectEqual(ReconnectManager.State.connected, rm.state);
    try std.testing.expectEqual(ReconnectManager.Action.none, rm.poll(0));
}

test "ReconnectManager: disconnect triggers backoff" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 1000, .jitter_percent = 0 });
    rm.onDisconnect(100_000);
    try std.testing.expectEqual(ReconnectManager.State.backoff, rm.state);

    // Too early
    try std.testing.expectEqual(ReconnectManager.Action.wait, rm.poll(500_000));

    // After delay (1000ms = 1_000_000 us)
    try std.testing.expectEqual(ReconnectManager.Action.reconnect_now, rm.poll(1_100_001));
    try std.testing.expectEqual(ReconnectManager.State.reconnecting, rm.state);
}

test "ReconnectManager: exponential backoff" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 100, .max_delay_ms = 10_000, .jitter_percent = 0 });
    rm.onDisconnect(0);

    // attempt 0: 100ms
    try std.testing.expectEqual(@as(u64, 100), rm.currentDelayMs());

    rm.onReconnectFailed(100_000);
    // attempt 1: 200ms
    try std.testing.expectEqual(@as(u64, 200), rm.currentDelayMs());

    rm.onReconnectFailed(300_000);
    // attempt 2: 400ms
    try std.testing.expectEqual(@as(u64, 400), rm.currentDelayMs());

    rm.onReconnectFailed(700_000);
    // attempt 3: 800ms
    try std.testing.expectEqual(@as(u64, 800), rm.currentDelayMs());
}

test "ReconnectManager: max delay cap" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 1000, .max_delay_ms = 5000, .jitter_percent = 0 });
    rm.onDisconnect(0);
    rm.attempt = 10; // 1000 * 2^10 = 1024000, capped at 5000
    try std.testing.expectEqual(@as(u64, 5000), rm.currentDelayMs());
}

test "ReconnectManager: max attempts gives up" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 100, .max_attempts = 3, .jitter_percent = 0 });
    rm.onDisconnect(0);

    rm.onReconnectFailed(100_000);
    try std.testing.expectEqual(ReconnectManager.State.backoff, rm.state);

    rm.onReconnectFailed(300_000);
    try std.testing.expectEqual(ReconnectManager.State.backoff, rm.state);

    rm.onReconnectFailed(700_000);
    try std.testing.expectEqual(ReconnectManager.State.gave_up, rm.state);
    try std.testing.expectEqual(ReconnectManager.Action.give_up, rm.poll(1_000_000));
}

test "ReconnectManager: successful reconnect resets" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 100, .jitter_percent = 0 });
    rm.onDisconnect(0);
    rm.onReconnectFailed(100_000);
    rm.onReconnectFailed(300_000);
    try std.testing.expectEqual(@as(u32, 2), rm.attempt);

    rm.onReconnected();
    try std.testing.expectEqual(ReconnectManager.State.connected, rm.state);
    try std.testing.expectEqual(@as(u32, 0), rm.attempt);
    try std.testing.expectEqual(@as(u32, 0), rm.consecutive_failures);
}

test "ReconnectManager: timeUntilNext" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 1000, .jitter_percent = 0 });
    rm.onDisconnect(0);

    // next_attempt_us = 0 + 1000*1000 = 1_000_000
    try std.testing.expectEqual(@as(?u64, 500_000), rm.timeUntilNext(500_000));
    try std.testing.expectEqual(@as(?u64, 0), rm.timeUntilNext(1_000_000));
    try std.testing.expectEqual(@as(?u64, 0), rm.timeUntilNext(2_000_000));
}

test "ReconnectManager: reset clears state" {
    var rm = ReconnectManager.init(.{ .initial_delay_ms = 100, .max_attempts = 10, .jitter_percent = 0 });
    rm.onDisconnect(0);
    rm.onReconnectFailed(100_000);
    rm.onReconnectFailed(300_000);

    rm.reset();
    try std.testing.expectEqual(ReconnectManager.State.connected, rm.state);
    try std.testing.expectEqual(@as(u32, 0), rm.attempt);
    try std.testing.expectEqual(ReconnectManager.Action.none, rm.poll(0));
}
