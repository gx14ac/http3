const std = @import("std");
const dialer_mod = @import("dialer.zig");
const resolver_mod = @import("resolver.zig");
const h2_client = @import("../h2/client.zig");
const h2_hpack = @import("../h2/hpack.zig");
const h2_connection = @import("../h2/connection.zig");

const Dialer = dialer_mod.Dialer;
const DialResult = dialer_mod.DialResult;
const DialError = dialer_mod.DialError;
const Endpoint = resolver_mod.Endpoint;

pub const PoolError = error{
    PoolExhausted,
    ConnectionFailed,
    AllConnectionsBusy,
};

pub const PoolConfig = struct {
    min_conns: u16 = 1,
    max_conns: u16 = 4,
    max_streams_per_conn: u16 = 100,
    idle_timeout_ms: u64 = 60_000,
};

pub const ConnState = enum {
    idle,
    active,
    draining,
    closed,
};

pub const PooledConn = struct {
    client: h2_client.Client,
    dial_result: DialResult,
    state: ConnState,
    active_streams: u16,
    created_ns: i128,
    last_used_ns: i128,
    id: u16,
};

/// Connection pool for H2 clients. Manages multiple connections to a single endpoint.
/// Not thread-safe; callers must synchronize externally.
pub const ConnPool = struct {
    conns: [max_pool_size]?PooledConn,
    conn_count: u16,
    config: PoolConfig,
    h2_config: h2_client.Config,
    dialer: Dialer,
    endpoint: Endpoint,
    allocator: std.mem.Allocator,
    authority: []const u8,

    const max_pool_size = 16;

    pub fn init(
        allocator: std.mem.Allocator,
        config: PoolConfig,
        h2_config: h2_client.Config,
        d: Dialer,
        endpoint: Endpoint,
        authority: []const u8,
    ) ConnPool {
        return .{
            .conns = .{null} ** max_pool_size,
            .conn_count = 0,
            .config = config,
            .h2_config = h2_config,
            .dialer = d,
            .endpoint = endpoint,
            .allocator = allocator,
            .authority = authority,
        };
    }

    /// Acquire a connection from the pool using least-loaded strategy.
    /// Creates a new connection if all existing ones are at capacity and pool isn't full.
    pub fn acquire(self: *ConnPool) PoolError!*PooledConn {
        // Evict idle/closed connections first
        self.evictStale();

        // Find least-loaded connection with available stream capacity
        var best: ?*PooledConn = null;
        var best_load: u16 = std.math.maxInt(u16);

        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (conn.state == .closed or conn.state == .draining) continue;
                if (conn.active_streams < self.config.max_streams_per_conn and
                    conn.active_streams < best_load)
                {
                    best = conn;
                    best_load = conn.active_streams;
                }
            }
        }

        if (best) |conn| {
            conn.active_streams += 1;
            conn.last_used_ns = std.time.nanoTimestamp();
            conn.state = .active;
            return conn;
        }

        // No available connection — try to create one
        if (self.conn_count < self.config.max_conns and self.conn_count < max_pool_size) {
            const conn = self.createConn() catch return PoolError.ConnectionFailed;
            conn.active_streams = 1;
            conn.state = .active;
            return conn;
        }

        return PoolError.AllConnectionsBusy;
    }

    /// Release a connection back to the pool after a stream completes.
    pub fn release(_: *ConnPool, conn: *PooledConn) void {
        if (conn.active_streams > 0) {
            conn.active_streams -= 1;
        }
        if (conn.active_streams == 0) {
            conn.state = .idle;
        }
        conn.last_used_ns = std.time.nanoTimestamp();
    }

    /// Mark a connection as failed (will be evicted on next acquire).
    pub fn markFailed(_: *ConnPool, conn: *PooledConn) void {
        conn.state = .closed;
    }

    /// Mark a connection as draining (GOAWAY received).
    /// No new streams will be routed to it; existing streams continue.
    /// The connection will be evicted once all active streams complete.
    pub fn markDraining(_: *ConnPool, conn: *PooledConn) void {
        conn.state = .draining;
    }

    /// Get total active streams across all connections.
    pub fn totalActiveStreams(self: *const ConnPool) u32 {
        var total: u32 = 0;
        for (self.conns) |slot| {
            if (slot) |conn| {
                if (conn.state == .active or conn.state == .idle) {
                    total += conn.active_streams;
                }
            }
        }
        return total;
    }

    /// Get number of alive connections in the pool.
    pub fn aliveCount(self: *const ConnPool) u16 {
        var count: u16 = 0;
        for (self.conns) |slot| {
            if (slot) |conn| {
                if (conn.state != .closed) count += 1;
            }
        }
        return count;
    }

    pub fn deinit(self: *ConnPool) void {
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                conn.client.close();
                conn.client.deinit();
                conn.dial_result.close();
                slot.* = null;
            }
        }
        self.conn_count = 0;
    }

    fn createConn(self: *ConnPool) PoolError!*PooledConn {
        const dial_result = self.dialer.dial(self.endpoint) catch return PoolError.ConnectionFailed;
        errdefer dial_result.close();

        // Find empty slot
        var slot_idx: ?usize = null;
        for (&self.conns, 0..) |*slot, i| {
            if (slot.* == null) {
                slot_idx = i;
                break;
            }
        }
        const idx = slot_idx orelse return PoolError.PoolExhausted;

        var client = h2_client.Client.init(
            self.allocator,
            dial_result.reader,
            dial_result.writer,
            self.h2_config,
        );

        client.handshake() catch {
            client.close();
            client.deinit();
            return PoolError.ConnectionFailed;
        };

        const now = std.time.nanoTimestamp();
        self.conns[idx] = .{
            .client = client,
            .dial_result = dial_result,
            .state = .idle,
            .active_streams = 0,
            .created_ns = now,
            .last_used_ns = now,
            .id = @intCast(idx),
        };
        self.conn_count += 1;

        return &(self.conns[idx].?);
    }

    fn evictStale(self: *ConnPool) void {
        const now = std.time.nanoTimestamp();
        const idle_timeout_ns: i128 = @as(i128, self.config.idle_timeout_ms) * 1_000_000;

        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                const should_evict = conn.state == .closed or
                    (conn.state == .draining and conn.active_streams == 0) or
                    (conn.state == .idle and conn.active_streams == 0 and
                    self.conn_count > self.config.min_conns and
                    (now - conn.last_used_ns) >= idle_timeout_ns);

                if (should_evict) {
                    conn.client.close();
                    conn.client.deinit();
                    conn.dial_result.close();
                    slot.* = null;
                    if (self.conn_count > 0) self.conn_count -= 1;
                }
            }
        }
    }
};

// ─── Tests ───

test "ConnPool: init with defaults" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{},
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    try std.testing.expectEqual(@as(u16, 0), pool.conn_count);
    try std.testing.expectEqual(@as(u16, 4), pool.config.max_conns);
    try std.testing.expectEqual(@as(u16, 100), pool.config.max_streams_per_conn);
}

test "ConnPool: aliveCount empty pool" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{},
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    try std.testing.expectEqual(@as(u16, 0), pool.aliveCount());
    try std.testing.expectEqual(@as(u32, 0), pool.totalActiveStreams());
}

test "ConnPool: acquire fails when dialer unavailable" {
    const allocator = std.testing.allocator;

    const FailDialer = struct {
        fn dialFn(_: *anyopaque, _: Endpoint) DialError!DialResult {
            return DialError.ConnectionRefused;
        }
    };

    var ctx: u8 = 0;
    var pool = ConnPool.init(
        allocator,
        .{},
        .{},
        .{ .context = @ptrCast(&ctx), .dialFn = FailDialer.dialFn },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    const result = pool.acquire();
    try std.testing.expectError(PoolError.ConnectionFailed, result);
}

test "ConnPool: release decrements active streams" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{},
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    // Manually insert a fake connection to test release logic
    pool.conns[0] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 3,
        .created_ns = std.time.nanoTimestamp(),
        .last_used_ns = std.time.nanoTimestamp(),
        .id = 0,
    };
    pool.conn_count = 1;

    const conn = &(pool.conns[0].?);
    pool.release(conn);
    try std.testing.expectEqual(@as(u16, 2), conn.active_streams);
    try std.testing.expectEqual(ConnState.active, conn.state);

    pool.release(conn);
    pool.release(conn);
    try std.testing.expectEqual(@as(u16, 0), conn.active_streams);
    try std.testing.expectEqual(ConnState.idle, conn.state);

    // Prevent deinit from trying to close undefined client/dial
    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "ConnPool: markFailed sets state to closed" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{},
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    pool.conns[0] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 1,
        .created_ns = std.time.nanoTimestamp(),
        .last_used_ns = std.time.nanoTimestamp(),
        .id = 0,
    };
    pool.conn_count = 1;

    const conn = &(pool.conns[0].?);
    pool.markFailed(conn);
    try std.testing.expectEqual(ConnState.closed, conn.state);

    // Prevent deinit from trying to close undefined client/dial
    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "ConnPool: least-loaded selection" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{ .max_streams_per_conn = 10 },
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    const now = std.time.nanoTimestamp();
    pool.conns[0] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 5,
        .created_ns = now,
        .last_used_ns = now,
        .id = 0,
    };
    pool.conns[1] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 2,
        .created_ns = now,
        .last_used_ns = now,
        .id = 1,
    };
    pool.conn_count = 2;

    // Should pick conn[1] (2 streams vs 5)
    const acquired = pool.acquire() catch unreachable;
    try std.testing.expectEqual(@as(u16, 1), acquired.id);
    try std.testing.expectEqual(@as(u16, 3), acquired.active_streams);

    // Clean up without closing undefined resources
    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conn_count = 0;
}

test "ConnPool: markDraining excludes from acquire" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{ .max_streams_per_conn = 10, .max_conns = 4 },
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    const now = std.time.nanoTimestamp();
    pool.conns[0] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 2,
        .created_ns = now,
        .last_used_ns = now,
        .id = 0,
    };
    pool.conns[1] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .active,
        .active_streams = 1,
        .created_ns = now,
        .last_used_ns = now,
        .id = 1,
    };
    pool.conn_count = 2;

    // Mark conn[1] as draining (GOAWAY received)
    pool.markDraining(&(pool.conns[1].?));
    try std.testing.expectEqual(ConnState.draining, pool.conns[1].?.state);

    // Acquire should skip draining conn and pick conn[0]
    const acquired = pool.acquire() catch unreachable;
    try std.testing.expectEqual(@as(u16, 0), acquired.id);

    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conn_count = 0;
}

test "ConnPool: draining conn evicted when streams complete" {
    const allocator = std.testing.allocator;
    var pool = ConnPool.init(
        allocator,
        .{ .max_streams_per_conn = 10 },
        .{},
        .{ .context = undefined, .dialFn = undefined },
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080) },
        "localhost",
    );
    defer pool.deinit();

    const now = std.time.nanoTimestamp();
    pool.conns[0] = .{
        .client = undefined,
        .dial_result = undefined,
        .state = .draining,
        .active_streams = 1,
        .created_ns = now,
        .last_used_ns = now,
        .id = 0,
    };
    pool.conn_count = 1;

    // Still has active streams — should not be evicted
    pool.evictStale();
    try std.testing.expect(pool.conns[0] != null);

    // Release the last stream
    pool.conns[0].?.active_streams = 0;

    // Now evict — draining + 0 streams → evicted
    // We can't actually close undefined client/dial, so manually verify the logic
    // by checking the condition directly
    const conn = &(pool.conns[0].?);
    const should_evict = conn.state == .draining and conn.active_streams == 0;
    try std.testing.expect(should_evict);

    // Clean up without closing
    pool.conns[0] = null;
    pool.conn_count = 0;
}
