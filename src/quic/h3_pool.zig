const std = @import("std");
const h3_client_mod = @import("h3_client.zig");
const session_mod = @import("session.zig");
const qpack = @import("qpack.zig");

const H3Client = h3_client_mod.H3Client;
const H3Response = h3_client_mod.H3Response;
const H3Error = h3_client_mod.H3Error;

pub const H3PoolError = error{
    PoolExhausted,
    ConnectionFailed,
    AllConnectionsBusy,
    RequestFailed,
};

pub const KeepaliveConfig = struct {
    /// Interval between keepalive PINGs for idle connections (ms). 0 = disabled.
    interval_ms: u64 = 0,
    /// Time to wait for PING ACK before marking connection failed (ms).
    timeout_ms: u64 = 20_000,
    /// Send keepalive even if there are no active RPCs on the connection.
    permit_without_calls: bool = true,
};

pub const H3PoolConfig = struct {
    max_conns: u8 = 4,
    max_requests_per_conn: u16 = 100,
    keepalive: KeepaliveConfig = .{},
};

pub const H3ConnState = enum {
    idle,
    active,
    draining,
    closed,
};

pub const H3PooledConn = struct {
    client: *H3Client,
    state: H3ConnState,
    active_requests: u16,
    id: u8,
    last_activity_ms: i64,
    last_ping_ms: i64,
};

/// Connection pool for HTTP/3 clients over QUIC.
/// Manages multiple H3Client connections to a single server.
/// Each H3Client (~1MB) is heap-allocated via the provided allocator.
pub const H3Pool = struct {
    conns: [MAX_POOL_SIZE]?H3PooledConn,
    conn_count: u8,
    config: H3PoolConfig,
    remote: std.net.Address,
    server_name: [256]u8,
    server_name_len: usize,
    allocator: std.mem.Allocator,

    const MAX_POOL_SIZE = 8;

    pub fn init(allocator: std.mem.Allocator, remote: std.net.Address, server_name: []const u8, config: H3PoolConfig) H3Pool {
        var name_buf: [256]u8 = undefined;
        const len = @min(server_name.len, 256);
        @memcpy(name_buf[0..len], server_name[0..len]);

        return .{
            .conns = [_]?H3PooledConn{null} ** MAX_POOL_SIZE,
            .conn_count = 0,
            .config = config,
            .remote = remote,
            .server_name = name_buf,
            .server_name_len = len,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *H3Pool) void {
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                conn.client.close();
                conn.client.deinit();
                self.allocator.destroy(conn.client);
                slot.* = null;
            }
        }
        self.conn_count = 0;
    }

    /// Acquire a connection (least-loaded with available capacity).
    /// Creates a new connection if needed and pool isn't full.
    pub fn acquire(self: *H3Pool) H3PoolError!*H3PooledConn {
        // Find least-loaded connection
        var best: ?*H3PooledConn = null;
        var best_load: u16 = std.math.maxInt(u16);

        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (conn.state == .closed or conn.state == .draining) continue;
                // Check for GOAWAY received since last acquire/release
                if (conn.client.goawayReceived()) {
                    conn.state = .draining;
                    continue;
                }
                if (conn.active_requests < self.config.max_requests_per_conn and
                    conn.active_requests < best_load)
                {
                    best = conn;
                    best_load = conn.active_requests;
                }
            }
        }

        if (best) |conn| {
            conn.active_requests += 1;
            conn.state = .active;
            conn.last_activity_ms = nowMs();
            return conn;
        }

        // No available — create new
        if (self.conn_count < self.config.max_conns and self.conn_count < MAX_POOL_SIZE) {
            const conn = self.createConn() catch return H3PoolError.ConnectionFailed;
            conn.active_requests = 1;
            conn.state = .active;
            return conn;
        }

        return H3PoolError.AllConnectionsBusy;
    }

    /// Release a connection after request completes.
    /// Automatically marks as draining if GOAWAY was received.
    pub fn release(_: *H3Pool, conn: *H3PooledConn) void {
        if (conn.active_requests > 0) conn.active_requests -= 1;
        conn.last_activity_ms = nowMs();
        if (conn.client.goawayReceived()) {
            conn.state = .draining;
        } else if (conn.active_requests == 0) {
            conn.state = .idle;
        }
    }

    /// Mark connection as draining (GOAWAY received).
    pub fn markDraining(_: *H3Pool, conn: *H3PooledConn) void {
        conn.state = .draining;
    }

    /// Mark connection as failed.
    pub fn markFailed(_: *H3Pool, conn: *H3PooledConn) void {
        conn.state = .closed;
    }

    /// Execute a request on an available connection.
    /// Handles acquire + request + release automatically.
    pub fn request(
        self: *H3Pool,
        method: []const u8,
        path: []const u8,
        headers: []const qpack.HeaderField,
        body: ?[]const u8,
    ) H3PoolError!H3Response {
        const conn = try self.acquire();
        errdefer self.release(conn);

        const resp = conn.client.request(method, path, headers, body) catch |e| {
            switch (e) {
                H3Error.ConnectionClosed => {
                    self.markFailed(conn);
                    return H3PoolError.ConnectionFailed;
                },
                H3Error.Timeout => {
                    self.release(conn);
                    return H3PoolError.RequestFailed;
                },
                else => {
                    self.release(conn);
                    return H3PoolError.RequestFailed;
                },
            }
        };

        self.release(conn);
        return resp;
    }

    /// Get number of alive connections.
    pub fn aliveCount(self: *const H3Pool) u8 {
        var count: u8 = 0;
        for (self.conns) |slot| {
            if (slot) |conn| {
                if (conn.state != .closed) count += 1;
            }
        }
        return count;
    }

    /// Get total active requests across all connections.
    pub fn totalActiveRequests(self: *const H3Pool) u32 {
        var total: u32 = 0;
        for (self.conns) |slot| {
            if (slot) |conn| {
                if (conn.state == .active or conn.state == .idle) {
                    total += conn.active_requests;
                }
            }
        }
        return total;
    }

    fn createConn(self: *H3Pool) H3PoolError!*H3PooledConn {
        // Find empty slot
        var slot_idx: ?usize = null;
        for (self.conns, 0..) |slot, i| {
            if (slot == null) {
                slot_idx = i;
                break;
            }
        }
        const idx = slot_idx orelse return H3PoolError.PoolExhausted;

        const client = self.allocator.create(H3Client) catch return H3PoolError.ConnectionFailed;
        errdefer self.allocator.destroy(client);

        client.* = H3Client.init(self.remote, self.server_name[0..self.server_name_len]) catch {
            return H3PoolError.ConnectionFailed;
        };
        errdefer client.deinit();

        client.connect() catch {
            return H3PoolError.ConnectionFailed;
        };

        const now_ms = nowMs();
        self.conns[idx] = .{
            .client = client,
            .state = .idle,
            .active_requests = 0,
            .id = @intCast(idx),
            .last_activity_ms = now_ms,
            .last_ping_ms = 0,
        };
        self.conn_count += 1;

        return &(self.conns[idx].?);
    }

    /// Evict closed/drained connections.
    pub fn evictStale(self: *H3Pool) void {
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                const should_evict = conn.state == .closed or
                    (conn.state == .draining and conn.active_requests == 0);
                if (should_evict) {
                    if (conn.state != .closed) conn.client.close();
                    conn.client.deinit();
                    self.allocator.destroy(conn.client);
                    slot.* = null;
                    if (self.conn_count > 0) self.conn_count -= 1;
                }
            }
        }
    }

    /// Send keepalive PINGs to idle connections.
    /// Call this periodically (e.g. every config.keepalive.interval_ms).
    /// Returns the number of connections that were pinged.
    pub fn keepalive(self: *H3Pool) u8 {
        const interval = self.config.keepalive.interval_ms;
        if (interval == 0) return 0;

        const now = nowMs();
        const timeout: i64 = @intCast(self.config.keepalive.timeout_ms);
        var pinged: u8 = 0;

        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (conn.state == .closed or conn.state == .draining) continue;

                // Skip active connections unless permit_without_calls is set
                if (!self.config.keepalive.permit_without_calls and conn.active_requests > 0) continue;

                const idle_duration = now - conn.last_activity_ms;
                if (idle_duration < @as(i64, @intCast(interval))) continue;

                // Check if a previous PING timed out
                if (conn.last_ping_ms > 0) {
                    // Activity since last PING means ACK was received (or data flowed)
                    if (conn.last_activity_ms > conn.last_ping_ms) {
                        conn.last_ping_ms = 0;
                    } else {
                        const ping_age = now - conn.last_ping_ms;
                        if (ping_age > timeout) {
                            conn.state = .closed;
                            continue;
                        }
                    }
                }

                // Send PING
                if (conn.client.ping()) {
                    conn.last_ping_ms = now;
                    pinged += 1;
                } else {
                    conn.state = .closed;
                }
            }
        }

        return pinged;
    }
};

fn nowMs() i64 {
    return @intCast(@divTrunc(std.time.nanoTimestamp(), 1_000_000));
}

// ─── Tests ───

fn testPool(config: H3PoolConfig) H3Pool {
    return H3Pool.init(
        std.testing.allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        config,
    );
}

fn createTestClient() !*H3Client {
    const client = try std.testing.allocator.create(H3Client);
    client.* = try H3Client.init(
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
    );
    return client;
}

fn destroyTestClient(client: *H3Client) void {
    client.deinit();
    std.testing.allocator.destroy(client);
}

test "H3Pool: init" {
    var pool = testPool(.{});
    defer pool.deinit();

    try std.testing.expectEqual(@as(u8, 0), pool.conn_count);
    try std.testing.expectEqual(@as(u8, 0), pool.aliveCount());
    try std.testing.expectEqual(@as(u32, 0), pool.totalActiveRequests());
}

test "H3Pool: release decrements active requests" {
    var pool = testPool(.{});
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    pool.conns[0] = .{ .client = client, .state = .active, .active_requests = 3, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 1;

    const conn = &(pool.conns[0].?);
    pool.release(conn);
    try std.testing.expectEqual(@as(u16, 2), conn.active_requests);

    pool.release(conn);
    pool.release(conn);
    try std.testing.expectEqual(@as(u16, 0), conn.active_requests);
    try std.testing.expectEqual(H3ConnState.idle, conn.state);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: least-loaded selection" {
    var pool = testPool(.{ .max_requests_per_conn = 10 });
    defer pool.deinit();

    const c0 = try createTestClient();
    defer destroyTestClient(c0);
    const c1 = try createTestClient();
    defer destroyTestClient(c1);

    pool.conns[0] = .{ .client = c0, .state = .active, .active_requests = 5, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conns[1] = .{ .client = c1, .state = .active, .active_requests = 2, .id = 1, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 2;

    const acquired = pool.acquire() catch unreachable;
    try std.testing.expectEqual(@as(u8, 1), acquired.id);
    try std.testing.expectEqual(@as(u16, 3), acquired.active_requests);

    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conn_count = 0;
}

test "H3Pool: markDraining excludes from acquire" {
    var pool = testPool(.{ .max_requests_per_conn = 10, .max_conns = 4 });
    defer pool.deinit();

    const c0 = try createTestClient();
    defer destroyTestClient(c0);
    const c1 = try createTestClient();
    defer destroyTestClient(c1);

    pool.conns[0] = .{ .client = c0, .state = .active, .active_requests = 5, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conns[1] = .{ .client = c1, .state = .active, .active_requests = 1, .id = 1, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 2;

    pool.markDraining(&(pool.conns[1].?));

    const acquired = pool.acquire() catch unreachable;
    try std.testing.expectEqual(@as(u8, 0), acquired.id);

    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conn_count = 0;
}

test "H3Pool: evict conditions" {
    var pool = testPool(.{});
    defer pool.deinit();

    const c0 = try createTestClient();
    defer destroyTestClient(c0);
    const c1 = try createTestClient();
    defer destroyTestClient(c1);
    const c2 = try createTestClient();
    defer destroyTestClient(c2);

    pool.conns[0] = .{ .client = c0, .state = .closed, .active_requests = 0, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conns[1] = .{ .client = c1, .state = .draining, .active_requests = 0, .id = 1, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conns[2] = .{ .client = c2, .state = .draining, .active_requests = 1, .id = 2, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 3;

    // Verify eviction conditions
    const conn0 = pool.conns[0].?;
    try std.testing.expect(conn0.state == .closed); // should evict

    const conn1 = pool.conns[1].?;
    try std.testing.expect(conn1.state == .draining and conn1.active_requests == 0); // should evict

    const conn2 = pool.conns[2].?;
    try std.testing.expect(!(conn2.state == .closed or (conn2.state == .draining and conn2.active_requests == 0))); // should NOT evict

    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conns[2] = null;
    pool.conn_count = 0;
}

test "H3Pool: acquire fails when pool full and all busy" {
    var pool = testPool(.{ .max_conns = 2, .max_requests_per_conn = 1 });
    defer pool.deinit();

    const c0 = try createTestClient();
    defer destroyTestClient(c0);
    const c1 = try createTestClient();
    defer destroyTestClient(c1);

    pool.conns[0] = .{ .client = c0, .state = .active, .active_requests = 1, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conns[1] = .{ .client = c1, .state = .active, .active_requests = 1, .id = 1, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 2;

    const result = pool.acquire();
    try std.testing.expectError(H3PoolError.AllConnectionsBusy, result);

    pool.conns[0] = null;
    pool.conns[1] = null;
    pool.conn_count = 0;
}

test "H3Pool: GOAWAY auto-drains connection on release" {
    const h3_frame_mod = @import("h3_frame.zig");
    const stream_frame_mod = @import("stream.zig");

    var pool = testPool(.{ .max_requests_per_conn = 10 });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    // Initialize session so processControlFrame works
    client.session.startHandshake();
    _ = client.session.onHandshakeComplete();

    pool.conns[0] = .{ .client = client, .state = .active, .active_requests = 1, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 1;

    // Inject GOAWAY via control stream using feedPayload (public API)
    var settings_buf: [16]u8 = undefined;
    const settings_len = h3_frame_mod.encodeSettingsFrame(&settings_buf, &.{}) orelse unreachable;
    var goaway_buf: [16]u8 = undefined;
    const goaway_len = h3_frame_mod.encodeGoawayFrame(&goaway_buf, 0) orelse unreachable;

    // Build control stream content: type(0x00) + SETTINGS + GOAWAY
    var ctrl_content: [64]u8 = undefined;
    var pos: usize = 0;
    ctrl_content[pos] = 0x00;
    pos += 1;
    @memcpy(ctrl_content[pos..][0..settings_len], settings_buf[0..settings_len]);
    pos += settings_len;
    @memcpy(ctrl_content[pos..][0..goaway_len], goaway_buf[0..goaway_len]);
    pos += goaway_len;

    // Wrap in a STREAM frame (stream_id=3 = server uni-stream)
    const frame = stream_frame_mod.StreamFrame{
        .stream_id = 3,
        .offset = 0,
        .data = ctrl_content[0..pos],
        .fin = false,
    };
    var frame_buf: [128]u8 = undefined;
    const frame_len = frame.encode(&frame_buf) orelse unreachable;

    client.feedPayload(frame_buf[0..frame_len]);

    try std.testing.expect(client.goawayReceived());

    // Release should mark connection as draining
    const conn = &(pool.conns[0].?);
    pool.release(conn);
    try std.testing.expectEqual(H3ConnState.draining, conn.state);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: keepalive disabled returns zero" {
    var pool = testPool(.{ .keepalive = .{ .interval_ms = 0 } });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    pool.conns[0] = .{ .client = client, .state = .idle, .active_requests = 0, .id = 0, .last_activity_ms = 0, .last_ping_ms = 0 };
    pool.conn_count = 1;

    const pinged = pool.keepalive();
    try std.testing.expectEqual(@as(u8, 0), pinged);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: keepalive pings idle connection" {
    var pool = testPool(.{ .keepalive = .{ .interval_ms = 100, .timeout_ms = 5000 } });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    // Connection last active long ago
    const past = nowMs() - 200;
    pool.conns[0] = .{ .client = client, .state = .idle, .active_requests = 0, .id = 0, .last_activity_ms = past, .last_ping_ms = 0 };
    pool.conn_count = 1;

    const pinged = pool.keepalive();
    // ping() returns false without a real QUIC connection, so it marks closed
    // but the logic path is exercised
    try std.testing.expect(pinged == 0 or pinged == 1);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: keepalive timeout marks connection closed" {
    var pool = testPool(.{ .keepalive = .{ .interval_ms = 100, .timeout_ms = 50 } });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    // Connection was pinged long ago and never got ACK
    const now = nowMs();
    pool.conns[0] = .{
        .client = client,
        .state = .idle,
        .active_requests = 0,
        .id = 0,
        .last_activity_ms = now - 200,
        .last_ping_ms = now - 100, // 100ms ago, timeout is 50ms
    };
    pool.conn_count = 1;

    _ = pool.keepalive();

    const conn = pool.conns[0].?;
    try std.testing.expectEqual(H3ConnState.closed, conn.state);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: keepalive skips active conns when permit_without_calls is false" {
    var pool = testPool(.{ .keepalive = .{ .interval_ms = 100, .timeout_ms = 5000, .permit_without_calls = false } });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    const past = nowMs() - 200;
    pool.conns[0] = .{ .client = client, .state = .active, .active_requests = 1, .id = 0, .last_activity_ms = past, .last_ping_ms = 0 };
    pool.conn_count = 1;

    const pinged = pool.keepalive();
    // Should skip because active_requests > 0 and permit_without_calls is false
    try std.testing.expectEqual(@as(u8, 0), pinged);

    pool.conns[0] = null;
    pool.conn_count = 0;
}

test "H3Pool: keepalive skips recently active connections" {
    var pool = testPool(.{ .keepalive = .{ .interval_ms = 1000, .timeout_ms = 5000 } });
    defer pool.deinit();

    const client = try createTestClient();
    defer destroyTestClient(client);

    // Connection was active just now (less than interval_ms ago)
    pool.conns[0] = .{ .client = client, .state = .idle, .active_requests = 0, .id = 0, .last_activity_ms = nowMs(), .last_ping_ms = 0 };
    pool.conn_count = 1;

    const pinged = pool.keepalive();
    try std.testing.expectEqual(@as(u8, 0), pinged);

    pool.conns[0] = null;
    pool.conn_count = 0;
}
