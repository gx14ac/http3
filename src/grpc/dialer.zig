const std = @import("std");
const resolver_mod = @import("resolver.zig");
const Endpoint = resolver_mod.Endpoint;

pub const DialError = error{
    ConnectionRefused,
    Timeout,
    NetworkUnreachable,
    IoError,
};

/// Result of a dial operation: a reader/writer pair for the connection.
/// Caller owns the connection and is responsible for cleanup via `closeFn`.
pub const DialResult = struct {
    reader: std.io.AnyReader,
    writer: std.io.AnyWriter,
    closeFn: *const fn (ctx: *anyopaque) void,
    close_ctx: *anyopaque,

    pub fn close(self: DialResult) void {
        self.closeFn(self.close_ctx);
    }
};

/// Type-erased dialer interface: connects to an endpoint and returns reader/writer.
pub const Dialer = struct {
    context: *anyopaque,
    dialFn: *const fn (ctx: *anyopaque, endpoint: Endpoint) DialError!DialResult,

    pub fn dial(self: Dialer, endpoint: Endpoint) DialError!DialResult {
        return self.dialFn(self.context, endpoint);
    }
};

/// TCP dialer: connects via TCP to the endpoint's address.
/// Connections are returned as raw TCP reader/writer pairs.
pub const TcpDialer = struct {
    timeout: ?std.posix.timeval = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TcpDialer {
        return .{ .allocator = allocator };
    }

    pub fn withTimeout(allocator: std.mem.Allocator, timeout_sec: i64) TcpDialer {
        return .{ .allocator = allocator, .timeout = .{ .sec = timeout_sec, .usec = 0 } };
    }

    pub fn dialer(self: *TcpDialer) Dialer {
        return .{
            .context = @ptrCast(self),
            .dialFn = dialFn,
        };
    }

    fn dialFn(ctx: *anyopaque, endpoint: Endpoint) DialError!DialResult {
        const self: *TcpDialer = @alignCast(@ptrCast(ctx));
        const stream = std.net.tcpConnectToAddress(endpoint.address) catch
            return DialError.ConnectionRefused;

        if (self.timeout) |t| {
            std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&t)) catch {};
            std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&t)) catch {};
        }

        const conn = self.allocator.create(TcpConn) catch return DialError.IoError;
        conn.* = .{ .stream = stream, .allocator = self.allocator };

        return .{
            .reader = .{ .context = @ptrCast(conn), .readFn = tcpReadFn },
            .writer = .{ .context = @ptrCast(conn), .writeFn = tcpWriteFn },
            .closeFn = tcpCloseFn,
            .close_ctx = @ptrCast(conn),
        };
    }
};

const TcpConn = struct {
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
};

fn tcpReadFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
    const conn: *TcpConn = @constCast(@alignCast(@ptrCast(ctx)));
    return conn.stream.read(buf) catch return error.IoError;
}

fn tcpWriteFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
    const conn: *TcpConn = @constCast(@alignCast(@ptrCast(ctx)));
    conn.stream.writeAll(data) catch return error.IoError;
    return data.len;
}

fn tcpCloseFn(ctx: *anyopaque) void {
    const conn: *TcpConn = @alignCast(@ptrCast(ctx));
    conn.stream.close();
    conn.allocator.destroy(conn);
}

// ─── Tests ───

test "TcpDialer: connection refused returns DialError" {
    var td = TcpDialer.init(std.testing.allocator);
    const d = td.dialer();

    // Connect to a port that's (almost certainly) not listening
    const ep = Endpoint{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 1) };
    const result = d.dial(ep);
    try std.testing.expectError(DialError.ConnectionRefused, result);
}

test "TcpDialer: withTimeout sets timeout" {
    const td = TcpDialer.withTimeout(std.testing.allocator, 5);
    try std.testing.expectEqual(@as(i64, 5), td.timeout.?.sec);
}
