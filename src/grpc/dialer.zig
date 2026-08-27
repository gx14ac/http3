const std = @import("std");
const compat = @import("../io/compat.zig");
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
    reader: compat.AnyReader,
    writer: compat.AnyWriter,
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
/// Note: In 0.16.0, direct TCP connections are handled by the transport layer.
/// This stub exists for API compatibility.
pub const TcpDialer = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TcpDialer {
        return .{ .allocator = allocator };
    }

    pub fn dialer(self: *TcpDialer) Dialer {
        return .{
            .context = @ptrCast(self),
            .dialFn = dialFn,
        };
    }

    fn dialFn(_: *anyopaque, _: Endpoint) DialError!DialResult {
        return DialError.ConnectionRefused;
    }
};

// ─── Tests ───

test "TcpDialer: connection refused returns DialError" {
    var td = TcpDialer.init(std.testing.allocator);
    const d = td.dialer();

    const ep = Endpoint{ .address = resolver_mod.Address.initIp4(.{ 127, 0, 0, 1 }, 1) };
    const result = d.dial(ep);
    try std.testing.expectError(DialError.ConnectionRefused, result);
}
