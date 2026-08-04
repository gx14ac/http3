const std = @import("std");
const posix = std.posix;
const net = std.net;

pub const TcpTransport = struct {
    fd: posix.fd_t,

    pub const ConnectError = net.TcpConnectToHostError;

    pub fn connect(host: []const u8, port: u16) ConnectError!TcpTransport {
        const stream = try net.tcpConnectToHost(std.heap.page_allocator, host, port);
        setNoDelay(stream.handle);
        return .{ .fd = stream.handle };
    }

    pub fn connectAddress(address: net.Address) net.TcpConnectToAddressError!TcpTransport {
        const stream = try net.tcpConnectToAddress(address);
        setNoDelay(stream.handle);
        return .{ .fd = stream.handle };
    }

    fn setNoDelay(fd: posix.fd_t) void {
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};
    }

    pub fn close(self: TcpTransport) void {
        posix.close(self.fd);
    }

    pub fn reader(self: *TcpTransport) std.io.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }

    pub fn writer(self: *TcpTransport) std.io.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
    }

    fn readFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
        const self: *TcpTransport = @constCast(@alignCast(@ptrCast(ctx)));
        return posix.read(self.fd, buf) catch |e| return e;
    }

    fn writeFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
        const self: *TcpTransport = @constCast(@alignCast(@ptrCast(ctx)));
        return posix.write(self.fd, data) catch |e| return e;
    }
};
