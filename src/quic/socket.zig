const std = @import("std");
const posix = std.posix;

pub const UdpSocketError = error{
    SocketCreationFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    Timeout,
};

/// Minimal UDP socket wrapper for QUIC datagram I/O.
pub const UdpSocket = struct {
    fd: posix.socket_t,
    remote: std.net.Address,

    /// Create a UDP socket and bind to an ephemeral port.
    pub fn init(remote: std.net.Address) UdpSocketError!UdpSocket {
        const family: u32 = switch (remote.any.family) {
            posix.AF.INET => posix.AF.INET,
            posix.AF.INET6 => posix.AF.INET6,
            else => return UdpSocketError.SocketCreationFailed,
        };

        const fd = posix.socket(family, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch
            return UdpSocketError.SocketCreationFailed;

        return .{ .fd = fd, .remote = remote };
    }

    /// Set receive timeout.
    pub fn setTimeout(self: *UdpSocket, timeout_ms: u64) void {
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }

    /// Send a datagram to the remote address.
    pub fn send(self: *UdpSocket, data: []const u8) UdpSocketError!usize {
        const n = posix.sendto(self.fd, data, 0, &self.remote.any, self.remote.getOsSockLen()) catch
            return UdpSocketError.SendFailed;
        return n;
    }

    /// Receive a datagram. Returns the number of bytes received.
    pub fn recv(self: *UdpSocket, buf: []u8) UdpSocketError!usize {
        const n = posix.recvfrom(self.fd, buf, 0, null, null) catch |e| {
            return switch (e) {
                error.WouldBlock => UdpSocketError.Timeout,
                else => UdpSocketError.RecvFailed,
            };
        };
        return n;
    }

    pub fn close(self: *UdpSocket) void {
        posix.close(self.fd);
    }
};

// ─── Tests ───

test "UdpSocket: create and close" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9999);
    var sock = try UdpSocket.init(addr);
    defer sock.close();
    // Just verify socket was created successfully
    try std.testing.expect(sock.fd != 0);
}

test "UdpSocket: send to unreachable returns ok (UDP is fire-and-forget)" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 1);
    var sock = try UdpSocket.init(addr);
    defer sock.close();

    const data = "test datagram";
    const n = try sock.send(data);
    try std.testing.expectEqual(data.len, n);
}

test "UdpSocket: recv timeout" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 1);
    var sock = try UdpSocket.init(addr);
    defer sock.close();

    // Set very short timeout
    sock.setTimeout(1);

    var buf: [1024]u8 = undefined;
    const result = sock.recv(&buf);
    try std.testing.expectError(UdpSocketError.Timeout, result);
}
