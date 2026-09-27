// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const posix = std.posix;
const compat = @import("compat.zig");

pub const TcpTransport = struct {
    fd: posix.fd_t,

    pub fn connect(host: []const u8, port: u16) !TcpTransport {
        _ = host;
        _ = port;
        return error.Unsupported;
    }

    pub fn connectFd(fd: posix.fd_t) TcpTransport {
        setNoDelay(fd);
        return .{ .fd = fd };
    }

    fn setNoDelay(fd: posix.fd_t) void {
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};
    }

    pub fn close(self: TcpTransport) void {
        posix.close(self.fd);
    }

    pub fn reader(self: *TcpTransport) compat.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }

    pub fn writer(self: *TcpTransport) compat.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
    }

    fn readFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
        const self: *TcpTransport = @constCast(@alignCast(@ptrCast(ctx)));
        return posix.read(self.fd, buf) catch |e| return e;
    }

    fn writeFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
        const self: *TcpTransport = @constCast(@alignCast(@ptrCast(ctx)));
        const rc = std.c.write(self.fd, data.ptr, data.len);
        if (rc < 0) return error.WriteFailed;
        return @intCast(rc);
    }
};
