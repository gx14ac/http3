const std = @import("std");
const frame = @import("frame.zig");

pub const TestPipe = struct {
    read_buf: []const u8,
    read_pos: usize,
    write_buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, input: []const u8) TestPipe {
        return .{
            .read_buf = input,
            .read_pos = 0,
            .write_buf = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TestPipe) void {
        self.write_buf.deinit(self.allocator);
    }

    pub fn reader(self: *TestPipe) std.io.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }

    pub fn writer(self: *TestPipe) std.io.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
    }

    pub fn written(self: TestPipe) []const u8 {
        return self.write_buf.items;
    }

    fn readFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
        const self: *TestPipe = @constCast(@alignCast(@ptrCast(ctx)));
        if (self.read_pos >= self.read_buf.len) return 0;
        const available = self.read_buf[self.read_pos..];
        const len = @min(buf.len, available.len);
        @memcpy(buf[0..len], available[0..len]);
        self.read_pos += len;
        return len;
    }

    fn writeFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
        const self: *TestPipe = @constCast(@alignCast(@ptrCast(ctx)));
        try self.write_buf.appendSlice(self.allocator, data);
        return data.len;
    }
};

pub fn appendSettingsAck(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) !void {
    var ack_buf: [9]u8 = undefined;
    _ = frame.buildSettingsAck(&ack_buf);
    try buf.appendSlice(allocator, &ack_buf);
}
