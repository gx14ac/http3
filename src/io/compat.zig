const std = @import("std");

pub const AnyReader = struct {
    context: *const anyopaque,
    readFn: *const fn (context: *const anyopaque, buffer: []u8) anyerror!usize,

    pub fn read(self: AnyReader, buffer: []u8) anyerror!usize {
        return self.readFn(self.context, buffer);
    }

    pub fn readAll(self: AnyReader, buffer: []u8) anyerror!usize {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.read(buffer[index..]);
            if (n == 0) return index;
            index += n;
        }
        return index;
    }
};

pub const AnyWriter = struct {
    context: *const anyopaque,
    writeFn: *const fn (context: *const anyopaque, bytes: []const u8) anyerror!usize,

    pub fn write(self: AnyWriter, bytes: []const u8) anyerror!usize {
        return self.writeFn(self.context, bytes);
    }

    pub fn writeAll(self: AnyWriter, bytes: []const u8) anyerror!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.write(bytes[index..]);
        }
    }
};
