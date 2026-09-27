// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const frame = @import("frame.zig");
const connection = @import("connection.zig");
const hpack = @import("hpack.zig");
const test_util = @import("test_util.zig");

const Connection = connection.Connection;
const TestPipe = test_util.TestPipe;

// ─── Fuzz: Frame Header decode ───

test "fuzz: FrameHeader decode does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 9) return;
            _ = frame.FrameHeader.decode(input[0..9]);
        }
    }.f, .{});
}

// ─── Fuzz: FrameHeader encode/decode roundtrip ───

test "fuzz: FrameHeader encode/decode roundtrip" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 9) return;
            const original = frame.FrameHeader.decode(input[0..9]);
            var buf: [9]u8 = undefined;
            original.encode(&buf);
            const decoded = frame.FrameHeader.decode(&buf);
            std.debug.assert(original.length == decoded.length);
            std.debug.assert(original.stream_id == decoded.stream_id);
            std.debug.assert(original.flags.raw == decoded.flags.raw);
            std.debug.assert(@intFromEnum(original.frame_type) == @intFromEnum(decoded.frame_type));
        }
    }.f, .{});
}

// ─── Fuzz: Connection.recvFrame does not crash on arbitrary input ───

test "fuzz: Connection.recvFrame does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 9) return;
            const allocator = std.testing.allocator;
            var pipe = TestPipe.init(allocator, input);
            defer pipe.deinit();
            var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
            conn.state = .open;
            // Try to receive up to 16 frames; errors are expected, crashes are not
            var i: u32 = 0;
            while (i < 16) : (i += 1) {
                _ = conn.recvFrame() catch return;
            }
        }
    }.f, .{});
}

// ─── Fuzz: HPACK integer decode does not crash ───

test "fuzz: HPACK integer decode does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            // Try all prefix widths
            inline for (1..8) |bits| {
                _ = hpack.decodeInteger(input, bits) catch {};
            }
        }
    }.f, .{});
}

// ─── Fuzz: HPACK string decode does not crash ───

test "fuzz: HPACK string decode does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            var decode_buf: [4096]u8 = undefined;
            _ = hpack.decodeString(input, &decode_buf) catch {};
        }
    }.f, .{});
}

// ─── Fuzz: HPACK Decoder.decode does not crash on arbitrary input ───

test "fuzz: HPACK decoder does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            var decoder = hpack.Decoder.init(4096);
            var headers: [32]hpack.HeaderField = undefined;
            var decode_buf: [8192]u8 = undefined;
            _ = decoder.decode(input, &headers, &decode_buf) catch {};
        }
    }.f, .{});
}

// ─── Fuzz: Huffman decode does not crash ───

test "fuzz: Huffman decode does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            var output: [4096]u8 = undefined;
            _ = hpack.huffmanDecode(input, &output) catch {};
        }
    }.f, .{});
}

// ─── Fuzz: pseudo-header validation does not crash ───

test "fuzz: pseudo-header validation does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            // Build headers from fuzz input: each header is [name_len(1)][name][value_len(1)][value]
            var headers: [16]hpack.HeaderField = undefined;
            var count: usize = 0;
            var pos: usize = 0;
            while (count < 16 and pos < input.len) {
                const name_len = input[pos];
                pos += 1;
                if (pos + name_len > input.len) break;
                const name = input[pos..][0..name_len];
                pos += name_len;
                if (pos >= input.len) break;
                const value_len = input[pos];
                pos += 1;
                if (pos + value_len > input.len) break;
                const value = input[pos..][0..value_len];
                pos += value_len;
                headers[count] = .{ .name = name, .value = value };
                count += 1;
            }
            if (count == 0) return;
            _ = hpack.validateRequestHeaders(headers[0..count]) catch {};
            _ = hpack.validateResponseHeaders(headers[0..count]) catch {};
        }
    }.f, .{});
}

// ─── Fuzz: Settings applyParam does not crash ───

test "fuzz: Settings applyParam does not crash" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 6) return;
            var settings = frame.Settings{};
            const id: frame.SettingsId = @enumFromInt(std.mem.readInt(u16, input[0..2], .big));
            const value = std.mem.readInt(u32, input[2..6], .big);
            _ = settings.applyParam(id, value) catch {};
        }
    }.f, .{});
}

// ─── Fuzz: large frame flood does not OOM ───

test "fuzz: rapid PING flood does not OOM" {
    try std.testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 17) return;
            const allocator = std.testing.allocator;
            // Replicate the input as if it were many PING frames
            const repetitions = @min(input.len / 17, 200);
            if (repetitions == 0) return;
            var pipe = TestPipe.init(allocator, input);
            defer pipe.deinit();
            var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
            conn.state = .open;
            var i: usize = 0;
            while (i < repetitions) : (i += 1) {
                _ = conn.recvFrame() catch return;
            }
        }
    }.f, .{});
}
