// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// gRPC Length-Prefixed Message framing (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
///
/// Wire format:
///   [compressed: 1 byte] [message length: 4 bytes (big-endian)] [message: N bytes]
pub const FrameHeader = struct {
    compressed: bool,
    length: u32,

    pub const encoded_size = 5;

    pub fn encode(self: FrameHeader, buf: *[5]u8) void {
        buf[0] = if (self.compressed) 1 else 0;
        std.mem.writeInt(u32, buf[1..5], self.length, .big);
    }

    pub fn decode(buf: *const [5]u8) FrameHeader {
        return .{
            .compressed = buf[0] != 0,
            .length = std.mem.readInt(u32, buf[1..5], .big),
        };
    }
};

pub const EncodeError = error{
    MessageTooLarge,
    BufferTooSmall,
};

pub const DecodeError = error{
    BufferTooSmall,
    IncompleteMessage,
    MessageTooLarge,
};

/// Encode a gRPC message into a buffer with length-prefix framing.
/// Returns the total encoded slice (5-byte header + payload).
pub fn encodeMessage(buf: []u8, payload: []const u8, compressed: bool) EncodeError![]u8 {
    const total = FrameHeader.encoded_size + payload.len;
    if (total > buf.len) return EncodeError.BufferTooSmall;

    const hdr = FrameHeader{
        .compressed = compressed,
        .length = @intCast(payload.len),
    };
    hdr.encode(buf[0..5]);
    @memcpy(buf[5..][0..payload.len], payload);
    return buf[0..total];
}

/// Decode a gRPC message from a buffer. Returns the payload slice and bytes consumed.
pub fn decodeMessage(buf: []const u8, max_message_size: u32) DecodeError!struct { payload: []const u8, consumed: usize } {
    if (buf.len < FrameHeader.encoded_size) return DecodeError.IncompleteMessage;

    const hdr = FrameHeader.decode(buf[0..5]);
    if (hdr.length > max_message_size) return DecodeError.MessageTooLarge;

    const total = FrameHeader.encoded_size + @as(usize, hdr.length);
    if (buf.len < total) return DecodeError.IncompleteMessage;

    return .{
        .payload = buf[5..total],
        .consumed = total,
    };
}

// ─── Tests ───

test "encode and decode message" {
    var buf: [256]u8 = undefined;
    const payload = "hello gRPC";
    const encoded = try encodeMessage(&buf, payload, false);

    try std.testing.expectEqual(@as(usize, 5 + payload.len), encoded.len);
    try std.testing.expectEqual(@as(u8, 0), encoded[0]); // not compressed

    const decoded = try decodeMessage(encoded, 1024);
    try std.testing.expectEqualStrings(payload, decoded.payload);
    try std.testing.expectEqual(@as(usize, 5 + payload.len), decoded.consumed);
}

test "encode compressed flag" {
    var buf: [64]u8 = undefined;
    const encoded = try encodeMessage(&buf, "data", true);
    try std.testing.expectEqual(@as(u8, 1), encoded[0]);
}

test "decode incomplete header" {
    const buf = [_]u8{ 0, 0, 0 };
    try std.testing.expectError(DecodeError.IncompleteMessage, decodeMessage(&buf, 1024));
}

test "decode incomplete payload" {
    var buf: [8]u8 = undefined;
    const hdr = FrameHeader{ .compressed = false, .length = 100 };
    hdr.encode(buf[0..5]);
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    try std.testing.expectError(DecodeError.IncompleteMessage, decodeMessage(&buf, 1024));
}

test "decode message too large" {
    var buf: [10]u8 = undefined;
    const hdr = FrameHeader{ .compressed = false, .length = 1000 };
    hdr.encode(buf[0..5]);
    try std.testing.expectError(DecodeError.MessageTooLarge, decodeMessage(buf[0..5], 512));
}

test "encode buffer too small" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(EncodeError.BufferTooSmall, encodeMessage(&buf, "hello", false));
}

test "empty message" {
    var buf: [5]u8 = undefined;
    const encoded = try encodeMessage(&buf, "", false);
    try std.testing.expectEqual(@as(usize, 5), encoded.len);

    const decoded = try decodeMessage(encoded, 1024);
    try std.testing.expectEqual(@as(usize, 0), decoded.payload.len);
}
