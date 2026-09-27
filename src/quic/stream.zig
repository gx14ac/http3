// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const packet_mod = @import("packet.zig");

/// QUIC stream types (RFC 9000 §2.1).
/// Stream ID encoding: low 2 bits = type.
pub const StreamType = enum(u2) {
    client_bidi = 0,
    server_bidi = 1,
    client_uni = 2,
    server_uni = 3,
};

/// Stream state machine (RFC 9000 §3).
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset,
};

/// A single QUIC stream with send/recv buffers and flow control.
pub const Stream = struct {
    id: u62,
    state: StreamState,
    // Send side
    send_offset: u64,
    send_fin: bool,
    send_max: u64,
    // Recv side
    recv_offset: u64,
    recv_fin: bool,
    recv_max: u64,

    pub fn init(id: u62, initial_max_data: u64) Stream {
        return .{
            .id = id,
            .state = .idle,
            .send_offset = 0,
            .send_fin = false,
            .send_max = initial_max_data,
            .recv_offset = 0,
            .recv_fin = false,
            .recv_max = initial_max_data,
        };
    }

    pub fn streamType(self: *const Stream) StreamType {
        return @enumFromInt(@as(u2, @intCast(self.id & 0x03)));
    }

    pub fn isLocallyInitiated(self: *const Stream, is_server: bool) bool {
        const stype = self.streamType();
        if (is_server) {
            return stype == .server_bidi or stype == .server_uni;
        }
        return stype == .client_bidi or stype == .client_uni;
    }

    /// Mark the send side as finished. Transitions state.
    pub fn finishSend(self: *Stream) void {
        self.send_fin = true;
        switch (self.state) {
            .open => self.state = .half_closed_local,
            .half_closed_remote => self.state = .closed,
            else => {},
        }
    }

    /// Mark the recv side as finished. Transitions state.
    pub fn finishRecv(self: *Stream) void {
        self.recv_fin = true;
        switch (self.state) {
            .open => self.state = .half_closed_remote,
            .half_closed_local => self.state = .closed,
            else => {},
        }
    }

    /// Mark stream as reset.
    pub fn reset(self: *Stream) void {
        self.state = .reset;
    }
};

/// STREAM frame (RFC 9000 §19.8).
/// Frame type encodes flags: 0x08 | OFF(0x04) | LEN(0x02) | FIN(0x01).
pub const StreamFrame = struct {
    stream_id: u62,
    offset: u64,
    data: []const u8,
    fin: bool,

    /// Encode a STREAM frame into buf. Returns bytes written.
    pub fn encode(self: StreamFrame, buf: []u8) ?usize {
        var pos: usize = 0;

        // Frame type byte: 0x08 base + flags
        var frame_type: u8 = 0x08;
        if (self.offset > 0) frame_type |= 0x04; // OFF
        frame_type |= 0x02; // LEN (always include length for safety)
        if (self.fin) frame_type |= 0x01; // FIN

        if (buf.len < 1) return null;
        buf[pos] = frame_type;
        pos += 1;

        // Stream ID (varint)
        pos += packet_mod.encodeVarint(buf[pos..], self.stream_id) orelse return null;

        // Offset (varint, only if OFF flag set)
        if (self.offset > 0) {
            pos += packet_mod.encodeVarint(buf[pos..], @intCast(self.offset)) orelse return null;
        }

        // Length (varint)
        pos += packet_mod.encodeVarint(buf[pos..], self.data.len) orelse return null;

        // Data
        if (buf.len < pos + self.data.len) return null;
        @memcpy(buf[pos..][0..self.data.len], self.data);
        pos += self.data.len;

        return pos;
    }

    /// Decode a STREAM frame from payload starting at frame type byte.
    pub fn decode(data: []const u8) ?DecodedStreamFrame {
        if (data.len == 0) return null;
        const frame_type = data[0];
        if (frame_type & 0xF8 != 0x08) return null; // not a STREAM frame

        const has_offset = (frame_type & 0x04) != 0;
        const has_length = (frame_type & 0x02) != 0;
        const has_fin = (frame_type & 0x01) != 0;

        var pos: usize = 1;

        // Stream ID
        const id_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
        const stream_id: u62 = @intCast(id_result.value);
        pos += id_result.consumed;

        // Offset
        var offset: u64 = 0;
        if (has_offset) {
            const off_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
            offset = off_result.value;
            pos += off_result.consumed;
        }

        // Length and data
        var frame_data: []const u8 = undefined;
        var consumed: usize = undefined;
        if (has_length) {
            const len_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += len_result.consumed;
            const data_len: usize = @intCast(len_result.value);
            if (data.len < pos + data_len) return null;
            frame_data = data[pos..][0..data_len];
            consumed = pos + data_len;
        } else {
            // No length: data extends to end of packet
            frame_data = data[pos..];
            consumed = data.len;
        }

        return .{
            .frame = .{
                .stream_id = stream_id,
                .offset = offset,
                .data = frame_data,
                .fin = has_fin,
            },
            .consumed = consumed,
        };
    }
};

pub const DecodedStreamFrame = struct {
    frame: StreamFrame,
    consumed: usize,
};

/// Stream ID allocator for a QUIC connection.
pub const StreamAllocator = struct {
    next_bidi: u62,
    next_uni: u62,
    max_bidi: u62,
    max_uni: u62,
    is_server: bool,

    pub fn init(is_server: bool, max_bidi: u62, max_uni: u62) StreamAllocator {
        return .{
            .next_bidi = if (is_server) 1 else 0,
            .next_uni = if (is_server) 3 else 2,
            .max_bidi = max_bidi,
            .max_uni = max_uni,
            .is_server = is_server,
        };
    }

    /// Peek at the next bidi stream ID without allocating.
    pub fn peekNextBidi(self: *const StreamAllocator) ?u62 {
        const id = self.next_bidi;
        if (id / 4 >= self.max_bidi) return null;
        return id;
    }

    /// Allocate the next bidirectional stream ID.
    pub fn allocBidi(self: *StreamAllocator) ?u62 {
        const id = self.next_bidi;
        if (id / 4 >= self.max_bidi) return null;
        self.next_bidi += 4;
        return id;
    }

    /// Allocate the next unidirectional stream ID.
    pub fn allocUni(self: *StreamAllocator) ?u62 {
        const id = self.next_uni;
        if (id / 4 >= self.max_uni) return null;
        self.next_uni += 4;
        return id;
    }

    /// Update the max streams limit (from MAX_STREAMS frame).
    pub fn updateMaxBidi(self: *StreamAllocator, max: u62) void {
        if (max > self.max_bidi) self.max_bidi = max;
    }

    pub fn updateMaxUni(self: *StreamAllocator, max: u62) void {
        if (max > self.max_uni) self.max_uni = max;
    }
};

/// MAX_DATA frame (RFC 9000 §19.9).
pub const MaxDataFrame = struct {
    maximum_data: u64,

    pub fn encode(self: MaxDataFrame, buf: []u8) ?usize {
        var pos: usize = 0;
        if (buf.len < 1) return null;
        buf[0] = 0x10; // MAX_DATA
        pos = 1;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(self.maximum_data)) orelse return null;
        return pos;
    }

    pub fn decode(data: []const u8) ?MaxDataFrame {
        if (data.len < 2) return null;
        if (data[0] != 0x10) return null;
        const v = packet_mod.decodeVarint(data[1..]) orelse return null;
        return .{ .maximum_data = v.value };
    }
};

/// MAX_STREAM_DATA frame (RFC 9000 §19.10).
pub const MaxStreamDataFrame = struct {
    stream_id: u62,
    maximum_stream_data: u64,

    pub fn encode(self: MaxStreamDataFrame, buf: []u8) ?usize {
        var pos: usize = 0;
        if (buf.len < 1) return null;
        buf[0] = 0x11; // MAX_STREAM_DATA
        pos = 1;
        pos += packet_mod.encodeVarint(buf[pos..], self.stream_id) orelse return null;
        pos += packet_mod.encodeVarint(buf[pos..], @intCast(self.maximum_stream_data)) orelse return null;
        return pos;
    }

    pub fn decode(data: []const u8) ?MaxStreamDataFrame {
        if (data.len < 2) return null;
        if (data[0] != 0x11) return null;
        var pos: usize = 1;
        const id = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += id.consumed;
        const max = packet_mod.decodeVarint(data[pos..]) orelse return null;
        return .{
            .stream_id = @intCast(id.value),
            .maximum_stream_data = max.value,
        };
    }
};

// ─── Tests ───

test "StreamAllocator: client bidi stream IDs" {
    var alloc = StreamAllocator.init(false, 10, 10);
    try std.testing.expectEqual(@as(u62, 0), alloc.allocBidi().?);
    try std.testing.expectEqual(@as(u62, 4), alloc.allocBidi().?);
    try std.testing.expectEqual(@as(u62, 8), alloc.allocBidi().?);
}

test "StreamAllocator: server bidi stream IDs" {
    var alloc = StreamAllocator.init(true, 10, 10);
    try std.testing.expectEqual(@as(u62, 1), alloc.allocBidi().?);
    try std.testing.expectEqual(@as(u62, 5), alloc.allocBidi().?);
}

test "StreamAllocator: client uni stream IDs" {
    var alloc = StreamAllocator.init(false, 10, 10);
    try std.testing.expectEqual(@as(u62, 2), alloc.allocUni().?);
    try std.testing.expectEqual(@as(u62, 6), alloc.allocUni().?);
}

test "StreamAllocator: respects max_streams limit" {
    var alloc = StreamAllocator.init(false, 2, 1);
    try std.testing.expect(alloc.allocBidi() != null);
    try std.testing.expect(alloc.allocBidi() != null);
    try std.testing.expect(alloc.allocBidi() == null); // limit reached

    try std.testing.expect(alloc.allocUni() != null);
    try std.testing.expect(alloc.allocUni() == null); // limit reached
}

test "StreamAllocator: updateMaxBidi extends limit" {
    var alloc = StreamAllocator.init(false, 1, 1);
    _ = alloc.allocBidi();
    try std.testing.expect(alloc.allocBidi() == null);
    alloc.updateMaxBidi(2);
    try std.testing.expect(alloc.allocBidi() != null);
}

test "Stream: state transitions" {
    var s = Stream.init(0, 65536);
    try std.testing.expectEqual(StreamState.idle, s.state);

    s.state = .open;
    s.finishSend();
    try std.testing.expectEqual(StreamState.half_closed_local, s.state);

    s.finishRecv();
    try std.testing.expectEqual(StreamState.closed, s.state);
}

test "Stream: recv then send closes" {
    var s = Stream.init(4, 65536);
    s.state = .open;
    s.finishRecv();
    try std.testing.expectEqual(StreamState.half_closed_remote, s.state);
    s.finishSend();
    try std.testing.expectEqual(StreamState.closed, s.state);
}

test "Stream: type detection" {
    const s0 = Stream.init(0, 0);
    try std.testing.expectEqual(StreamType.client_bidi, s0.streamType());

    const s1 = Stream.init(1, 0);
    try std.testing.expectEqual(StreamType.server_bidi, s1.streamType());

    const s2 = Stream.init(2, 0);
    try std.testing.expectEqual(StreamType.client_uni, s2.streamType());

    const s3 = Stream.init(3, 0);
    try std.testing.expectEqual(StreamType.server_uni, s3.streamType());
}

test "StreamFrame: encode/decode roundtrip" {
    const data = "hello quic";
    const frame = StreamFrame{
        .stream_id = 4,
        .offset = 0,
        .data = data,
        .fin = false,
    };

    var buf: [64]u8 = undefined;
    const written = frame.encode(&buf) orelse unreachable;
    const decoded = StreamFrame.decode(buf[0..written]) orelse unreachable;

    try std.testing.expectEqual(@as(u62, 4), decoded.frame.stream_id);
    try std.testing.expectEqual(@as(u64, 0), decoded.frame.offset);
    try std.testing.expectEqualStrings(data, decoded.frame.data);
    try std.testing.expect(!decoded.frame.fin);
    try std.testing.expectEqual(written, decoded.consumed);
}

test "StreamFrame: with offset and fin" {
    const data = "world";
    const frame = StreamFrame{
        .stream_id = 8,
        .offset = 1024,
        .data = data,
        .fin = true,
    };

    var buf: [64]u8 = undefined;
    const written = frame.encode(&buf) orelse unreachable;
    const decoded = StreamFrame.decode(buf[0..written]) orelse unreachable;

    try std.testing.expectEqual(@as(u62, 8), decoded.frame.stream_id);
    try std.testing.expectEqual(@as(u64, 1024), decoded.frame.offset);
    try std.testing.expectEqualStrings(data, decoded.frame.data);
    try std.testing.expect(decoded.frame.fin);
}

test "StreamFrame: empty data with fin" {
    const frame = StreamFrame{
        .stream_id = 0,
        .offset = 0,
        .data = &.{},
        .fin = true,
    };

    var buf: [16]u8 = undefined;
    const written = frame.encode(&buf) orelse unreachable;
    const decoded = StreamFrame.decode(buf[0..written]) orelse unreachable;

    try std.testing.expect(decoded.frame.fin);
    try std.testing.expectEqual(@as(usize, 0), decoded.frame.data.len);
}

test "MaxDataFrame: encode/decode" {
    const frame = MaxDataFrame{ .maximum_data = 1048576 };
    var buf: [16]u8 = undefined;
    const written = frame.encode(&buf) orelse unreachable;
    const decoded = MaxDataFrame.decode(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 1048576), decoded.maximum_data);
}

test "MaxStreamDataFrame: encode/decode" {
    const frame = MaxStreamDataFrame{ .stream_id = 12, .maximum_stream_data = 262144 };
    var buf: [16]u8 = undefined;
    const written = frame.encode(&buf) orelse unreachable;
    const decoded = MaxStreamDataFrame.decode(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 12), decoded.stream_id);
    try std.testing.expectEqual(@as(u64, 262144), decoded.maximum_stream_data);
}
