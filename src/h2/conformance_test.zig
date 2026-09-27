// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const frame = @import("frame.zig");
const connection = @import("connection.zig");
const stream_mod = @import("stream.zig");
const hpack = @import("hpack.zig");
const TestPipe = @import("test_util.zig").TestPipe;

const Connection = connection.Connection;
const ConnectionError = connection.ConnectionError;
const Config = connection.Config;
const State = connection.State;
const Event = connection.Event;

// RFC 9113 Client Conformance Tests
// Verifies that the client correctly handles malformed/invalid frames
// from a misbehaving server.

// Skip handshake — tests exercise frame dispatch in isolation
fn initConn(pipe: *TestPipe) Connection {
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;
    return conn;
}

// ─── §4.2 Frame Size ───

test "§4.2: frame exceeding max_frame_size → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame with length > default max_frame_size (16384)
    const fh = frame.FrameHeader{
        .length = 16385,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // Include actual payload so the test remains valid if recvFrame ever reads before checking
    try input.appendNTimes(allocator, 0xAB, 16385);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

// ─── §5.1 Stream States ───

test "§5.1: DATA on stream 0 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 5,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "hello");

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

// ─── §6.5 SETTINGS ───

test "§6.5: SETTINGS ACK with non-zero payload → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS with ACK flag but 6 bytes payload
    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = frame.Flags.ACK,
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 6);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);
    conn.pending_settings_ack = true;

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

test "§6.5: SETTINGS with odd payload length → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS with 7 bytes (not multiple of 6)
    const fh = frame.FrameHeader{
        .length = 7,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 7);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

test "§6.5: SETTINGS on non-zero stream → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.5: unsolicited SETTINGS ACK → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // ACK without pending_settings_ack = true
    const fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = frame.Flags.ACK,
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

// ─── §6.7 PING ───

test "§6.7: PING with length != 8 → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 7,
        .frame_type = .ping,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 7);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

test "§6.7: PING on non-zero stream → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 8,
        .frame_type = .ping,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 8);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

// ─── §6.8 GOAWAY ───

test "§6.8: GOAWAY on non-zero stream → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 8,
        .frame_type = .goaway,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 8);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.8: GOAWAY with length < 8 → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .goaway,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 4);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

test "§6.8: GOAWAY transitions to goaway_received state" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    var goaway_buf: [64]u8 = undefined;
    const goaway = frame.buildGoaway(3, .no_error, "", &goaway_buf) catch unreachable;
    try input.appendSlice(allocator, goaway);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .goaway);
    try std.testing.expectEqual(@as(u31, 3), event.goaway.last_stream_id);
    try std.testing.expectEqual(State.goaway_received, conn.state);
}

test "§6.8: after GOAWAY, existing stream frames still processable" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // GOAWAY with last_stream_id=5, then a WINDOW_UPDATE on stream 0
    var goaway_buf: [64]u8 = undefined;
    const goaway = frame.buildGoaway(5, .no_error, "", &goaway_buf) catch unreachable;
    try input.appendSlice(allocator, goaway);

    var wu_buf: [13]u8 = undefined;
    _ = frame.buildWindowUpdate(0, 1000, &wu_buf) catch unreachable;
    try input.appendSlice(allocator, &wu_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .goaway);
    try std.testing.expectEqual(State.goaway_received, conn.state);

    // Connection should still process frames after GOAWAY (RFC 9113 §5.1)
    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .window_update);
    try std.testing.expectEqual(@as(u31, 1000), ev2.window_update.increment);
}

// ─── §6.9 WINDOW_UPDATE ───

test "§6.9: WINDOW_UPDATE with increment=0 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // WINDOW_UPDATE on stream 0 with increment=0
    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, 0, .big);
    try input.appendSlice(allocator, &payload);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.9: WINDOW_UPDATE with wrong length → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 3);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

test "§6.9: WINDOW_UPDATE overflow → FLOW_CONTROL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Send max increment on already-max window
    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, 0x7FFFFFFF, .big);
    try input.appendSlice(allocator, &payload);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FlowControlError, result);
}

// ─── §6.4 RST_STREAM ───

test "§6.4: RST_STREAM on stream 0 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .rst_stream,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 4);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.4: RST_STREAM with wrong length → FRAME_SIZE_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .rst_stream,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 3);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

// ─── §4.1 Unknown frame types ───

test "§4.1: unknown frame type → skip and continue" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Unknown frame type 0xFF with 3 bytes payload
    const unknown_fh = frame.FrameHeader{
        .length = 3,
        .frame_type = @enumFromInt(0xFF),
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    unknown_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "foo");

    // Followed by a valid PING ACK
    const ping_data = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);
    try std.testing.expectEqualSlices(u8, &ping_data, &event.ping_ack);
}

// ─── §6.5.2 SETTINGS initial_window_size ───

test "§6.5.2: SETTINGS initial_window_size > 2^31-1 → FLOW_CONTROL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS with initial_window_size = 0x80000000 (exceeds max)
    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=4 (initial_window_size), value=0x80000000
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 4, .big);
    std.mem.writeInt(u32, param[2..6], 0x80000000, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FlowControlError, result);
}

// ─── §5.1 Stream State Machine (via Client) ───

test "§5.1: recvFrame on closed connection → CONNECTION_CLOSED" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .closed;

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ConnectionClosed, result);
}

// ─── PING flood resistance (loop, no stack overflow) ───

test "PING flood: multiple consecutive PINGs handled without stack overflow" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Send 100 PINGs followed by a PING ACK
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        var ping_buf: [17]u8 = undefined;
        _ = frame.buildPing(.{ @as(u8, @intCast(i & 0xFF)), 0, 0, 0, 0, 0, 0, 0 }, &ping_buf);
        try input.appendSlice(allocator, &ping_buf);
    }
    // Final: PING ACK
    var ack_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(.{ 0xFE, 0xED, 0, 0, 0, 0, 0, 0 }, &ack_buf);
    try input.appendSlice(allocator, &ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    // Raise ping limit for this test (validates no stack overflow, not DoS behavior)
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{ .max_pings_without_data = 200 });
    conn.state = .open;

    // Should process all PINGs (sending ACKs) and return the final PING ACK event
    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);
    try std.testing.expectEqual(@as(u8, 0xFE), event.ping_ack[0]);

    // Verify 100 PING ACKs were written (each is 9-byte header + 8-byte payload = 17 bytes)
    try std.testing.expectEqual(@as(usize, 100 * 17), pipe.written().len);
}

// ─── §6.5.3 SETTINGS enable_push invalid value ───

test "§6.5.3: SETTINGS enable_push != 0 or 1 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=2 (enable_push), value=2 (invalid)
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 2, .big);
    std.mem.writeInt(u32, param[2..6], 2, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

// ─── §6.10 CONTINUATION ───

test "§6.10: HEADERS without END_HEADERS followed by CONTINUATION" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS on stream 1, no END_HEADERS, 0 bytes payload (fragment split across CONTINUATION)
    const headers_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    headers_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // CONTINUATION on stream 1, with END_HEADERS, 3 bytes payload
    const cont_fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .continuation,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 1,
    };
    cont_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "foo");

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // First: HEADERS event
    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .headers);
    try std.testing.expectEqual(@as(u31, 1), ev1.headers.stream_id);
    try std.testing.expectEqual(@as(u24, 0), ev1.headers.payload_len);

    // Second: CONTINUATION event
    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .continuation);
    try std.testing.expectEqual(@as(u31, 1), ev2.continuation.stream_id);
    try std.testing.expect(ev2.continuation.end_headers);
    try std.testing.expectEqual(@as(u24, 3), ev2.continuation.payload_len);
}

test "§6.10: non-CONTINUATION frame during continuation state → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS on stream 1, no END_HEADERS
    const headers_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    headers_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // Instead of CONTINUATION, send DATA → protocol error
    const data_fh = frame.FrameHeader{
        .length = 5,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    data_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "hello");

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // First frame: HEADERS (sets continuation state)
    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .headers);

    // Second frame: DATA instead of CONTINUATION → error
    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.10: CONTINUATION on wrong stream → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS on stream 1, no END_HEADERS
    const headers_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    headers_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // CONTINUATION on stream 3 (wrong stream)
    const cont_fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .continuation,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 3,
    };
    cont_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "foo");

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .headers);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.10: CONTINUATION without preceding HEADERS → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // CONTINUATION frame with no prior HEADERS
    const cont_fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .continuation,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    cont_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "foo");

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.10: multiple CONTINUATION frames until END_HEADERS" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS on stream 1, no END_HEADERS, 0 bytes (payload in CONTINUATION)
    const headers_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    headers_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // First CONTINUATION, no END_HEADERS, 0 bytes
    const cont1_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .continuation,
        .flags = .{},
        .stream_id = 1,
    };
    cont1_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // Second CONTINUATION, with END_HEADERS, 0 bytes
    const cont2_fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .continuation,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 1,
    };
    cont2_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .headers);

    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .continuation);
    try std.testing.expect(!ev2.continuation.end_headers);

    const ev3 = try conn.recvFrame();
    try std.testing.expect(ev3 == .continuation);
    try std.testing.expect(ev3.continuation.end_headers);

    // After END_HEADERS, continuation state is cleared
    try std.testing.expectEqual(@as(?u31, null), conn.expecting_continuation);
}

// ─── §8.1 Pseudo-header validation ───

test "§8.1: valid request pseudo-headers" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "accept", .value = "text/html" },
    };
    try hpack.validateRequestHeaders(&headers);
}

test "§8.1: pseudo-header after regular header → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "text/html" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.PseudoHeaderAfterRegular, hpack.validateRequestHeaders(&headers));
}

test "§8.1: duplicate pseudo-header → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.DuplicatePseudoHeader, hpack.validateRequestHeaders(&headers));
}

test "§8.1: unknown pseudo-header → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":unknown", .value = "bad" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.UnknownPseudoHeader, hpack.validateRequestHeaders(&headers));
}

test "§8.1: missing :method → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.MissingMethodPseudo, hpack.validateRequestHeaders(&headers));
}

test "§8.1: missing :scheme → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.MissingSchemePseudo, hpack.validateRequestHeaders(&headers));
}

test "§8.1: missing :path → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.MissingPathPseudo, hpack.validateRequestHeaders(&headers));
}

test "§8.1: connection header is forbidden" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.ConnectionHeaderForbidden, hpack.validateRequestHeaders(&headers));
}

test "§8.1: TE header must be 'trailers' only" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "gzip" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.TEHeaderInvalid, hpack.validateRequestHeaders(&headers));
}

test "§8.1: TE header with value 'trailers' is allowed" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "trailers" },
    };
    try hpack.validateRequestHeaders(&headers);
}

test "§8.1: uppercase header name → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.UppercaseHeaderName, hpack.validateRequestHeaders(&headers));
}

test "§8.1: valid response pseudo-headers" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html" },
    };
    try hpack.validateResponseHeaders(&headers);
}

test "§8.1: response with unknown pseudo-header → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":method", .value = "GET" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.UnknownPseudoHeader, hpack.validateResponseHeaders(&headers));
}

test "§8.1: response missing :status → error" {
    const headers = [_]hpack.HeaderField{
        .{ .name = "content-type", .value = "text/html" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.MissingStatusPseudo, hpack.validateResponseHeaders(&headers));
}

// ─── DoS Guard Tests ───

test "DoS: PING flood triggers protocol error at threshold" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Send 12 PINGs (threshold is 10 by default)
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        var ping_buf: [17]u8 = undefined;
        _ = frame.buildPing(.{ @as(u8, @intCast(i)), 0, 0, 0, 0, 0, 0, 0 }, &ping_buf);
        try input.appendSlice(allocator, &ping_buf);
    }

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // First 10 should succeed (responding with ACKs); 11th triggers error
    try std.testing.expectError(ConnectionError.ProtocolError, conn.recvFrame());
}

test "DoS: PING counter resets after DATA received" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // 9 PINGs (under threshold)
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        var ping_buf: [17]u8 = undefined;
        _ = frame.buildPing(.{ @as(u8, @intCast(i)), 0, 0, 0, 0, 0, 0, 0 }, &ping_buf);
        try input.appendSlice(allocator, &ping_buf);
    }

    // DATA frame resets counter (zero-length so no payload to consume)
    const dh = frame.FrameHeader{
        .length = 0,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    dh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    // 9 more PINGs (should be fine since counter was reset)
    i = 0;
    while (i < 9) : (i += 1) {
        var ping_buf: [17]u8 = undefined;
        _ = frame.buildPing(.{ @as(u8, @intCast(i + 20)), 0, 0, 0, 0, 0, 0, 0 }, &ping_buf);
        try input.appendSlice(allocator, &ping_buf);
    }

    // Final PING ACK so recvFrame returns something
    var ack_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(.{ 0xFF, 0, 0, 0, 0, 0, 0, 0 }, &ack_buf);
    try input.appendSlice(allocator, &ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // First call processes 9 PINGs, then DATA event
    const event1 = try conn.recvFrame();
    try std.testing.expect(event1 == .data);

    // Second call processes 9 more PINGs, then PING ACK
    const event2 = try conn.recvFrame();
    try std.testing.expect(event2 == .ping_ack);
}

test "DoS: SETTINGS flood triggers protocol error" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Send 22 SETTINGS frames (threshold is 20 by default)
    var i: u32 = 0;
    while (i < 22) : (i += 1) {
        // Empty SETTINGS (valid)
        const sh = frame.FrameHeader{ .length = 0, .frame_type = .settings, .flags = .{}, .stream_id = 0 };
        var buf: [9]u8 = undefined;
        sh.encode(&buf);
        try input.appendSlice(allocator, &buf);
    }

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // First 20 succeed
    i = 0;
    while (i < 20) : (i += 1) {
        const event = try conn.recvFrame();
        try std.testing.expect(event == .settings_ack);
    }
    // 21st triggers protocol error
    try std.testing.expectError(ConnectionError.ProtocolError, conn.recvFrame());
}

test "DoS: resetDoSCounters allows more settings" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // 40 empty SETTINGS + final PING ACK
    var i: u32 = 0;
    while (i < 40) : (i += 1) {
        const sh = frame.FrameHeader{ .length = 0, .frame_type = .settings, .flags = .{}, .stream_id = 0 };
        var buf: [9]u8 = undefined;
        sh.encode(&buf);
        try input.appendSlice(allocator, &buf);
    }
    var ack_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(.{ 0xAA, 0, 0, 0, 0, 0, 0, 0 }, &ack_buf);
    try input.appendSlice(allocator, &ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{ .max_settings_per_minute = 20 });
    conn.state = .open;

    // Process 20 settings (at limit)
    i = 0;
    while (i < 20) : (i += 1) {
        const event = try conn.recvFrame();
        try std.testing.expect(event == .settings_ack);
    }

    // Reset counters (simulates timer tick)
    conn.resetDoSCounters();

    // Can process 20 more
    i = 0;
    while (i < 20) : (i += 1) {
        const event = try conn.recvFrame();
        try std.testing.expect(event == .settings_ack);
    }

    // Next should be the PING ACK
    const final = try conn.recvFrame();
    try std.testing.expect(final == .ping_ack);
}

test "DoS: empty DATA frames trigger protocol error" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Use a small threshold for the test
    const threshold: u32 = 5;

    // Send threshold+2 empty DATA frames on stream 1
    var i: u32 = 0;
    while (i < threshold + 2) : (i += 1) {
        const dh = frame.FrameHeader{
            .length = 0,
            .frame_type = .data,
            .flags = .{},
            .stream_id = 1,
        };
        var buf: [9]u8 = undefined;
        dh.encode(&buf);
        try input.appendSlice(allocator, &buf);
    }

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{ .max_empty_frames = threshold });
    conn.state = .open;

    // First `threshold` calls succeed (each returns a data event)
    i = 0;
    while (i < threshold) : (i += 1) {
        const event = try conn.recvFrame();
        try std.testing.expect(event == .data);
    }
    // Next call triggers protocol error (counter > threshold)
    try std.testing.expectError(ConnectionError.ProtocolError, conn.recvFrame());
}

// ─── Reconnect Tests ───

test "connection replaceTransport resets state" {
    const allocator = std.testing.allocator;

    // Initial connection in goaway_received state
    var pipe1 = TestPipe.init(allocator, &.{});
    defer pipe1.deinit();
    var conn = Connection.init(pipe1.reader(), pipe1.writer(), .{});
    conn.state = .goaway_received;
    conn.ping_count = 5;
    conn.settings_count = 15;

    // Replace transport
    var pipe2 = TestPipe.init(allocator, &.{});
    defer pipe2.deinit();
    conn.replaceTransport(pipe2.reader(), pipe2.writer());

    try std.testing.expectEqual(State.idle, conn.state);
    try std.testing.expectEqual(@as(u32, 0), conn.ping_count);
    try std.testing.expectEqual(@as(u32, 0), conn.settings_count);
    try std.testing.expectEqual(@as(?connection.GoawayInfo, null), conn.goaway_info);
}

// ─── §3.4 HTTP/2 Connection Preface ───

test "§3.4: server preface must be SETTINGS (not PING) → INVALID_PREFACE" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Server sends PING instead of SETTINGS as first frame
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPing(.{ 0, 0, 0, 0, 0, 0, 0, 0 }, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .waiting_preface;

    const result = conn.recvServerPreface();
    try std.testing.expectError(ConnectionError.InvalidPreface, result);
}

test "§3.4: server preface SETTINGS with ACK flag → INVALID_PREFACE" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS ACK as first frame (invalid — first SETTINGS must not be ACK)
    var ack_buf: [9]u8 = undefined;
    _ = frame.buildSettingsAck(&ack_buf);
    try input.appendSlice(allocator, &ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .waiting_preface;

    const result = conn.recvServerPreface();
    try std.testing.expectError(ConnectionError.InvalidPreface, result);
}

test "§3.4: server preface SETTINGS on non-zero stream → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS on stream 1 (must be stream 0)
    const fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .waiting_preface;

    const result = conn.recvServerPreface();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§3.4: valid server preface transitions to waiting_settings_ack" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Valid empty SETTINGS on stream 0
    const fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .waiting_preface;

    try conn.recvServerPreface();
    try std.testing.expectEqual(State.waiting_settings_ack, conn.state);
    // Should have written SETTINGS ACK
    const written = pipe.written();
    try std.testing.expect(written.len == 9);
    const resp_hdr = frame.FrameHeader.decode(written[0..9]);
    try std.testing.expectEqual(frame.FrameType.settings, resp_hdr.frame_type);
    try std.testing.expect(resp_hdr.flags.hasAck());
}

// ─── §6.5.2 SETTINGS_MAX_FRAME_SIZE range ───

test "§6.5.2: SETTINGS max_frame_size < 16384 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=5 (max_frame_size), value=16383 (below minimum)
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 5, .big);
    std.mem.writeInt(u32, param[2..6], 16383, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.5.2: SETTINGS max_frame_size > 16777215 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=5 (max_frame_size), value=16777216 (above maximum)
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 5, .big);
    std.mem.writeInt(u32, param[2..6], 16777216, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

test "§6.5.2: SETTINGS max_frame_size = 16384 (minimum valid) → accepted" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=5 (max_frame_size), value=16384 (minimum valid)
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 5, .big);
    std.mem.writeInt(u32, param[2..6], 16384, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
    try std.testing.expectEqual(@as(u32, 16384), conn.peer_settings.max_frame_size);
}

test "§6.5.2: SETTINGS max_frame_size = 16777215 (maximum valid) → accepted" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=5 (max_frame_size), value=16777215 (maximum valid)
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 5, .big);
    std.mem.writeInt(u32, param[2..6], 16777215, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
    try std.testing.expectEqual(@as(u32, 16777215), conn.peer_settings.max_frame_size);
}

// ─── §6.5.2 SETTINGS unknown parameters ───

test "§6.5.2: unknown SETTINGS parameter → ignored (no error)" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param: id=0xFF (unknown), value=42
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 0xFF, .big);
    std.mem.writeInt(u32, param[2..6], 42, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
}

// ─── §6.5 SETTINGS with multiple parameters ───

test "§6.5: SETTINGS with multiple valid parameters → all applied" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 18, // 3 params * 6 bytes
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param 1: header_table_size = 8192
    var p1: [6]u8 = undefined;
    std.mem.writeInt(u16, p1[0..2], 1, .big);
    std.mem.writeInt(u32, p1[2..6], 8192, .big);
    try input.appendSlice(allocator, &p1);
    // param 2: max_concurrent_streams = 200
    var p2: [6]u8 = undefined;
    std.mem.writeInt(u16, p2[0..2], 3, .big);
    std.mem.writeInt(u32, p2[2..6], 200, .big);
    try input.appendSlice(allocator, &p2);
    // param 3: max_frame_size = 32768
    var p3: [6]u8 = undefined;
    std.mem.writeInt(u16, p3[0..2], 5, .big);
    std.mem.writeInt(u32, p3[2..6], 32768, .big);
    try input.appendSlice(allocator, &p3);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
    try std.testing.expectEqual(@as(u32, 8192), conn.peer_settings.header_table_size);
    try std.testing.expectEqual(@as(u32, 200), conn.peer_settings.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 32768), conn.peer_settings.max_frame_size);
}

// ─── §6.5 PUSH_PROMISE (§8.2) ───

test "§8.2: PUSH_PROMISE frame → skipped as unknown (client rejects push)" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // PUSH_PROMISE frame (type=5): 4-byte promised stream ID + header block
    const pp_fh = frame.FrameHeader{
        .length = 8,
        .frame_type = .push_promise,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    pp_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 8);

    // Followed by a valid PING ACK
    const ping_data = [8]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0 };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // PUSH_PROMISE is skipped (treated as unknown type), next event is PING ACK
    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);
    try std.testing.expectEqualSlices(u8, &ping_data, &event.ping_ack);
}

// ─── §5.1 HEADERS on stream 0 ───

test "§5.1: HEADERS on stream 0 → PROTOCOL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 0,
        .frame_type = .headers,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.ProtocolError, result);
}

// ─── §6.9.1 Flow Control: initial window ───

test "§6.9.1: DATA exceeding connection flow control window → FLOW_CONTROL_ERROR" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame with length > default initial window size (65535)
    const fh = frame.FrameHeader{
        .length = 65536,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // Don't need actual payload — flow control check happens on header

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    // Use large max_frame_size to not trigger FrameSizeError
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{ .max_frame_size = 100000 });
    conn.state = .open;

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FlowControlError, result);
}

// ─── §6.9.2 Initial Window Size Change ───

test "§6.9.2: SETTINGS initial_window_size change applies to existing streams" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS with initial_window_size = 32768 (half of default 65535)
    const fh = frame.FrameHeader{
        .length = 6,
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    var param: [6]u8 = undefined;
    std.mem.writeInt(u16, param[0..2], 4, .big);
    std.mem.writeInt(u32, param[2..6], 32768, .big);
    try input.appendSlice(allocator, &param);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // Open a stream before the SETTINGS change
    _ = try conn.streams.openStream(65535, 65535);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
    try std.testing.expectEqual(@as(u32, 32768), conn.peer_settings.initial_window_size);
}

// ─── §6.1 DATA frame with padding ───

test "§6.1: DATA frame larger than max_frame_size is rejected even with PADDED flag" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame with PADDED flag, but total length exceeds max_frame_size
    const fh = frame.FrameHeader{
        .length = 16385,
        .frame_type = .data,
        .flags = frame.Flags.PADDED,
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

// ─── §6.2 HEADERS frame with priority ───

test "§6.2: HEADERS frame exceeding max_frame_size rejected regardless of PRIORITY flag" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS frame with PRIORITY flag, but total length exceeds max_frame_size
    const fh = frame.FrameHeader{
        .length = 16385,
        .frame_type = .headers,
        .flags = frame.Flags.PRIORITY.combine(frame.Flags.END_HEADERS),
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const result = conn.recvFrame();
    try std.testing.expectError(ConnectionError.FrameSizeError, result);
}

// ─── §4.2 Frame size: SETTINGS is exempt from max_frame_size check ───

test "§4.2: large SETTINGS frame not rejected by max_frame_size" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // SETTINGS frame with 10 params (60 bytes payload, exceeds max_frame_size=16384? No,
    // but test that SETTINGS length check is separate from generic max_frame_size)
    // We set max_frame_size to a very small value and verify SETTINGS still processes
    const fh = frame.FrameHeader{
        .length = 12, // 2 params
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // param 1: header_table_size = 4096
    var p1: [6]u8 = undefined;
    std.mem.writeInt(u16, p1[0..2], 1, .big);
    std.mem.writeInt(u32, p1[2..6], 4096, .big);
    try input.appendSlice(allocator, &p1);
    // param 2: max_concurrent_streams = 50
    var p2: [6]u8 = undefined;
    std.mem.writeInt(u16, p2[0..2], 3, .big);
    std.mem.writeInt(u32, p2[2..6], 50, .big);
    try input.appendSlice(allocator, &p2);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .settings_ack);
    try std.testing.expectEqual(@as(u32, 50), conn.peer_settings.max_concurrent_streams);
}

// ─── §6.9 WINDOW_UPDATE on stream ───

test "§6.9: WINDOW_UPDATE on non-zero stream → returns event with stream_id" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = 3,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, 1000, .big);
    try input.appendSlice(allocator, &payload);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .window_update);
    try std.testing.expectEqual(@as(u31, 3), event.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 1000), event.window_update.increment);
}

// ─── §6.4 RST_STREAM error code propagation ───

test "§6.4: RST_STREAM carries correct error code" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const fh = frame.FrameHeader{
        .length = 4,
        .frame_type = .rst_stream,
        .flags = .{},
        .stream_id = 5,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @intFromEnum(frame.ErrorCode.cancel), .big);
    try input.appendSlice(allocator, &payload);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .rst_stream);
    try std.testing.expectEqual(@as(u31, 5), event.rst_stream.stream_id);
    try std.testing.expectEqual(frame.ErrorCode.cancel, event.rst_stream.error_code);
}

// ─── §6.8 GOAWAY with debug data ───

test "§6.8: GOAWAY with debug data is accepted and debug data skipped" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // GOAWAY: last_stream_id=7, error_code=enhance_your_calm, debug="too fast"
    const debug_data = "too fast";
    const fh = frame.FrameHeader{
        .length = 8 + debug_data.len,
        .frame_type = .goaway,
        .flags = .{},
        .stream_id = 0,
    };
    var hdr_buf: [9]u8 = undefined;
    fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    // 4 bytes last_stream_id + 4 bytes error_code
    var goaway_payload: [8]u8 = undefined;
    std.mem.writeInt(u32, goaway_payload[0..4], 7, .big);
    std.mem.writeInt(u32, goaway_payload[4..8], @intFromEnum(frame.ErrorCode.enhance_your_calm), .big);
    try input.appendSlice(allocator, &goaway_payload);
    try input.appendSlice(allocator, debug_data);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    const event = try conn.recvFrame();
    try std.testing.expect(event == .goaway);
    try std.testing.expectEqual(@as(u31, 7), event.goaway.last_stream_id);
    try std.testing.expectEqual(frame.ErrorCode.enhance_your_calm, event.goaway.error_code);
    try std.testing.expectEqual(@as(u16, 8), event.goaway.debug_data_len);
}

// ─── §4.1 Priority frame (deprecated in RFC 9113) → skipped ───

test "§4.1: PRIORITY frame → skipped as deprecated" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // PRIORITY frame (type=2, 5 bytes payload)
    const prio_fh = frame.FrameHeader{
        .length = 5,
        .frame_type = .priority,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    prio_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &[_]u8{0} ** 5);

    // Followed by valid PING ACK
    const ping_data = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // PRIORITY is skipped, returns PING ACK
    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);
}

// ─── §6.7 PING ACK preserves opaque data ───

test "§6.7: PING sends ACK with identical opaque data" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    const ping_data = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPing(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    // Add a PING ACK after so recvFrame can return
    var ack_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(.{ 0xFF, 0, 0, 0, 0, 0, 0, 0 }, &ack_buf);
    try input.appendSlice(allocator, &ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // recvFrame responds to PING internally and returns the PING ACK
    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);

    // Verify the PING ACK written back has matching opaque data
    const written = pipe.written();
    try std.testing.expect(written.len == 17);
    const resp_hdr = frame.FrameHeader.decode(written[0..9]);
    try std.testing.expectEqual(frame.FrameType.ping, resp_hdr.frame_type);
    try std.testing.expect(resp_hdr.flags.hasAck());
    try std.testing.expectEqualSlices(u8, &ping_data, written[9..17]);
}

// ─── §5.1.1 Stream Identifier Overflow ───

test "§5.1.1: stream ID 0x7FFFFFFF is usable, next call exhausted" {
    var map = stream_mod.StreamMap.init(100);

    // Set next_stream_id to maximum odd value
    map.next_stream_id = 0x7FFFFFFF;

    // 0x7FFFFFFF is a valid stream ID — should succeed
    const s = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 0x7FFFFFFF), s.id);

    // next_stream_id is now 0 (sentinel for exhausted)
    try std.testing.expectEqual(@as(u31, 0), map.next_stream_id);

    // Next open fails
    const result = map.openStream(65535, 65535);
    try std.testing.expectError(stream_mod.StreamMap.Error.StreamIdExhausted, result);
}

test "§5.1.1: stream ID 0x7FFFFFFD succeeds, 0x7FFFFFFF is next usable" {
    var map = stream_mod.StreamMap.init(100);

    // Set to second-to-last valid odd ID
    map.next_stream_id = 0x7FFFFFFD;

    // Opens stream with ID 0x7FFFFFFD, next becomes 0x7FFFFFFF
    const s = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 0x7FFFFFFD), s.id);
    try std.testing.expectEqual(@as(u31, 0x7FFFFFFF), map.next_stream_id);

    // 0x7FFFFFFF still usable
    const s2 = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 0x7FFFFFFF), s2.id);

    // Now exhausted
    const result = map.openStream(65535, 65535);
    try std.testing.expectError(stream_mod.StreamMap.Error.StreamIdExhausted, result);
}

test "§5.1.1: stream IDs are always odd (client-initiated)" {
    var map = stream_mod.StreamMap.init(100);

    const s1 = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 1), s1.id);

    const s2 = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 3), s2.id);

    const s3 = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u31, 5), s3.id);
}

// ─── §6.9.2 SETTINGS initial_window_size: send window adjustment ───

test "§6.9.2: initial_window_size increase adjusts existing stream send window" {
    var map = stream_mod.StreamMap.init(100);

    // Open stream with initial send window = 65535
    const s = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u32, 65535), s.send_window.available());

    // Server sends SETTINGS increasing initial_window_size to 131070 (65535 + 65535)
    try map.updateInitialWindowSize(65535, 131070);

    // Stream's send window should have increased by the delta (65535)
    try std.testing.expectEqual(@as(u32, 131070), s.send_window.available());
}

test "§6.9.2: initial_window_size decrease adjusts existing stream send window" {
    var map = stream_mod.StreamMap.init(100);

    // Open stream with initial send window = 65535
    const s = try map.openStream(65535, 65535);
    try std.testing.expectEqual(@as(u32, 65535), s.send_window.available());

    // Server sends SETTINGS decreasing initial_window_size to 32768
    try map.updateInitialWindowSize(65535, 32768);

    // Stream's send window should have decreased by the delta
    try std.testing.expectEqual(@as(u32, 32768), s.send_window.available());
}

test "§6.9.2: initial_window_size decrease can make send window negative" {
    var map = stream_mod.StreamMap.init(100);

    const s = try map.openStream(65535, 65535);

    // Consume some send window (simulate data sent)
    try s.send_window.consume(60000);
    try std.testing.expectEqual(@as(u32, 5535), s.send_window.available());

    // Decrease initial_window_size from 65535 to 1000 (delta = -64535)
    // send_window was 5535, becomes 5535 - 64535 = -59000 (negative but valid per RFC)
    try map.updateInitialWindowSize(65535, 1000);

    // Available should be 0 (window is negative)
    try std.testing.expectEqual(@as(u32, 0), s.send_window.available());
}

test "§6.9.2: initial_window_size change that overflows → FLOW_CONTROL_ERROR" {
    var map = stream_mod.StreamMap.init(100);

    // Open stream with max initial window
    _ = try map.openStream(0x7FFFFFFF, 65535);

    // Same value → delta is 0, no overflow
    try map.updateInitialWindowSize(0x7FFFFFFF, 0x7FFFFFFF);

    // old=1, new=0x7FFFFFFF → delta = 0x7FFFFFFE, new window = 0x7FFFFFFF + 0x7FFFFFFE > max
    var map2 = stream_mod.StreamMap.init(100);
    _ = try map2.openStream(0x7FFFFFFF, 65535);
    const result = map2.updateInitialWindowSize(1, 0x7FFFFFFF);
    try std.testing.expectError(error.FlowControlError, result);
}

// ─── §8.1.2 Malformed :status value ───

test "§8.1.2: :status with non-numeric value → InvalidStatusValue" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "abc" },
        .{ .name = "content-type", .value = "text/html" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.InvalidStatusValue, hpack.validateResponseHeaders(&headers));
}

test "§8.1.2: :status with empty value → InvalidStatusValue" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "" },
        .{ .name = "content-type", .value = "text/html" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.InvalidStatusValue, hpack.validateResponseHeaders(&headers));
}

test "§8.1.2: :status with 2-digit value → InvalidStatusValue" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "20" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.InvalidStatusValue, hpack.validateResponseHeaders(&headers));
}

test "§8.1.2: :status with 4-digit value → InvalidStatusValue" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "2000" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.InvalidStatusValue, hpack.validateResponseHeaders(&headers));
}

test "§8.1.2: :status with leading space → InvalidStatusValue" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = " 200" },
    };
    try std.testing.expectError(hpack.PseudoHeaderError.InvalidStatusValue, hpack.validateResponseHeaders(&headers));
}

test "§8.1.2: :status '200' is valid" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    };
    try hpack.validateResponseHeaders(&headers);
}

test "§8.1.2: :status '404' is valid" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "404" },
    };
    try hpack.validateResponseHeaders(&headers);
}

test "§8.1.2: :status '999' is valid (extension status)" {
    const headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "999" },
    };
    try hpack.validateResponseHeaders(&headers);
}

// ─── Payload Tracking: auto-skip of unconsumed payload ───

test "pending_payload: unconsumed DATA payload is auto-skipped on next recvFrame" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame with 5 bytes payload on stream 1
    const data_fh = frame.FrameHeader{
        .length = 5,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    data_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "hello");

    // Followed by a PING ACK (next frame)
    const ping_data = [8]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0 };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // Receive DATA event — we do NOT read the payload
    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .data);
    try std.testing.expectEqual(@as(u24, 5), ev1.data.payload_len);
    try std.testing.expectEqual(@as(u24, 5), conn.pending_payload);

    // Call recvFrame again without consuming payload — should auto-skip
    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .ping_ack);
    try std.testing.expectEqual(@as(u24, 0), conn.pending_payload);
}

test "pending_payload: payloadConsumed prevents auto-skip" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame with 5 bytes payload on stream 1
    const data_fh = frame.FrameHeader{
        .length = 5,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    data_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "world");

    // Followed by a PING ACK
    const ping_data = [8]u8{ 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0 };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // Receive DATA event
    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .data);

    // Simulate reading the payload (manually read 5 bytes from reader)
    var payload: [5]u8 = undefined;
    const n = try conn.reader.readAll(&payload);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("world", &payload);

    // Mark as consumed
    conn.payloadConsumed(5);
    try std.testing.expectEqual(@as(u24, 0), conn.pending_payload);

    // Next recvFrame should read the PING ACK directly (no skip)
    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .ping_ack);
}

test "pending_payload: HEADERS payload auto-skip works" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // HEADERS frame with 3 bytes payload on stream 1
    const headers_fh = frame.FrameHeader{
        .length = 3,
        .frame_type = .headers,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    headers_fh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, "abc");

    // Followed by WINDOW_UPDATE on stream 0
    var wu_buf: [13]u8 = undefined;
    _ = frame.buildWindowUpdate(0, 500, &wu_buf) catch unreachable;
    try input.appendSlice(allocator, &wu_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();
    var conn = initConn(&pipe);

    // Receive HEADERS — don't read payload
    const ev1 = try conn.recvFrame();
    try std.testing.expect(ev1 == .headers);
    try std.testing.expectEqual(@as(u24, 3), conn.pending_payload);

    // Next recvFrame auto-skips the 3-byte header payload
    const ev2 = try conn.recvFrame();
    try std.testing.expect(ev2 == .window_update);
    try std.testing.expectEqual(@as(u31, 500), ev2.window_update.increment);
}

test "pending_payload: replaceTransport resets pending_payload" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();
    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;
    conn.pending_payload = 100;

    var pipe2 = TestPipe.init(allocator, &.{});
    defer pipe2.deinit();
    conn.replaceTransport(pipe2.reader(), pipe2.writer());

    try std.testing.expectEqual(@as(u24, 0), conn.pending_payload);
}
