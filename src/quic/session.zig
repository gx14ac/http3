// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const h3_frame = @import("h3_frame.zig");
const h3_conn = @import("h3_conn.zig");
const qpack = @import("qpack.zig");
const stream_mod = @import("stream.zig");
const packet_mod = @import("packet.zig");

/// QUIC session state machine.
pub const SessionState = enum {
    idle,
    handshaking,
    connected,
    draining,
    closed,
};

/// A QUIC client session managing the HTTP/3 layer over a QUIC connection.
/// Orchestrates: handshake → open control/QPACK streams → issue requests.
pub const Session = struct {
    state: SessionState,
    h3: h3_conn.H3Connection,
    /// Unidirectional stream allocator (separate from bidi in H3Connection).
    uni_alloc: stream_mod.StreamAllocator,
    /// Control stream ID (our side).
    control_stream_id: ?u62,
    /// QPACK encoder stream ID (our side).
    qpack_enc_stream_id: ?u62,
    /// QPACK decoder stream ID (our side).
    qpack_dec_stream_id: ?u62,
    /// Next expected packet number (for receive ordering).
    next_pn: u64,
    /// Server name (for TLS SNI).
    server_name: []const u8,
    /// Active request streams (stream_id → RequestState).
    requests: [MAX_CONCURRENT_REQUESTS]?RequestState,

    const MAX_CONCURRENT_REQUESTS = 128;

    pub fn init(server_name: []const u8) Session {
        return .{
            .state = .idle,
            .h3 = h3_conn.H3Connection.init(false, 100, 100),
            .uni_alloc = stream_mod.StreamAllocator.init(false, 0, 100),
            .control_stream_id = null,
            .qpack_enc_stream_id = null,
            .qpack_dec_stream_id = null,
            .next_pn = 0,
            .server_name = server_name,
            .requests = [_]?RequestState{null} ** MAX_CONCURRENT_REQUESTS,
        };
    }

    /// Transition to handshaking state.
    pub fn startHandshake(self: *Session) void {
        self.state = .handshaking;
    }

    /// Called when handshake completes. Opens required HTTP/3 unidirectional streams.
    /// Returns the stream open payloads that must be sent on the respective streams.
    pub fn onHandshakeComplete(self: *Session) ?InitialStreams {
        self.state = .connected;

        // Allocate unidirectional streams (RFC 9114 §6.2, RFC 9204 §4.2)
        self.control_stream_id = self.uni_alloc.allocUni() orelse return null;
        self.qpack_enc_stream_id = self.uni_alloc.allocUni() orelse return null;
        self.qpack_dec_stream_id = self.uni_alloc.allocUni() orelse return null;

        self.h3.control_stream_id = self.control_stream_id;
        self.h3.qpack_encoder_stream_id = self.qpack_enc_stream_id;
        self.h3.qpack_decoder_stream_id = self.qpack_dec_stream_id;

        // Build control stream payload (stream_type + SETTINGS)
        var control_buf: [256]u8 = undefined;
        const control_len = self.h3.buildControlStreamData(&control_buf) orelse return null;

        // QPACK encoder stream: just stream type (0x02), no instructions in static-only mode
        var enc_buf: [8]u8 = undefined;
        const enc_len = h3_frame.encodeUniStreamType(&enc_buf, .qpack_encoder) orelse return null;

        // QPACK decoder stream: just stream type (0x03)
        var dec_buf: [8]u8 = undefined;
        const dec_len = h3_frame.encodeUniStreamType(&dec_buf, .qpack_decoder) orelse return null;

        return .{
            .control_stream_id = self.control_stream_id.?,
            .control_data = control_buf,
            .control_data_len = control_len,
            .qpack_enc_stream_id = self.qpack_enc_stream_id.?,
            .qpack_enc_data = enc_buf,
            .qpack_enc_data_len = enc_len,
            .qpack_dec_stream_id = self.qpack_dec_stream_id.?,
            .qpack_dec_data = dec_buf,
            .qpack_dec_data_len = dec_len,
        };
    }

    /// Send a request: allocate stream, build HEADERS + optional DATA frames.
    /// Returns the stream ID and frames to send.
    pub fn sendRequest(self: *Session, headers: []const qpack.HeaderField, body: ?[]const u8) ?RequestFrames {
        if (self.state != .connected) return null;
        if (self.h3.goaway_received) return null;

        const stream_id = self.h3.allocRequestStream() orelse return null;

        // Build HEADERS frame
        var headers_buf: [4096]u8 = undefined;
        const headers_len = h3_conn.H3Connection.buildHeadersFrame(&headers_buf, headers) orelse return null;

        // Build DATA frame if body present
        var data_buf: [4096]u8 = undefined;
        var data_len: usize = 0;
        if (body) |b| {
            data_len = h3_conn.H3Connection.buildDataFrame(&data_buf, b) orelse return null;
        }

        // Track request
        const slot = self.findFreeSlot() orelse return null;
        self.requests[slot] = .{
            .stream_id = stream_id,
            .state = .headers_sent,
            .response_headers_received = false,
        };

        return .{
            .stream_id = stream_id,
            .headers_frame = headers_buf,
            .headers_frame_len = headers_len,
            .data_frame = data_buf,
            .data_frame_len = data_len,
            .has_body = body != null,
        };
    }

    /// Process a received HEADERS frame on a request stream.
    /// Decodes QPACK and returns the response headers.
    pub fn processResponseHeaders(self: *Session, stream_id: u62, frame_payload: []const u8) ?DecodedResponse {
        const slot = self.findRequest(stream_id) orelse return null;
        self.requests[slot].?.response_headers_received = true;

        var headers: [32]qpack.HeaderField = undefined;
        const count = qpack.Decoder.decode(frame_payload, &headers) orelse return null;

        return .{
            .stream_id = stream_id,
            .headers = headers,
            .header_count = count,
        };
    }

    /// Mark a request stream as complete (received all data + FIN).
    pub fn completeRequest(self: *Session, stream_id: u62) void {
        const slot = self.findRequest(stream_id) orelse return;
        self.requests[slot].?.state = .complete;
    }

    /// Close a request (remove from tracking).
    pub fn closeRequest(self: *Session, stream_id: u62) void {
        const slot = self.findRequest(stream_id) orelse return;
        self.requests[slot] = null;
    }

    /// Initiate graceful shutdown.
    pub fn initiateShutdown(self: *Session, buf: []u8) ?ShutdownData {
        if (self.state != .connected) return null;
        self.state = .draining;
        // GOAWAY with last processed stream ID (use the highest allocated so far)
        const last_id = if (self.h3.stream_alloc.next_bidi >= 4)
            self.h3.stream_alloc.next_bidi - 4
        else
            0;
        const len = self.h3.buildGoaway(buf, last_id) orelse return null;
        return .{ .goaway_len = len };
    }

    /// Process a GOAWAY received from peer.
    pub fn onGoaway(self: *Session, last_stream_id: u62) void {
        self.h3.goaway_received = true;
        self.h3.goaway_id = last_stream_id;
        self.state = .draining;
    }

    /// Transition to closed.
    pub fn close(self: *Session) void {
        self.state = .closed;
    }

    /// Number of active (in-flight) requests.
    pub fn activeRequests(self: *const Session) usize {
        var count: usize = 0;
        for (self.requests) |r| {
            if (r != null and r.?.state != .complete) count += 1;
        }
        return count;
    }

    fn findFreeSlot(self: *const Session) ?usize {
        for (self.requests, 0..) |r, i| {
            if (r == null) return i;
        }
        return null;
    }

    fn findRequest(self: *const Session, stream_id: u62) ?usize {
        for (self.requests, 0..) |r, i| {
            if (r != null and r.?.stream_id == stream_id) return i;
        }
        return null;
    }
};

pub const RequestState = struct {
    stream_id: u62,
    state: enum { headers_sent, data_sent, complete },
    response_headers_received: bool,
};

pub const InitialStreams = struct {
    control_stream_id: u62,
    control_data: [256]u8,
    control_data_len: usize,
    qpack_enc_stream_id: u62,
    qpack_enc_data: [8]u8,
    qpack_enc_data_len: usize,
    qpack_dec_stream_id: u62,
    qpack_dec_data: [8]u8,
    qpack_dec_data_len: usize,
};

pub const RequestFrames = struct {
    stream_id: u62,
    headers_frame: [4096]u8,
    headers_frame_len: usize,
    data_frame: [4096]u8,
    data_frame_len: usize,
    has_body: bool,
};

pub const DecodedResponse = struct {
    stream_id: u62,
    headers: [32]qpack.HeaderField,
    header_count: usize,
};

pub const ShutdownData = struct {
    goaway_len: usize,
};

// ─── Tests ───

test "Session: lifecycle idle → handshaking → connected" {
    var session = Session.init("example.com");
    try std.testing.expectEqual(SessionState.idle, session.state);

    session.startHandshake();
    try std.testing.expectEqual(SessionState.handshaking, session.state);

    const streams = session.onHandshakeComplete() orelse unreachable;
    try std.testing.expectEqual(SessionState.connected, session.state);

    // Control stream allocated
    try std.testing.expect(session.control_stream_id != null);
    try std.testing.expect(streams.control_data_len > 0);

    // QPACK streams allocated
    try std.testing.expect(session.qpack_enc_stream_id != null);
    try std.testing.expect(session.qpack_dec_stream_id != null);

    // QPACK encoder stream starts with type 0x02
    try std.testing.expectEqual(@as(u8, 0x02), streams.qpack_enc_data[0]);
    // QPACK decoder stream starts with type 0x03
    try std.testing.expectEqual(@as(u8, 0x03), streams.qpack_dec_data[0]);
}

test "Session: stream IDs are client-initiated unidirectional" {
    var session = Session.init("test.com");
    session.startHandshake();
    const streams = session.onHandshakeComplete() orelse unreachable;

    // Client uni stream IDs: 2, 6, 10, ... (low 2 bits = 0b10 = 2)
    try std.testing.expectEqual(@as(u62, 2), streams.control_stream_id);
    try std.testing.expectEqual(@as(u62, 6), streams.qpack_enc_stream_id);
    try std.testing.expectEqual(@as(u62, 10), streams.qpack_dec_stream_id);
}

test "Session: sendRequest" {
    var session = Session.init("api.example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = ":path", .value = "/v1/status" },
    };

    const req = session.sendRequest(&headers, null) orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), req.stream_id); // first bidi
    try std.testing.expect(req.headers_frame_len > 0);
    try std.testing.expect(!req.has_body);
    try std.testing.expectEqual(@as(usize, 1), session.activeRequests());
}

test "Session: sendRequest with body" {
    var session = Session.init("api.example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = ":path", .value = "/v1/data" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const body = "{\"key\":\"value\"}";

    const req = session.sendRequest(&headers, body) orelse unreachable;
    try std.testing.expect(req.has_body);
    try std.testing.expect(req.data_frame_len > 0);
}

test "Session: sendRequest fails when not connected" {
    var session = Session.init("example.com");
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
    };
    try std.testing.expect(session.sendRequest(&headers, null) == null);
}

test "Session: sendRequest fails after GOAWAY" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    session.onGoaway(0);
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
    };
    try std.testing.expect(session.sendRequest(&headers, null) == null);
}

test "Session: processResponseHeaders" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    const req_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };
    const req = session.sendRequest(&req_headers, null) orelse unreachable;

    // Simulate response: encode :status 200
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &resp_headers) orelse unreachable;

    const decoded = session.processResponseHeaders(req.stream_id, qpack_buf[0..qpack_len]) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), decoded.header_count);
    try std.testing.expectEqualStrings(":status", decoded.headers[0].name);
    try std.testing.expectEqualStrings("200", decoded.headers[0].value);
}

test "Session: completeRequest and closeRequest" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };
    const req = session.sendRequest(&headers, null) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), session.activeRequests());

    session.completeRequest(req.stream_id);
    try std.testing.expectEqual(@as(usize, 0), session.activeRequests());

    session.closeRequest(req.stream_id);
    // Slot freed, can be reused
    try std.testing.expect(session.findRequest(req.stream_id) == null);
}

test "Session: initiateShutdown" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    var buf: [32]u8 = undefined;
    const shutdown = session.initiateShutdown(&buf) orelse unreachable;
    try std.testing.expect(shutdown.goaway_len > 0);
    try std.testing.expectEqual(SessionState.draining, session.state);
    try std.testing.expect(session.h3.goaway_sent);
}

test "Session: onGoaway transitions to draining" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    session.onGoaway(4);
    try std.testing.expectEqual(SessionState.draining, session.state);
    try std.testing.expect(session.h3.goaway_received);
    try std.testing.expectEqual(@as(u62, 4), session.h3.goaway_id);
}

test "Session: close" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();
    session.close();
    try std.testing.expectEqual(SessionState.closed, session.state);
}

test "Session: multiple concurrent requests" {
    var session = Session.init("example.com");
    session.startHandshake();
    _ = session.onHandshakeComplete();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };

    const r0 = session.sendRequest(&headers, null) orelse unreachable;
    const r1 = session.sendRequest(&headers, null) orelse unreachable;
    const r2 = session.sendRequest(&headers, null) orelse unreachable;

    try std.testing.expectEqual(@as(u62, 0), r0.stream_id);
    try std.testing.expectEqual(@as(u62, 4), r1.stream_id);
    try std.testing.expectEqual(@as(u62, 8), r2.stream_id);
    try std.testing.expectEqual(@as(usize, 3), session.activeRequests());

    session.completeRequest(r1.stream_id);
    try std.testing.expectEqual(@as(usize, 2), session.activeRequests());
}
