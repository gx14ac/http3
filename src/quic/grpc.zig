const std = @import("std");
const qpack = @import("qpack.zig");
const h3_frame = @import("h3_frame.zig");

/// gRPC status codes (https://grpc.github.io/grpc/core/md_doc_statuscodes.html).
pub const StatusCode = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,
    _,
};

pub const GrpcError = error{
    BufferTooSmall,
    InvalidFrame,
    InvalidMessage,
    TruncatedMessage,
    InvalidStatus,
    EncodingFailed,
};

// ─── 1. gRPC Length-Prefixed Message Framing ───

/// gRPC message frame: compress_flag(1) + message_length(4, big-endian) + message
pub const MESSAGE_HEADER_LEN: usize = 5;

/// Encode a gRPC Length-Prefixed Message into buf.
/// Returns total bytes written (5 + message.len).
pub fn encodeMessage(buf: []u8, message: []const u8, compressed: bool) GrpcError!usize {
    const total = MESSAGE_HEADER_LEN + message.len;
    if (buf.len < total) return GrpcError.BufferTooSmall;

    buf[0] = if (compressed) 1 else 0;
    std.mem.writeInt(u32, buf[1..5], @intCast(message.len), .big);
    @memcpy(buf[MESSAGE_HEADER_LEN..][0..message.len], message);
    return total;
}

/// Decoded gRPC message frame.
pub const DecodedMessage = struct {
    compressed: bool,
    data: []const u8,
    consumed: usize,
};

/// Decode a gRPC Length-Prefixed Message from data.
pub fn decodeMessage(data: []const u8) GrpcError!DecodedMessage {
    if (data.len < MESSAGE_HEADER_LEN) return GrpcError.TruncatedMessage;

    const compressed = data[0] == 1;
    const msg_len: usize = std.mem.readInt(u32, data[1..5], .big);
    const total = MESSAGE_HEADER_LEN + msg_len;

    if (data.len < total) return GrpcError.TruncatedMessage;

    return .{
        .compressed = compressed,
        .data = data[MESSAGE_HEADER_LEN..][0..msg_len],
        .consumed = total,
    };
}

// ─── 2. gRPC Request Building ───

/// Build the QPACK-encoded HEADERS for a gRPC request.
/// Required pseudo-headers: :method POST, :path, :scheme https
/// Required headers: content-type: application/grpc, te: trailers
pub fn encodeRequestHeaders(
    buf: []u8,
    path: []const u8,
    authority: []const u8,
) GrpcError!usize {
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    return qpack.Encoder.encode(buf, &headers) orelse GrpcError.EncodingFailed;
}

/// Build a complete HEADERS frame for a gRPC request (frame header + QPACK payload).
pub fn buildRequestHeadersFrame(
    buf: []u8,
    path: []const u8,
    authority: []const u8,
) GrpcError!usize {
    // Encode QPACK headers into a temporary area
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = try encodeRequestHeaders(&qpack_buf, path, authority);

    // Encode as HTTP/3 HEADERS frame
    const frame_len = h3_frame.encodeHeadersFrame(buf, qpack_buf[0..qpack_len]) orelse
        return GrpcError.BufferTooSmall;
    return frame_len;
}

/// Build a complete DATA frame wrapping a gRPC message.
pub fn buildDataFrame(
    buf: []u8,
    message: []const u8,
) GrpcError!usize {
    // First encode the gRPC length-prefixed message
    var grpc_msg: [4096]u8 = undefined;
    const msg_len = try encodeMessage(&grpc_msg, message, false);

    // Wrap in HTTP/3 DATA frame
    const frame_len = h3_frame.encodeDataFrame(buf, grpc_msg[0..msg_len]) orelse
        return GrpcError.BufferTooSmall;
    return frame_len;
}

// ─── 3. gRPC Response Parsing ───

/// Parsed gRPC response (from HEADERS + DATA + trailers).
pub const GrpcResponse = struct {
    status_code: StatusCode,
    message: ?[]const u8,
    grpc_message: ?[]const u8,
    http_status: u16,
};

/// Parse grpc-status from trailer headers.
/// Trailers are QPACK-encoded; we look for "grpc-status" and "grpc-message" fields.
pub fn parseTrailers(
    encoded: []const u8,
    status_out: *StatusCode,
    grpc_message_out: *?[]const u8,
) GrpcError!void {
    var headers: [16]qpack.HeaderField = undefined;
    const count = qpack.Decoder.decode(encoded, &headers) orelse
        return GrpcError.InvalidFrame;

    status_out.* = .ok;
    grpc_message_out.* = null;

    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status")) {
            const code = std.fmt.parseInt(u8, h.value, 10) catch
                return GrpcError.InvalidStatus;
            status_out.* = @enumFromInt(code);
        } else if (std.mem.eql(u8, h.name, "grpc-message")) {
            grpc_message_out.* = h.value;
        }
    }
}

/// Parse initial response HEADERS to get HTTP status.
pub fn parseResponseHeaders(
    encoded: []const u8,
    http_status_out: *u16,
    content_type_out: *?[]const u8,
) GrpcError!void {
    var headers: [16]qpack.HeaderField = undefined;
    const count = qpack.Decoder.decode(encoded, &headers) orelse
        return GrpcError.InvalidFrame;

    http_status_out.* = 200;
    content_type_out.* = null;

    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            http_status_out.* = std.fmt.parseInt(u16, h.value, 10) catch 0;
        } else if (std.mem.eql(u8, h.name, "content-type")) {
            content_type_out.* = h.value;
        }
    }
}

// ─── 4. Unary RPC State Machine ───

/// State for a unary gRPC call.
pub const UnaryRpcState = enum {
    idle,
    headers_sent,
    awaiting_response_headers,
    awaiting_data,
    awaiting_trailers,
    complete,
    failed,
};

/// Unary RPC handler: manages the lifecycle of a single request-response call.
pub const UnaryRpc = struct {
    state: UnaryRpcState,
    stream_id: u64,
    status: StatusCode,
    http_status: u16,
    response_data: ?[]const u8,
    grpc_message: ?[]const u8,

    pub fn init(stream_id: u64) UnaryRpc {
        return .{
            .state = .idle,
            .stream_id = stream_id,
            .status = .ok,
            .http_status = 0,
            .response_data = null,
            .grpc_message = null,
        };
    }

    /// Build the request frames (HEADERS + DATA) for sending.
    /// Returns total bytes written to buf.
    pub fn buildRequest(
        self: *UnaryRpc,
        buf: []u8,
        path: []const u8,
        authority: []const u8,
        message: []const u8,
    ) GrpcError!usize {
        if (self.state != .idle) return GrpcError.InvalidFrame;

        var pos: usize = 0;

        // HEADERS frame
        const headers_len = try buildRequestHeadersFrame(buf[pos..], path, authority);
        pos += headers_len;

        // DATA frame
        const data_len = try buildDataFrame(buf[pos..], message);
        pos += data_len;

        self.state = .headers_sent;
        return pos;
    }

    /// Process a received response HEADERS frame (initial headers).
    pub fn onResponseHeaders(self: *UnaryRpc, encoded: []const u8) GrpcError!void {
        if (self.state != .headers_sent and self.state != .awaiting_response_headers)
            return GrpcError.InvalidFrame;

        var content_type: ?[]const u8 = null;
        try parseResponseHeaders(encoded, &self.http_status, &content_type);

        if (self.http_status != 200) {
            self.state = .failed;
            return;
        }

        self.state = .awaiting_data;
    }

    /// Process a received DATA frame payload (contains gRPC length-prefixed message).
    pub fn onResponseData(self: *UnaryRpc, data: []const u8) GrpcError!void {
        if (self.state != .awaiting_data) return GrpcError.InvalidFrame;

        const msg = try decodeMessage(data);
        self.response_data = msg.data;
        self.state = .awaiting_trailers;
    }

    /// Process received trailers (final HEADERS frame with grpc-status).
    pub fn onTrailers(self: *UnaryRpc, encoded: []const u8) GrpcError!void {
        if (self.state != .awaiting_trailers and self.state != .awaiting_data)
            return GrpcError.InvalidFrame;

        try parseTrailers(encoded, &self.status, &self.grpc_message);
        self.state = .complete;
    }

    pub fn isComplete(self: *const UnaryRpc) bool {
        return self.state == .complete or self.state == .failed;
    }

    pub fn isSuccess(self: *const UnaryRpc) bool {
        return self.state == .complete and self.status == .ok and self.http_status == 200;
    }
};

// ─── Tests ───

test "encodeMessage/decodeMessage: roundtrip" {
    const payload = "Hello gRPC";
    var buf: [64]u8 = undefined;
    const len = try encodeMessage(&buf, payload, false);
    try std.testing.expectEqual(@as(usize, 15), len); // 5 + 10

    const decoded = try decodeMessage(buf[0..len]);
    try std.testing.expect(!decoded.compressed);
    try std.testing.expectEqualStrings("Hello gRPC", decoded.data);
    try std.testing.expectEqual(@as(usize, 15), decoded.consumed);
}

test "encodeMessage: compressed flag" {
    var buf: [64]u8 = undefined;
    const len = try encodeMessage(&buf, "data", true);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
    const decoded = try decodeMessage(buf[0..len]);
    try std.testing.expect(decoded.compressed);
}

test "encodeMessage: buffer too small" {
    var buf: [3]u8 = undefined;
    const result = encodeMessage(&buf, "data", false);
    try std.testing.expectError(GrpcError.BufferTooSmall, result);
}

test "decodeMessage: truncated header" {
    const data = [_]u8{ 0x00, 0x00, 0x00 };
    const result = decodeMessage(&data);
    try std.testing.expectError(GrpcError.TruncatedMessage, result);
}

test "decodeMessage: truncated body" {
    const data = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x10 }; // says 16 bytes, has 0
    const result = decodeMessage(&data);
    try std.testing.expectError(GrpcError.TruncatedMessage, result);
}

test "decodeMessage: empty payload" {
    var buf: [5]u8 = undefined;
    const len = try encodeMessage(&buf, "", false);
    try std.testing.expectEqual(@as(usize, 5), len);
    const decoded = try decodeMessage(buf[0..len]);
    try std.testing.expectEqual(@as(usize, 0), decoded.data.len);
}

test "encodeRequestHeaders: valid output" {
    var buf: [256]u8 = undefined;
    const len = try encodeRequestHeaders(&buf, "/pkg.Svc/Method", "example.com");
    try std.testing.expect(len > 0);

    // Decode and verify headers
    var headers: [16]qpack.HeaderField = undefined;
    const count = qpack.Decoder.decode(buf[0..len], &headers) orelse unreachable;
    try std.testing.expect(count >= 6);

    // Check required headers
    var found_method = false;
    var found_path = false;
    var found_content_type = false;
    var found_te = false;
    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, ":method") and std.mem.eql(u8, h.value, "POST")) found_method = true;
        if (std.mem.eql(u8, h.name, ":path") and std.mem.eql(u8, h.value, "/pkg.Svc/Method")) found_path = true;
        if (std.mem.eql(u8, h.name, "content-type") and std.mem.eql(u8, h.value, "application/grpc")) found_content_type = true;
        if (std.mem.eql(u8, h.name, "te") and std.mem.eql(u8, h.value, "trailers")) found_te = true;
    }
    try std.testing.expect(found_method);
    try std.testing.expect(found_path);
    try std.testing.expect(found_content_type);
    try std.testing.expect(found_te);
}

test "buildRequestHeadersFrame: produces HEADERS frame" {
    var buf: [512]u8 = undefined;
    const len = try buildRequestHeadersFrame(&buf, "/svc/Rpc", "host.example");
    try std.testing.expect(len > 0);

    // Verify it's an HTTP/3 HEADERS frame (type=0x01)
    const frame = h3_frame.decodeFrameHeader(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x01), frame.frame_type);
}

test "buildDataFrame: wraps gRPC message in DATA frame" {
    var buf: [256]u8 = undefined;
    const len = try buildDataFrame(&buf, "protobuf bytes");
    try std.testing.expect(len > 0);

    // Verify it's an HTTP/3 DATA frame (type=0x00)
    const frame = h3_frame.decodeFrameHeader(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x00), frame.frame_type);

    // Inner payload should be gRPC framed: 5 + 14 = 19 bytes
    try std.testing.expectEqual(@as(u64, 19), frame.length);
}

test "parseTrailers: grpc-status ok" {
    // Encode trailers
    const trailers = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "0" },
    };
    var buf: [64]u8 = undefined;
    const len = qpack.Encoder.encode(&buf, &trailers) orelse unreachable;

    var status: StatusCode = .unknown;
    var msg: ?[]const u8 = null;
    try parseTrailers(buf[0..len], &status, &msg);
    try std.testing.expectEqual(StatusCode.ok, status);
    try std.testing.expect(msg == null);
}

test "parseTrailers: error with message" {
    const trailers = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "13" },
        .{ .name = "grpc-message", .value = "internal error" },
    };
    var buf: [128]u8 = undefined;
    const len = qpack.Encoder.encode(&buf, &trailers) orelse unreachable;

    var status: StatusCode = .ok;
    var msg: ?[]const u8 = null;
    try parseTrailers(buf[0..len], &status, &msg);
    try std.testing.expectEqual(StatusCode.internal, status);
    try std.testing.expectEqualStrings("internal error", msg.?);
}

test "UnaryRpc: full lifecycle" {
    var rpc = UnaryRpc.init(0);
    try std.testing.expectEqual(UnaryRpcState.idle, rpc.state);

    // Build request
    var req_buf: [1024]u8 = undefined;
    const req_len = try rpc.buildRequest(&req_buf, "/pkg.Svc/Call", "server.example", "request body");
    try std.testing.expect(req_len > 0);
    try std.testing.expectEqual(UnaryRpcState.headers_sent, rpc.state);

    // Simulate response headers (:status 200)
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    var resp_hdr_buf: [128]u8 = undefined;
    const resp_hdr_len = qpack.Encoder.encode(&resp_hdr_buf, &resp_headers) orelse unreachable;
    try rpc.onResponseHeaders(resp_hdr_buf[0..resp_hdr_len]);
    try std.testing.expectEqual(UnaryRpcState.awaiting_data, rpc.state);
    try std.testing.expectEqual(@as(u16, 200), rpc.http_status);

    // Simulate DATA (gRPC framed response)
    var data_buf: [64]u8 = undefined;
    const data_len = try encodeMessage(&data_buf, "response body", false);
    try rpc.onResponseData(data_buf[0..data_len]);
    try std.testing.expectEqual(UnaryRpcState.awaiting_trailers, rpc.state);
    try std.testing.expectEqualStrings("response body", rpc.response_data.?);

    // Simulate trailers
    const trailer_hdrs = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "0" },
    };
    var trailer_buf: [64]u8 = undefined;
    const trailer_len = qpack.Encoder.encode(&trailer_buf, &trailer_hdrs) orelse unreachable;
    try rpc.onTrailers(trailer_buf[0..trailer_len]);
    try std.testing.expectEqual(UnaryRpcState.complete, rpc.state);
    try std.testing.expect(rpc.isComplete());
    try std.testing.expect(rpc.isSuccess());
}

test "UnaryRpc: HTTP error" {
    var rpc = UnaryRpc.init(4);

    var req_buf: [1024]u8 = undefined;
    _ = try rpc.buildRequest(&req_buf, "/pkg.Svc/Call", "server.example", "req");

    // 404 response
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "404" },
    };
    var resp_hdr_buf: [64]u8 = undefined;
    const resp_hdr_len = qpack.Encoder.encode(&resp_hdr_buf, &resp_headers) orelse unreachable;
    try rpc.onResponseHeaders(resp_hdr_buf[0..resp_hdr_len]);
    try std.testing.expectEqual(UnaryRpcState.failed, rpc.state);
    try std.testing.expectEqual(@as(u16, 404), rpc.http_status);
    try std.testing.expect(!rpc.isSuccess());
}

test "UnaryRpc: gRPC error in trailers" {
    var rpc = UnaryRpc.init(8);

    var req_buf: [1024]u8 = undefined;
    _ = try rpc.buildRequest(&req_buf, "/pkg.Svc/Call", "host", "data");

    // 200 OK response
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    var resp_hdr_buf: [128]u8 = undefined;
    const resp_hdr_len = qpack.Encoder.encode(&resp_hdr_buf, &resp_headers) orelse unreachable;
    try rpc.onResponseHeaders(resp_hdr_buf[0..resp_hdr_len]);

    // Empty data
    var data_buf: [64]u8 = undefined;
    const data_len = try encodeMessage(&data_buf, "", false);
    try rpc.onResponseData(data_buf[0..data_len]);

    // Trailers with error
    const trailer_hdrs = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "14" },
        .{ .name = "grpc-message", .value = "service unavailable" },
    };
    var trailer_buf: [128]u8 = undefined;
    const trailer_len = qpack.Encoder.encode(&trailer_buf, &trailer_hdrs) orelse unreachable;
    try rpc.onTrailers(trailer_buf[0..trailer_len]);

    try std.testing.expect(rpc.isComplete());
    try std.testing.expect(!rpc.isSuccess());
    try std.testing.expectEqual(StatusCode.unavailable, rpc.status);
    try std.testing.expectEqualStrings("service unavailable", rpc.grpc_message.?);
}

test "UnaryRpc: trailers-only response (no DATA)" {
    var rpc = UnaryRpc.init(12);

    var req_buf: [1024]u8 = undefined;
    _ = try rpc.buildRequest(&req_buf, "/pkg.Svc/Call", "host", "req");

    // 200 OK
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    var resp_hdr_buf: [128]u8 = undefined;
    const resp_hdr_len = qpack.Encoder.encode(&resp_hdr_buf, &resp_headers) orelse unreachable;
    try rpc.onResponseHeaders(resp_hdr_buf[0..resp_hdr_len]);

    // Server sends trailers immediately (trailers-only response, e.g. UNIMPLEMENTED)
    const trailer_hdrs = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "12" },
        .{ .name = "grpc-message", .value = "method not found" },
    };
    var trailer_buf: [128]u8 = undefined;
    const trailer_len = qpack.Encoder.encode(&trailer_buf, &trailer_hdrs) orelse unreachable;

    // In trailers-only, we go from awaiting_data directly to complete
    try rpc.onTrailers(trailer_buf[0..trailer_len]);
    try std.testing.expect(rpc.isComplete());
    try std.testing.expectEqual(StatusCode.unimplemented, rpc.status);
}
