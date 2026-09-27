// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const server_mod = @import("server.zig");
const h3_frame = @import("h3_frame.zig");
const qpack = @import("qpack.zig");
const packet_mod = @import("packet.zig");

const QuicServer = server_mod.QuicServer;
const ServerError = server_mod.ServerError;

pub const H3ServerError = error{
    NotConnected,
    EncodeFailed,
    WriteFailed,
    BufferTooSmall,
    InvalidRequest,
    StreamFull,
    Timeout,
};

/// An incoming HTTP/3 request.
pub const H3Request = struct {
    method: [16]u8,
    method_len: usize,
    path: [1024]u8,
    path_len: usize,
    authority: [256]u8,
    authority_len: usize,
    scheme: [8]u8,
    scheme_len: usize,
    content_type: [128]u8,
    content_type_len: usize,
    headers: [32]qpack.HeaderField,
    header_count: usize,
    body: [MAX_BODY]u8,
    body_len: usize,
    stream_id: u62,
    conn_idx: usize,
    fin: bool,

    const MAX_BODY = 16384;

    pub fn methodSlice(self: *const H3Request) []const u8 {
        return self.method[0..self.method_len];
    }

    pub fn pathSlice(self: *const H3Request) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn authoritySlice(self: *const H3Request) []const u8 {
        return self.authority[0..self.authority_len];
    }

    pub fn contentTypeSlice(self: *const H3Request) []const u8 {
        return self.content_type[0..self.content_type_len];
    }

    pub fn bodySlice(self: *const H3Request) []const u8 {
        return self.body[0..self.body_len];
    }
};

/// Data received on an established stream (after initial request headers).
pub const H3StreamData = struct {
    conn_idx: usize,
    stream_id: u62,
    body: [H3Request.MAX_BODY]u8,
    body_len: usize,
    fin: bool,

    pub fn bodySlice(self: *const H3StreamData) []const u8 {
        return self.body[0..self.body_len];
    }
};

/// HTTP/3 server event.
pub const H3ServerEvent = union(enum) {
    none,
    request: H3Request,
    data: H3StreamData,
    connected,
    timeout,
};

/// Per-stream receive buffer for reassembling H3 frames.
const StreamBuf = struct {
    stream_id: ?u62,
    conn_idx: usize,
    data: [MAX_STREAM_BUF]u8,
    len: usize,
    fin: bool,
    headers_emitted: bool,

    const MAX_STREAM_BUF = 32768;

    fn init() StreamBuf {
        return .{
            .stream_id = null,
            .conn_idx = 0,
            .data = undefined,
            .len = 0,
            .fin = false,
            .headers_emitted = false,
        };
    }

    fn reset(self: *StreamBuf) void {
        self.stream_id = null;
        self.len = 0;
        self.fin = false;
        self.headers_emitted = false;
    }
};

/// HTTP/3 server that wraps a QuicServer.
/// Handles H3 frame parsing (HEADERS + DATA) and exposes a request/response API.
pub const H3Server = struct {
    quic: QuicServer,
    stream_bufs: [MAX_STREAMS]StreamBuf,
    control_sent: [QuicServer.MAX_CONNS]bool,
    shutting_down: bool,
    goaway_stream_id: u62,

    const MAX_STREAMS = 32;
    const POLL_TIMEOUT_MS: u64 = 5000;

    pub fn init(bind_addr: std.net.Address, config: QuicServer.Config) ServerError!H3Server {
        var server = try QuicServer.init(bind_addr, config);
        server.setTimeout(POLL_TIMEOUT_MS);

        var s: H3Server = .{
            .quic = server,
            .stream_bufs = undefined,
            .control_sent = [_]bool{false} ** QuicServer.MAX_CONNS,
            .shutting_down = false,
            .goaway_stream_id = std.math.maxInt(u62),
        };
        for (&s.stream_bufs) |*sb| {
            sb.* = StreamBuf.init();
        }
        return s;
    }

    pub fn deinit(self: *H3Server) void {
        self.quic.deinit();
    }

    pub fn getPort(self: *const H3Server) u16 {
        return self.quic.getPort();
    }

    pub fn setTimeout(self: *H3Server, ms: u64) void {
        self.quic.setTimeout(ms);
    }

    /// Poll for the next H3 event. Drives the QUIC handshake and H3 frame processing.
    pub fn poll(self: *H3Server) H3ServerEvent {
        var buf: [4096]u8 = undefined;
        const event = self.quic.poll(&buf) catch |e| {
            return switch (e) {
                ServerError.Timeout => .timeout,
                else => .none,
            };
        };

        switch (event) {
            .handshake_started => return .none,
            .connected => |ci| {
                if (!self.sendControlSettings(ci)) return .none;
                return .connected;
            },
            .data_received => |sd| {
                return self.handleStreamData(sd.stream_id, sd.conn_idx, sd.data, sd.fin);
            },
            .closed => return .none,
            .none => return .none,
        }
    }

    /// Send an HTTP/3 response on the given stream.
    pub fn sendResponse(
        self: *H3Server,
        conn_idx: usize,
        stream_id: u62,
        status: u16,
        headers: []const qpack.HeaderField,
        body: []const u8,
    ) H3ServerError!void {
        // Encode response headers with QPACK
        var all_headers: [34]qpack.HeaderField = undefined;
        var hcount: usize = 0;

        // :status pseudo-header
        var status_buf: [3]u8 = undefined;
        const status_str = statusToStr(status, &status_buf);
        all_headers[hcount] = .{ .name = ":status", .value = status_str };
        hcount += 1;

        // User-provided headers
        for (headers) |h| {
            if (hcount >= all_headers.len) break;
            all_headers[hcount] = h;
            hcount += 1;
        }

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = qpack.Encoder.encode(&qpack_buf, all_headers[0..hcount]) orelse
            return H3ServerError.EncodeFailed;

        // Build HEADERS frame
        var frame_buf: [8192]u8 = undefined;
        var pos: usize = 0;
        const hdr_frame_len = h3_frame.encodeHeadersFrame(frame_buf[pos..], qpack_buf[0..qpack_len]) orelse
            return H3ServerError.EncodeFailed;
        pos += hdr_frame_len;

        // Build DATA frame if body is non-empty
        if (body.len > 0) {
            const data_frame_len = h3_frame.encodeDataFrame(frame_buf[pos..], body) orelse
                return H3ServerError.EncodeFailed;
            pos += data_frame_len;
        }

        // Send on QUIC stream with FIN
        self.quic.sendStreamDataOn(conn_idx, stream_id, frame_buf[0..pos], true) catch
            return H3ServerError.WriteFailed;
    }

    /// Send response headers only (no FIN). Use for streaming responses.
    pub fn sendHeaders(
        self: *H3Server,
        conn_idx: usize,
        stream_id: u62,
        status: u16,
        headers: []const qpack.HeaderField,
    ) H3ServerError!void {
        var all_headers: [34]qpack.HeaderField = undefined;
        var hcount: usize = 0;

        var status_buf: [3]u8 = undefined;
        const status_str = statusToStr(status, &status_buf);
        all_headers[hcount] = .{ .name = ":status", .value = status_str };
        hcount += 1;

        for (headers) |h| {
            if (hcount >= all_headers.len) break;
            all_headers[hcount] = h;
            hcount += 1;
        }

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = qpack.Encoder.encode(&qpack_buf, all_headers[0..hcount]) orelse
            return H3ServerError.EncodeFailed;

        var frame_buf: [4096]u8 = undefined;
        const hdr_frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse
            return H3ServerError.EncodeFailed;

        self.quic.sendStreamDataOn(conn_idx, stream_id, frame_buf[0..hdr_frame_len], false) catch
            return H3ServerError.WriteFailed;
    }

    /// Send trailing HEADERS frame with FIN (used for gRPC trailers).
    pub fn sendTrailers(
        self: *H3Server,
        conn_idx: usize,
        stream_id: u62,
        headers: []const qpack.HeaderField,
    ) H3ServerError!void {
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = qpack.Encoder.encode(&qpack_buf, headers) orelse
            return H3ServerError.EncodeFailed;

        var frame_buf: [4096]u8 = undefined;
        const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse
            return H3ServerError.EncodeFailed;

        self.quic.sendStreamDataOn(conn_idx, stream_id, frame_buf[0..frame_len], true) catch
            return H3ServerError.WriteFailed;
    }

    /// Send a DATA frame on a stream. Set fin=true on the last message.
    pub fn sendData(
        self: *H3Server,
        conn_idx: usize,
        stream_id: u62,
        body: []const u8,
        fin: bool,
    ) H3ServerError!void {
        var frame_buf: [8192]u8 = undefined;
        const data_frame_len = h3_frame.encodeDataFrame(&frame_buf, body) orelse
            return H3ServerError.EncodeFailed;

        self.quic.sendStreamDataOn(conn_idx, stream_id, frame_buf[0..data_frame_len], fin) catch
            return H3ServerError.WriteFailed;
    }

    /// Send a GOAWAY frame to a specific connection on its control stream.
    /// `last_stream_id` is the highest client-initiated stream ID the server will process.
    pub fn sendGoaway(self: *H3Server, conn_idx: usize, last_stream_id: u62) H3ServerError!void {
        var frame_buf: [32]u8 = undefined;
        const frame_len = h3_frame.encodeGoawayFrame(&frame_buf, last_stream_id) orelse
            return H3ServerError.EncodeFailed;

        // GOAWAY is sent on the server-initiated control stream (stream_id=3)
        self.quic.sendStreamDataOn(conn_idx, 3, frame_buf[0..frame_len], false) catch
            return H3ServerError.WriteFailed;
    }

    /// Initiate graceful shutdown: send GOAWAY to all connected clients,
    /// reject new streams above the GOAWAY stream ID.
    /// `last_stream_id` should be the highest client-initiated bidi stream ID
    /// that the server is willing to process (typically current max + 4).
    pub fn gracefulShutdown(self: *H3Server, last_stream_id: u62) void {
        self.shutting_down = true;
        self.goaway_stream_id = last_stream_id;

        for (0..self.quic.conn_count) |ci| {
            if (self.quic.conns[ci].active and self.quic.conns[ci].state == .connected) {
                self.sendGoaway(ci, last_stream_id) catch {};
            }
        }
    }

    /// Close all connections with CONNECTION_CLOSE after drain period.
    /// Call this after gracefulShutdown once in-flight requests are done.
    pub fn forceClose(self: *H3Server) void {
        // H3_NO_ERROR = 0x0100
        self.quic.closeAllConnections(0x0100, "");
    }

    pub fn isShuttingDown(self: *const H3Server) bool {
        return self.shutting_down;
    }

    pub fn activeConnectionCount(self: *const H3Server) usize {
        var count: usize = 0;
        for (0..self.quic.conn_count) |ci| {
            if (self.quic.conns[ci].active and self.quic.conns[ci].state == .connected) {
                count += 1;
            }
        }
        return count;
    }

    /// Handle received stream data: buffer it and try to parse H3 frames.
    fn handleStreamData(self: *H3Server, stream_id: u62, conn_idx: usize, data: []const u8, fin: bool) H3ServerEvent {
        // Only process client-initiated bidirectional streams (stream_id & 0x03 == 0x00)
        // Skip unidirectional streams (control, QPACK encoder/decoder)
        if (stream_id & 0x03 != 0x00) return .none;

        // Reject new streams above the GOAWAY stream ID during shutdown
        if (self.shutting_down and stream_id >= self.goaway_stream_id) return .none;

        const sb = self.getOrAllocStream(stream_id, conn_idx) orelse return .none;

        // Reject if buffer would overflow
        const space = StreamBuf.MAX_STREAM_BUF - sb.len;
        if (data.len > space) {
            sb.reset();
            return .none;
        }

        if (data.len > 0) {
            @memcpy(sb.data[sb.len..][0..data.len], data);
            sb.len += data.len;
        }
        if (fin) sb.fin = true;

        return self.tryParseRequest(sb);
    }

    fn tryParseRequest(self: *H3Server, sb: *StreamBuf) H3ServerEvent {
        if (sb.len == 0) {
            // Empty buffer but FIN received on already-emitted stream → emit empty data with fin
            if (sb.fin and sb.headers_emitted) {
                const sid = sb.stream_id orelse return .none;
                const ci = sb.conn_idx;
                sb.reset();
                var sd: H3StreamData = undefined;
                sd.conn_idx = ci;
                sd.stream_id = sid;
                sd.body_len = 0;
                sd.fin = true;
                return .{ .data = sd };
            }
            return .none;
        }

        // If we already emitted the initial request, subsequent data goes through .data path
        if (sb.headers_emitted) {
            return self.tryParseStreamData(sb);
        }

        const data = sb.data[0..sb.len];
        var pos: usize = 0;

        var request: H3Request = undefined;
        request.method_len = 0;
        request.path_len = 0;
        request.authority_len = 0;
        request.scheme_len = 0;
        request.content_type_len = 0;
        request.header_count = 0;
        request.body_len = 0;
        request.stream_id = sb.stream_id orelse return .none;
        request.conn_idx = sb.conn_idx;
        request.fin = sb.fin;

        // Parse H3 frames
        while (pos < data.len) {
            const frame_hdr = h3_frame.decodeFrameHeader(data[pos..]) orelse break;
            const frame_end = pos + frame_hdr.header_len + @as(usize, @intCast(frame_hdr.length));
            if (frame_end > data.len) break;

            const frame_payload = data[pos + frame_hdr.header_len ..][0..@intCast(frame_hdr.length)];
            pos = frame_end;

            switch (frame_hdr.frame_type) {
                0x01 => {
                    // HEADERS frame — decode QPACK
                    var headers: [32]qpack.HeaderField = undefined;
                    const hcount = qpack.Decoder.decode(frame_payload, &headers) orelse continue;
                    request.header_count = hcount;
                    request.headers = headers;

                    // Extract pseudo-headers
                    for (headers[0..hcount]) |h| {
                        if (std.mem.eql(u8, h.name, ":method")) {
                            const len = @min(h.value.len, request.method.len);
                            @memcpy(request.method[0..len], h.value[0..len]);
                            request.method_len = len;
                        } else if (std.mem.eql(u8, h.name, ":path")) {
                            const len = @min(h.value.len, request.path.len);
                            @memcpy(request.path[0..len], h.value[0..len]);
                            request.path_len = len;
                        } else if (std.mem.eql(u8, h.name, ":authority")) {
                            const len = @min(h.value.len, request.authority.len);
                            @memcpy(request.authority[0..len], h.value[0..len]);
                            request.authority_len = len;
                        } else if (std.mem.eql(u8, h.name, ":scheme")) {
                            const len = @min(h.value.len, request.scheme.len);
                            @memcpy(request.scheme[0..len], h.value[0..len]);
                            request.scheme_len = len;
                        } else if (std.mem.eql(u8, h.name, "content-type")) {
                            const len = @min(h.value.len, request.content_type.len);
                            @memcpy(request.content_type[0..len], h.value[0..len]);
                            request.content_type_len = len;
                        }
                    }
                },
                0x00 => {
                    // DATA frame
                    const copy_len = @min(frame_payload.len, H3Request.MAX_BODY - request.body_len);
                    @memcpy(request.body[request.body_len..][0..copy_len], frame_payload[0..copy_len]);
                    request.body_len += copy_len;
                },
                else => {},
            }
        }

        if (request.method_len == 0) return .none;

        // Emit request when:
        // - FIN received (stream closed by client), OR
        // - Method that never carries a body (GET, HEAD, DELETE), OR
        // - gRPC/streaming POST: always emit on first HEADERS so server can start processing
        if (request.fin or isBodylessMethod(request.method[0..request.method_len])) {
            sb.reset();
            return .{ .request = request };
        }

        // Streaming case: emit request with fin=false, keep stream buffer alive
        sb.headers_emitted = true;
        sb.len = 0; // consumed all buffered data
        return .{ .request = request };
    }

    /// Parse subsequent DATA frames on an already-established stream.
    fn tryParseStreamData(self: *H3Server, sb: *StreamBuf) H3ServerEvent {
        _ = self;
        const data = sb.data[0..sb.len];
        var pos: usize = 0;

        var sd: H3StreamData = undefined;
        sd.conn_idx = sb.conn_idx;
        sd.stream_id = sb.stream_id orelse return .none;
        sd.body_len = 0;
        sd.fin = sb.fin;

        while (pos < data.len) {
            const frame_hdr = h3_frame.decodeFrameHeader(data[pos..]) orelse break;
            const frame_end = pos + frame_hdr.header_len + @as(usize, @intCast(frame_hdr.length));
            if (frame_end > data.len) break;

            const frame_payload = data[pos + frame_hdr.header_len ..][0..@intCast(frame_hdr.length)];
            pos = frame_end;

            if (frame_hdr.frame_type == 0x00) {
                // DATA frame
                const copy_len = @min(frame_payload.len, H3Request.MAX_BODY - sd.body_len);
                @memcpy(sd.body[sd.body_len..][0..copy_len], frame_payload[0..copy_len]);
                sd.body_len += copy_len;
            }
        }

        // FIN: emit whatever we have and release the stream buffer
        if (sd.fin) {
            sb.reset();
            return .{ .data = sd };
        }

        // Retain partial (unparsed) frames for next poll
        if (pos > 0 and pos < sb.len) {
            std.mem.copyForwards(u8, sb.data[0 .. sb.len - pos], sb.data[pos..sb.len]);
            sb.len -= pos;
        } else if (pos >= sb.len) {
            sb.len = 0;
        }

        if (sd.body_len == 0) return .none;
        return .{ .data = sd };
    }

    /// Send SETTINGS on the server control stream. Returns false on failure.
    fn sendControlSettings(self: *H3Server, ci: usize) bool {
        if (self.control_sent[ci]) return true;

        var ctrl_buf: [64]u8 = undefined;
        var pos: usize = 0;

        pos += packet_mod.encodeVarint(ctrl_buf[pos..], 0x00) orelse return false;

        const settings = [_]h3_frame.Setting{};
        pos += h3_frame.encodeSettingsFrame(ctrl_buf[pos..], &settings) orelse return false;

        // Server-initiated uni stream (stream_id = 3)
        self.quic.sendStreamDataOn(ci, 3, ctrl_buf[0..pos], false) catch return false;
        self.control_sent[ci] = true;
        return true;
    }

    fn getOrAllocStream(self: *H3Server, stream_id: u62, conn_idx: usize) ?*StreamBuf {
        // Find existing
        for (&self.stream_bufs) |*sb| {
            if (sb.stream_id) |sid| {
                if (sid == stream_id and sb.conn_idx == conn_idx) return sb;
            }
        }
        // Allocate new
        for (&self.stream_bufs) |*sb| {
            if (sb.stream_id == null) {
                sb.stream_id = stream_id;
                sb.conn_idx = conn_idx;
                sb.len = 0;
                sb.fin = false;
                return sb;
            }
        }
        return null;
    }

};

fn isBodylessMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "DELETE") or
        std.mem.eql(u8, method, "OPTIONS");
}

fn statusToStr(status: u16, buf: *[3]u8) []const u8 {
    buf[0] = '0' + @as(u8, @intCast(status / 100));
    buf[1] = '0' + @as(u8, @intCast((status / 10) % 10));
    buf[2] = '0' + @as(u8, @intCast(status % 10));
    return buf[0..3];
}

// ─── Tests ───

test "H3Server: create and close" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();
    try std.testing.expect(server.getPort() > 0);
}

test "H3Server: poll timeout" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();
    server.setTimeout(10);
    const event = server.poll();
    try std.testing.expect(event == .timeout);
}

test "statusToStr" {
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "200", statusToStr(200, &buf));
    try std.testing.expectEqualSlices(u8, "404", statusToStr(404, &buf));
    try std.testing.expectEqualSlices(u8, "500", statusToStr(500, &buf));
}

test "H3Request: parse HEADERS frame" {
    // Simulate a HEADERS frame with a POST request
    var headers_to_encode = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/test" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers_to_encode) orelse unreachable;

    // Build HEADERS frame
    var frame_buf: [1024]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    // Create a stream buffer and inject the data
    var sb = StreamBuf.init();
    sb.stream_id = 0;
    sb.conn_idx = 0;
    sb.fin = true;
    @memcpy(sb.data[0..frame_len], frame_buf[0..frame_len]);
    sb.len = frame_len;

    // Parse
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    const event = server.tryParseRequest(&sb);
    switch (event) {
        .request => |req| {
            try std.testing.expectEqualSlices(u8, "POST", req.methodSlice());
            try std.testing.expectEqualSlices(u8, "/api/test", req.pathSlice());
            try std.testing.expectEqualSlices(u8, "https", req.scheme[0..req.scheme_len]);
            try std.testing.expectEqualSlices(u8, "localhost", req.authoritySlice());
            try std.testing.expectEqualSlices(u8, "application/grpc", req.contentTypeSlice());
        },
        else => unreachable,
    }
}

test "H3Request: HEADERS + DATA frames" {
    var headers_to_encode = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers_to_encode) orelse unreachable;

    var frame_buf: [2048]u8 = undefined;
    var pos: usize = 0;

    // HEADERS frame
    pos += h3_frame.encodeHeadersFrame(frame_buf[pos..], qpack_buf[0..qpack_len]) orelse unreachable;

    // DATA frame with body
    const body = "Hello, World!";
    pos += h3_frame.encodeDataFrame(frame_buf[pos..], body) orelse unreachable;

    var sb = StreamBuf.init();
    sb.stream_id = 4;
    sb.conn_idx = 0;
    sb.fin = true;
    @memcpy(sb.data[0..pos], frame_buf[0..pos]);
    sb.len = pos;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    const event = server.tryParseRequest(&sb);
    switch (event) {
        .request => |req| {
            try std.testing.expectEqualSlices(u8, "POST", req.methodSlice());
            try std.testing.expectEqualSlices(u8, "/echo", req.pathSlice());
            try std.testing.expectEqualSlices(u8, "Hello, World!", req.bodySlice());
            try std.testing.expect(req.fin);
        },
        else => unreachable,
    }
}

test "H3Request: GET emits without FIN (bodyless method)" {
    var headers_to_encode = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers_to_encode) orelse unreachable;

    var frame_buf: [1024]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    var sb = StreamBuf.init();
    sb.stream_id = 0;
    sb.conn_idx = 0;
    sb.fin = false; // No FIN yet
    @memcpy(sb.data[0..frame_len], frame_buf[0..frame_len]);
    sb.len = frame_len;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    // GET is bodyless — should emit request even without FIN
    const event = server.tryParseRequest(&sb);
    try std.testing.expect(event == .request);
}

test "H3Request: POST without FIN emits request immediately (streaming)" {
    var headers_to_encode = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/upload" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers_to_encode) orelse unreachable;

    var frame_buf: [1024]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    var sb = StreamBuf.init();
    sb.stream_id = 0;
    sb.conn_idx = 0;
    sb.fin = false; // No FIN — streaming case
    @memcpy(sb.data[0..frame_len], frame_buf[0..frame_len]);
    sb.len = frame_len;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    // POST without FIN emits request immediately (for streaming support)
    const event = server.tryParseRequest(&sb);
    try std.testing.expect(event == .request);
    const req = event.request;
    try std.testing.expectEqualSlices(u8, "POST", req.methodSlice());
    try std.testing.expect(!req.fin);
    try std.testing.expect(sb.headers_emitted);
}

test "H3Request: unidirectional stream ignored" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    // Stream ID 2 = client-initiated unidirectional (0x02 & 0x03 == 0x02 != 0x00)
    const event = server.handleStreamData(2, 0, "some data", true);
    try std.testing.expect(event == .none);
}

test "H3Server: response encoding produces valid QPACK" {
    // Verify the encoding logic works by testing the components directly
    var status_buf: [3]u8 = undefined;
    const status_str = statusToStr(200, &status_buf);
    try std.testing.expectEqualSlices(u8, "200", status_str);

    // Encode a response header block
    var all_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &all_headers) orelse unreachable;
    try std.testing.expect(qpack_len > 0);

    // Encode as HEADERS frame
    var frame_buf: [512]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;
    try std.testing.expect(frame_len > 0);

    // Verify frame can be decoded
    const decoded = h3_frame.decodeFrameHeader(frame_buf[0..frame_len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x01), decoded.frame_type);
}

test "H3Server: gracefulShutdown sets state" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    try std.testing.expect(!server.isShuttingDown());
    server.gracefulShutdown(4);
    try std.testing.expect(server.isShuttingDown());
    try std.testing.expectEqual(@as(u62, 4), server.goaway_stream_id);
}

test "H3Server: shutdown rejects streams above goaway_stream_id" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();

    // Before shutdown, stream 8 is accepted (gets buffered)
    const event1 = server.handleStreamData(8, 0, "data", false);
    // Returns .none because no complete HEADERS yet, but it was buffered
    _ = event1;

    // After shutdown with goaway_stream_id=4, stream 8 is rejected
    server.gracefulShutdown(4);
    const event2 = server.handleStreamData(8, 0, "more", true);
    try std.testing.expect(event2 == .none);

    // Stream 0 (below goaway) is still accepted
    var headers_to_encode = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/test" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers_to_encode) orelse unreachable;
    var frame_buf: [1024]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    const event3 = server.handleStreamData(0, 0, frame_buf[0..frame_len], true);
    try std.testing.expect(event3 == .request);
}

test "H3Server: activeConnectionCount" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(addr, .{});
    defer server.deinit();
    try std.testing.expectEqual(@as(usize, 0), server.activeConnectionCount());
}
