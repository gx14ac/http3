const std = @import("std");
const client_mod = @import("client.zig");
const session_mod = @import("session.zig");
const h3_frame = @import("h3_frame.zig");
const qpack = @import("qpack.zig");
const stream_mod = @import("stream.zig");
const packet_mod = @import("packet.zig");

const QuicClient = client_mod.QuicClient;
const PollResult = client_mod.PollResult;
const ConnectError = client_mod.ConnectError;
const Session = session_mod.Session;
const StreamFrame = stream_mod.StreamFrame;

/// HTTP/3 response received from the server.
pub const H3Response = struct {
    status: u16,
    headers: [32]qpack.HeaderField,
    header_count: usize,
    body: [MAX_BODY]u8,
    body_len: usize,
    stream_id: u62,

    const MAX_BODY = 65536;

    pub fn statusCode(self: *const H3Response) u16 {
        return self.status;
    }

    pub fn getHeader(self: *const H3Response, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |h| {
            if (std.mem.eql(u8, h.name, name)) return h.value;
        }
        return null;
    }

    pub fn bodySlice(self: *const H3Response) []const u8 {
        return self.body[0..self.body_len];
    }
};

pub const H3Error = error{
    NotConnected,
    SessionFull,
    EncodeFailed,
    WriteFailed,
    Timeout,
    ConnectionClosed,
    InvalidResponse,
};

/// HTTP/3 client: QuicClient + Session + frame parsing.
/// This struct is ~1MB due to per-stream receive buffers. Allocate on the heap:
///   const h3 = try allocator.create(H3Client);
///   h3.* = try H3Client.init(addr, "example.com");
///   defer { h3.deinit(); allocator.destroy(h3); }
pub const H3Client = struct {
    quic: QuicClient,
    session: Session,
    server_name: [256]u8,
    server_name_len: usize,

    stream_bufs: [MAX_STREAMS]StreamBuf,
    server_control_stream_id: ?u62,
    control_parse_pos: usize,

    const MAX_STREAMS = 16;
    const RECV_TIMEOUT_ITERATIONS = 200;

    const StreamBuf = struct {
        stream_id: ?u62,
        data: [65536]u8,
        // Highest byte position written (max offset + data.len across all received segments)
        len: usize,
        // Contiguous bytes from offset 0 — only this range is safe to parse
        contiguous_len: usize,
        // Bitmap tracking which byte ranges have been received (per 64-byte granularity)
        // 1024 bits = 64KB coverage at 64-byte granularity
        recv_bitmap: [128]u8,
        fin_received: bool,

        fn init() StreamBuf {
            return .{
                .stream_id = null,
                .data = undefined,
                .len = 0,
                .contiguous_len = 0,
                .recv_bitmap = [_]u8{0} ** 128,
                .fin_received = false,
            };
        }

        fn reset(self: *StreamBuf) void {
            self.stream_id = null;
            self.len = 0;
            self.contiguous_len = 0;
            self.recv_bitmap = [_]u8{0} ** 128;
            self.fin_received = false;
        }

        const GRANULARITY = 64;

        fn markReceived(self: *StreamBuf, offset: usize, length: usize) void {
            const start_chunk = offset / GRANULARITY;
            const end_byte = offset + length;
            const end_chunk = (end_byte + GRANULARITY - 1) / GRANULARITY;
            var chunk = start_chunk;
            while (chunk < end_chunk and chunk < 1024) : (chunk += 1) {
                self.recv_bitmap[chunk / 8] |= @as(u8, 1) << @intCast(chunk % 8);
            }
            self.updateContiguous();
        }

        fn updateContiguous(self: *StreamBuf) void {
            var chunk: usize = self.contiguous_len / GRANULARITY;
            while (chunk < 1024) : (chunk += 1) {
                const byte_idx = chunk / 8;
                const bit_idx: u3 = @intCast(chunk % 8);
                if (self.recv_bitmap[byte_idx] & (@as(u8, 1) << bit_idx) == 0) break;
            }
            const new_contiguous = @min(chunk * GRANULARITY, self.len);
            if (new_contiguous > self.contiguous_len) {
                self.contiguous_len = new_contiguous;
            }
        }

        fn isContiguous(self: *const StreamBuf) bool {
            return self.contiguous_len >= self.len;
        }
    };

    pub const H3Config = struct {
        congestion: client_mod.CongestionAlgorithm = .cubic,
    };

    pub fn init(remote: std.net.Address, server_name: []const u8) !H3Client {
        return initWithConfig(remote, server_name, .{});
    }

    pub fn initWithConfig(remote: std.net.Address, server_name: []const u8, config: H3Config) !H3Client {
        var dcid: [8]u8 = undefined;
        var scid: [8]u8 = undefined;
        std.crypto.random.bytes(&dcid);
        std.crypto.random.bytes(&scid);

        var quic_client = try QuicClient.initWithConfig(remote, &dcid, &scid, .{ .congestion = config.congestion });
        errdefer quic_client.deinit();

        var name_buf: [256]u8 = undefined;
        const name_len = @min(server_name.len, 256);
        @memcpy(name_buf[0..name_len], server_name[0..name_len]);

        return .{
            .quic = quic_client,
            .session = Session.init(server_name),
            .server_name = name_buf,
            .server_name_len = name_len,
            .stream_bufs = [_]StreamBuf{StreamBuf.init()} ** MAX_STREAMS,
            .server_control_stream_id = null,
            .control_parse_pos = 0,
        };
    }

    pub fn deinit(self: *H3Client) void {
        self.quic.deinit();
    }

    /// Perform QUIC handshake + open H3 control/QPACK streams.
    pub fn connect(self: *H3Client) H3Error!void {
        self.session.startHandshake();
        self.quic.connect(self.server_name[0..self.server_name_len]) catch |e| {
            return switch (e) {
                ConnectError.Timeout => H3Error.Timeout,
                ConnectError.SocketError => H3Error.WriteFailed,
                else => H3Error.WriteFailed,
            };
        };

        const streams = self.session.onHandshakeComplete() orelse return H3Error.EncodeFailed;

        try self.writeWithRetry(streams.control_stream_id, streams.control_data[0..streams.control_data_len], false);
        try self.writeWithRetry(streams.qpack_enc_stream_id, streams.qpack_enc_data[0..streams.qpack_enc_data_len], false);
        try self.writeWithRetry(streams.qpack_dec_stream_id, streams.qpack_dec_data[0..streams.qpack_dec_data_len], false);
    }

    /// Send an HTTP/3 request and wait for the response.
    pub fn request(
        self: *H3Client,
        method: []const u8,
        path: []const u8,
        extra_headers: []const qpack.HeaderField,
        body: ?[]const u8,
    ) H3Error!H3Response {
        if (!self.quic.isConnected()) return H3Error.NotConnected;

        var all_headers: [36]qpack.HeaderField = undefined;
        var hdr_count: usize = 0;

        all_headers[hdr_count] = .{ .name = ":method", .value = method };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":scheme", .value = "https" };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":authority", .value = self.server_name[0..self.server_name_len] };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":path", .value = path };
        hdr_count += 1;

        for (extra_headers) |h| {
            if (hdr_count >= all_headers.len) break;
            all_headers[hdr_count] = h;
            hdr_count += 1;
        }

        const req = self.session.sendRequest(all_headers[0..hdr_count], body) orelse
            return H3Error.SessionFull;

        _ = self.allocStreamBuf(req.stream_id) orelse return H3Error.SessionFull;

        try self.writeWithRetry(req.stream_id, req.headers_frame[0..req.headers_frame_len], !req.has_body);

        if (req.has_body) {
            try self.writeWithRetry(req.stream_id, req.data_frame[0..req.data_frame_len], true);
        }

        return self.awaitResponse(req.stream_id);
    }

    const WRITE_RETRY_LIMIT = 20;

    /// Write stream data with CC/pacer retry. Polls until send window opens.
    fn writeWithRetry(self: *H3Client, stream_id: u62, data: []const u8, fin: bool) H3Error!void {
        var attempts: usize = 0;
        while (attempts < WRITE_RETRY_LIMIT) : (attempts += 1) {
            if (self.quic.writeStream(stream_id, data, fin) != null) return;
            // CC-blocked or pacer-limited — poll to advance timers and drain ACKs
            const poll_result = self.quic.poll();
            if (poll_result == .closed) return H3Error.ConnectionClosed;
            if (poll_result == .received) {
                const payload = self.quic.lastStreamData();
                if (payload.len > 0) self.feedPayload(payload);
            }
        }
        return H3Error.WriteFailed;
    }

    /// Poll until we receive a complete response for the given stream.
    fn awaitResponse(self: *H3Client, stream_id: u62) H3Error!H3Response {
        var iterations: usize = 0;
        while (iterations < RECV_TIMEOUT_ITERATIONS) : (iterations += 1) {
            const poll_result = self.quic.poll();

            switch (poll_result) {
                .received => {
                    const payload = self.quic.lastStreamData();
                    if (payload.len > 0) {
                        self.feedPayload(payload);
                    }
                    if (self.isResponseComplete(stream_id)) {
                        return self.buildResponse(stream_id);
                    }
                },
                .closed => return H3Error.ConnectionClosed,
                .connected, .timeout, .idle => {},
            }
        }

        return H3Error.Timeout;
    }

    /// Feed raw QUIC payload into stream buffers by parsing STREAM frames.
    /// Called externally when data arrives (or by poll integration).
    pub fn feedPayload(self: *H3Client, plaintext: []const u8) void {
        var pos: usize = 0;
        while (pos < plaintext.len) {
            const remaining = plaintext[pos..];
            if (remaining.len == 0) break;

            const frame_type = remaining[0];
            if (frame_type & 0xF8 == 0x08) {
                // STREAM frame
                const decoded = StreamFrame.decode(remaining) orelse break;
                self.onStreamData(decoded.frame.stream_id, decoded.frame.offset, decoded.frame.data, decoded.frame.fin);
                pos += decoded.consumed;
            } else {
                // Skip non-STREAM frames using proper frame length decoding
                const skipped = skipQuicFrame(remaining) orelse break;
                pos += skipped;
            }
        }
    }

    /// Deliver stream data to the appropriate buffer at the correct offset.
    fn onStreamData(self: *H3Client, stream_id: u62, offset: u64, data: []const u8, fin: bool) void {
        // Track received bytes for flow control
        if (data.len > 0) {
            self.quic.onStreamDataReceived(stream_id, data.len);
        }

        // Detect new server-initiated uni-stream (low 2 bits = 0b11)
        if (stream_id & 0x03 == 0x03 and offset == 0 and self.server_control_stream_id == null) {
            if (data.len > 0 and data[0] == 0x00) {
                self.server_control_stream_id = stream_id;
                _ = self.allocStreamBuf(stream_id) orelse return;
                // Store full data (including type byte) in StreamBuf; parse_pos starts at 1
                self.control_parse_pos = 1;
                self.writeToStreamBuf(stream_id, offset, data, fin);
                self.tryParseControlStream();
                return;
            }
        }

        // Route data to existing control stream StreamBuf (offset used as-is)
        if (self.server_control_stream_id != null and self.server_control_stream_id.? == stream_id) {
            self.writeToStreamBuf(stream_id, offset, data, fin);
            self.tryParseControlStream();
            return;
        }

        self.writeToStreamBuf(stream_id, offset, data, fin);
    }

    /// Write data into a StreamBuf at the given offset, handling reassembly.
    fn writeToStreamBuf(self: *H3Client, stream_id: u62, offset: u64, data: []const u8, fin: bool) void {
        const sb = self.getStreamBuf(stream_id) orelse return;
        const write_pos: usize = @intCast(offset);
        if (write_pos > sb.data.len) return;
        const space = sb.data.len - write_pos;
        const copy_len = @min(data.len, space);
        if (copy_len > 0) {
            @memcpy(sb.data[write_pos..][0..copy_len], data[0..copy_len]);
            const new_end = write_pos + copy_len;
            if (new_end > sb.len) sb.len = new_end;
            sb.markReceived(write_pos, copy_len);
        }
        if (fin) sb.fin_received = true;
    }

    /// Parse H3 frames from the control stream's StreamBuf (contiguous region only).
    fn tryParseControlStream(self: *H3Client) void {
        const ctrl_id = self.server_control_stream_id orelse return;
        const sb = self.getStreamBuf(ctrl_id) orelse return;

        while (self.control_parse_pos < sb.contiguous_len) {
            const remaining = sb.data[self.control_parse_pos..sb.contiguous_len];
            if (remaining.len < 2) break;

            const result = self.session.h3.processControlFrame(remaining) orelse break;
            const consumed: usize = result.header_len + @as(usize, @intCast(result.payload_len));
            if (consumed > remaining.len) break;

            if (result.frame_type == .goaway) {
                self.session.state = .draining;
            }

            self.control_parse_pos += consumed;
        }
    }

    /// Check if we have a complete response (FIN received + no gaps in data).
    fn isResponseComplete(self: *H3Client, stream_id: u62) bool {
        const sb = self.getStreamBuf(stream_id) orelse return false;
        return sb.fin_received and sb.len > 0 and sb.isContiguous();
    }

    /// Build the response from accumulated stream data.
    fn buildResponse(self: *H3Client, stream_id: u62) H3Error!H3Response {
        const sb = self.getStreamBuf(stream_id) orelse return H3Error.InvalidResponse;
        if (sb.len == 0) return H3Error.InvalidResponse;

        var response = H3Response{
            .status = 0,
            .headers = undefined,
            .header_count = 0,
            .body = undefined,
            .body_len = 0,
            .stream_id = stream_id,
        };

        var pos: usize = 0;
        while (pos < sb.len) {
            const remaining = sb.data[pos..sb.len];
            if (remaining.len < 2) break;

            const fh = h3_frame.decodeFrameHeader(remaining) orelse break;
            const payload_len: usize = @intCast(fh.length);
            const frame_end = fh.header_len + payload_len;
            if (remaining.len < frame_end) break;

            const payload = remaining[fh.header_len..frame_end];

            if (fh.frame_type == 0x01) {
                // HEADERS frame
                const decoded = self.session.processResponseHeaders(stream_id, payload) orelse {
                    pos += frame_end;
                    continue;
                };
                response.headers = decoded.headers;
                response.header_count = decoded.header_count;

                for (decoded.headers[0..decoded.header_count]) |h| {
                    if (std.mem.eql(u8, h.name, ":status")) {
                        response.status = std.fmt.parseInt(u16, h.value, 10) catch 0;
                        break;
                    }
                }
            } else if (fh.frame_type == 0x00) {
                // DATA frame
                const copy_len = @min(payload.len, H3Response.MAX_BODY - response.body_len);
                @memcpy(response.body[response.body_len..][0..copy_len], payload[0..copy_len]);
                response.body_len += copy_len;
            }
            pos += frame_end;
        }

        self.session.completeRequest(stream_id);
        self.session.closeRequest(stream_id);
        self.freeStreamBuf(stream_id);

        return response;
    }

    fn allocStreamBuf(self: *H3Client, stream_id: u62) ?usize {
        for (&self.stream_bufs, 0..) |*sb, i| {
            if (sb.stream_id == null) {
                sb.stream_id = stream_id;
                sb.len = 0;
                sb.contiguous_len = 0;
                sb.recv_bitmap = [_]u8{0} ** 128;
                sb.fin_received = false;
                return i;
            }
        }
        return null;
    }

    fn getStreamBuf(self: *H3Client, stream_id: u62) ?*StreamBuf {
        for (&self.stream_bufs) |*sb| {
            if (sb.stream_id != null and sb.stream_id.? == stream_id) return sb;
        }
        return null;
    }

    fn freeStreamBuf(self: *H3Client, stream_id: u62) void {
        for (&self.stream_bufs) |*sb| {
            if (sb.stream_id != null and sb.stream_id.? == stream_id) {
                sb.reset();
                return;
            }
        }
    }

    /// Send an HTTP/3 request and return a stream handle for receiving
    /// multiple DATA frames (server-streaming RPCs).
    pub fn requestStream(
        self: *H3Client,
        method: []const u8,
        path: []const u8,
        extra_headers: []const qpack.HeaderField,
        body: ?[]const u8,
    ) H3Error!H3StreamHandle {
        if (!self.quic.isConnected()) return H3Error.NotConnected;

        var all_headers: [36]qpack.HeaderField = undefined;
        var hdr_count: usize = 0;

        all_headers[hdr_count] = .{ .name = ":method", .value = method };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":scheme", .value = "https" };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":authority", .value = self.server_name[0..self.server_name_len] };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":path", .value = path };
        hdr_count += 1;

        for (extra_headers) |h| {
            if (hdr_count >= all_headers.len) break;
            all_headers[hdr_count] = h;
            hdr_count += 1;
        }

        const req = self.session.sendRequest(all_headers[0..hdr_count], body) orelse
            return H3Error.SessionFull;

        _ = self.allocStreamBuf(req.stream_id) orelse return H3Error.SessionFull;

        try self.writeWithRetry(req.stream_id, req.headers_frame[0..req.headers_frame_len], !req.has_body);

        if (req.has_body) {
            try self.writeWithRetry(req.stream_id, req.data_frame[0..req.data_frame_len], true);
        }

        return H3StreamHandle{
            .client = self,
            .stream_id = req.stream_id,
            .headers_received = false,
            .stream_ended = false,
            .parse_pos = 0,
            .resp_status = 0,
            .resp_headers = undefined,
            .resp_header_count = 0,
            .trailer_headers = undefined,
            .trailer_header_count = 0,
        };
    }

    /// Open a stream for client-streaming or bidi: send headers only (no FIN).
    /// Caller uses handle.send() to write DATA frames, handle.closeSend() to finish.
    pub fn requestStreamOpen(
        self: *H3Client,
        method: []const u8,
        path: []const u8,
        extra_headers: []const qpack.HeaderField,
    ) H3Error!H3StreamHandle {
        if (!self.quic.isConnected()) return H3Error.NotConnected;

        var all_headers: [36]qpack.HeaderField = undefined;
        var hdr_count: usize = 0;

        all_headers[hdr_count] = .{ .name = ":method", .value = method };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":scheme", .value = "https" };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":authority", .value = self.server_name[0..self.server_name_len] };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":path", .value = path };
        hdr_count += 1;

        for (extra_headers) |h| {
            if (hdr_count >= all_headers.len) break;
            all_headers[hdr_count] = h;
            hdr_count += 1;
        }

        const req = self.session.sendRequest(all_headers[0..hdr_count], null) orelse
            return H3Error.SessionFull;

        _ = self.allocStreamBuf(req.stream_id) orelse return H3Error.SessionFull;

        // Send HEADERS only, no FIN — stream stays open for writing
        try self.writeWithRetry(req.stream_id, req.headers_frame[0..req.headers_frame_len], false);

        return H3StreamHandle{
            .client = self,
            .stream_id = req.stream_id,
            .headers_received = false,
            .stream_ended = false,
            .parse_pos = 0,
            .resp_status = 0,
            .resp_headers = undefined,
            .resp_header_count = 0,
            .trailer_headers = undefined,
            .trailer_header_count = 0,
        };
    }

    pub fn isConnected(self: *const H3Client) bool {
        return self.quic.isConnected();
    }

    /// Send a QUIC PING for keepalive. Returns true if sent.
    pub fn ping(self: *H3Client) bool {
        return self.quic.sendPing();
    }

    /// Returns true if the server has sent a GOAWAY frame.
    pub fn goawayReceived(self: *const H3Client) bool {
        return self.session.h3.goaway_received;
    }

    /// Returns the last stream ID from the GOAWAY frame (valid only if goawayReceived()).
    pub fn goawayId(self: *const H3Client) u62 {
        return self.session.h3.goaway_id;
    }

    // ─── Multiplexed (non-blocking) request API ───

    /// Submit a request without waiting for the response.
    /// Returns the stream ID which can later be used with takeResponse().
    /// Multiple requests can be submitted before polling for responses.
    pub fn submitRequest(
        self: *H3Client,
        method: []const u8,
        path: []const u8,
        extra_headers: []const qpack.HeaderField,
        body: ?[]const u8,
    ) H3Error!u62 {
        if (!self.quic.isConnected()) return H3Error.NotConnected;

        var all_headers: [36]qpack.HeaderField = undefined;
        var hdr_count: usize = 0;

        all_headers[hdr_count] = .{ .name = ":method", .value = method };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":scheme", .value = "https" };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":authority", .value = self.server_name[0..self.server_name_len] };
        hdr_count += 1;
        all_headers[hdr_count] = .{ .name = ":path", .value = path };
        hdr_count += 1;

        for (extra_headers) |h| {
            if (hdr_count >= all_headers.len) break;
            all_headers[hdr_count] = h;
            hdr_count += 1;
        }

        const req = self.session.sendRequest(all_headers[0..hdr_count], body) orelse
            return H3Error.SessionFull;

        _ = self.allocStreamBuf(req.stream_id) orelse return H3Error.SessionFull;

        try self.writeWithRetry(req.stream_id, req.headers_frame[0..req.headers_frame_len], !req.has_body);

        if (req.has_body) {
            try self.writeWithRetry(req.stream_id, req.data_frame[0..req.data_frame_len], true);
        }

        return req.stream_id;
    }

    /// Result of a single poll cycle for multiplexed requests.
    pub const PollEvent = union(enum) {
        none,
        response_ready: u62,
        closed,
    };

    /// Drive the connection: process one round of incoming data.
    /// Returns .response_ready with the stream_id if any request's response is complete.
    /// Call repeatedly in a loop to process all in-flight requests.
    pub fn pollEvent(self: *H3Client) PollEvent {
        const poll_result = self.quic.poll();
        switch (poll_result) {
            .received => {
                const payload = self.quic.lastStreamData();
                if (payload.len > 0) {
                    self.feedPayload(payload);
                }
                // Check all active streams for completion
                for (&self.stream_bufs) |*sb| {
                    if (sb.stream_id) |sid| {
                        if (self.isResponseComplete(sid)) {
                            return .{ .response_ready = sid };
                        }
                    }
                }
                return .none;
            },
            .closed => return .closed,
            .connected, .timeout, .idle => return .none,
        }
    }

    /// Take a completed response for the given stream ID.
    /// Only valid after pollEvent() returned .response_ready for this stream.
    pub fn takeResponse(self: *H3Client, stream_id: u62) H3Error!H3Response {
        return self.buildResponse(stream_id);
    }

    /// Check how many requests are currently in flight (submitted but not yet taken).
    pub fn inFlightCount(self: *const H3Client) usize {
        var count: usize = 0;
        for (&self.stream_bufs) |*sb| {
            if (sb.stream_id) |sid| {
                // Exclude control/qpack streams (uni streams have bit 1 set)
                if (sid & 0x02 == 0) count += 1;
            }
        }
        return count;
    }

    pub fn close(self: *H3Client) void {
        self.session.close();
        self.quic.close();
    }

    /// Configure reconnection parameters.
    pub fn setReconnectConfig(self: *H3Client, config: client_mod.QuicClient.ReconnectConfig) void {
        self.quic.setReconnectConfig(config);
    }

    /// Reconnect after disconnection: fresh QUIC handshake + re-establish H3 control streams.
    /// Uses 0-RTT resumption if a session ticket is available.
    pub fn reconnect(self: *H3Client) H3Error!void {
        // Reset H3-level state
        self.resetH3State();

        // Reconnect at QUIC level
        self.quic.reconnect() catch |e| {
            return switch (e) {
                ConnectError.Timeout => H3Error.Timeout,
                ConnectError.SocketError => H3Error.WriteFailed,
                else => H3Error.WriteFailed,
            };
        };

        // Re-establish H3 control streams
        const streams = self.session.onHandshakeComplete() orelse return H3Error.EncodeFailed;

        try self.writeWithRetry(streams.control_stream_id, streams.control_data[0..streams.control_data_len], false);
        try self.writeWithRetry(streams.qpack_enc_stream_id, streams.qpack_enc_data[0..streams.qpack_enc_data_len], false);
        try self.writeWithRetry(streams.qpack_dec_stream_id, streams.qpack_dec_data[0..streams.qpack_dec_data_len], false);
    }

    /// Check if the reconnect manager has given up retrying.
    pub fn reconnectGaveUp(self: *const H3Client) bool {
        return self.quic.reconnect_mgr.state == .gave_up;
    }

    fn resetH3State(self: *H3Client) void {
        self.session = Session.init(self.server_name[0..self.server_name_len]);
        self.session.startHandshake();
        for (&self.stream_bufs) |*sb| sb.reset();
        self.server_control_stream_id = null;
        self.control_parse_pos = 0;
    }
};

/// Handle for reading streaming responses from an H3 request.
/// Receives individual DATA frame payloads one at a time.
pub const H3StreamHandle = struct {
    client: *H3Client,
    stream_id: u62,
    headers_received: bool,
    stream_ended: bool,
    parse_pos: usize,
    resp_status: u16,
    resp_headers: [32]qpack.HeaderField,
    resp_header_count: usize,
    trailer_headers: [16]qpack.HeaderField,
    trailer_header_count: usize,

    const STREAM_RECV_TIMEOUT = 200;

    /// Wait for response headers. Must be called before recv().
    /// Returns the HTTP status code.
    pub fn recvHeaders(self: *H3StreamHandle) H3Error!u16 {
        if (self.headers_received) return self.resp_status;

        var iterations: usize = 0;
        while (iterations < STREAM_RECV_TIMEOUT) : (iterations += 1) {
            self.pollOnce();

            const sb = self.client.getStreamBuf(self.stream_id) orelse
                return H3Error.InvalidResponse;

            if (sb.contiguous_len > self.parse_pos) {
                if (self.tryParseHeaders(sb)) return self.resp_status;
            }

            if (sb.fin_received and sb.isContiguous()) {
                if (!self.headers_received) return H3Error.InvalidResponse;
                break;
            }
        }

        if (!self.headers_received) return H3Error.Timeout;
        return self.resp_status;
    }

    /// Receive the next DATA frame payload from the stream.
    /// Returns null when the stream ends (FIN received, no more data).
    pub fn recv(self: *H3StreamHandle, buf: []u8) H3Error!?[]const u8 {
        if (self.stream_ended) return null;

        var iterations: usize = 0;
        while (iterations < STREAM_RECV_TIMEOUT) : (iterations += 1) {
            self.pollOnce();

            const sb = self.client.getStreamBuf(self.stream_id) orelse
                return H3Error.InvalidResponse;

            if (sb.contiguous_len > self.parse_pos) {
                if (self.tryParseNextData(sb, buf)) |payload_len| {
                    return buf[0..payload_len];
                }
            }

            if (sb.fin_received and sb.isContiguous() and sb.len <= self.parse_pos) {
                self.stream_ended = true;
                return null;
            }
        }

        return H3Error.Timeout;
    }

    /// Send a gRPC/H3 DATA frame on this stream (client-streaming / bidi).
    /// Large payloads are split into multiple DATA frames (max ~4080B payload each).
    /// Does NOT set FIN — call closeSend() when done writing.
    pub fn send(self: *H3StreamHandle, payload: []const u8) H3Error!void {
        const MAX_PAYLOAD_PER_FRAME = 4080;
        var offset: usize = 0;
        while (offset < payload.len) {
            const chunk_len = @min(payload.len - offset, MAX_PAYLOAD_PER_FRAME);
            var frame_buf: [4096]u8 = undefined;
            const frame_len = h3_frame.encodeDataFrame(&frame_buf, payload[offset..][0..chunk_len]) orelse
                return H3Error.EncodeFailed;
            try self.client.writeWithRetry(self.stream_id, frame_buf[0..frame_len], false);
            offset += chunk_len;
        }
    }

    /// Close the send side of the stream (FIN). No more send() calls after this.
    pub fn closeSend(self: *H3StreamHandle) H3Error!void {
        try self.client.writeWithRetry(self.stream_id, &.{}, true);
    }

    /// Get a trailer header value by name. Available after stream ends.
    pub fn trailerValue(self: *const H3StreamHandle, name: []const u8) ?[]const u8 {
        for (self.trailer_headers[0..self.trailer_header_count]) |h| {
            if (std.mem.eql(u8, h.name, name)) return h.value;
        }
        return null;
    }

    /// Release stream resources.
    pub fn close(self: *H3StreamHandle) void {
        self.client.session.completeRequest(self.stream_id);
        self.client.session.closeRequest(self.stream_id);
        self.client.freeStreamBuf(self.stream_id);
        self.stream_ended = true;
    }

    fn pollOnce(self: *H3StreamHandle) void {
        const poll_result = self.client.quic.poll();
        switch (poll_result) {
            .received => {
                const payload = self.client.quic.lastStreamData();
                if (payload.len > 0) self.client.feedPayload(payload);
            },
            .closed => self.stream_ended = true,
            .connected, .timeout, .idle => {},
        }
    }

    fn tryParseHeaders(self: *H3StreamHandle, sb: *H3Client.StreamBuf) bool {
        const remaining = sb.data[self.parse_pos..sb.contiguous_len];
        if (remaining.len < 2) return false;

        const fh = h3_frame.decodeFrameHeader(remaining) orelse return false;
        const payload_len: usize = @intCast(fh.length);
        const frame_end = fh.header_len + payload_len;
        if (remaining.len < frame_end) return false;

        if (fh.frame_type == 0x01) {
            const payload = remaining[fh.header_len..frame_end];
            const decoded = self.client.session.processResponseHeaders(self.stream_id, payload) orelse {
                self.parse_pos += frame_end;
                return false;
            };
            self.resp_headers = decoded.headers;
            self.resp_header_count = decoded.header_count;

            for (decoded.headers[0..decoded.header_count]) |h| {
                if (std.mem.eql(u8, h.name, ":status")) {
                    self.resp_status = std.fmt.parseInt(u16, h.value, 10) catch 0;
                    break;
                }
            }
            self.headers_received = true;
            self.parse_pos += frame_end;
            return true;
        }

        // Skip non-HEADERS frame before headers arrive
        self.parse_pos += frame_end;
        return false;
    }

    fn tryParseNextData(self: *H3StreamHandle, sb: *H3Client.StreamBuf, buf: []u8) ?usize {
        while (self.parse_pos < sb.contiguous_len) {
            const remaining = sb.data[self.parse_pos..sb.contiguous_len];
            if (remaining.len < 2) return null;

            const fh = h3_frame.decodeFrameHeader(remaining) orelse return null;
            const payload_len: usize = @intCast(fh.length);
            const frame_end = fh.header_len + payload_len;
            if (remaining.len < frame_end) return null;

            self.parse_pos += frame_end;

            if (fh.frame_type == 0x00) {
                // DATA frame
                const copy_len = @min(payload_len, buf.len);
                @memcpy(buf[0..copy_len], remaining[fh.header_len..][0..copy_len]);
                return copy_len;
            } else if (fh.frame_type == 0x01) {
                // Trailing HEADERS (trailers)
                const trailer_payload = remaining[fh.header_len..frame_end];
                if (self.client.session.processResponseHeaders(self.stream_id, trailer_payload)) |decoded| {
                    const count = @min(decoded.header_count, self.trailer_headers.len);
                    @memcpy(self.trailer_headers[0..count], decoded.headers[0..count]);
                    self.trailer_header_count = count;
                }
                self.stream_ended = true;
                return null;
            }
            // Skip other frame types (SETTINGS on control stream, etc.)
        }
        return null;
    }
};

/// Skip a non-STREAM QUIC frame using proper frame structure (RFC 9000 §12.4).
/// Returns bytes consumed, or null if the frame cannot be parsed.
fn skipQuicFrame(data: []const u8) ?usize {
    if (data.len == 0) return null;

    // Decode frame type as varint
    const ft_result = packet_mod.decodeVarint(data) orelse return null;
    const ft = ft_result.value;
    var pos: usize = ft_result.consumed;

    // Fixed-length frames (no length field)
    switch (ft) {
        0x00 => return 1, // PADDING
        0x01 => return 1, // PING
        0x02, 0x03 => {
            // ACK: largest_ack(vi) + ack_delay(vi) + ack_range_count(vi) + first_range(vi) + ranges...
            const largest = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += largest.consumed;
            const delay = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += delay.consumed;
            const range_count = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += range_count.consumed;
            const first_range = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += first_range.consumed;
            // Each additional range: gap(vi) + range_len(vi)
            var i: usize = 0;
            while (i < range_count.value) : (i += 1) {
                const gap = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += gap.consumed;
                const range_len = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += range_len.consumed;
            }
            // ECN counts for ACK_ECN (type 0x03)
            if (ft == 0x03) {
                const ect0 = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += ect0.consumed;
                const ect1 = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += ect1.consumed;
                const ecn_ce = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += ecn_ce.consumed;
            }
            return pos;
        },
        0x04 => {
            // MAX_DATA: maximum_data(vi)
            const max = packet_mod.decodeVarint(data[pos..]) orelse return null;
            return pos + max.consumed;
        },
        0x05 => {
            // MAX_STREAM_DATA: stream_id(vi) + maximum_data(vi)
            const sid = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += sid.consumed;
            const max = packet_mod.decodeVarint(data[pos..]) orelse return null;
            return pos + max.consumed;
        },
        0x06, 0x07 => {
            // CRYPTO: offset(vi) + length(vi) + data[length]
            const offset = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += offset.consumed;
            const length = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += length.consumed;
            const len: usize = @intCast(length.value);
            if (data.len < pos + len) return null;
            return pos + len;
        },
        0x10, 0x11 => {
            // RESET_STREAM / STOP_SENDING: stream_id(vi) + code(vi) [+ final_size(vi) for RESET]
            const sid = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += sid.consumed;
            const code = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += code.consumed;
            if (ft == 0x10) {
                // RESET_STREAM has final_size
                const fs = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += fs.consumed;
            }
            return pos;
        },
        0x12, 0x13 => {
            // MAX_STREAMS (bidi/uni): maximum_streams(vi)
            const max = packet_mod.decodeVarint(data[pos..]) orelse return null;
            return pos + max.consumed;
        },
        0x18, 0x19 => {
            // NEW_CONNECTION_ID / RETIRE_CONNECTION_ID
            if (ft == 0x18) {
                // seq(vi) + retire_prior(vi) + len(1) + cid[len] + token[16]
                const seq = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += seq.consumed;
                const retire = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += retire.consumed;
                if (pos >= data.len) return null;
                const cid_len = data[pos];
                pos += 1;
                pos += cid_len;
                pos += 16; // stateless reset token
                if (pos > data.len) return null;
                return pos;
            } else {
                // RETIRE_CONNECTION_ID: seq(vi)
                const seq = packet_mod.decodeVarint(data[pos..]) orelse return null;
                return pos + seq.consumed;
            }
        },
        0x1C, 0x1D => {
            // CONNECTION_CLOSE: error_code(vi) + [frame_type(vi)] + reason_len(vi) + reason[len]
            const code = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += code.consumed;
            if (ft == 0x1C) {
                // Type 0x1C includes frame_type
                const frame_t = packet_mod.decodeVarint(data[pos..]) orelse return null;
                pos += frame_t.consumed;
            }
            const reason_len = packet_mod.decodeVarint(data[pos..]) orelse return null;
            pos += reason_len.consumed;
            const rlen: usize = @intCast(reason_len.value);
            if (data.len < pos + rlen) return null;
            return pos + rlen;
        },
        0x1E => {
            // HANDSHAKE_DONE: no payload
            return pos;
        },
        else => {
            // Unknown frame type — cannot determine length, bail
            return null;
        },
    }
}

// ─── Tests ───

test "H3Client: init" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    try std.testing.expect(!h3.isConnected());
    try std.testing.expectEqual(session_mod.SessionState.idle, h3.session.state);
}

test "H3Client: request fails when not connected" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    const result = h3.request("GET", "/", &.{}, null);
    try std.testing.expectError(H3Error.NotConnected, result);
}

test "H3Client: stream buffer allocation" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    const idx = h3.allocStreamBuf(4);
    try std.testing.expect(idx != null);

    const sb = h3.getStreamBuf(4);
    try std.testing.expect(sb != null);
    try std.testing.expectEqual(@as(u62, 4), sb.?.stream_id.?);

    h3.freeStreamBuf(4);
    try std.testing.expect(h3.getStreamBuf(4) == null);
}

test "H3Client: feedPayload parses STREAM frames" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    // Allocate a stream buffer for stream_id=0
    _ = h3.allocStreamBuf(0);

    // Build a STREAM frame: stream_id=0, offset=0, data="hello", fin=true
    const frame = StreamFrame{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .fin = true,
    };
    var frame_buf: [64]u8 = undefined;
    const frame_len = frame.encode(&frame_buf) orelse unreachable;

    // Feed the payload
    h3.feedPayload(frame_buf[0..frame_len]);

    // Verify data arrived
    const sb = h3.getStreamBuf(0).?;
    try std.testing.expectEqual(@as(usize, 5), sb.len);
    try std.testing.expectEqualStrings("hello", sb.data[0..5]);
    try std.testing.expect(sb.fin_received);
}

test "H3Client: feedPayload skips ACK frame before STREAM" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    _ = h3.allocStreamBuf(0);

    // Build a payload: ACK frame (type=0x02) + STREAM frame
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    // ACK frame: type=0x02, largest=5, delay=0, range_count=0, first_range=5
    buf[pos] = 0x02;
    pos += 1;
    buf[pos] = 5; // largest_ack
    pos += 1;
    buf[pos] = 0; // ack_delay
    pos += 1;
    buf[pos] = 0; // ack_range_count
    pos += 1;
    buf[pos] = 5; // first_ack_range
    pos += 1;

    // STREAM frame after ACK
    const frame = StreamFrame{
        .stream_id = 0,
        .offset = 0,
        .data = "world",
        .fin = true,
    };
    const frame_len = frame.encode(buf[pos..]) orelse unreachable;
    pos += frame_len;

    h3.feedPayload(buf[0..pos]);

    const sb = h3.getStreamBuf(0).?;
    try std.testing.expectEqual(@as(usize, 5), sb.len);
    try std.testing.expectEqualStrings("world", sb.data[0..5]);
    try std.testing.expect(sb.fin_received);
}

test "H3Client: feedPayload handles offset-based reassembly" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    _ = h3.allocStreamBuf(4);

    // Second chunk arrives first (offset=5)
    const frame2 = StreamFrame{ .stream_id = 4, .offset = 5, .data = "world", .fin = true };
    var buf2: [64]u8 = undefined;
    const len2 = frame2.encode(&buf2) orelse unreachable;
    h3.feedPayload(buf2[0..len2]);

    // First chunk arrives later (offset=0)
    const frame1 = StreamFrame{ .stream_id = 4, .offset = 0, .data = "hello", .fin = false };
    var buf1: [64]u8 = undefined;
    const len1 = frame1.encode(&buf1) orelse unreachable;
    h3.feedPayload(buf1[0..len1]);

    const sb = h3.getStreamBuf(4).?;
    try std.testing.expectEqual(@as(usize, 10), sb.len);
    try std.testing.expectEqualStrings("helloworld", sb.data[0..10]);
    try std.testing.expect(sb.fin_received);
}

test "H3Client: gap detection prevents premature response" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    _ = h3.allocStreamBuf(0);

    // Receive bytes at offset=128 with FIN (simulates loss of first segment)
    const frame_late = StreamFrame{ .stream_id = 0, .offset = 128, .data = "tail", .fin = true };
    var buf_late: [64]u8 = undefined;
    const len_late = frame_late.encode(&buf_late) orelse unreachable;
    h3.feedPayload(buf_late[0..len_late]);

    // FIN received but data has a gap — should NOT be considered complete
    const sb = h3.getStreamBuf(0).?;
    try std.testing.expect(sb.fin_received);
    try std.testing.expect(!sb.isContiguous());
    try std.testing.expect(!h3.isResponseComplete(0));

    // Now fill the gap (offset=0, 128 bytes)
    var fill_data: [128]u8 = undefined;
    @memset(&fill_data, 'A');
    const frame_fill = StreamFrame{ .stream_id = 0, .offset = 0, .data = &fill_data, .fin = false };
    var buf_fill: [192]u8 = undefined;
    const len_fill = frame_fill.encode(&buf_fill) orelse unreachable;
    h3.feedPayload(buf_fill[0..len_fill]);

    // Now it should be contiguous and complete
    try std.testing.expect(sb.isContiguous());
    try std.testing.expect(h3.isResponseComplete(0));
}

test "H3Client: skipQuicFrame handles PADDING and PING" {
    // PADDING
    try std.testing.expectEqual(@as(?usize, 1), skipQuicFrame(&[_]u8{0x00}));
    // PING
    try std.testing.expectEqual(@as(?usize, 1), skipQuicFrame(&[_]u8{0x01}));
    // HANDSHAKE_DONE
    try std.testing.expectEqual(@as(?usize, 1), skipQuicFrame(&[_]u8{0x1E}));
}

test "H3Client: E2E connect to cloudflare-quic.com" {
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);
    var h3 = H3Client.init(server_addr, "cloudflare-quic.com") catch return;
    defer h3.deinit();

    h3.connect() catch return;

    try std.testing.expect(h3.isConnected());
    try std.testing.expectEqual(session_mod.SessionState.connected, h3.session.state);
    try std.testing.expect(h3.session.control_stream_id != null);

    h3.close();
}

test "H3Client: E2E GET request to cloudflare-quic.com" {
    const server_addr = std.net.Address.initIp4(.{ 104, 16, 132, 229 }, 443);
    var h3 = H3Client.init(server_addr, "cloudflare-quic.com") catch return;
    defer h3.deinit();

    h3.connect() catch return;
    if (!h3.isConnected()) return;

    const resp = h3.request("GET", "/", &.{}, null) catch |e| {
        switch (e) {
            H3Error.Timeout => return, // Server didn't respond in time
            H3Error.ConnectionClosed => return,
            else => return,
        }
    };

    // Verify we got an HTTP response
    try std.testing.expect(resp.status >= 100 and resp.status < 600);
    // Cloudflare typically returns 200 or 301/302
    try std.testing.expect(resp.header_count > 0);

    h3.close();
}

test "H3Client: response parsing" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    // Set up session
    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    // Send a request through session
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };
    const req = h3.session.sendRequest(&headers, null) orelse unreachable;

    // Allocate stream buffer and fill with a fake H3 response
    _ = h3.allocStreamBuf(req.stream_id);
    const sb = h3.getStreamBuf(req.stream_id).?;

    // Build HEADERS frame with QPACK-encoded :status 200
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &resp_headers) orelse unreachable;

    var frame_buf: [300]u8 = undefined;
    const hdr_frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    // DATA frame
    var data_frame_buf: [64]u8 = undefined;
    const data_frame_len = h3_frame.encodeDataFrame(&data_frame_buf, "hello") orelse unreachable;

    // Copy into stream buffer
    @memcpy(sb.data[0..hdr_frame_len], frame_buf[0..hdr_frame_len]);
    @memcpy(sb.data[hdr_frame_len..][0..data_frame_len], data_frame_buf[0..data_frame_len]);
    sb.len = hdr_frame_len + data_frame_len;
    sb.fin_received = true;

    // Parse
    const resp = h3.buildResponse(req.stream_id) catch unreachable;
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(usize, 2), resp.header_count);
    try std.testing.expectEqualStrings("hello", resp.bodySlice());
}

test "H3StreamHandle: recvHeaders parses initial HEADERS frame" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    const req_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/svc/Method" },
    };
    const req = h3.session.sendRequest(&req_headers, null) orelse unreachable;
    _ = h3.allocStreamBuf(req.stream_id);
    const sb = h3.getStreamBuf(req.stream_id).?;

    // Build response HEADERS frame
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &resp_headers) orelse unreachable;

    var frame_buf: [300]u8 = undefined;
    const hdr_frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse unreachable;

    @memcpy(sb.data[0..hdr_frame_len], frame_buf[0..hdr_frame_len]);
    sb.len = hdr_frame_len;
    sb.contiguous_len = hdr_frame_len;

    var handle = H3StreamHandle{
        .client = &h3,
        .stream_id = req.stream_id,
        .headers_received = false,
        .stream_ended = false,
        .parse_pos = 0,
        .resp_status = 0,
        .resp_headers = undefined,
        .resp_header_count = 0,
        .trailer_headers = undefined,
        .trailer_header_count = 0,
    };
    defer handle.close();

    // tryParseHeaders should find the HEADERS frame
    const found = handle.tryParseHeaders(sb);
    try std.testing.expect(found);
    try std.testing.expectEqual(@as(u16, 200), handle.resp_status);
    try std.testing.expect(handle.headers_received);
    try std.testing.expectEqual(@as(usize, hdr_frame_len), handle.parse_pos);
}

test "H3StreamHandle: recv yields DATA frames sequentially" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    const req_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/svc/Stream" },
    };
    const req = h3.session.sendRequest(&req_headers, null) orelse unreachable;
    _ = h3.allocStreamBuf(req.stream_id);
    const sb = h3.getStreamBuf(req.stream_id).?;

    // Build: HEADERS + DATA("msg1") + DATA("msg2") + HEADERS (trailers)
    var pos: usize = 0;

    // HEADERS frame
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &resp_headers) orelse unreachable;
    var hdr_buf: [300]u8 = undefined;
    const hdr_len = h3_frame.encodeHeadersFrame(&hdr_buf, qpack_buf[0..qpack_len]) orelse unreachable;
    @memcpy(sb.data[pos..][0..hdr_len], hdr_buf[0..hdr_len]);
    pos += hdr_len;

    // DATA frame 1
    var d1_buf: [64]u8 = undefined;
    const d1_len = h3_frame.encodeDataFrame(&d1_buf, "msg1") orelse unreachable;
    @memcpy(sb.data[pos..][0..d1_len], d1_buf[0..d1_len]);
    pos += d1_len;

    // DATA frame 2
    var d2_buf: [64]u8 = undefined;
    const d2_len = h3_frame.encodeDataFrame(&d2_buf, "msg2") orelse unreachable;
    @memcpy(sb.data[pos..][0..d2_len], d2_buf[0..d2_len]);
    pos += d2_len;

    // Trailing HEADERS (trailers with grpc-status)
    const trailer_headers = [_]qpack.HeaderField{
        .{ .name = "grpc-status", .value = "0" },
    };
    var tqp_buf: [128]u8 = undefined;
    const tqp_len = qpack.Encoder.encode(&tqp_buf, &trailer_headers) orelse unreachable;
    var trailer_buf: [200]u8 = undefined;
    const trailer_len = h3_frame.encodeHeadersFrame(&trailer_buf, tqp_buf[0..tqp_len]) orelse unreachable;
    @memcpy(sb.data[pos..][0..trailer_len], trailer_buf[0..trailer_len]);
    pos += trailer_len;

    sb.len = pos;
    sb.contiguous_len = pos;
    sb.fin_received = true;

    var handle = H3StreamHandle{
        .client = &h3,
        .stream_id = req.stream_id,
        .headers_received = false,
        .stream_ended = false,
        .parse_pos = 0,
        .resp_status = 0,
        .resp_headers = undefined,
        .resp_header_count = 0,
        .trailer_headers = undefined,
        .trailer_header_count = 0,
    };

    // Parse headers first
    _ = handle.tryParseHeaders(sb);
    try std.testing.expect(handle.headers_received);

    // Recv first DATA
    var recv_buf: [256]u8 = undefined;
    const r1 = handle.tryParseNextData(sb, &recv_buf);
    try std.testing.expect(r1 != null);
    try std.testing.expectEqualStrings("msg1", recv_buf[0..r1.?]);

    // Recv second DATA
    const r2 = handle.tryParseNextData(sb, &recv_buf);
    try std.testing.expect(r2 != null);
    try std.testing.expectEqualStrings("msg2", recv_buf[0..r2.?]);

    // Recv trailers — returns null, stream ended
    const r3 = handle.tryParseNextData(sb, &recv_buf);
    try std.testing.expect(r3 == null);
    try std.testing.expect(handle.stream_ended);

    // Verify trailer headers were parsed
    try std.testing.expectEqual(@as(usize, 1), handle.trailer_header_count);
    const grpc_status_val = handle.trailerValue("grpc-status");
    try std.testing.expect(grpc_status_val != null);
    try std.testing.expectEqualStrings("0", grpc_status_val.?);

    handle.close();
}

test "H3StreamHandle: requestStream fails when not connected" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    const result = h3.requestStream("POST", "/svc/Watch", &.{}, null);
    try std.testing.expectError(H3Error.NotConnected, result);
}

test "H3StreamHandle: requestStreamOpen fails when not connected" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    const result = h3.requestStreamOpen("POST", "/svc/BidiStream", &.{});
    try std.testing.expectError(H3Error.NotConnected, result);
}

test "H3StreamHandle: send encodes DATA frame" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    const req_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/svc/ClientStream" },
    };
    const req = h3.session.sendRequest(&req_headers, null) orelse unreachable;
    _ = h3.allocStreamBuf(req.stream_id);

    var handle = H3StreamHandle{
        .client = &h3,
        .stream_id = req.stream_id,
        .headers_received = false,
        .stream_ended = false,
        .parse_pos = 0,
        .resp_status = 0,
        .resp_headers = undefined,
        .resp_header_count = 0,
        .trailer_headers = undefined,
        .trailer_header_count = 0,
    };
    defer handle.close();

    // send() will fail since quic isn't actually connected —
    // tests that the DATA frame encoding path compiles and runs
    if (handle.send("hello")) |_| {
        try std.testing.expect(false); // should not succeed
    } else |e| {
        try std.testing.expect(e == H3Error.WriteFailed or e == H3Error.ConnectionClosed);
    }
}

test "H3Client: GOAWAY detection on server control stream" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    try std.testing.expect(!h3.goawayReceived());

    // Simulate server opening control stream (stream_id=3, server-initiated uni)
    // First byte = 0x00 (control stream type), followed by SETTINGS then GOAWAY

    // Build SETTINGS frame (empty)
    var settings_buf: [16]u8 = undefined;
    const settings_len = h3_frame.encodeSettingsFrame(&settings_buf, &.{}) orelse unreachable;

    // Build GOAWAY frame with stream_id=4
    var goaway_buf: [16]u8 = undefined;
    const goaway_len = h3_frame.encodeGoawayFrame(&goaway_buf, 4) orelse unreachable;

    // Compose: type_byte + SETTINGS + GOAWAY
    var payload: [64]u8 = undefined;
    var pos: usize = 0;
    payload[pos] = 0x00; // uni-stream type = control
    pos += 1;
    @memcpy(payload[pos..][0..settings_len], settings_buf[0..settings_len]);
    pos += settings_len;
    @memcpy(payload[pos..][0..goaway_len], goaway_buf[0..goaway_len]);
    pos += goaway_len;

    // Feed as if arriving on server uni-stream 3 at offset 0
    h3.onStreamData(3, 0, payload[0..pos], false);

    try std.testing.expect(h3.goawayReceived());
    try std.testing.expectEqual(@as(u62, 4), h3.goawayId());
    try std.testing.expectEqual(session_mod.SessionState.draining, h3.session.state);
}

test "H3Client: control stream data arriving in chunks" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    // First chunk: stream type byte only
    h3.onStreamData(3, 0, &[_]u8{0x00}, false);
    try std.testing.expect(h3.server_control_stream_id != null);
    try std.testing.expectEqual(@as(u62, 3), h3.server_control_stream_id.?);
    try std.testing.expect(!h3.goawayReceived());

    // Second chunk: SETTINGS frame (empty)
    var settings_buf: [16]u8 = undefined;
    const settings_len = h3_frame.encodeSettingsFrame(&settings_buf, &.{}) orelse unreachable;
    h3.onStreamData(3, 1, settings_buf[0..settings_len], false);

    try std.testing.expect(h3.session.h3.settings_received);
    try std.testing.expect(!h3.goawayReceived());

    // Third chunk: GOAWAY
    var goaway_buf: [16]u8 = undefined;
    const goaway_len = h3_frame.encodeGoawayFrame(&goaway_buf, 8) orelse unreachable;
    h3.onStreamData(3, 1 + settings_len, goaway_buf[0..goaway_len], false);

    try std.testing.expect(h3.goawayReceived());
    try std.testing.expectEqual(@as(u62, 8), h3.goawayId());
}

test "H3Client: non-control server uni-stream is ignored" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    // Server uni-stream with type 0x02 (QPACK encoder) — should NOT become control stream
    h3.onStreamData(3, 0, &[_]u8{0x02}, false);
    try std.testing.expect(h3.server_control_stream_id == null);
}

test "H3Client: goawayReceived blocks new requests via session" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    var h3 = try H3Client.init(addr, "example.com");
    defer h3.deinit();

    h3.session.startHandshake();
    _ = h3.session.onHandshakeComplete();

    // Inject GOAWAY on control stream
    var settings_buf: [16]u8 = undefined;
    const settings_len = h3_frame.encodeSettingsFrame(&settings_buf, &.{}) orelse unreachable;
    var goaway_buf: [16]u8 = undefined;
    const goaway_len = h3_frame.encodeGoawayFrame(&goaway_buf, 0) orelse unreachable;

    var payload: [64]u8 = undefined;
    var pos: usize = 0;
    payload[pos] = 0x00;
    pos += 1;
    @memcpy(payload[pos..][0..settings_len], settings_buf[0..settings_len]);
    pos += settings_len;
    @memcpy(payload[pos..][0..goaway_len], goaway_buf[0..goaway_len]);
    pos += goaway_len;

    h3.onStreamData(3, 0, payload[0..pos], false);

    // Session should reject new requests after GOAWAY
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expect(h3.session.sendRequest(&headers, null) == null);
}
