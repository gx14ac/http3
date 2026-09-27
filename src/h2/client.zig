// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const compat = @import("../io/compat.zig");
const frame = @import("frame.zig");
const stream_mod = @import("stream.zig");
const hpack = @import("hpack.zig");
const connection = @import("connection.zig");

pub const Connection = connection.Connection;
pub const Config = connection.Config;
pub const State = connection.State;
pub const Event = connection.Event;

pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,

    pub fn asString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .PATCH => "PATCH",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
        };
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestOptions = struct {
    extra_headers: []const Header = &.{},
    end_stream: bool = true,
};

pub const Response = struct {
    status: u16,
    headers: []const hpack.HeaderField,
    header_count: usize,
};

pub const ClientError = error{
    ConnectionNotOpen,
    StreamExhausted,
    MaxConcurrentStreams,
    FlowControlError,
    EncodingError,
    IoError,
    ProtocolError,
    InvalidResponse,
    BufferTooSmall,
    FrameSizeError,
    ConnectionClosed,
    GoawayReceived,
};

/// Buffered frame for per-stream demultiplexing.
const BufferedFrame = struct {
    tag: FrameTag,
    stream_id: u31,
    payload: []u8,
    end_stream: bool,
    payload_len: u24,
    alloc_buf: []u8,
};

const FrameTag = enum { headers, data, rst_stream };

pub const Client = struct {
    conn: Connection,
    encoder: hpack.Encoder,
    decoder: hpack.Decoder,
    allocator: std.mem.Allocator,
    scheme: []const u8,
    stream_buffers: std.AutoHashMapUnmanaged(u31, FrameQueue),

    const FrameQueue = struct {
        frames: std.ArrayListUnmanaged(BufferedFrame),

        fn init() FrameQueue {
            return .{ .frames = .empty };
        }

        fn deinit(self: *FrameQueue, allocator: std.mem.Allocator) void {
            for (self.frames.items) |f| {
                allocator.free(f.alloc_buf);
            }
            self.frames.deinit(allocator);
        }

        fn push(self: *FrameQueue, allocator: std.mem.Allocator, f: BufferedFrame) !void {
            try self.frames.append(allocator, f);
        }

        fn popFirst(self: *FrameQueue) ?BufferedFrame {
            if (self.frames.items.len == 0) return null;
            return self.frames.orderedRemove(0);
        }
    };

    pub fn init(allocator: std.mem.Allocator, reader: compat.AnyReader, writer: compat.AnyWriter, config: Config) Client {
        return .{
            .conn = Connection.init(reader, writer, config),
            .encoder = hpack.Encoder.init(config.header_table_size),
            .decoder = hpack.Decoder.init(config.header_table_size),
            .allocator = allocator,
            .scheme = config.scheme,
            .stream_buffers = .{},
        };
    }

    pub fn deinit(self: *Client) void {
        var it = self.stream_buffers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.stream_buffers.deinit(self.allocator);
    }

    pub fn handshake(self: *Client) ClientError!void {
        self.conn.sendClientPreface() catch return ClientError.IoError;
        self.conn.recvServerPreface() catch |e| return mapConnError(e);

        // Server may send WINDOW_UPDATE or other frames before SETTINGS ACK
        var attempts: u8 = 0;
        while (attempts < 10) : (attempts += 1) {
            const event = self.conn.recvFrame() catch |e| return mapConnError(e);
            switch (event) {
                .settings_ack => return,
                .window_update => continue,
                else => return ClientError.ProtocolError,
            }
        }
        return ClientError.ProtocolError;
    }

    pub fn request(
        self: *Client,
        method: Method,
        path: []const u8,
        authority: []const u8,
        body: ?[]const u8,
        opts: RequestOptions,
    ) ClientError!RequestHandle {
        if (self.conn.state != .open and self.conn.state != .waiting_settings_ack) {
            return ClientError.ConnectionNotOpen;
        }

        const stream = self.conn.streams.openStream(
            self.conn.peer_settings.initial_window_size,
            self.conn.local_settings.initial_window_size,
        ) catch |e| return switch (e) {
            error.MaxConcurrentStreams => ClientError.MaxConcurrentStreams,
            error.StreamIdExhausted => ClientError.StreamExhausted,
        };

        const stream_id = stream.id;
        const has_body = body != null and body.?.len > 0;
        const end_stream_on_headers = opts.end_stream and !has_body;

        var header_buf: [4096]u8 = undefined;
        const header_len = self.encodeRequestHeaders(
            &header_buf,
            method,
            path,
            authority,
            opts.extra_headers,
        ) orelse return ClientError.EncodingError;

        self.conn.sendHeaders(
            stream_id,
            header_buf[0..header_len],
            end_stream_on_headers,
        ) catch |e| return mapConnError(e);

        stream.sendHeaders(end_stream_on_headers) catch
            return ClientError.ProtocolError;

        if (has_body) {
            const data = body.?;
            self.conn.sendData(stream_id, data, opts.end_stream) catch |e| return mapConnError(e);
            stream.sendData(@intCast(data.len), opts.end_stream) catch |e| return switch (e) {
                error.StreamClosed => ClientError.ProtocolError,
                error.FlowControlError => ClientError.FlowControlError,
                error.ProtocolError => ClientError.ProtocolError,
            };
        }

        return RequestHandle{ .stream_id = stream_id };
    }

    pub fn recvResponse(
        self: *Client,
        handle: RequestHandle,
        header_out: []hpack.HeaderField,
        decode_buf: []u8,
        body_buf: []u8,
    ) ClientError!ResponseData {
        var header_count: usize = 0;
        var body_len: usize = 0;
        var status: u16 = 0;
        var got_headers = false;
        // Track header alloc for deferred free (decoded values may reference it)
        var hdr_alloc: ?[]u8 = null;
        defer if (hdr_alloc) |a| self.allocator.free(a);

        // First drain any buffered frames for this stream
        while (self.popBufferedFrame(handle.stream_id)) |bf| {
            switch (bf.tag) {
                .headers => {
                    // Free previous header alloc if we somehow get two HEADERS frames
                    if (hdr_alloc) |a| self.allocator.free(a);
                    hdr_alloc = bf.alloc_buf;

                    header_count = self.decoder.decode(
                        bf.payload,
                        header_out,
                        decode_buf,
                    ) catch return ClientError.InvalidResponse;

                    status = parseStatus(header_out[0..header_count]);
                    got_headers = true;

                    if (bf.end_stream) {
                        const stream = self.conn.streams.get(handle.stream_id);
                        if (stream) |s| s.recvHeaders(true) catch {};
                        return ResponseData{
                            .status = status,
                            .headers = header_out,
                            .header_count = header_count,
                            .body = body_buf[0..body_len],
                        };
                    }
                    const stream = self.conn.streams.get(handle.stream_id);
                    if (stream) |s| s.recvHeaders(false) catch {};
                },
                .data => {
                    const payload_len = bf.payload.len;
                    if (body_len + payload_len > body_buf.len) {
                        self.allocator.free(bf.alloc_buf);
                        return ClientError.BufferTooSmall;
                    }
                    @memcpy(body_buf[body_len..][0..payload_len], bf.payload);
                    self.allocator.free(bf.alloc_buf);
                    body_len += payload_len;

                    // Flow control already updated at buffer time (bufferData)

                    if (bf.end_stream) {
                        if (!got_headers) return ClientError.InvalidResponse;
                        return ResponseData{
                            .status = status,
                            .headers = header_out,
                            .header_count = header_count,
                            .body = body_buf[0..body_len],
                        };
                    }
                },
                .rst_stream => {
                    self.allocator.free(bf.alloc_buf);
                    const stream = self.conn.streams.get(handle.stream_id);
                    if (stream) |s| s.recvReset();
                    return ClientError.ProtocolError;
                },
            }
        }

        // Read from wire, buffering frames for other streams
        while (true) {
            const event = self.conn.recvFrame() catch |e| {
                return mapConnError(e);
            };
            switch (event) {
                .headers => |h| {
                    if (h.stream_id != handle.stream_id) {
                        self.bufferHeaders(h.stream_id, h.payload_len, h.end_stream) catch {
                            self.skipPayload(h.payload_len) catch {};
                            self.conn.payloadConsumed(h.payload_len);
                        };
                        continue;
                    }

                    var hdr_payload: [16384]u8 = undefined;
                    var total_len: usize = h.payload_len;
                    if (total_len > hdr_payload.len) return ClientError.BufferTooSmall;
                    self.readExact(hdr_payload[0..total_len]) catch return ClientError.IoError;
                    self.conn.payloadConsumed(h.payload_len);

                    if (self.conn.expecting_continuation != null) {
                        while (self.conn.expecting_continuation != null) {
                            const cont_event = self.conn.recvFrame() catch |e| return mapConnError(e);
                            switch (cont_event) {
                                .continuation => |c| {
                                    const clen: usize = c.payload_len;
                                    if (total_len + clen > hdr_payload.len) return ClientError.BufferTooSmall;
                                    self.readExact(hdr_payload[total_len..][0..clen]) catch return ClientError.IoError;
                                    self.conn.payloadConsumed(c.payload_len);
                                    total_len += clen;
                                },
                                else => return ClientError.ProtocolError,
                            }
                        }
                    }

                    header_count = self.decoder.decode(
                        hdr_payload[0..total_len],
                        header_out,
                        decode_buf,
                    ) catch {
                        return ClientError.InvalidResponse;
                    };

                    status = parseStatus(header_out[0..header_count]);
                    got_headers = true;

                    if (h.end_stream) {
                        const stream = self.conn.streams.get(handle.stream_id);
                        if (stream) |s| s.recvHeaders(true) catch {};
                        break;
                    }

                    const stream = self.conn.streams.get(handle.stream_id);
                    if (stream) |s| s.recvHeaders(false) catch {};
                },
                .data => |d| {
                    if (d.stream_id != handle.stream_id) {
                        self.bufferData(d.stream_id, d.payload_len, d.end_stream) catch {
                            self.skipPayload(d.payload_len) catch {};
                            self.conn.payloadConsumed(d.payload_len);
                        };
                        continue;
                    }

                    const payload_len: usize = d.payload_len;
                    if (body_len + payload_len > body_buf.len) return ClientError.BufferTooSmall;
                    self.readExact(body_buf[body_len..][0..payload_len]) catch return ClientError.IoError;
                    self.conn.payloadConsumed(d.payload_len);
                    body_len += payload_len;

                    const stream = self.conn.streams.get(handle.stream_id);
                    if (stream) |s| s.recvData(@intCast(payload_len), d.end_stream) catch {};

                    self.conn.maybeUpdateConnectionWindow() catch {};
                    self.conn.maybeUpdateStreamWindow(handle.stream_id) catch {};

                    if (d.end_stream) break;
                },
                .rst_stream => |r| {
                    if (r.stream_id == handle.stream_id) {
                        const stream = self.conn.streams.get(handle.stream_id);
                        if (stream) |s| s.recvReset();
                        return ClientError.ProtocolError;
                    }
                    // Buffer RST_STREAM for other stream
                    self.bufferRstStream(r.stream_id) catch {};
                },
                .goaway => return ClientError.GoawayReceived,
                .settings_ack => continue,
                .ping_ack => continue,
                .window_update => continue,
                .continuation => |c| {
                    self.skipPayload(c.payload_len) catch return ClientError.IoError;
                    self.conn.payloadConsumed(c.payload_len);
                    return ClientError.ProtocolError;
                },
            }
        }

        if (!got_headers) return ClientError.InvalidResponse;

        return ResponseData{
            .status = status,
            .headers = header_out,
            .header_count = header_count,
            .body = body_buf[0..body_len],
        };
    }

    /// Send DATA on an existing stream. Used by gRPC streaming layer.
    pub fn sendStreamData(self: *Client, handle: RequestHandle, data: []const u8, end_stream: bool) ClientError!void {
        self.conn.sendData(handle.stream_id, data, end_stream) catch |e| return mapConnError(e);
        const stream = self.conn.streams.get(handle.stream_id);
        if (stream) |s| {
            s.sendData(@intCast(data.len), end_stream) catch |e| return switch (e) {
                error.StreamClosed => ClientError.ProtocolError,
                error.FlowControlError => ClientError.FlowControlError,
                error.ProtocolError => ClientError.ProtocolError,
            };
        }
    }

    /// Receive a single frame event. Used by gRPC streaming layer for frame-by-frame reading.
    pub fn recvEvent(self: *Client) ClientError!connection.Event {
        return self.conn.recvFrame() catch |e| return mapConnError(e);
    }

    /// Read exact bytes from the connection's reader. Used by gRPC streaming layer.
    pub fn readPayload(self: *Client, buf: []u8) ClientError!void {
        self.readExact(buf) catch return ClientError.IoError;
    }

    /// Skip payload bytes. Used when receiving frames for other streams.
    pub fn skipFramePayload(self: *Client, length: u24) ClientError!void {
        self.skipPayload(length) catch return ClientError.IoError;
    }

    pub fn close(self: *Client) void {
        self.conn.sendGoaway(.no_error, "") catch {};
    }

    fn getOrCreateQueue(self: *Client, stream_id: u31) ?*FrameQueue {
        const gop = self.stream_buffers.getOrPut(self.allocator, stream_id) catch return null;
        if (!gop.found_existing) {
            gop.value_ptr.* = FrameQueue.init();
        }
        return gop.value_ptr;
    }

    fn popBufferedFrame(self: *Client, stream_id: u31) ?BufferedFrame {
        const queue = self.stream_buffers.getPtr(stream_id) orelse return null;
        return queue.popFirst();
    }

    fn bufferHeaders(self: *Client, stream_id: u31, payload_len: u24, end_stream: bool) !void {
        const len: usize = payload_len;
        var total_len = len;
        const buf = self.allocator.alloc(u8, 16384) catch return error.OutOfMemory;
        errdefer self.allocator.free(buf);

        self.readExact(buf[0..len]) catch {
            self.allocator.free(buf);
            return error.IoError;
        };
        self.conn.payloadConsumed(payload_len);

        // Handle CONTINUATION frames
        if (self.conn.expecting_continuation != null) {
            while (self.conn.expecting_continuation != null) {
                const cont_event = self.conn.recvFrame() catch {
                    self.allocator.free(buf);
                    return error.IoError;
                };
                switch (cont_event) {
                    .continuation => |c| {
                        const clen: usize = c.payload_len;
                        if (total_len + clen > buf.len) {
                            self.allocator.free(buf);
                            return error.BufferTooSmall;
                        }
                        self.readExact(buf[total_len..][0..clen]) catch {
                            self.allocator.free(buf);
                            return error.IoError;
                        };
                        self.conn.payloadConsumed(c.payload_len);
                        total_len += clen;
                    },
                    else => {
                        self.allocator.free(buf);
                        return error.ProtocolError;
                    },
                }
            }
        }

        const queue = self.getOrCreateQueue(stream_id) orelse {
            self.allocator.free(buf);
            return error.OutOfMemory;
        };
        queue.push(self.allocator, .{
            .tag = .headers,
            .stream_id = stream_id,
            .payload = buf[0..total_len],
            .end_stream = end_stream,
            .payload_len = payload_len,
            .alloc_buf = buf,
        }) catch {
            self.allocator.free(buf);
            return error.OutOfMemory;
        };
    }

    fn bufferData(self: *Client, stream_id: u31, payload_len: u24, end_stream: bool) !void {
        const len: usize = payload_len;
        const payload = self.allocator.alloc(u8, len) catch return error.OutOfMemory;
        errdefer self.allocator.free(payload);

        self.readExact(payload) catch {
            self.allocator.free(payload);
            return error.IoError;
        };
        self.conn.payloadConsumed(payload_len);

        // Update flow control for buffered data
        const stream = self.conn.streams.get(stream_id);
        if (stream) |s| s.recvData(@intCast(len), end_stream) catch {};
        self.conn.maybeUpdateConnectionWindow() catch {};
        self.conn.maybeUpdateStreamWindow(stream_id) catch {};

        const queue = self.getOrCreateQueue(stream_id) orelse {
            self.allocator.free(payload);
            return error.OutOfMemory;
        };
        queue.push(self.allocator, .{
            .tag = .data,
            .stream_id = stream_id,
            .payload = payload,
            .end_stream = end_stream,
            .payload_len = payload_len,
            .alloc_buf = payload,
        }) catch {
            self.allocator.free(payload);
            return error.OutOfMemory;
        };
    }

    fn bufferRstStream(self: *Client, stream_id: u31) !void {
        const queue = self.getOrCreateQueue(stream_id) orelse return error.OutOfMemory;
        const empty = self.allocator.alloc(u8, 0) catch return error.OutOfMemory;
        queue.push(self.allocator, .{
            .tag = .rst_stream,
            .stream_id = stream_id,
            .payload = empty,
            .end_stream = true,
            .payload_len = 0,
            .alloc_buf = empty,
        }) catch {
            self.allocator.free(empty);
            return error.OutOfMemory;
        };
    }

    fn encodeRequestHeaders(
        self: *Client,
        buf: []u8,
        method: Method,
        path: []const u8,
        authority: []const u8,
        extra_headers: []const Header,
    ) ?usize {
        var offset: usize = 0;

        offset += self.encoder.encodeHeader(buf[offset..], ":method", method.asString(), .without_indexing);
        offset += self.encoder.encodeHeader(buf[offset..], ":scheme", self.scheme, .without_indexing);
        offset += self.encoder.encodeHeader(buf[offset..], ":path", path, .without_indexing);
        offset += self.encoder.encodeHeader(buf[offset..], ":authority", authority, .without_indexing);

        for (extra_headers) |h| {
            if (offset >= buf.len) return null;
            offset += self.encoder.encodeHeader(buf[offset..], h.name, h.value, .without_indexing);
        }

        return offset;
    }

    fn readExact(self: *Client, buf: []u8) !void {
        const n = try self.conn.reader.readAll(buf);
        if (n < buf.len) return error.EndOfStream;
    }

    fn skipPayload(self: *Client, length: u24) !void {
        var remaining: u32 = length;
        var discard: [256]u8 = undefined;
        while (remaining > 0) {
            const to_read: usize = @min(remaining, 256);
            const n = try self.conn.reader.readAll(discard[0..to_read]);
            if (n == 0) return error.EndOfStream;
            remaining -= @intCast(n);
        }
    }

    fn parseStatus(headers: []const hpack.HeaderField) u16 {
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, ":status")) {
                return std.fmt.parseInt(u16, h.value, 10) catch 0;
            }
        }
        return 0;
    }

    fn mapConnError(e: connection.ConnectionError) ClientError {
        return switch (e) {
            error.ProtocolError => ClientError.ProtocolError,
            error.FlowControlError => ClientError.FlowControlError,
            error.SettingsTimeout => ClientError.ProtocolError,
            error.FrameSizeError => ClientError.FrameSizeError,
            error.ConnectionClosed => ClientError.ConnectionClosed,
            error.GoawayReceived => ClientError.GoawayReceived,
            error.InvalidPreface => ClientError.ProtocolError,
            error.IoError => ClientError.IoError,
        };
    }
};

pub const RequestHandle = struct {
    stream_id: u31,
};

pub const ResponseData = struct {
    status: u16,
    headers: []const hpack.HeaderField,
    header_count: usize,
    body: []const u8,
};

// ─── Tests ───

const TestPipe = struct {
    read_buf: []const u8,
    read_pos: usize,
    write_buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, input: []const u8) TestPipe {
        return .{
            .read_buf = input,
            .read_pos = 0,
            .write_buf = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestPipe) void {
        self.write_buf.deinit(self.allocator);
    }

    fn reader(self: *TestPipe) compat.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }

    fn writer(self: *TestPipe) compat.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
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

    fn written(self: TestPipe) []const u8 {
        return self.write_buf.items;
    }
};

fn buildServerPreface(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) !void {
    // SETTINGS frame (empty)
    var settings_hdr: [9]u8 = undefined;
    const sh = frame.FrameHeader{ .length = 0, .frame_type = .settings, .flags = .{}, .stream_id = 0 };
    sh.encode(&settings_hdr);
    try buf.appendSlice(allocator, &settings_hdr);

    // SETTINGS ACK
    var ack_buf: [9]u8 = undefined;
    _ = frame.buildSettingsAck(&ack_buf);
    try buf.appendSlice(allocator, &ack_buf);
}

fn buildResponseHeaders(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), stream_id: u31, status: []const u8, end_stream: bool) !void {
    var enc = hpack.Encoder.init(4096);
    var hdr_block: [512]u8 = undefined;
    var offset: usize = 0;
    offset += enc.encodeHeader(hdr_block[offset..], ":status", status, .without_indexing);

    var flags = frame.Flags.END_HEADERS;
    if (end_stream) flags = flags.combine(frame.Flags.END_STREAM);
    const fh = frame.FrameHeader{
        .length = @intCast(offset),
        .frame_type = .headers,
        .flags = flags,
        .stream_id = stream_id,
    };
    var frame_buf: [9]u8 = undefined;
    fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, hdr_block[0..offset]);
}

fn buildDataFrame(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), stream_id: u31, payload: []const u8, end_stream: bool) !void {
    const flags: frame.Flags = if (end_stream) frame.Flags.END_STREAM else .{};
    const fh = frame.FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = .data,
        .flags = flags,
        .stream_id = stream_id,
    };
    var frame_buf: [9]u8 = undefined;
    fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, payload);
}

test "client handshake" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();
    try std.testing.expectEqual(State.open, client.conn.state);
}

test "client GET request with response" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    // Server preface
    try buildServerPreface(allocator, &server_data);

    // Server response: HEADERS with :status 200 + DATA with body + END_STREAM
    try buildResponseHeaders(allocator, &server_data, 1, "200", false);
    try buildDataFrame(allocator, &server_data, 1, "hello", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();

    const handle = try client.request(.GET, "/index.html", "example.com", null, .{});
    try std.testing.expectEqual(@as(u31, 1), handle.stream_id);

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    const resp = try client.recvResponse(handle, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello", resp.body);
}

test "client POST request with body" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);
    try buildResponseHeaders(allocator, &server_data, 1, "201", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();

    const handle = try client.request(.POST, "/api/data", "example.com", "request body", .{});
    try std.testing.expectEqual(@as(u31, 1), handle.stream_id);

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    const resp = try client.recvResponse(handle, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 201), resp.status);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "client multiple streams (multiplexed)" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    // Response for stream 1
    try buildResponseHeaders(allocator, &server_data, 1, "200", true);
    // Response for stream 3
    try buildResponseHeaders(allocator, &server_data, 3, "404", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();

    const h1 = try client.request(.GET, "/page1", "example.com", null, .{});
    const h2 = try client.request(.GET, "/page2", "example.com", null, .{});
    try std.testing.expectEqual(@as(u31, 1), h1.stream_id);
    try std.testing.expectEqual(@as(u31, 3), h2.stream_id);

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    const resp1 = try client.recvResponse(h1, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp1.status);

    const resp2 = try client.recvResponse(h2, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 404), resp2.status);
}

test "client recvResponse reassembles CONTINUATION frames" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    // Build a response where HEADERS has no END_HEADERS and header block is split across CONTINUATION
    var enc = hpack.Encoder.init(4096);
    var hdr_block: [512]u8 = undefined;
    var offset: usize = 0;
    offset += enc.encodeHeader(hdr_block[offset..], ":status", "200", .without_indexing);
    offset += enc.encodeHeader(hdr_block[offset..], "content-type", "text/plain", .without_indexing);

    // Split: first part in HEADERS, second part in CONTINUATION
    const split = offset / 2;

    // HEADERS frame without END_HEADERS, with END_STREAM
    const hdr_fh = frame.FrameHeader{
        .length = @intCast(split),
        .frame_type = .headers,
        .flags = frame.Flags.END_STREAM,
        .stream_id = 1,
    };
    var frame_buf: [9]u8 = undefined;
    hdr_fh.encode(&frame_buf);
    try server_data.appendSlice(allocator, &frame_buf);
    try server_data.appendSlice(allocator, hdr_block[0..split]);

    // CONTINUATION frame with END_HEADERS
    const cont_fh = frame.FrameHeader{
        .length = @intCast(offset - split),
        .frame_type = .continuation,
        .flags = frame.Flags.END_HEADERS,
        .stream_id = 1,
    };
    cont_fh.encode(&frame_buf);
    try server_data.appendSlice(allocator, &frame_buf);
    try server_data.appendSlice(allocator, hdr_block[split..offset]);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();

    const handle = try client.request(.GET, "/", "example.com", null, .{});

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    const resp = try client.recvResponse(handle, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(usize, 2), resp.header_count);
}

test "client request on closed connection fails" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    // Connection is in idle state (not open)
    const result = client.request(.GET, "/", "example.com", null, .{});
    try std.testing.expectError(ClientError.ConnectionNotOpen, result);
}

test "client sends stream WINDOW_UPDATE for large response" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);
    try buildResponseHeaders(allocator, &server_data, 1, "200", false);

    // Send 4 DATA frames of 16000 bytes each (total 64000, > threshold 32767)
    // The 3rd frame (cumulative 48000) crosses the threshold and triggers WINDOW_UPDATE
    // while the stream is still open. The 4th has end_stream=true.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const payload = try allocator.alloc(u8, 16000);
        defer allocator.free(payload);
        @memset(payload, 'X');
        try buildDataFrame(allocator, &server_data, 1, payload, i == 3);
    }

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    try client.handshake();

    const handle = try client.request(.GET, "/big", "example.com", null, .{});

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [65536]u8 = undefined;

    const resp = try client.recvResponse(handle, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(usize, 64000), resp.body.len);

    // Verify WINDOW_UPDATE frames were sent (connection + stream level)
    const out = pipe.written();
    var wu_count: u32 = 0;
    var stream_wu_found = false;
    // Skip client connection preface (24 bytes)
    var pos: usize = 24;
    while (pos + 9 <= out.len) {
        const hdr = frame.FrameHeader.decode(out[pos..][0..9]);
        if (hdr.frame_type == .window_update) {
            wu_count += 1;
            if (hdr.stream_id == 1) stream_wu_found = true;
        }
        pos += 9 + @as(usize, hdr.length);
    }
    try std.testing.expect(stream_wu_found);
    try std.testing.expect(wu_count >= 2); // At least connection + stream
}

test "client handles out-of-order responses (demux)" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    // Server sends stream 3's response FIRST, then stream 1's
    try buildResponseHeaders(allocator, &server_data, 3, "404", true);
    try buildResponseHeaders(allocator, &server_data, 1, "200", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    defer client.deinit();
    try client.handshake();

    const h1 = try client.request(.GET, "/page1", "example.com", null, .{});
    const h2 = try client.request(.GET, "/page2", "example.com", null, .{});
    try std.testing.expectEqual(@as(u31, 1), h1.stream_id);
    try std.testing.expectEqual(@as(u31, 3), h2.stream_id);

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    // Request response for stream 1, but stream 3 arrives first on the wire
    const resp1 = try client.recvResponse(h1, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp1.status);

    // Stream 3's response was buffered — now retrieve it
    const resp2 = try client.recvResponse(h2, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 404), resp2.status);
}

test "client handles out-of-order data frames (demux)" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    // Stream 3: headers + data, then stream 1: headers + data
    try buildResponseHeaders(allocator, &server_data, 3, "200", false);
    try buildDataFrame(allocator, &server_data, 3, "body3", true);
    try buildResponseHeaders(allocator, &server_data, 1, "200", false);
    try buildDataFrame(allocator, &server_data, 1, "body1", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    defer client.deinit();
    try client.handshake();

    const h1 = try client.request(.GET, "/page1", "example.com", null, .{});
    const h2 = try client.request(.GET, "/page2", "example.com", null, .{});

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    // Read stream 1 first — stream 3's frames get buffered
    const resp1 = try client.recvResponse(h1, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    try std.testing.expectEqualStrings("body1", resp1.body);

    // Read stream 3 from buffer
    const resp2 = try client.recvResponse(h2, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp2.status);
    try std.testing.expectEqualStrings("body3", resp2.body);
}

test "client handles interleaved frames from multiple streams (demux)" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    // Interleaved: stream1 headers, stream3 headers, stream3 data, stream1 data
    try buildResponseHeaders(allocator, &server_data, 1, "200", false);
    try buildResponseHeaders(allocator, &server_data, 3, "201", false);
    try buildDataFrame(allocator, &server_data, 3, "three", true);
    try buildDataFrame(allocator, &server_data, 1, "one", true);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var client = Client.init(allocator, pipe.reader(), pipe.writer(), .{});
    defer client.deinit();
    try client.handshake();

    const h1 = try client.request(.GET, "/a", "example.com", null, .{});
    const h2 = try client.request(.GET, "/b", "example.com", null, .{});

    var headers: [16]hpack.HeaderField = undefined;
    var decode_buf: [4096]u8 = undefined;
    var body_buf: [1024]u8 = undefined;

    // Read stream 1 — needs to buffer stream 3's headers and data along the way
    const resp1 = try client.recvResponse(h1, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    try std.testing.expectEqualStrings("one", resp1.body);

    // Read stream 3 — fully from buffer
    const resp2 = try client.recvResponse(h2, &headers, &decode_buf, &body_buf);
    try std.testing.expectEqual(@as(u16, 201), resp2.status);
    try std.testing.expectEqualStrings("three", resp2.body);
}
