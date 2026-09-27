// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const compat = @import("../io/compat.zig");
const frame = @import("frame.zig");
const stream_mod = @import("stream.zig");
const hpack = @import("hpack.zig");

pub const ConnectionError = error{
    ProtocolError,
    FlowControlError,
    SettingsTimeout,
    FrameSizeError,
    ConnectionClosed,
    GoawayReceived,
    InvalidPreface,
    IoError,
};

pub const GoawayInfo = struct {
    last_stream_id: u31,
    error_code: frame.ErrorCode,
    debug_data_len: u16,
};

pub const Event = union(enum) {
    settings_ack,
    ping_ack: [8]u8,
    goaway: GoawayInfo,
    window_update: struct { stream_id: u31, increment: u31 },
    headers: struct { stream_id: u31, end_stream: bool, payload_len: u24 },
    data: struct { stream_id: u31, end_stream: bool, payload_len: u24 },
    rst_stream: struct { stream_id: u31, error_code: frame.ErrorCode },
    continuation: struct { stream_id: u31, end_headers: bool, payload_len: u24 },
};

pub const Config = struct {
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
    header_table_size: u32 = 4096,
    enable_push: bool = false,
    ping_interval_ms: u64 = 30_000,
    scheme: []const u8 = "https",
    max_pings_without_data: u32 = 10,
    max_settings_per_minute: u32 = 20,
    max_empty_frames: u32 = 100,
};

pub const State = enum {
    idle,
    waiting_preface,
    waiting_settings_ack,
    open,
    goaway_sent,
    goaway_received,
    closed,
};

const SpinMutex = struct {
    state: std.atomic.Value(u8) = .init(0),

    pub fn lock(self: *SpinMutex) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinMutex) void {
        self.state.store(0, .release);
    }
};

pub const Connection = struct {
    state: State,
    local_settings: frame.Settings,
    peer_settings: frame.Settings,
    flow_control: stream_mod.ConnectionFlowControl,
    streams: stream_mod.StreamMap,
    pending_settings_ack: bool,
    last_peer_stream_id: u31,
    goaway_info: ?GoawayInfo,
    expecting_continuation: ?u31,
    reader: compat.AnyReader,
    writer: compat.AnyWriter,
    write_mu: SpinMutex = .{},

    // Payload tracking: bytes remaining from last HEADERS/DATA/CONTINUATION event
    pending_payload: u24,

    // DoS guard counters
    ping_count: u32,
    settings_count: u32,
    empty_frame_count: u32,
    max_pings_without_data: u32,
    max_settings_per_minute: u32,
    max_empty_frames: u32,
    data_received_since_ping: bool,

    pub fn init(reader: compat.AnyReader, writer: compat.AnyWriter, config: Config) Connection {
        const local = frame.Settings{
            .header_table_size = config.header_table_size,
            .enable_push = config.enable_push,
            .max_concurrent_streams = config.max_concurrent_streams,
            .initial_window_size = config.initial_window_size,
            .max_frame_size = config.max_frame_size,
            .max_header_list_size = config.max_header_list_size,
        };
        return .{
            .state = .idle,
            .local_settings = local,
            .peer_settings = frame.default_settings,
            .flow_control = stream_mod.ConnectionFlowControl.init(config.initial_window_size),
            .streams = stream_mod.StreamMap.init(config.max_concurrent_streams),
            .pending_settings_ack = false,
            .last_peer_stream_id = 0,
            .goaway_info = null,
            .expecting_continuation = null,
            .reader = reader,
            .writer = writer,
            .pending_payload = 0,
            .ping_count = 0,
            .settings_count = 0,
            .empty_frame_count = 0,
            .max_pings_without_data = config.max_pings_without_data,
            .max_settings_per_minute = config.max_settings_per_minute,
            .max_empty_frames = config.max_empty_frames,
            .data_received_since_ping = false,
        };
    }

    /// Send client connection preface (magic + SETTINGS)
    pub fn sendClientPreface(self: *Connection) ConnectionError!void {
        self.writeAll(frame.client_preface) catch return ConnectionError.IoError;
        self.sendSettings() catch return ConnectionError.IoError;
        self.state = .waiting_preface;
    }

    /// Read and validate the server's connection preface (first SETTINGS frame)
    pub fn recvServerPreface(self: *Connection) ConnectionError!void {
        const header = self.readFrameHeader() catch return ConnectionError.IoError;
        if (header.frame_type != .settings or header.flags.hasAck()) {
            return ConnectionError.InvalidPreface;
        }
        if (header.stream_id != 0) return ConnectionError.ProtocolError;
        self.applyPeerSettings(header) catch |e| return e;
        self.sendSettingsAck() catch return ConnectionError.IoError;
        self.state = .waiting_settings_ack;
    }

    /// Read the next frame and return an event describing it.
    /// Caller must read payload data separately for HEADERS/DATA/CONTINUATION frames.
    /// If the caller does not consume the payload before calling recvFrame again,
    /// the unconsumed payload is automatically skipped.
    pub fn recvFrame(self: *Connection) ConnectionError!Event {
        if (self.pending_payload > 0) {
            self.skipPayload(self.pending_payload) catch return ConnectionError.IoError;
            self.pending_payload = 0;
        }

        while (true) {
            if (self.state == .closed) return ConnectionError.ConnectionClosed;

            const header = self.readFrameHeader() catch return ConnectionError.IoError;

            if (header.length > self.local_settings.max_frame_size and
                header.frame_type != .settings)
            {
                return ConnectionError.FrameSizeError;
            }

            // RFC 9113 §6.10: while expecting CONTINUATION, any other frame type is a protocol error
            if (self.expecting_continuation) |expected_stream| {
                if (header.frame_type != .continuation) return ConnectionError.ProtocolError;
                if (header.stream_id != expected_stream) return ConnectionError.ProtocolError;
                const end_headers = header.flags.hasEndHeaders();
                if (end_headers) self.expecting_continuation = null;
                self.pending_payload = header.length;
                return Event{ .continuation = .{
                    .stream_id = header.stream_id,
                    .end_headers = end_headers,
                    .payload_len = header.length,
                } };
            }

            // DoS guard: empty frames (no payload, no semantic meaning)
            if (header.length == 0 and header.frame_type != .settings and
                header.frame_type != .ping and header.frame_type != .rst_stream and
                header.frame_type != .goaway and header.frame_type != .window_update and
                header.frame_type != .headers)
            {
                self.empty_frame_count += 1;
                if (self.empty_frame_count > self.max_empty_frames) {
                    return ConnectionError.ProtocolError;
                }
            }

            switch (header.frame_type) {
                .settings => return self.handleSettings(header),
                .ping => {
                    if (try self.handlePing(header)) |event| return event;
                    continue;
                },
                .goaway => return self.handleGoaway(header),
                .window_update => return self.handleWindowUpdate(header),
                .rst_stream => return self.handleRstStream(header),
                .headers => {
                    if (header.stream_id == 0) return ConnectionError.ProtocolError;
                    if (!header.flags.hasEndHeaders()) {
                        self.expecting_continuation = header.stream_id;
                    }
                    self.pending_payload = header.length;
                    return Event{ .headers = .{
                        .stream_id = header.stream_id,
                        .end_stream = header.flags.hasEndStream(),
                        .payload_len = header.length,
                    } };
                },
                .data => {
                    if (header.stream_id == 0) return ConnectionError.ProtocolError;
                    self.flow_control.consumeRecv(header.length) catch
                        return ConnectionError.FlowControlError;
                    self.data_received_since_ping = true;
                    self.ping_count = 0;
                    self.pending_payload = header.length;
                    return Event{ .data = .{
                        .stream_id = header.stream_id,
                        .end_stream = header.flags.hasEndStream(),
                        .payload_len = header.length,
                    } };
                },
                .continuation => {
                    // CONTINUATION without preceding HEADERS
                    return ConnectionError.ProtocolError;
                },
                else => {
                    self.skipPayload(header.length) catch return ConnectionError.IoError;
                    continue;
                },
            }
        }
    }

    /// Send a HEADERS frame (caller provides the encoded header block)
    pub fn sendHeaders(self: *Connection, stream_id: u31, header_block: []const u8, end_stream: bool) ConnectionError!void {
        var flags = frame.Flags.END_HEADERS;
        if (end_stream) flags = flags.combine(frame.Flags.END_STREAM);
        const fh = frame.FrameHeader{
            .length = @intCast(header_block.len),
            .frame_type = .headers,
            .flags = flags,
            .stream_id = stream_id,
        };
        var buf: [9]u8 = undefined;
        fh.encode(&buf);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(&buf) catch return ConnectionError.IoError;
        self.writeAll(header_block) catch return ConnectionError.IoError;
    }

    /// Send a DATA frame. Caller is responsible for flow control checks.
    pub fn sendData(self: *Connection, stream_id: u31, data: []const u8, end_stream: bool) ConnectionError!void {
        self.flow_control.consumeSend(@intCast(data.len)) catch
            return ConnectionError.FlowControlError;

        const flags: frame.Flags = if (end_stream) frame.Flags.END_STREAM else .{};
        const fh = frame.FrameHeader{
            .length = @intCast(data.len),
            .frame_type = .data,
            .flags = flags,
            .stream_id = stream_id,
        };
        var buf: [9]u8 = undefined;
        fh.encode(&buf);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(&buf) catch return ConnectionError.IoError;
        if (data.len > 0) {
            self.writeAll(data) catch return ConnectionError.IoError;
        }
    }

    /// Send a PING frame
    pub fn sendPing(self: *Connection, opaque_data: [8]u8) ConnectionError!void {
        var buf: [17]u8 = undefined;
        _ = frame.buildPing(opaque_data, &buf);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(&buf) catch return ConnectionError.IoError;
    }

    /// Send a GOAWAY frame and transition state
    pub fn sendGoaway(self: *Connection, error_code: frame.ErrorCode, debug_data: []const u8) ConnectionError!void {
        var buf: [256]u8 = undefined;
        const result = frame.buildGoaway(self.last_peer_stream_id, error_code, debug_data, &buf) catch
            return ConnectionError.FrameSizeError;
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(result) catch return ConnectionError.IoError;
        self.state = .goaway_sent;
    }

    /// Send a WINDOW_UPDATE frame (connection-level or stream-level)
    pub fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u31) ConnectionError!void {
        var buf: [13]u8 = undefined;
        _ = frame.buildWindowUpdate(stream_id, increment, &buf) catch
            return ConnectionError.ProtocolError;
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(&buf) catch return ConnectionError.IoError;
    }

    /// Send a RST_STREAM frame
    pub fn sendRstStream(self: *Connection, stream_id: u31, error_code: frame.ErrorCode) ConnectionError!void {
        var buf: [13]u8 = undefined;
        _ = frame.buildRstStream(stream_id, error_code, &buf);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        self.writeAll(&buf) catch return ConnectionError.IoError;
    }

    /// Check and send connection-level WINDOW_UPDATE if threshold exceeded
    pub fn maybeUpdateConnectionWindow(self: *Connection) ConnectionError!void {
        const increment = self.flow_control.shouldSendWindowUpdate();
        if (increment > 0) {
            self.sendWindowUpdate(0, increment) catch return ConnectionError.IoError;
            self.flow_control.ackWindowUpdate();
        }
    }

    /// Check and send stream-level WINDOW_UPDATE if threshold exceeded.
    /// Uses half of initial_window_size as the threshold (same heuristic as connection-level).
    pub fn maybeUpdateStreamWindow(self: *Connection, stream_id: u31) ConnectionError!void {
        const stream = self.streams.get(stream_id) orelse return;
        const threshold = self.local_settings.initial_window_size / 2;
        const increment = stream.shouldSendWindowUpdate(threshold);
        if (increment > 0) {
            self.sendWindowUpdate(stream_id, increment) catch return ConnectionError.IoError;
            stream.ackWindowUpdate();
        }
    }

    /// Mark the current frame's payload as consumed by the caller.
    /// Call after reading payload_len bytes from the underlying reader.
    pub fn payloadConsumed(self: *Connection, len: u24) void {
        std.debug.assert(len <= self.pending_payload);
        self.pending_payload -= len;
    }

    pub fn isOpen(self: Connection) bool {
        return self.state == .open or self.state == .waiting_settings_ack;
    }

    /// Reset DoS counters. Call periodically (e.g. once per minute) to allow
    /// legitimate bursts while still protecting against sustained floods.
    pub fn resetDoSCounters(self: *Connection) void {
        self.settings_count = 0;
        self.empty_frame_count = 0;
    }

    /// Replace the underlying transport (for reconnect). Resets connection state.
    pub fn replaceTransport(self: *Connection, reader: compat.AnyReader, writer: compat.AnyWriter) void {
        self.reader = reader;
        self.writer = writer;
        self.state = .idle;
        self.pending_settings_ack = false;
        self.last_peer_stream_id = 0;
        self.goaway_info = null;
        self.expecting_continuation = null;
        self.pending_payload = 0;
        self.ping_count = 0;
        self.settings_count = 0;
        self.empty_frame_count = 0;
        self.data_received_since_ping = false;
        self.streams = stream_mod.StreamMap.init(self.local_settings.max_concurrent_streams);
        self.flow_control = stream_mod.ConnectionFlowControl.init(self.local_settings.initial_window_size);
        self.peer_settings = frame.default_settings;
    }

    // ─── Internal ───

    fn handleSettings(self: *Connection, header: frame.FrameHeader) ConnectionError!Event {
        if (header.stream_id != 0) return ConnectionError.ProtocolError;
        if (header.flags.hasAck()) {
            if (header.length != 0) return ConnectionError.FrameSizeError;
            if (!self.pending_settings_ack) return ConnectionError.ProtocolError;
            self.pending_settings_ack = false;
            if (self.state == .waiting_settings_ack) self.state = .open;
            return Event.settings_ack;
        }
        // DoS guard: reject SETTINGS floods
        self.settings_count += 1;
        if (self.settings_count > self.max_settings_per_minute) {
            return ConnectionError.ProtocolError;
        }
        self.applyPeerSettings(header) catch |e| return e;
        self.sendSettingsAck() catch return ConnectionError.IoError;
        return Event.settings_ack;
    }

    fn handlePing(self: *Connection, header: frame.FrameHeader) ConnectionError!?Event {
        if (header.stream_id != 0) return ConnectionError.ProtocolError;
        if (header.length != 8) return ConnectionError.FrameSizeError;
        var data: [8]u8 = undefined;
        self.readExact(&data) catch return ConnectionError.IoError;
        if (header.flags.hasAck()) {
            return Event{ .ping_ack = data };
        }
        // DoS guard: reject PING floods without intervening DATA
        if (!self.data_received_since_ping) {
            self.ping_count += 1;
            if (self.ping_count > self.max_pings_without_data) {
                return ConnectionError.ProtocolError;
            }
        } else {
            self.ping_count = 0;
            self.data_received_since_ping = false;
        }
        var resp_buf: [17]u8 = undefined;
        _ = frame.buildPingAck(data, &resp_buf);
        {
            self.write_mu.lock();
            defer self.write_mu.unlock();
            self.writeAll(&resp_buf) catch return ConnectionError.IoError;
        }
        return null;
    }

    fn handleGoaway(self: *Connection, header: frame.FrameHeader) ConnectionError!Event {
        if (header.stream_id != 0) return ConnectionError.ProtocolError;
        if (header.length < 8) return ConnectionError.FrameSizeError;
        var payload: [8]u8 = undefined;
        self.readExact(&payload) catch return ConnectionError.IoError;
        const last_id: u31 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF);
        const error_code: frame.ErrorCode = @enumFromInt(std.mem.readInt(u32, payload[4..8], .big));
        const debug_len = header.length - 8;
        self.skipPayload(debug_len) catch return ConnectionError.IoError;
        self.goaway_info = .{
            .last_stream_id = last_id,
            .error_code = error_code,
            .debug_data_len = @intCast(debug_len),
        };
        self.state = .goaway_received;
        return Event{ .goaway = self.goaway_info.? };
    }

    fn handleWindowUpdate(self: *Connection, header: frame.FrameHeader) ConnectionError!Event {
        if (header.length != 4) return ConnectionError.FrameSizeError;
        var payload: [4]u8 = undefined;
        self.readExact(&payload) catch return ConnectionError.IoError;
        const raw = std.mem.readInt(u32, &payload, .big);
        const increment: u31 = @intCast(raw & 0x7FFFFFFF);
        if (increment == 0) return ConnectionError.ProtocolError;
        if (header.stream_id == 0) {
            self.flow_control.creditSend(increment) catch
                return ConnectionError.FlowControlError;
        }
        return Event{ .window_update = .{
            .stream_id = header.stream_id,
            .increment = increment,
        } };
    }

    fn handleRstStream(self: *Connection, header: frame.FrameHeader) ConnectionError!Event {
        if (header.stream_id == 0) return ConnectionError.ProtocolError;
        if (header.length != 4) return ConnectionError.FrameSizeError;
        var payload: [4]u8 = undefined;
        self.readExact(&payload) catch return ConnectionError.IoError;
        const error_code: frame.ErrorCode = @enumFromInt(std.mem.readInt(u32, &payload, .big));
        return Event{ .rst_stream = .{
            .stream_id = header.stream_id,
            .error_code = error_code,
        } };
    }

    fn applyPeerSettings(self: *Connection, header: frame.FrameHeader) ConnectionError!void {
        if (header.length % 6 != 0) return ConnectionError.FrameSizeError;
        const payload_len = header.length;
        var remaining: u24 = payload_len;
        while (remaining > 0) {
            var param: [6]u8 = undefined;
            self.readExact(&param) catch return ConnectionError.IoError;
            const id: frame.SettingsId = @enumFromInt(std.mem.readInt(u16, param[0..2], .big));
            const value = std.mem.readInt(u32, param[2..6], .big);

            const old_window = self.peer_settings.initial_window_size;
            self.peer_settings.applyParam(id, value) catch |e| {
                return switch (e) {
                    error.FlowControlError => ConnectionError.FlowControlError,
                    error.ProtocolError => ConnectionError.ProtocolError,
                };
            };
            if (id == .initial_window_size) {
                self.streams.updateInitialWindowSize(old_window, value) catch
                    return ConnectionError.FlowControlError;
            }
            remaining -= 6;
        }
    }

    fn sendSettings(self: *Connection) anyerror!void {
        var buf: [45]u8 = undefined;
        const result = frame.buildSettings(self.local_settings, &buf);
        try self.writeAll(result);
        self.pending_settings_ack = true;
    }

    fn sendSettingsAck(self: *Connection) anyerror!void {
        var buf: [9]u8 = undefined;
        _ = frame.buildSettingsAck(&buf);
        self.write_mu.lock();
        defer self.write_mu.unlock();
        try self.writeAll(&buf);
    }

    fn readFrameHeader(self: *Connection) anyerror!frame.FrameHeader {
        var buf: [9]u8 = undefined;
        try self.readExact(&buf);
        return frame.FrameHeader.decode(&buf);
    }

    fn readExact(self: *Connection, buf: []u8) anyerror!void {
        const n = try self.reader.readAll(buf);
        if (n < buf.len) return error.EndOfStream;
    }

    fn writeAll(self: *Connection, data: []const u8) anyerror!void {
        try self.writer.writeAll(data);
    }

    fn skipPayload(self: *Connection, length: u24) anyerror!void {
        var remaining: u32 = length;
        var discard: [256]u8 = undefined;
        while (remaining > 0) {
            const to_read: usize = @min(remaining, 256);
            const n = try self.reader.readAll(discard[0..to_read]);
            if (n == 0) return error.EndOfStream;
            remaining -= @intCast(n);
        }
    }
};

// ─── Tests ───

const test_util = @import("test_util.zig");
const TestPipe = test_util.TestPipe;
const appendSettingsAck = test_util.appendSettingsAck;

test "client preface + settings exchange" {
    const allocator = std.testing.allocator;

    var server_input = std.ArrayListUnmanaged(u8){};
    defer server_input.deinit(allocator);

    // Server sends: SETTINGS (empty) + SETTINGS ACK
    var settings_frame: [9]u8 = undefined;
    const sh = frame.FrameHeader{ .length = 0, .frame_type = .settings, .flags = .{}, .stream_id = 0 };
    sh.encode(&settings_frame);
    try server_input.appendSlice(allocator, &settings_frame);
    try appendSettingsAck(&server_input, allocator);

    var pipe = TestPipe.init(allocator, server_input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    try conn.sendClientPreface();
    try std.testing.expectEqual(State.waiting_preface, conn.state);

    try conn.recvServerPreface();
    try std.testing.expectEqual(State.waiting_settings_ack, conn.state);

    const event = try conn.recvFrame();
    try std.testing.expectEqual(Event.settings_ack, event);
    try std.testing.expectEqual(State.open, conn.state);

    // Verify client sent: preface (24) + SETTINGS frame
    const out = pipe.written();
    try std.testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", out[0..24]);
    const client_settings_hdr = frame.FrameHeader.decode(out[24..33]);
    try std.testing.expectEqual(frame.FrameType.settings, client_settings_hdr.frame_type);
}

test "ping roundtrip" {
    const allocator = std.testing.allocator;

    // Server sends a PING
    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);
    const ping_data = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    var ping_buf: [17]u8 = undefined;
    _ = frame.buildPing(ping_data, &ping_buf);
    try input.appendSlice(allocator, &ping_buf);

    // Then PING ACK from server (so recvFrame has something to return)
    var ping_ack_buf: [17]u8 = undefined;
    _ = frame.buildPingAck(ping_data, &ping_ack_buf);
    try input.appendSlice(allocator, &ping_ack_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    // recvFrame should auto-respond with PING ACK and recurse to next frame
    const event = try conn.recvFrame();
    try std.testing.expect(event == .ping_ack);
    try std.testing.expectEqualSlices(u8, &ping_data, &event.ping_ack);

    // Verify we wrote a PING ACK
    const out = pipe.written();
    const resp_hdr = frame.FrameHeader.decode(out[0..9]);
    try std.testing.expectEqual(frame.FrameType.ping, resp_hdr.frame_type);
    try std.testing.expect(resp_hdr.flags.hasAck());
}

test "goaway received" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // Build GOAWAY: last_stream_id=5, error=no_error
    var goaway_buf: [64]u8 = undefined;
    const goaway = frame.buildGoaway(5, .no_error, "", &goaway_buf) catch unreachable;
    try input.appendSlice(allocator, goaway);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const event = try conn.recvFrame();
    try std.testing.expect(event == .goaway);
    try std.testing.expectEqual(@as(u31, 5), event.goaway.last_stream_id);
    try std.testing.expectEqual(frame.ErrorCode.no_error, event.goaway.error_code);
    try std.testing.expectEqual(State.goaway_received, conn.state);
}

test "window update on connection" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // WINDOW_UPDATE on stream 0, increment=32768
    var wu_buf: [13]u8 = undefined;
    _ = frame.buildWindowUpdate(0, 32768, &wu_buf) catch unreachable;
    try input.appendSlice(allocator, &wu_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const event = try conn.recvFrame();
    try std.testing.expect(event == .window_update);
    try std.testing.expectEqual(@as(u31, 0), event.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 32768), event.window_update.increment);
    try std.testing.expectEqual(@as(u32, 65535 + 32768), conn.flow_control.availableSend());
}

test "rst_stream received" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    var rst_buf: [13]u8 = undefined;
    _ = frame.buildRstStream(3, .cancel, &rst_buf);
    try input.appendSlice(allocator, &rst_buf);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const event = try conn.recvFrame();
    try std.testing.expect(event == .rst_stream);
    try std.testing.expectEqual(@as(u31, 3), event.rst_stream.stream_id);
    try std.testing.expectEqual(frame.ErrorCode.cancel, event.rst_stream.error_code);
}

test "data frame updates connection flow control" {
    const allocator = std.testing.allocator;

    var input = std.ArrayListUnmanaged(u8){};
    defer input.deinit(allocator);

    // DATA frame: stream 1, 100 bytes, no end_stream
    const data_payload = [_]u8{0xAB} ** 100;
    const dh = frame.FrameHeader{
        .length = 100,
        .frame_type = .data,
        .flags = .{},
        .stream_id = 1,
    };
    var hdr_buf: [9]u8 = undefined;
    dh.encode(&hdr_buf);
    try input.appendSlice(allocator, &hdr_buf);
    try input.appendSlice(allocator, &data_payload);

    var pipe = TestPipe.init(allocator, input.items);
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const event = try conn.recvFrame();
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u31, 1), event.data.stream_id);
    try std.testing.expectEqual(@as(u24, 100), event.data.payload_len);
    try std.testing.expectEqual(@as(u32, 100), conn.flow_control.recv_window_consumed);
}

test "sendHeaders writes correct frame" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const header_block = "fake-hpack-data";
    try conn.sendHeaders(1, header_block, true);

    const out = pipe.written();
    const hdr = frame.FrameHeader.decode(out[0..9]);
    try std.testing.expectEqual(frame.FrameType.headers, hdr.frame_type);
    try std.testing.expectEqual(@as(u31, 1), hdr.stream_id);
    try std.testing.expect(hdr.flags.hasEndStream());
    try std.testing.expect(hdr.flags.hasEndHeaders());
    try std.testing.expectEqualStrings(header_block, out[9..]);
}

test "sendData writes correct frame and consumes window" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const payload = "hello world";
    try conn.sendData(3, payload, false);

    const out = pipe.written();
    const hdr = frame.FrameHeader.decode(out[0..9]);
    try std.testing.expectEqual(frame.FrameType.data, hdr.frame_type);
    try std.testing.expectEqual(@as(u31, 3), hdr.stream_id);
    try std.testing.expect(!hdr.flags.hasEndStream());
    try std.testing.expectEqualStrings(payload, out[9..]);
    try std.testing.expectEqual(@as(u32, 65535 - 11), conn.flow_control.availableSend());
}

test "maybeUpdateStreamWindow sends WINDOW_UPDATE when threshold exceeded" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    // Open a stream and simulate receiving data that exhausts half the window
    const stream = try conn.streams.openStream(
        conn.peer_settings.initial_window_size,
        conn.local_settings.initial_window_size,
    );
    stream.state = .open;
    const stream_id = stream.id;

    // Consume 40000 bytes (> threshold of 65535/2 = 32767)
    try stream.recvData(40000, false);
    try std.testing.expectEqual(@as(u32, 40000), stream.recv_window_consumed);

    // Should send WINDOW_UPDATE
    try conn.maybeUpdateStreamWindow(stream_id);

    const out = pipe.written();
    try std.testing.expect(out.len == 13); // One WINDOW_UPDATE frame
    const hdr = frame.FrameHeader.decode(out[0..9]);
    try std.testing.expectEqual(frame.FrameType.window_update, hdr.frame_type);
    try std.testing.expectEqual(stream_id, hdr.stream_id);
    const increment = std.mem.readInt(u32, out[9..13], .big) & 0x7FFFFFFF;
    try std.testing.expectEqual(@as(u32, 40000), increment);

    // After ack, consumed should be 0
    const s = conn.streams.get(stream_id).?;
    try std.testing.expectEqual(@as(u32, 0), s.recv_window_consumed);
    try std.testing.expectEqual(@as(u32, 65535), s.recv_window.available());
}

test "maybeUpdateStreamWindow does nothing below threshold" {
    const allocator = std.testing.allocator;
    var pipe = TestPipe.init(allocator, &.{});
    defer pipe.deinit();

    var conn = Connection.init(pipe.reader(), pipe.writer(), .{});
    conn.state = .open;

    const stream = try conn.streams.openStream(
        conn.peer_settings.initial_window_size,
        conn.local_settings.initial_window_size,
    );
    stream.state = .open;

    // Consume 10000 bytes (< threshold of 32767)
    try stream.recvData(10000, false);

    try conn.maybeUpdateStreamWindow(stream.id);

    // No WINDOW_UPDATE should be sent
    try std.testing.expectEqual(@as(usize, 0), pipe.written().len);
}
