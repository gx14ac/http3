// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const h3_frame = @import("h3_frame.zig");
const qpack = @import("qpack.zig");
const qpack_dynamic = @import("qpack_dynamic.zig");
const stream_mod = @import("stream.zig");

/// HTTP/3 connection state (RFC 9114 §3).
/// Manages control streams, QPACK streams, and request lifecycle.
pub const H3Connection = struct {
    /// Local control stream ID (client-initiated uni, type=0x00).
    control_stream_id: ?u62,
    /// Peer's control stream ID (received).
    peer_control_stream_id: ?u62,
    /// QPACK encoder stream ID (type=0x02).
    qpack_encoder_stream_id: ?u62,
    /// QPACK decoder stream ID (type=0x03).
    qpack_decoder_stream_id: ?u62,
    /// Local SETTINGS (sent to peer).
    local_settings: Settings,
    /// Peer SETTINGS (received from peer).
    peer_settings: ?Settings,
    /// Whether we've received the peer's SETTINGS frame.
    settings_received: bool,
    /// Whether GOAWAY has been sent.
    goaway_sent: bool,
    /// Whether GOAWAY has been received.
    goaway_received: bool,
    /// Last stream ID in GOAWAY.
    goaway_id: u62,
    /// Stream allocator.
    stream_alloc: stream_mod.StreamAllocator,
    /// Is this the server side?
    is_server: bool,
    /// QPACK dynamic encoder (local → peer).
    qpack_encoder: qpack_dynamic.DynamicEncoder,
    /// QPACK dynamic decoder (peer → local).
    qpack_decoder: qpack_dynamic.DynamicDecoder,

    pub const Settings = struct {
        max_field_section_size: u64 = 0, // 0 = unlimited
        qpack_max_table_capacity: u64 = 0,
        qpack_blocked_streams: u64 = 0,
    };

    pub fn init(is_server: bool, max_bidi: u62, max_uni: u62) H3Connection {
        return .{
            .control_stream_id = null,
            .peer_control_stream_id = null,
            .qpack_encoder_stream_id = null,
            .qpack_decoder_stream_id = null,
            .local_settings = .{},
            .peer_settings = null,
            .settings_received = false,
            .goaway_sent = false,
            .goaway_received = false,
            .goaway_id = 0,
            .stream_alloc = stream_mod.StreamAllocator.init(is_server, max_bidi, max_uni),
            .is_server = is_server,
            .qpack_encoder = qpack_dynamic.DynamicEncoder.init(0),
            .qpack_decoder = qpack_dynamic.DynamicDecoder.init(0),
        };
    }

    /// Apply peer's QPACK settings after receiving SETTINGS frame.
    /// Must be called after processControlFrame returns .settings.
    pub fn applyQpackSettings(self: *H3Connection) void {
        if (self.peer_settings) |ps| {
            if (ps.qpack_max_table_capacity > 0) {
                self.qpack_encoder = qpack_dynamic.DynamicEncoder.init(ps.qpack_max_table_capacity);
            }
        }
        if (self.local_settings.qpack_max_table_capacity > 0) {
            self.qpack_decoder = qpack_dynamic.DynamicDecoder.init(self.local_settings.qpack_max_table_capacity);
        }
    }

    /// Build the initial control stream data: stream_type(varint) + SETTINGS frame.
    /// This must be sent on a new unidirectional stream.
    pub fn buildControlStreamData(self: *const H3Connection, buf: []u8) ?usize {
        var pos: usize = 0;

        // Stream type = control (0x00)
        pos += h3_frame.encodeUniStreamType(buf[pos..], .control) orelse return null;

        // SETTINGS frame
        var settings_arr: [3]h3_frame.Setting = undefined;
        var n: usize = 0;
        if (self.local_settings.max_field_section_size > 0) {
            settings_arr[n] = .{
                .id = @intFromEnum(h3_frame.SettingsId.max_field_section_size),
                .value = self.local_settings.max_field_section_size,
            };
            n += 1;
        }
        if (self.local_settings.qpack_max_table_capacity > 0) {
            settings_arr[n] = .{
                .id = @intFromEnum(h3_frame.SettingsId.qpack_max_table_capacity),
                .value = self.local_settings.qpack_max_table_capacity,
            };
            n += 1;
        }
        if (self.local_settings.qpack_blocked_streams > 0) {
            settings_arr[n] = .{
                .id = @intFromEnum(h3_frame.SettingsId.qpack_blocked_streams),
                .value = self.local_settings.qpack_blocked_streams,
            };
            n += 1;
        }

        pos += h3_frame.encodeSettingsFrame(buf[pos..], settings_arr[0..n]) orelse return null;
        return pos;
    }

    /// Build a request HEADERS frame: QPACK-encode the headers into a HEADERS frame.
    pub fn buildHeadersFrame(buf: []u8, headers: []const qpack.HeaderField) ?usize {
        // First QPACK-encode
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = qpack.Encoder.encode(&qpack_buf, headers) orelse return null;

        // Then wrap in HEADERS frame
        return h3_frame.encodeHeadersFrame(buf, qpack_buf[0..qpack_len]);
    }

    /// Build a HEADERS frame using the dynamic QPACK encoder.
    /// Returns: field section wrapped in a HEADERS frame.
    /// encoder_stream_buf receives any encoder stream instructions to send to the peer.
    pub fn buildHeadersFrameDynamic(
        self: *H3Connection,
        buf: []u8,
        headers: []const qpack.HeaderField,
        encoder_stream_buf: []u8,
        encoder_stream_len: *usize,
    ) ?usize {
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = self.qpack_encoder.encode(
            &qpack_buf,
            headers,
            encoder_stream_buf,
            encoder_stream_len,
        ) orelse return null;
        return h3_frame.encodeHeadersFrame(buf, qpack_buf[0..qpack_len]);
    }

    /// Process data received on the peer's QPACK encoder stream.
    /// Call this when data arrives on the unidirectional stream of type 0x02.
    pub fn processEncoderStream(self: *H3Connection, data: []const u8) ?usize {
        var dec = self.qpack_decoder.encoderStreamDecoder();
        return dec.process(data);
    }

    /// Decode a HEADERS frame payload using the dynamic decoder.
    pub fn decodeHeadersDynamic(self: *const H3Connection, data: []const u8, headers: []qpack.HeaderField) ?qpack_dynamic.DecodeResult {
        return self.qpack_decoder.decode(data, headers);
    }

    /// Build decoder stream "Section Acknowledgement" for a decoded header block.
    pub fn buildSectionAck(buf: []u8, stream_id: usize) ?usize {
        return qpack_dynamic.DecoderStreamWriter.sectionAck(buf, stream_id);
    }

    /// Build decoder stream "Insert Count Increment".
    pub fn buildInsertCountIncrement(buf: []u8, increment: usize) ?usize {
        return qpack_dynamic.DecoderStreamWriter.insertCountIncrement(buf, increment);
    }

    /// Build a DATA frame containing the given payload.
    pub fn buildDataFrame(buf: []u8, payload: []const u8) ?usize {
        return h3_frame.encodeDataFrame(buf, payload);
    }

    /// Process a received frame on the control stream.
    /// Returns the frame type for caller to handle.
    pub fn processControlFrame(self: *H3Connection, data: []const u8) ?ProcessedFrame {
        const hdr = h3_frame.decodeFrameHeader(data) orelse return null;

        if (hdr.frame_type == @intFromEnum(h3_frame.FrameType.settings)) {
            if (self.settings_received) return null; // duplicate SETTINGS = error
            var settings: [8]h3_frame.Setting = undefined;
            const payload = data[hdr.header_len..][0..@intCast(hdr.length)];
            const count = h3_frame.decodeSettingsPayload(payload, &settings) orelse return null;

            var peer = Settings{};
            for (settings[0..count]) |s| {
                if (s.id == @intFromEnum(h3_frame.SettingsId.max_field_section_size)) {
                    peer.max_field_section_size = s.value;
                } else if (s.id == @intFromEnum(h3_frame.SettingsId.qpack_max_table_capacity)) {
                    peer.qpack_max_table_capacity = s.value;
                } else if (s.id == @intFromEnum(h3_frame.SettingsId.qpack_blocked_streams)) {
                    peer.qpack_blocked_streams = s.value;
                }
            }
            self.peer_settings = peer;
            self.settings_received = true;

            return .{ .frame_type = .settings, .payload_len = hdr.length, .header_len = hdr.header_len };
        } else if (hdr.frame_type == @intFromEnum(h3_frame.FrameType.goaway)) {
            const packet_mod = @import("packet.zig");
            const payload = data[hdr.header_len..][0..@intCast(hdr.length)];
            const id = packet_mod.decodeVarint(payload) orelse return null;
            self.goaway_received = true;
            self.goaway_id = @intCast(id.value);
            return .{ .frame_type = .goaway, .payload_len = hdr.length, .header_len = hdr.header_len };
        }

        return .{ .frame_type = .unknown, .payload_len = hdr.length, .header_len = hdr.header_len };
    }

    /// Allocate a new request stream (bidi) for sending a request.
    /// Returns null if GOAWAY has been received and the next stream ID >= goaway_id.
    pub fn allocRequestStream(self: *H3Connection) ?u62 {
        if (self.goaway_received) {
            const next_id = self.stream_alloc.peekNextBidi() orelse return null;
            if (next_id >= self.goaway_id) return null;
        }
        return self.stream_alloc.allocBidi();
    }

    /// Check if a stream ID is allowed (not blocked by GOAWAY).
    /// RFC 9114 §5.2: Streams with ID >= goaway_id MUST NOT be opened.
    pub fn isStreamAllowed(self: *const H3Connection, stream_id: u62) bool {
        if (!self.goaway_received) return true;
        return stream_id < self.goaway_id;
    }

    /// Send GOAWAY: returns bytes written to buf.
    pub fn buildGoaway(self: *H3Connection, buf: []u8, last_stream_id: u62) ?usize {
        self.goaway_sent = true;
        self.goaway_id = last_stream_id;
        return h3_frame.encodeGoawayFrame(buf, last_stream_id);
    }
};

pub const ProcessedFrameType = enum {
    settings,
    goaway,
    unknown,
};

pub const ProcessedFrame = struct {
    frame_type: ProcessedFrameType,
    payload_len: u64,
    header_len: usize,
};

// ─── Tests ───

test "H3Connection: buildControlStreamData with default settings" {
    var conn = H3Connection.init(false, 100, 100);
    var buf: [256]u8 = undefined;
    const written = conn.buildControlStreamData(&buf) orelse unreachable;

    // First byte: stream type = 0x00
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    // Second byte should start the SETTINGS frame (type=0x04)
    const hdr = h3_frame.decodeFrameHeader(buf[1..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x04), hdr.frame_type);
    // Empty settings → length = 0
    try std.testing.expectEqual(@as(u64, 0), hdr.length);
}

test "H3Connection: buildControlStreamData with custom settings" {
    var conn = H3Connection.init(false, 100, 100);
    conn.local_settings.max_field_section_size = 16384;
    conn.local_settings.qpack_max_table_capacity = 4096;

    var buf: [256]u8 = undefined;
    const written = conn.buildControlStreamData(&buf) orelse unreachable;
    try std.testing.expect(written > 3); // type + settings frame with data

    const hdr = h3_frame.decodeFrameHeader(buf[1..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x04), hdr.frame_type);
    try std.testing.expect(hdr.length > 0);
}

test "H3Connection: buildHeadersFrame" {
    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    };

    var buf: [512]u8 = undefined;
    const written = H3Connection.buildHeadersFrame(&buf, &headers) orelse unreachable;

    const hdr = h3_frame.decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type); // HEADERS
    try std.testing.expect(hdr.length > 0);

    // Verify QPACK can decode the payload
    const payload = buf[hdr.header_len..][0..@intCast(hdr.length)];
    var decoded: [8]qpack.HeaderField = undefined;
    const count = qpack.Decoder.decode(payload, &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 4), count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "H3Connection: buildDataFrame" {
    const payload = "Hello World";
    var buf: [64]u8 = undefined;
    const written = H3Connection.buildDataFrame(&buf, payload) orelse unreachable;

    const hdr = h3_frame.decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x00), hdr.frame_type);
    try std.testing.expectEqual(@as(u64, payload.len), hdr.length);
}

test "H3Connection: processControlFrame SETTINGS" {
    var conn = H3Connection.init(false, 100, 100);

    // Build a SETTINGS frame
    const settings = [_]h3_frame.Setting{
        .{ .id = @intFromEnum(h3_frame.SettingsId.max_field_section_size), .value = 8192 },
    };
    var frame_buf: [64]u8 = undefined;
    const frame_len = h3_frame.encodeSettingsFrame(&frame_buf, &settings) orelse unreachable;

    const result = conn.processControlFrame(frame_buf[0..frame_len]) orelse unreachable;
    try std.testing.expectEqual(ProcessedFrameType.settings, result.frame_type);
    try std.testing.expect(conn.settings_received);
    try std.testing.expectEqual(@as(u64, 8192), conn.peer_settings.?.max_field_section_size);
}

test "H3Connection: processControlFrame GOAWAY" {
    var conn = H3Connection.init(false, 100, 100);
    conn.settings_received = true;

    var frame_buf: [16]u8 = undefined;
    const frame_len = h3_frame.encodeGoawayFrame(&frame_buf, 8) orelse unreachable;

    const result = conn.processControlFrame(frame_buf[0..frame_len]) orelse unreachable;
    try std.testing.expectEqual(ProcessedFrameType.goaway, result.frame_type);
    try std.testing.expect(conn.goaway_received);
    try std.testing.expectEqual(@as(u62, 8), conn.goaway_id);
}

test "H3Connection: allocRequestStream" {
    var conn = H3Connection.init(false, 100, 100);
    const s0 = conn.allocRequestStream() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 0), s0);
    const s1 = conn.allocRequestStream() orelse unreachable;
    try std.testing.expectEqual(@as(u62, 4), s1);
}

test "H3Connection: buildGoaway" {
    var conn = H3Connection.init(true, 100, 100);
    var buf: [16]u8 = undefined;
    const written = conn.buildGoaway(&buf, 12) orelse unreachable;
    try std.testing.expect(written > 0);
    try std.testing.expect(conn.goaway_sent);
    try std.testing.expectEqual(@as(u62, 12), conn.goaway_id);
}

test "H3Connection: duplicate SETTINGS is rejected" {
    var conn = H3Connection.init(false, 100, 100);

    const settings = [_]h3_frame.Setting{
        .{ .id = @intFromEnum(h3_frame.SettingsId.max_field_section_size), .value = 4096 },
    };
    var frame_buf: [64]u8 = undefined;
    const frame_len = h3_frame.encodeSettingsFrame(&frame_buf, &settings) orelse unreachable;

    // First SETTINGS is fine
    _ = conn.processControlFrame(frame_buf[0..frame_len]) orelse unreachable;
    // Second SETTINGS returns null (protocol error)
    try std.testing.expect(conn.processControlFrame(frame_buf[0..frame_len]) == null);
}

test "H3Connection: applyQpackSettings initializes dynamic table" {
    var conn = H3Connection.init(false, 100, 100);
    conn.local_settings.qpack_max_table_capacity = 4096;

    // Simulate receiving peer's SETTINGS with dynamic table capacity
    const settings = [_]h3_frame.Setting{
        .{ .id = @intFromEnum(h3_frame.SettingsId.qpack_max_table_capacity), .value = 2048 },
    };
    var frame_buf: [64]u8 = undefined;
    const frame_len = h3_frame.encodeSettingsFrame(&frame_buf, &settings) orelse unreachable;
    _ = conn.processControlFrame(frame_buf[0..frame_len]) orelse unreachable;

    conn.applyQpackSettings();
    try std.testing.expectEqual(@as(usize, 2048), conn.qpack_encoder.table.max_capacity);
    try std.testing.expectEqual(@as(usize, 4096), conn.qpack_decoder.table.max_capacity);
}

test "H3Connection: buildHeadersFrameDynamic roundtrip" {
    var conn = H3Connection.init(false, 100, 100);
    conn.local_settings.qpack_max_table_capacity = 4096;

    // Simulate peer allows 4096 capacity
    conn.peer_settings = .{ .qpack_max_table_capacity = 4096 };
    conn.applyQpackSettings();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "grpc.example.com" },
        .{ .name = ":path", .value = "/pkg.Service/Call" },
        .{ .name = "content-type", .value = "application/grpc" },
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    const written = conn.buildHeadersFrameDynamic(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expect(written > 0);
    try std.testing.expect(es_len > 0); // encoder stream instructions generated

    // Feed encoder stream instructions to the decoder side
    const consumed = conn.processEncoderStream(es_buf[0..es_len]) orelse unreachable;
    try std.testing.expectEqual(es_len, consumed);

    // Decode the HEADERS frame
    const hdr = h3_frame.decodeFrameHeader(buf[0..written]) orelse unreachable;
    const payload = buf[hdr.header_len..][0..@intCast(hdr.length)];
    var decoded: [8]qpack.HeaderField = undefined;
    const result = conn.decodeHeadersDynamic(payload, &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 5), result.count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("POST", decoded[0].value);
    try std.testing.expectEqualStrings(":authority", decoded[2].name);
    try std.testing.expectEqualStrings("grpc.example.com", decoded[2].value);
}

test "H3Connection: buildSectionAck" {
    var buf: [8]u8 = undefined;
    const len = H3Connection.buildSectionAck(&buf, 4) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x84), buf[0]);
}

test "H3Connection: second request uses dynamic table (no new encoder stream data)" {
    var conn = H3Connection.init(false, 100, 100);
    conn.peer_settings = .{ .qpack_max_table_capacity = 4096 };
    conn.applyQpackSettings();

    const headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":authority", .value = "grpc.example.com" },
        .{ .name = "content-type", .value = "application/grpc" },
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    // First request — populates dynamic table
    _ = conn.buildHeadersFrameDynamic(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expect(es_len > 0);

    // Second request — references existing dynamic entries
    _ = conn.buildHeadersFrameDynamic(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 0), es_len);
}
