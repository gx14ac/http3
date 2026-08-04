const std = @import("std");

/// HTTP/2 frame types (RFC 9113 Section 4)
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

/// HTTP/2 frame flags (RFC 9113 Section 4.1)
/// Bit 0x01 is ACK for SETTINGS/PING, END_STREAM for DATA/HEADERS.
/// We use a raw u8 with named constructors to avoid semantic confusion.
pub const Flags = struct {
    raw: u8 = 0,

    pub const ACK: Flags = .{ .raw = 0x01 };
    pub const END_STREAM: Flags = .{ .raw = 0x01 };
    pub const END_HEADERS: Flags = .{ .raw = 0x04 };
    pub const PADDED: Flags = .{ .raw = 0x08 };
    pub const PRIORITY: Flags = .{ .raw = 0x20 };

    pub fn combine(a: Flags, b: Flags) Flags {
        return .{ .raw = a.raw | b.raw };
    }

    pub fn has(self: Flags, flag: Flags) bool {
        return (self.raw & flag.raw) == flag.raw;
    }

    pub fn hasEndStream(self: Flags) bool {
        return self.has(END_STREAM);
    }

    pub fn hasEndHeaders(self: Flags) bool {
        return self.has(END_HEADERS);
    }

    pub fn hasAck(self: Flags) bool {
        return self.has(ACK);
    }

    pub fn hasPadded(self: Flags) bool {
        return self.has(PADDED);
    }

    pub fn hasPriority(self: Flags) bool {
        return self.has(PRIORITY);
    }
};

/// HTTP/2 frame header (9 bytes, RFC 9113 Section 4.1)
pub const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: Flags,
    stream_id: u31,

    pub const encoded_size = 9;

    /// Encode frame header into a 9-byte buffer. Zero allocation.
    pub fn encode(self: FrameHeader, buf: *[9]u8) void {
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @intFromEnum(self.frame_type);
        buf[4] = self.flags.raw;
        const sid: u32 = @intCast(self.stream_id);
        buf[5] = @intCast((sid >> 24) & 0x7F);
        buf[6] = @intCast((sid >> 16) & 0xFF);
        buf[7] = @intCast((sid >> 8) & 0xFF);
        buf[8] = @intCast(sid & 0xFF);
    }

    /// Decode frame header from 9 bytes. Zero allocation.
    pub fn decode(buf: *const [9]u8) FrameHeader {
        const length: u24 = @intCast(
            (@as(u32, buf[0]) << 16) | (@as(u32, buf[1]) << 8) | @as(u32, buf[2]),
        );
        const stream_id: u31 = @intCast(
            (@as(u32, buf[5] & 0x7F) << 24) | (@as(u32, buf[6]) << 16) |
                (@as(u32, buf[7]) << 8) | @as(u32, buf[8]),
        );
        return .{
            .length = length,
            .frame_type = @enumFromInt(buf[3]),
            .flags = .{ .raw = buf[4] },
            .stream_id = stream_id,
        };
    }
};

/// HTTP/2 frame (header + payload reference)
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
};

/// HTTP/2 error codes (RFC 9113 Section 7)
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

/// SETTINGS parameters (RFC 9113 Section 6.5.2)
pub const SettingsId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const default_settings = Settings{};

pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = false,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,

    pub fn applyParam(self: *Settings, id: SettingsId, value: u32) !void {
        switch (id) {
            .header_table_size => self.header_table_size = value,
            .enable_push => {
                if (value > 1) return error.ProtocolError;
                self.enable_push = value == 1;
            },
            .max_concurrent_streams => self.max_concurrent_streams = value,
            .initial_window_size => {
                if (value > 0x7FFFFFFF) return error.FlowControlError;
                self.initial_window_size = value;
            },
            .max_frame_size => {
                if (value < 16384 or value > 16777215) return error.ProtocolError;
                self.max_frame_size = value;
            },
            .max_header_list_size => self.max_header_list_size = value,
            _ => {},
        }
    }

    /// Encode only non-default parameters into buf. Returns bytes written.
    pub fn encodeDiff(self: Settings, buf: []u8) usize {
        const defaults = default_settings;
        var offset: usize = 0;

        if (self.header_table_size != defaults.header_table_size)
            offset = writeParam(buf, offset, 0x1, self.header_table_size);
        if (self.enable_push != defaults.enable_push)
            offset = writeParam(buf, offset, 0x2, if (self.enable_push) @as(u32, 1) else 0);
        if (self.max_concurrent_streams != defaults.max_concurrent_streams)
            offset = writeParam(buf, offset, 0x3, self.max_concurrent_streams);
        if (self.initial_window_size != defaults.initial_window_size)
            offset = writeParam(buf, offset, 0x4, self.initial_window_size);
        if (self.max_frame_size != defaults.max_frame_size)
            offset = writeParam(buf, offset, 0x5, self.max_frame_size);
        if (self.max_header_list_size != defaults.max_header_list_size)
            offset = writeParam(buf, offset, 0x6, self.max_header_list_size);

        return offset;
    }

    /// Decode settings from payload.
    pub fn decodePayload(self: *Settings, payload: []const u8) !void {
        if (payload.len % 6 != 0) return error.FrameSizeError;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const id: SettingsId = @enumFromInt(std.mem.readInt(u16, payload[i..][0..2], .big));
            const value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            try self.applyParam(id, value);
        }
    }

    fn writeParam(buf: []u8, offset: usize, id: u16, val: u32) usize {
        std.mem.writeInt(u16, buf[offset..][0..2], id, .big);
        std.mem.writeInt(u32, buf[offset + 2 ..][0..4], val, .big);
        return offset + 6;
    }
};

// ─── Frame builders (zero allocation, write into caller buffer) ───

/// Build a SETTINGS frame. Encodes only non-default params directly into buf.
/// buf must be at least 45 bytes (9 header + 6 params * 6 bytes max).
pub fn buildSettings(settings: Settings, buf: *[45]u8) []u8 {
    const payload_len = settings.encodeDiff(buf[9..]);
    const header = FrameHeader{
        .length = @intCast(payload_len),
        .frame_type = .settings,
        .flags = .{},
        .stream_id = 0,
    };
    header.encode(buf[0..9]);
    return buf[0 .. 9 + payload_len];
}

/// Build a SETTINGS ACK frame.
pub fn buildSettingsAck(buf: *[9]u8) []u8 {
    const header = FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = Flags.ACK,
        .stream_id = 0,
    };
    header.encode(buf);
    return buf;
}

/// Build a WINDOW_UPDATE frame. increment must be > 0 (RFC 9113 §6.9).
pub fn buildWindowUpdate(stream_id: u31, increment: u31, buf: *[13]u8) ![]u8 {
    if (increment == 0) return error.ProtocolError;
    const header = FrameHeader{
        .length = 4,
        .frame_type = .window_update,
        .flags = .{},
        .stream_id = stream_id,
    };
    header.encode(buf[0..9]);
    std.mem.writeInt(u32, buf[9..13], @intCast(increment), .big);
    return buf;
}

/// Build a PING frame.
pub fn buildPing(opaque_data: [8]u8, buf: *[17]u8) []u8 {
    const header = FrameHeader{
        .length = 8,
        .frame_type = .ping,
        .flags = .{},
        .stream_id = 0,
    };
    header.encode(buf[0..9]);
    @memcpy(buf[9..17], &opaque_data);
    return buf;
}

/// Build a PING ACK frame.
pub fn buildPingAck(opaque_data: [8]u8, buf: *[17]u8) []u8 {
    const header = FrameHeader{
        .length = 8,
        .frame_type = .ping,
        .flags = Flags.ACK,
        .stream_id = 0,
    };
    header.encode(buf[0..9]);
    @memcpy(buf[9..17], &opaque_data);
    return buf;
}

/// Build a RST_STREAM frame.
pub fn buildRstStream(stream_id: u31, error_code: ErrorCode, buf: *[13]u8) []u8 {
    const header = FrameHeader{
        .length = 4,
        .frame_type = .rst_stream,
        .flags = .{},
        .stream_id = stream_id,
    };
    header.encode(buf[0..9]);
    std.mem.writeInt(u32, buf[9..13], @intFromEnum(error_code), .big);
    return buf;
}

/// Build a GOAWAY frame. Returns error if buf is too small.
pub fn buildGoaway(last_stream_id: u31, error_code: ErrorCode, debug_data: []const u8, buf: []u8) ![]u8 {
    const total_len = 17 + debug_data.len;
    if (buf.len < total_len) return error.BufferTooSmall;

    const payload_len: u24 = @intCast(8 + debug_data.len);
    const header = FrameHeader{
        .length = payload_len,
        .frame_type = .goaway,
        .flags = .{},
        .stream_id = 0,
    };
    header.encode(buf[0..9]);
    std.mem.writeInt(u32, buf[9..13], @intCast(last_stream_id), .big);
    std.mem.writeInt(u32, buf[13..17], @intFromEnum(error_code), .big);
    if (debug_data.len > 0) {
        @memcpy(buf[17..][0..debug_data.len], debug_data);
    }
    return buf[0..total_len];
}

/// HTTP/2 connection preface (RFC 9113 Section 3.4)
pub const client_preface: *const [24]u8 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ─── Tests ───

test "FrameHeader encode/decode roundtrip" {
    const original = FrameHeader{
        .length = 1024,
        .frame_type = .headers,
        .flags = Flags.END_HEADERS,
        .stream_id = 7,
    };

    var buf: [9]u8 = undefined;
    original.encode(&buf);
    const decoded = FrameHeader.decode(&buf);

    try std.testing.expectEqual(original.length, decoded.length);
    try std.testing.expectEqual(original.frame_type, decoded.frame_type);
    try std.testing.expectEqual(original.flags.raw, decoded.flags.raw);
    try std.testing.expectEqual(original.stream_id, decoded.stream_id);
}

test "FrameHeader max values" {
    const original = FrameHeader{
        .length = 0xFFFFFF,
        .frame_type = .data,
        .flags = .{ .raw = 0xFF },
        .stream_id = 0x7FFFFFFF,
    };

    var buf: [9]u8 = undefined;
    original.encode(&buf);
    const decoded = FrameHeader.decode(&buf);

    try std.testing.expectEqual(original.length, decoded.length);
    try std.testing.expectEqual(original.stream_id, decoded.stream_id);
}

test "Flags combine and check" {
    const flags = Flags.END_STREAM.combine(Flags.END_HEADERS);
    try std.testing.expect(flags.hasEndStream());
    try std.testing.expect(flags.hasEndHeaders());
    try std.testing.expect(!flags.hasPadded());
}

test "Settings encodeDiff only encodes non-defaults" {
    const settings = Settings{
        .max_concurrent_streams = 256,
        .initial_window_size = 131072,
    };

    var buf: [36]u8 = undefined;
    const len = settings.encodeDiff(&buf);
    // Only 2 params changed = 12 bytes
    try std.testing.expectEqual(@as(usize, 12), len);

    var decoded = Settings{};
    try decoded.decodePayload(buf[0..len]);
    try std.testing.expectEqual(@as(u32, 256), decoded.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 131072), decoded.initial_window_size);
    // Others stay at default
    try std.testing.expectEqual(@as(u32, 4096), decoded.header_table_size);
}

test "Settings default encodes zero bytes" {
    const settings = Settings{};
    var buf: [36]u8 = undefined;
    const len = settings.encodeDiff(&buf);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "Settings invalid initial_window_size" {
    var settings = Settings{};
    try std.testing.expectError(error.FlowControlError, settings.applyParam(.initial_window_size, 0x80000000));
}

test "Settings invalid max_frame_size" {
    var settings = Settings{};
    try std.testing.expectError(error.ProtocolError, settings.applyParam(.max_frame_size, 100));
    try std.testing.expectError(error.ProtocolError, settings.applyParam(.max_frame_size, 16777216));
}

test "buildSettings writes directly without intermediate copy" {
    const settings = Settings{ .max_frame_size = 32768 };
    var buf: [45]u8 = undefined;
    const result = buildSettings(settings, &buf);
    // 9 header + 6 payload (1 param)
    try std.testing.expectEqual(@as(usize, 15), result.len);

    const header = FrameHeader.decode(result[0..9]);
    try std.testing.expectEqual(FrameType.settings, header.frame_type);
    try std.testing.expectEqual(@as(u24, 6), header.length);
}

test "buildWindowUpdate" {
    var buf: [13]u8 = undefined;
    _ = try buildWindowUpdate(1, 65535, &buf);

    const header = FrameHeader.decode(buf[0..9]);
    try std.testing.expectEqual(FrameType.window_update, header.frame_type);
    try std.testing.expectEqual(@as(u24, 4), header.length);
    try std.testing.expectEqual(@as(u31, 1), header.stream_id);

    const increment = std.mem.readInt(u32, buf[9..13], .big);
    try std.testing.expectEqual(@as(u32, 65535), increment);
}

test "buildWindowUpdate rejects zero increment" {
    var buf: [13]u8 = undefined;
    try std.testing.expectError(error.ProtocolError, buildWindowUpdate(1, 0, &buf));
}

test "buildPing roundtrip" {
    const data = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var buf: [17]u8 = undefined;
    _ = buildPing(data, &buf);

    const header = FrameHeader.decode(buf[0..9]);
    try std.testing.expectEqual(FrameType.ping, header.frame_type);
    try std.testing.expectEqual(@as(u24, 8), header.length);
    try std.testing.expect(!header.flags.hasAck());
    try std.testing.expectEqualSlices(u8, &data, buf[9..17]);
}

test "buildGoaway with debug data" {
    var buf: [64]u8 = undefined;
    const debug = "test error";
    const result = try buildGoaway(3, .protocol_error, debug, &buf);

    const header = FrameHeader.decode(result[0..9]);
    try std.testing.expectEqual(FrameType.goaway, header.frame_type);
    try std.testing.expectEqual(@as(u24, 18), header.length);

    const last_id = std.mem.readInt(u32, result[9..13], .big);
    try std.testing.expectEqual(@as(u32, 3), last_id);
    try std.testing.expectEqualStrings(debug, result[17..]);
}

test "buildGoaway buffer too small" {
    var buf: [10]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, buildGoaway(0, .no_error, "", &buf));
}

test "client preface is correct" {
    try std.testing.expectEqual(@as(usize, 24), client_preface.len);
    try std.testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", client_preface);
}
