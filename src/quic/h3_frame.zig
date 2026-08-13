const std = @import("std");
const packet_mod = @import("packet.zig");

/// HTTP/3 frame types (RFC 9114 §7.2).
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0D,
    _,
};

/// HTTP/3 unidirectional stream types (RFC 9114 §6.2).
pub const UniStreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,
};

/// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4.1).
pub const SettingsId = enum(u62) {
    max_field_section_size = 0x06,
    qpack_max_table_capacity = 0x01,
    qpack_blocked_streams = 0x07,
    _,
};

/// A single HTTP/3 setting (id + value pair).
pub const Setting = struct {
    id: u62,
    value: u64,
};

/// HTTP/3 frame header: type(varint) + length(varint).
pub const H3Frame = struct {
    frame_type: u64,
    length: u64,
    payload: []const u8,
};

/// Encode an HTTP/3 frame header (type + length). Returns bytes written.
pub fn encodeFrameHeader(buf: []u8, frame_type: u64, payload_len: u64) ?usize {
    var pos: usize = 0;
    pos += packet_mod.encodeVarint(buf[pos..], @intCast(frame_type)) orelse return null;
    pos += packet_mod.encodeVarint(buf[pos..], @intCast(payload_len)) orelse return null;
    return pos;
}

/// Decode an HTTP/3 frame header. Returns the frame type, payload length, and bytes consumed.
pub fn decodeFrameHeader(data: []const u8) ?DecodedFrameHeader {
    var pos: usize = 0;
    const type_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
    pos += type_result.consumed;
    const len_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
    pos += len_result.consumed;
    return .{
        .frame_type = type_result.value,
        .length = len_result.value,
        .header_len = pos,
    };
}

pub const DecodedFrameHeader = struct {
    frame_type: u64,
    length: u64,
    header_len: usize,
};

/// Encode a DATA frame (type=0x00).
pub fn encodeDataFrame(buf: []u8, payload: []const u8) ?usize {
    var pos: usize = 0;
    pos += encodeFrameHeader(buf, 0x00, payload.len) orelse return null;
    if (buf.len < pos + payload.len) return null;
    @memcpy(buf[pos..][0..payload.len], payload);
    pos += payload.len;
    return pos;
}

/// Encode a HEADERS frame (type=0x01).
/// `encoded_headers` is the QPACK-encoded header block.
pub fn encodeHeadersFrame(buf: []u8, encoded_headers: []const u8) ?usize {
    var pos: usize = 0;
    pos += encodeFrameHeader(buf, 0x01, encoded_headers.len) orelse return null;
    if (buf.len < pos + encoded_headers.len) return null;
    @memcpy(buf[pos..][0..encoded_headers.len], encoded_headers);
    pos += encoded_headers.len;
    return pos;
}

/// Encode a SETTINGS frame (type=0x04).
pub fn encodeSettingsFrame(buf: []u8, settings: []const Setting) ?usize {
    // First encode settings payload
    var payload_buf: [256]u8 = undefined;
    var ppos: usize = 0;
    for (settings) |s| {
        ppos += packet_mod.encodeVarint(payload_buf[ppos..], s.id) orelse return null;
        ppos += packet_mod.encodeVarint(payload_buf[ppos..], @intCast(s.value)) orelse return null;
    }

    // Frame header + payload
    var pos: usize = 0;
    pos += encodeFrameHeader(buf, 0x04, ppos) orelse return null;
    if (buf.len < pos + ppos) return null;
    @memcpy(buf[pos..][0..ppos], payload_buf[0..ppos]);
    pos += ppos;
    return pos;
}

/// Decode a SETTINGS frame payload into settings array.
pub fn decodeSettingsPayload(data: []const u8, settings: []Setting) ?usize {
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < data.len and count < settings.len) {
        const id_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += id_result.consumed;
        const val_result = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += val_result.consumed;
        settings[count] = .{
            .id = @intCast(id_result.value),
            .value = val_result.value,
        };
        count += 1;
    }
    return count;
}

/// Encode a GOAWAY frame (type=0x07).
pub fn encodeGoawayFrame(buf: []u8, stream_id: u62) ?usize {
    var id_buf: [8]u8 = undefined;
    const id_len = packet_mod.encodeVarint(&id_buf, stream_id) orelse return null;

    var pos: usize = 0;
    pos += encodeFrameHeader(buf, 0x07, id_len) orelse return null;
    if (buf.len < pos + id_len) return null;
    @memcpy(buf[pos..][0..id_len], id_buf[0..id_len]);
    pos += id_len;
    return pos;
}

/// Encode the unidirectional stream type byte (RFC 9114 §6.2).
pub fn encodeUniStreamType(buf: []u8, stream_type: UniStreamType) ?usize {
    return packet_mod.encodeVarint(buf, @intFromEnum(stream_type));
}

// ─── Tests ───

test "encodeFrameHeader/decodeFrameHeader roundtrip" {
    var buf: [16]u8 = undefined;
    const written = encodeFrameHeader(&buf, 0x04, 42) orelse unreachable;
    const decoded = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x04), decoded.frame_type);
    try std.testing.expectEqual(@as(u64, 42), decoded.length);
    try std.testing.expectEqual(written, decoded.header_len);
}

test "encodeDataFrame" {
    const payload = "Hello HTTP/3";
    var buf: [64]u8 = undefined;
    const written = encodeDataFrame(&buf, payload) orelse unreachable;

    const hdr = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x00), hdr.frame_type);
    try std.testing.expectEqual(@as(u64, payload.len), hdr.length);
    try std.testing.expectEqualStrings(payload, buf[hdr.header_len..][0..payload.len]);
}

test "encodeHeadersFrame" {
    const headers = [_]u8{ 0x00, 0x00, 0xD1, 0xD7 }; // fake QPACK data
    var buf: [64]u8 = undefined;
    const written = encodeHeadersFrame(&buf, &headers) orelse unreachable;

    const hdr = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 4), hdr.length);
}

test "encodeSettingsFrame/decodeSettingsPayload" {
    const settings = [_]Setting{
        .{ .id = @intFromEnum(SettingsId.max_field_section_size), .value = 8192 },
        .{ .id = @intFromEnum(SettingsId.qpack_max_table_capacity), .value = 4096 },
    };

    var buf: [64]u8 = undefined;
    const written = encodeSettingsFrame(&buf, &settings) orelse unreachable;

    const hdr = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x04), hdr.frame_type);

    var decoded_settings: [8]Setting = undefined;
    const count = decodeSettingsPayload(buf[hdr.header_len..][0..@intCast(hdr.length)], &decoded_settings) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u62, 0x06), decoded_settings[0].id);
    try std.testing.expectEqual(@as(u64, 8192), decoded_settings[0].value);
    try std.testing.expectEqual(@as(u62, 0x01), decoded_settings[1].id);
    try std.testing.expectEqual(@as(u64, 4096), decoded_settings[1].value);
}

test "encodeGoawayFrame" {
    var buf: [16]u8 = undefined;
    const written = encodeGoawayFrame(&buf, 4) orelse unreachable;

    const hdr = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x07), hdr.frame_type);

    const id = packet_mod.decodeVarint(buf[hdr.header_len..]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 4), id.value);
}

test "encodeUniStreamType: control stream" {
    var buf: [8]u8 = undefined;
    const written = encodeUniStreamType(&buf, .control) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
}

test "encodeUniStreamType: qpack encoder" {
    var buf: [8]u8 = undefined;
    const written = encodeUniStreamType(&buf, .qpack_encoder) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0x02), buf[0]);
}

test "decodeFrameHeader: various frame types" {
    var buf: [16]u8 = undefined;

    // DATA frame
    _ = encodeFrameHeader(&buf, 0x00, 100) orelse unreachable;
    const data_hdr = decodeFrameHeader(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x00), data_hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 100), data_hdr.length);

    // Large payload length (needs 2-byte varint)
    const written = encodeFrameHeader(&buf, 0x01, 8000) orelse unreachable;
    const hdr = decodeFrameHeader(buf[0..written]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 8000), hdr.length);
}
