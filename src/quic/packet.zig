// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// QUIC version 1 (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// Long header packet types (RFC 9000 §17.2).
pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// QUIC long header (RFC 9000 §17.2).
/// First byte: 1 (form) | 1 (fixed) | 2 (type) | 4 (reserved/pn_len)
pub const LongHeader = struct {
    packet_type: PacketType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,

    /// Encode the long header fixed portion (before type-specific fields).
    /// Returns number of bytes written.
    pub fn encode(self: LongHeader, buf: []u8) ?usize {
        // Minimum: 1 (first byte) + 4 (version) + 1 (dcid_len) + dcid + 1 (scid_len) + scid
        const needed = 7 + self.dcid.len + self.scid.len;
        if (buf.len < needed) return null;

        // First byte: form=1, fixed=1, type(2 bits), reserved+pn_len will be set later
        buf[0] = 0xC0 | (@as(u8, @intFromEnum(self.packet_type)) << 4);
        std.mem.writeInt(u32, buf[1..5], self.version, .big);
        buf[5] = @intCast(self.dcid.len);
        @memcpy(buf[6..][0..self.dcid.len], self.dcid);
        const scid_offset = 6 + self.dcid.len;
        buf[scid_offset] = @intCast(self.scid.len);
        @memcpy(buf[scid_offset + 1 ..][0..self.scid.len], self.scid);

        return needed;
    }

    /// Decode a long header from wire bytes.
    pub fn decode(data: []const u8) ?DecodedLongHeader {
        if (data.len < 7) return null;
        const first = data[0];
        if (first & 0x80 == 0) return null; // not a long header

        const ptype: u2 = @intCast((first >> 4) & 0x03);
        const version = std.mem.readInt(u32, data[1..5], .big);
        const dcid_len: usize = data[5];
        if (data.len < 6 + dcid_len + 1) return null;
        const dcid = data[6..][0..dcid_len];
        const scid_len: usize = data[6 + dcid_len];
        if (data.len < 7 + dcid_len + scid_len) return null;
        const scid = data[7 + dcid_len ..][0..scid_len];

        return .{
            .header = .{
                .packet_type = @enumFromInt(ptype),
                .version = version,
                .dcid = dcid,
                .scid = scid,
            },
            .payload_offset = 7 + dcid_len + scid_len,
        };
    }
};

pub const DecodedLongHeader = struct {
    header: LongHeader,
    payload_offset: usize,
};

/// Version Negotiation packet (RFC 9000 §17.2.1).
/// Sent by server when it doesn't support the client's proposed version.
pub const VersionNegotiation = struct {
    dcid: []const u8,
    scid: []const u8,
    versions: [max_versions]u32,
    version_count: usize,

    const max_versions = 16;

    pub fn decode(data: []const u8) ?VersionNegotiation {
        if (data.len < 7) return null;
        if (data[0] & 0x80 == 0) return null;

        const version = std.mem.readInt(u32, data[1..5], .big);
        if (version != 0) return null; // Version Negotiation has version=0

        const dcid_len: usize = data[5];
        if (data.len < 6 + dcid_len + 1) return null;
        const dcid = data[6..][0..dcid_len];
        const scid_len: usize = data[6 + dcid_len];
        const header_end = 7 + dcid_len + scid_len;
        if (data.len < header_end) return null;
        const scid = data[7 + dcid_len ..][0..scid_len];

        const versions_data = data[header_end..];
        if (versions_data.len % 4 != 0) return null;

        var result: VersionNegotiation = .{
            .dcid = dcid,
            .scid = scid,
            .versions = undefined,
            .version_count = 0,
        };

        var i: usize = 0;
        while (i + 4 <= versions_data.len and result.version_count < max_versions) {
            result.versions[result.version_count] = std.mem.readInt(u32, versions_data[i..][0..4], .big);
            result.version_count += 1;
            i += 4;
        }

        return result;
    }

    pub fn supportedVersions(self: *const VersionNegotiation) []const u32 {
        return self.versions[0..self.version_count];
    }
};

/// QUIC Initial packet type-specific fields (RFC 9000 §17.2.2).
/// After the common long header: token_length(varint) + token + length(varint) + packet_number + payload.
pub const InitialPacket = struct {
    header: LongHeader,
    token: []const u8,
    packet_number: u32,
    pn_length: u2, // 0-based: actual length = pn_length + 1
    payload: []const u8,
    /// AEAD tag size (16 for AES-128-GCM). Included in the Length field on wire.
    aead_overhead: usize = 16,

    /// Encode a full Initial packet (unprotected). Caller must apply header protection after.
    pub fn encode(self: InitialPacket, buf: []u8) ?usize {
        var pos: usize = 0;

        // Long header
        const hdr_len = self.header.encode(buf) orelse return null;
        // Set pn_length in first byte (lower 2 bits of reserved+pn_len field)
        buf[0] = (buf[0] & 0xFC) | self.pn_length;
        pos = hdr_len;

        // Token length (varint)
        pos += encodeVarint(buf[pos..], self.token.len) orelse return null;
        // Token
        if (buf.len < pos + self.token.len) return null;
        @memcpy(buf[pos..][0..self.token.len], self.token);
        pos += self.token.len;

        // Length: pn_length+1 + payload.len + aead_overhead (varint)
        // RFC 9000 §17.2: Length includes PN field + encrypted payload + AEAD tag
        const pn_len: usize = @as(usize, self.pn_length) + 1;
        const length_value = pn_len + self.payload.len + self.aead_overhead;
        pos += encodeVarint(buf[pos..], length_value) orelse return null;

        // Packet number
        if (buf.len < pos + pn_len) return null;
        switch (self.pn_length) {
            0 => buf[pos] = @intCast(self.packet_number & 0xFF),
            1 => std.mem.writeInt(u16, buf[pos..][0..2], @intCast(self.packet_number & 0xFFFF), .big),
            2 => {
                buf[pos] = @intCast((self.packet_number >> 16) & 0xFF);
                std.mem.writeInt(u16, buf[pos + 1 ..][0..2], @intCast(self.packet_number & 0xFFFF), .big);
            },
            3 => std.mem.writeInt(u32, buf[pos..][0..4], self.packet_number, .big),
        }
        pos += pn_len;

        // Payload
        if (buf.len < pos + self.payload.len) return null;
        @memcpy(buf[pos..][0..self.payload.len], self.payload);
        pos += self.payload.len;

        return pos;
    }
};

// ─── Variable-length integer encoding (RFC 9000 §16) ───

/// Encode a QUIC variable-length integer. Returns bytes written, or null if buffer too small.
/// Return the number of bytes needed to encode a value as a QUIC varint.
pub fn varintSize(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

pub fn encodeVarint(buf: []u8, value: usize) ?usize {
    if (value <= 63) {
        if (buf.len < 1) return null;
        buf[0] = @intCast(value);
        return 1;
    } else if (value <= 16383) {
        if (buf.len < 2) return null;
        std.mem.writeInt(u16, buf[0..2], @as(u16, @intCast(value)) | 0x4000, .big);
        return 2;
    } else if (value <= 1073741823) {
        if (buf.len < 4) return null;
        std.mem.writeInt(u32, buf[0..4], @as(u32, @intCast(value)) | 0x80000000, .big);
        return 4;
    } else if (value <= 4611686018427387903) {
        if (buf.len < 8) return null;
        std.mem.writeInt(u64, buf[0..8], @as(u64, @intCast(value)) | 0xC000000000000000, .big);
        return 8;
    }
    return null;
}

/// Decode a QUIC variable-length integer. Returns value and bytes consumed.
pub fn decodeVarint(data: []const u8) ?VarintResult {
    if (data.len == 0) return null;
    const prefix: u2 = @intCast(data[0] >> 6);
    const len: usize = @as(usize, 1) << prefix;
    if (data.len < len) return null;

    switch (prefix) {
        0 => return .{ .value = data[0] & 0x3F, .consumed = 1 },
        1 => {
            const raw = std.mem.readInt(u16, data[0..2], .big);
            return .{ .value = raw & 0x3FFF, .consumed = 2 };
        },
        2 => {
            const raw = std.mem.readInt(u32, data[0..4], .big);
            return .{ .value = raw & 0x3FFFFFFF, .consumed = 4 };
        },
        3 => {
            const raw = std.mem.readInt(u64, data[0..8], .big);
            return .{ .value = raw & 0x3FFFFFFFFFFFFFFF, .consumed = 8 };
        },
    }
}

pub const VarintResult = struct {
    value: u64,
    consumed: usize,
};

// ─── Tests ───

test "varint encode/decode roundtrip" {
    var buf: [8]u8 = undefined;
    const cases = [_]usize{ 0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824 };
    for (cases) |v| {
        const written = encodeVarint(&buf, v) orelse unreachable;
        const decoded = decodeVarint(buf[0..written]) orelse unreachable;
        try std.testing.expectEqual(v, @as(usize, @intCast(decoded.value)));
        try std.testing.expectEqual(written, decoded.consumed);
    }
}

test "varint encoding lengths" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), encodeVarint(&buf, 0).?);
    try std.testing.expectEqual(@as(usize, 1), encodeVarint(&buf, 63).?);
    try std.testing.expectEqual(@as(usize, 2), encodeVarint(&buf, 64).?);
    try std.testing.expectEqual(@as(usize, 2), encodeVarint(&buf, 16383).?);
    try std.testing.expectEqual(@as(usize, 4), encodeVarint(&buf, 16384).?);
    try std.testing.expectEqual(@as(usize, 4), encodeVarint(&buf, 1073741823).?);
    try std.testing.expectEqual(@as(usize, 8), encodeVarint(&buf, 1073741824).?);
}

test "LongHeader encode/decode roundtrip" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4 };

    var buf: [64]u8 = undefined;
    const hdr = LongHeader{
        .packet_type = .initial,
        .version = QUIC_VERSION_1,
        .dcid = &dcid,
        .scid = &scid,
    };

    const written = hdr.encode(&buf) orelse unreachable;
    const decoded = LongHeader.decode(buf[0..written]) orelse unreachable;

    try std.testing.expectEqual(PacketType.initial, decoded.header.packet_type);
    try std.testing.expectEqual(QUIC_VERSION_1, decoded.header.version);
    try std.testing.expectEqualSlices(u8, &dcid, decoded.header.dcid);
    try std.testing.expectEqualSlices(u8, &scid, decoded.header.scid);
    try std.testing.expectEqual(written, decoded.payload_offset);
}

test "InitialPacket encode" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4 };
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    var buf: [128]u8 = undefined;
    const pkt = InitialPacket{
        .header = .{
            .packet_type = .initial,
            .version = QUIC_VERSION_1,
            .dcid = &dcid,
            .scid = &scid,
        },
        .token = &.{},
        .packet_number = 0,
        .pn_length = 0,
        .payload = &payload,
    };

    const written = pkt.encode(&buf) orelse unreachable;
    // 7 (header) + 8 (dcid) + 4 (scid) = 19
    // + 1 (token_len=0) + 0 (token) + 1 (length varint: 1+4=5) + 1 (pn) + 4 (payload)
    try std.testing.expectEqual(@as(usize, 26), written);

    // First byte: 1100_0000 | pn_length=0 = 0xC0
    try std.testing.expectEqual(@as(u8, 0xC0), buf[0]);

    // Verify version
    try std.testing.expectEqual(QUIC_VERSION_1, std.mem.readInt(u32, buf[1..5], .big));
}

test "LongHeader decode: short header rejected" {
    const data = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try std.testing.expect(LongHeader.decode(&data) == null);
}

test "decodeVarint: empty input" {
    try std.testing.expect(decodeVarint(&.{}) == null);
}
