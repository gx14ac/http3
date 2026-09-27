// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// QPACK static table (RFC 9204 §Appendix A).
/// Subset of the most commonly used entries for HTTP/3 requests.
pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":path", .value = "/" }, // 22
    .{ .name = ":scheme", .value = "http" }, // 23
    .{ .name = ":scheme", .value = "https" }, // 24
    .{ .name = ":status", .value = "103" }, // 25
    .{ .name = ":status", .value = "200" }, // 26
    .{ .name = ":status", .value = "304" }, // 27
    .{ .name = ":status", .value = "404" }, // 28
    .{ .name = ":status", .value = "503" }, // 29
    .{ .name = "accept", .value = "*/*" }, // 30
    .{ .name = "accept", .value = "application/dns-message" }, // 31
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 32
    .{ .name = "accept-ranges", .value = "bytes" }, // 33
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 34
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 35
    .{ .name = "access-control-allow-origin", .value = "*" }, // 36
    .{ .name = "cache-control", .value = "max-age=0" }, // 37
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 38
    .{ .name = "cache-control", .value = "max-age=604800" }, // 39
    .{ .name = "cache-control", .value = "no-cache" }, // 40
    .{ .name = "cache-control", .value = "no-store" }, // 41
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 42
    .{ .name = "content-encoding", .value = "br" }, // 43
    .{ .name = "content-encoding", .value = "gzip" }, // 44
    .{ .name = "content-type", .value = "application/dns-message" }, // 45
    .{ .name = "content-type", .value = "application/javascript" }, // 46
    .{ .name = "content-type", .value = "application/json" }, // 47
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 48
    .{ .name = "content-type", .value = "image/gif" }, // 49
    .{ .name = "content-type", .value = "image/jpeg" }, // 50
    .{ .name = "content-type", .value = "image/png" }, // 51
    .{ .name = "content-type", .value = "text/css" }, // 52
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 53
    .{ .name = "content-type", .value = "text/plain" }, // 54
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 55
    .{ .name = "range", .value = "bytes=0-" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 58
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 59
    .{ .name = "vary", .value = "accept-encoding" }, // 60
    .{ .name = "vary", .value = "origin" }, // 61
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 62
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 63
    .{ .name = ":status", .value = "100" }, // 64
    .{ .name = ":status", .value = "204" }, // 65
    .{ .name = ":status", .value = "206" }, // 66
    .{ .name = ":status", .value = "302" }, // 67
    .{ .name = ":status", .value = "400" }, // 68
    .{ .name = ":status", .value = "403" }, // 69
    .{ .name = ":status", .value = "421" }, // 70
    .{ .name = ":status", .value = "425" }, // 71
    .{ .name = ":status", .value = "500" }, // 72
    .{ .name = "accept-language", .value = "" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 74
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 75
    .{ .name = "access-control-allow-headers", .value = "*" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get" }, // 77
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 78
    .{ .name = "access-control-allow-methods", .value = "options" }, // 79
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 80
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 81
    .{ .name = "access-control-request-method", .value = "get" }, // 82
    .{ .name = "access-control-request-method", .value = "post" }, // 83
    .{ .name = "alt-svc", .value = "clear" }, // 84
    .{ .name = "authorization", .value = "" }, // 85
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 86
    .{ .name = "early-data", .value = "1" }, // 87
    .{ .name = "expect-ct", .value = "" }, // 88
    .{ .name = "forwarded", .value = "" }, // 89
    .{ .name = "if-range", .value = "" }, // 90
    .{ .name = "origin", .value = "" }, // 91
    .{ .name = "purpose", .value = "prefetch" }, // 92
    .{ .name = "server", .value = "" }, // 93
    .{ .name = "timing-allow-origin", .value = "*" }, // 94
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 95
    .{ .name = "user-agent", .value = "" }, // 96
    .{ .name = "x-forwarded-for", .value = "" }, // 97
    .{ .name = "x-frame-options", .value = "deny" }, // 98
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 99
};

/// A header field (name-value pair).
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK encoder (RFC 9204) — static-only mode (no dynamic table).
/// Produces an encoded field section that can be placed into HEADERS frames.
pub const Encoder = struct {
    /// Encode a list of headers into QPACK representation.
    /// Returns bytes written to buf.
    /// Uses Section 4.5.2 (Indexed Field Line) for exact static table match,
    /// Section 4.5.4 (Literal with Name Reference) for name-only match,
    /// Section 4.5.6 (Literal with Literal Name) otherwise.
    pub fn encode(buf: []u8, headers: []const HeaderField) ?usize {
        var pos: usize = 0;

        // Required Insert Count = 0 (static only, §4.5.1)
        if (buf.len < 2) return null;
        buf[pos] = 0x00; // Required Insert Count = 0
        pos += 1;
        buf[pos] = 0x00; // S=0, Delta Base = 0
        pos += 1;

        for (headers) |hdr| {
            const match = findStaticMatch(hdr.name, hdr.value);

            if (match.exact_index) |idx| {
                // Indexed Field Line (§4.5.2): 1TNNNNNNN, T=1 (static)
                pos += encodePrefixedInt(buf[pos..], idx, 6, 0xC0) orelse return null;
            } else if (match.name_index) |idx| {
                // Literal with Name Reference (§4.5.4): 0101NNNNN (static, no Huffman)
                pos += encodePrefixedInt(buf[pos..], idx, 4, 0x50) orelse return null;
                // Value (no Huffman): 0 + length + value
                pos += encodeLiteralString(buf[pos..], hdr.value) orelse return null;
            } else {
                // Literal with Literal Name (RFC 9204 §4.5.6):
                // 001 N=0 H=0 NNN — 3-bit prefix for name length
                pos += encodePrefixedInt(buf[pos..], hdr.name.len, 3, 0x20) orelse return null;
                if (buf.len < pos + hdr.name.len) return null;
                @memcpy(buf[pos..][0..hdr.name.len], hdr.name);
                pos += hdr.name.len;
                // Value
                pos += encodeLiteralString(buf[pos..], hdr.value) orelse return null;
            }
        }

        return pos;
    }
};

/// QPACK decoder — static-only mode.
pub const Decoder = struct {
    /// Decode a QPACK-encoded header block into HeaderField array.
    /// Returns number of headers decoded.
    pub fn decode(data: []const u8, headers: []HeaderField) ?usize {
        if (data.len < 2) return null;

        // Required Insert Count and Delta Base (both should be 0 for static-only)
        var pos: usize = 0;
        const ric = decodePrefixedInt(data[pos..], 8) orelse return null;
        pos += ric.consumed;
        const db = decodePrefixedInt(data[pos..], 7) orelse return null;
        pos += db.consumed;

        var count: usize = 0;
        while (pos < data.len and count < headers.len) {
            const byte = data[pos];

            if (byte & 0xC0 == 0xC0) {
                // Indexed Field Line (static): 11NNNNNN
                const idx_result = decodePrefixedInt(data[pos..], 6) orelse return null;
                pos += idx_result.consumed;
                if (idx_result.value >= static_table.len) return null;
                const entry = static_table[idx_result.value];
                headers[count] = .{ .name = entry.name, .value = entry.value };
                count += 1;
            } else if (byte & 0xF0 == 0x50) {
                // Literal with Name Reference (static): 0101NNNN
                const idx_result = decodePrefixedInt(data[pos..], 4) orelse return null;
                pos += idx_result.consumed;
                if (idx_result.value >= static_table.len) return null;
                const entry = static_table[idx_result.value];
                const val = decodeLiteralString(data[pos..]) orelse return null;
                pos += val.consumed;
                headers[count] = .{ .name = entry.name, .value = val.value };
                count += 1;
            } else if (byte & 0xE0 == 0x20) {
                // Literal with Literal Name (RFC 9204 §4.5.6):
                // 001 N H NNN — 3-bit prefix for name length
                const name_len_result = decodePrefixedInt(data[pos..], 3) orelse return null;
                pos += name_len_result.consumed;
                if (pos + name_len_result.value > data.len) return null;
                const name = data[pos..][0..name_len_result.value];
                pos += name_len_result.value;
                const val = decodeLiteralString(data[pos..]) orelse return null;
                pos += val.consumed;
                headers[count] = .{ .name = name, .value = val.value };
                count += 1;
            } else {
                return null; // unknown instruction
            }
        }

        return count;
    }
};

// ─── QPACK integer encoding (RFC 9204 §4.1.1) ───

pub fn encodePrefixedInt(buf: []u8, value: usize, prefix_bits: u4, pattern: u8) ?usize {
    const max_prefix = (@as(usize, 1) << prefix_bits) - 1;
    var pos: usize = 0;

    if (buf.len == 0) return null;

    if (value < max_prefix) {
        buf[pos] = pattern | @as(u8, @intCast(value));
        pos += 1;
    } else {
        buf[pos] = pattern | @as(u8, @intCast(max_prefix));
        pos += 1;
        var remaining = value - max_prefix;
        while (remaining >= 128) {
            if (pos >= buf.len) return null;
            buf[pos] = @intCast((remaining & 0x7F) | 0x80);
            pos += 1;
            remaining >>= 7;
        }
        if (pos >= buf.len) return null;
        buf[pos] = @intCast(remaining);
        pos += 1;
    }

    return pos;
}

pub const PrefixedIntResult = struct {
    value: usize,
    consumed: usize,
};

pub fn decodePrefixedInt(data: []const u8, prefix_bits: u4) ?PrefixedIntResult {
    if (data.len == 0) return null;

    const max_prefix = (@as(usize, 1) << prefix_bits) - 1;
    const mask: u8 = @intCast(max_prefix);
    var value: usize = data[0] & mask;
    var pos: usize = 1;

    if (value < max_prefix) {
        return .{ .value = value, .consumed = pos };
    }

    var shift: u6 = 0;
    while (pos < data.len) {
        const b = data[pos];
        value += @as(usize, b & 0x7F) << shift;
        pos += 1;
        if (b & 0x80 == 0) {
            return .{ .value = value, .consumed = pos };
        }
        shift += 7;
    }
    return null;
}

pub fn encodeLiteralString(buf: []u8, s: []const u8) ?usize {
    var pos: usize = 0;
    // No Huffman encoding (H=0), length as prefixed int with 7-bit prefix
    pos += encodePrefixedInt(buf[pos..], s.len, 7, 0x00) orelse return null;
    if (buf.len < pos + s.len) return null;
    @memcpy(buf[pos..][0..s.len], s);
    pos += s.len;
    return pos;
}

pub const LiteralStringResult = struct {
    value: []const u8,
    consumed: usize,
};

pub fn decodeLiteralString(data: []const u8) ?LiteralStringResult {
    if (data.len == 0) return null;
    // H bit is bit 7; we only support H=0 (no Huffman)
    const huffman = (data[0] & 0x80) != 0;
    if (huffman) return null; // Huffman not implemented

    const len_result = decodePrefixedInt(data, 7) orelse return null;
    const str_len = len_result.value;
    const total = len_result.consumed + str_len;
    if (data.len < total) return null;
    return .{
        .value = data[len_result.consumed..][0..str_len],
        .consumed = total,
    };
}

// ─── Static table lookup ───

pub const StaticMatch = struct {
    exact_index: ?usize,
    name_index: ?usize,
};

pub fn findStaticMatch(name: []const u8, value: []const u8) StaticMatch {
    var result = StaticMatch{ .exact_index = null, .name_index = null };
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            if (result.name_index == null) {
                result.name_index = i;
            }
            if (std.mem.eql(u8, entry.value, value)) {
                result.exact_index = i;
                return result;
            }
        }
    }
    return result;
}

// ─── Tests ───

test "Encoder/Decoder roundtrip: static table exact match" {
    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };

    var buf: [256]u8 = undefined;
    const encoded_len = Encoder.encode(&buf, &headers) orelse unreachable;

    var decoded: [8]HeaderField = undefined;
    const count = Decoder.decode(buf[0..encoded_len], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings(":scheme", decoded[1].name);
    try std.testing.expectEqualStrings("https", decoded[1].value);
    try std.testing.expectEqualStrings(":path", decoded[2].name);
    try std.testing.expectEqualStrings("/", decoded[2].value);
}

test "Encoder/Decoder roundtrip: name reference with literal value" {
    const headers = [_]HeaderField{
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/api/v1/users" },
    };

    var buf: [256]u8 = undefined;
    const encoded_len = Encoder.encode(&buf, &headers) orelse unreachable;

    var decoded: [8]HeaderField = undefined;
    const count = Decoder.decode(buf[0..encoded_len], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings(":authority", decoded[0].name);
    try std.testing.expectEqualStrings("example.com", decoded[0].value);
    try std.testing.expectEqualStrings(":path", decoded[1].name);
    try std.testing.expectEqualStrings("/api/v1/users", decoded[1].value);
}

test "Encoder/Decoder roundtrip: fully literal" {
    const headers = [_]HeaderField{
        .{ .name = "x-custom-header", .value = "custom-value" },
    };

    var buf: [256]u8 = undefined;
    const encoded_len = Encoder.encode(&buf, &headers) orelse unreachable;

    var decoded: [8]HeaderField = undefined;
    const count = Decoder.decode(buf[0..encoded_len], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("x-custom-header", decoded[0].name);
    try std.testing.expectEqualStrings("custom-value", decoded[0].value);
}

test "Encoder/Decoder roundtrip: mixed" {
    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" }, // exact match
        .{ .name = ":scheme", .value = "https" }, // exact match
        .{ .name = ":authority", .value = "api.example.com" }, // name ref
        .{ .name = ":path", .value = "/grpc.health.v1.Health/Watch" }, // name ref
        .{ .name = "content-type", .value = "application/grpc" }, // name ref (no exact)
        .{ .name = "te", .value = "trailers" }, // fully literal
    };

    var buf: [512]u8 = undefined;
    const encoded_len = Encoder.encode(&buf, &headers) orelse unreachable;

    var decoded: [8]HeaderField = undefined;
    const count = Decoder.decode(buf[0..encoded_len], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 6), count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("POST", decoded[0].value);
    try std.testing.expectEqualStrings("content-type", decoded[4].name);
    try std.testing.expectEqualStrings("application/grpc", decoded[4].value);
    try std.testing.expectEqualStrings("te", decoded[5].name);
    try std.testing.expectEqualStrings("trailers", decoded[5].value);
}

test "encodePrefixedInt/decodePrefixedInt: small value" {
    var buf: [8]u8 = undefined;
    const written = encodePrefixedInt(&buf, 10, 6, 0xC0) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), written);
    try std.testing.expectEqual(@as(u8, 0xCA), buf[0]); // 0xC0 | 10

    const result = decodePrefixedInt(&buf, 6) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 10), result.value);
}

test "encodePrefixedInt/decodePrefixedInt: multi-byte" {
    var buf: [8]u8 = undefined;
    const written = encodePrefixedInt(&buf, 200, 6, 0xC0) orelse unreachable;
    try std.testing.expect(written > 1);

    const result = decodePrefixedInt(&buf, 6) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 200), result.value);
    try std.testing.expectEqual(written, result.consumed);
}

test "findStaticMatch: exact match" {
    const m = findStaticMatch(":method", "GET");
    try std.testing.expectEqual(@as(?usize, 17), m.exact_index);
}

test "findStaticMatch: name only" {
    const m = findStaticMatch(":authority", "example.com");
    try std.testing.expectEqual(@as(?usize, null), m.exact_index);
    try std.testing.expectEqual(@as(?usize, 0), m.name_index);
}

test "findStaticMatch: no match" {
    const m = findStaticMatch("x-nonexistent", "foo");
    try std.testing.expectEqual(@as(?usize, null), m.exact_index);
    try std.testing.expectEqual(@as(?usize, null), m.name_index);
}
