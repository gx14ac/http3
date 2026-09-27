// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const packet = @import("packet.zig");
const quic_crypto = @import("crypto.zig");

pub const DecodeError = error{
    NotLongHeader,
    NotInitial,
    TruncatedPacket,
    HeaderProtectionFailed,
    DecryptionFailed,
    InvalidFrame,
};

/// Result of decoding a server Initial packet.
pub const DecodedInitial = struct {
    scid: []const u8,
    dcid: []const u8,
    packet_number: u64,
    crypto_data: []const u8,
    crypto_offset: u64,
};

/// Decode and decrypt a server Initial packet.
/// `data` is the raw UDP datagram (may contain coalesced packets — only first is processed).
/// `original_dcid` is the DCID used in the client's first Initial (for key derivation).
pub fn decodeServerInitial(data: []u8, original_dcid: []const u8, out_buf: []u8) DecodeError!DecodedInitial {
    if (data.len < 7) return DecodeError.TruncatedPacket;
    if (data[0] & 0x80 == 0) return DecodeError.NotLongHeader;

    const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
    if (ptype != @intFromEnum(packet.PacketType.initial)) return DecodeError.NotInitial;

    // Parse long header fields
    const version = std.mem.readInt(u32, data[1..5], .big);
    _ = version;
    const dcid_len: usize = data[5];
    if (data.len < 6 + dcid_len + 1) return DecodeError.TruncatedPacket;
    const dcid = data[6..][0..dcid_len];
    const scid_len: usize = data[6 + dcid_len];
    if (data.len < 7 + dcid_len + scid_len) return DecodeError.TruncatedPacket;
    const scid = data[7 + dcid_len ..][0..scid_len];

    var pos: usize = 7 + dcid_len + scid_len;

    // Token length (varint) — server Initial usually has token_length=0
    const token_varint = packet.decodeVarint(data[pos..]) orelse return DecodeError.TruncatedPacket;
    pos += token_varint.consumed;
    const token_len: usize = @intCast(token_varint.value);
    pos += token_len; // skip token

    // Length (varint) — covers PN + encrypted payload + tag
    const length_varint = packet.decodeVarint(data[pos..]) orelse return DecodeError.TruncatedPacket;
    pos += length_varint.consumed;
    const length: usize = @intCast(length_varint.value);

    if (data.len < pos + length) return DecodeError.TruncatedPacket;

    // pn_offset is where packet number starts
    const pn_offset = pos;

    // Derive server keys from original DCID
    const keys = quic_crypto.deriveInitialKeys(original_dcid);

    // Remove header protection
    if (data.len < pn_offset + 4 + 16) return DecodeError.HeaderProtectionFailed;
    quic_crypto.removeHeaderProtection(data, pn_offset, keys.server_hp);

    // Read packet number length from unprotected first byte
    const pn_length: usize = (data[0] & 0x03) + 1;

    // Read packet number
    var pn: u64 = 0;
    for (0..pn_length) |i| {
        pn = (pn << 8) | data[pn_offset + i];
    }

    // AAD = header up to and including packet number
    const aad = data[0 .. pn_offset + pn_length];

    // Ciphertext + tag
    const ct_start = pn_offset + pn_length;
    const ct_len = length - pn_length - 16; // subtract PN and AEAD tag
    if (data.len < ct_start + ct_len + 16) return DecodeError.TruncatedPacket;
    const ciphertext = data[ct_start..][0..ct_len];
    const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

    // Decrypt
    if (out_buf.len < ct_len) return DecodeError.TruncatedPacket;
    const ok = quic_crypto.decryptPayload(
        out_buf[0..ct_len],
        ciphertext,
        tag.*,
        keys.server_key,
        keys.server_iv,
        pn,
        aad,
    );
    if (!ok) return DecodeError.DecryptionFailed;

    // Parse CRYPTO frames from decrypted payload
    const plaintext = out_buf[0..ct_len];
    const crypto_result = extractCryptoFrame(plaintext) orelse return DecodeError.InvalidFrame;

    return .{
        .scid = scid,
        .dcid = dcid,
        .packet_number = pn,
        .crypto_data = crypto_result.data,
        .crypto_offset = crypto_result.offset,
    };
}

const CryptoFrameResult = struct {
    offset: u64,
    data: []const u8,
};

/// Extract the first CRYPTO frame from a QUIC payload.
/// Skips ACK frames and PADDING.
fn extractCryptoFrame(payload: []const u8) ?CryptoFrameResult {
    var pos: usize = 0;
    while (pos < payload.len) {
        const frame_type = payload[pos];

        // PADDING (0x00) — skip
        if (frame_type == 0x00) {
            pos += 1;
            continue;
        }

        // PING (0x01) — skip
        if (frame_type == 0x01) {
            pos += 1;
            continue;
        }

        // ACK (0x02, 0x03) — skip by parsing its structure
        if (frame_type == 0x02 or frame_type == 0x03) {
            pos += 1;
            // largest_ack (varint)
            const la = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += la.consumed;
            // ack_delay (varint)
            const ad = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += ad.consumed;
            // ack_range_count (varint)
            const arc = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += arc.consumed;
            // first_ack_range (varint)
            const far_ = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += far_.consumed;
            // additional ranges
            var i: u64 = 0;
            while (i < arc.value) : (i += 1) {
                const gap = packet.decodeVarint(payload[pos..]) orelse return null;
                pos += gap.consumed;
                const range = packet.decodeVarint(payload[pos..]) orelse return null;
                pos += range.consumed;
            }
            // ECN counts for type 0x03
            if (frame_type == 0x03) {
                for (0..3) |_| {
                    const ecn = packet.decodeVarint(payload[pos..]) orelse return null;
                    pos += ecn.consumed;
                }
            }
            continue;
        }

        // CRYPTO (0x06)
        if (frame_type == 0x06) {
            pos += 1;
            const offset = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += offset.consumed;
            const length = packet.decodeVarint(payload[pos..]) orelse return null;
            pos += length.consumed;
            const data_len: usize = @intCast(length.value);
            if (pos + data_len > payload.len) return null;
            return .{
                .offset = offset.value,
                .data = payload[pos..][0..data_len],
            };
        }

        // Unknown frame type — can't skip safely
        return null;
    }
    return null;
}

// ─── Tests ───

test "extractCryptoFrame: basic" {
    // CRYPTO frame: type(0x06) + offset(0) + length(3) + data("abc")
    const payload = [_]u8{ 0x06, 0x00, 0x03, 'a', 'b', 'c' };
    const result = extractCryptoFrame(&payload) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), result.offset);
    try std.testing.expectEqualStrings("abc", result.data);
}

test "extractCryptoFrame: skip padding and ack" {
    // PADDING(3) + ACK(type=0x02, largest_ack=0, delay=0, count=0, first_range=0) + CRYPTO
    const payload = [_]u8{
        0x00, 0x00, 0x00, // 3 padding bytes
        0x02, 0x00, 0x00, 0x00, 0x00, // ACK: largest=0, delay=0, count=0, first_range=0
        0x06, 0x00, 0x02, 0xDE, 0xAD, // CRYPTO: offset=0, len=2, data
    };
    const result = extractCryptoFrame(&payload) orelse unreachable;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, result.data);
}

test "extractCryptoFrame: with offset" {
    // CRYPTO: type(0x06) + offset(varint 100=0x40,0x64) + length(1) + data
    const payload = [_]u8{ 0x06, 0x40, 0x64, 0x01, 0xFF };
    const result = extractCryptoFrame(&payload) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 100), result.offset);
    try std.testing.expectEqual(@as(u8, 0xFF), result.data[0]);
}

test "decodeServerInitial: truncated packet" {
    var data = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x01 };
    var out_buf: [1500]u8 = undefined;
    const result = decodeServerInitial(&data, &.{}, &out_buf);
    try std.testing.expectError(DecodeError.TruncatedPacket, result);
}

test "decodeServerInitial: short header rejected" {
    var data = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    var out_buf: [1500]u8 = undefined;
    const result = decodeServerInitial(&data, &.{}, &out_buf);
    try std.testing.expectError(DecodeError.NotLongHeader, result);
}

test "decodeServerInitial: handshake type rejected" {
    // Type = handshake (0x02), not initial (0x00)
    var data = [_]u8{ 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    var out_buf: [1500]u8 = undefined;
    const result = decodeServerInitial(&data, &.{}, &out_buf);
    try std.testing.expectError(DecodeError.NotInitial, result);
}
