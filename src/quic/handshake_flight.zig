const std = @import("std");
const packet_mod = @import("packet.zig");
const quic_crypto = @import("crypto.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Reassembles CRYPTO frames from multiple packets into a contiguous buffer.
/// Tracks received byte ranges to detect gaps.
pub const CryptoReassembler = struct {
    buf: [MAX_CRYPTO_DATA]u8,
    /// Tracks which byte ranges have been received (up to MAX_RANGES intervals).
    ranges: [MAX_RANGES]Range,
    range_count: usize,

    const MAX_CRYPTO_DATA = 16384;
    const MAX_RANGES = 32;

    const Range = struct {
        start: usize,
        end: usize,
    };

    pub fn init() CryptoReassembler {
        return .{
            .buf = undefined,
            .ranges = undefined,
            .range_count = 0,
        };
    }

    /// Insert CRYPTO frame content at the given offset.
    pub fn insert(self: *CryptoReassembler, offset: u64, content: []const u8) bool {
        if (offset > MAX_CRYPTO_DATA) return false;
        const off: usize = @intCast(offset);
        if (off + content.len > MAX_CRYPTO_DATA) return false;
        @memcpy(self.buf[off..][0..content.len], content);

        const new_start = off;
        const new_end = off + content.len;
        self.mergeRange(new_start, new_end);
        return true;
    }

    /// Returns true if all bytes from 0 to expected_len have been received without gaps.
    pub fn isContiguous(self: *const CryptoReassembler, expected_len: usize) bool {
        if (self.range_count == 0) return expected_len == 0;
        return self.ranges[0].start == 0 and self.ranges[0].end >= expected_len;
    }

    /// Returns the contiguous length from offset 0 (may be less than total received).
    pub fn contiguousLen(self: *const CryptoReassembler) usize {
        if (self.range_count == 0) return 0;
        if (self.ranges[0].start != 0) return 0;
        return self.ranges[0].end;
    }

    /// Get the contiguous data from offset 0. Only valid up to contiguousLen().
    pub fn getData(self: *const CryptoReassembler) []const u8 {
        return self.buf[0..self.contiguousLen()];
    }

    pub fn len(self: *const CryptoReassembler) usize {
        return self.contiguousLen();
    }

    /// Returns true if there are gaps in the received data.
    pub fn hasGaps(self: *const CryptoReassembler) bool {
        return self.range_count > 1 or (self.range_count == 1 and self.ranges[0].start != 0);
    }

    fn mergeRange(self: *CryptoReassembler, start: usize, end: usize) void {
        // Try to merge with existing ranges
        var new_start = start;
        var new_end = end;
        var write_idx: usize = 0;

        var i: usize = 0;
        while (i < self.range_count) : (i += 1) {
            const r = self.ranges[i];
            if (r.end < new_start) {
                // Range is entirely before new range — keep it
                self.ranges[write_idx] = r;
                write_idx += 1;
            } else if (r.start > new_end) {
                // Range is entirely after new range — keep it (insert new first)
                self.ranges[write_idx] = .{ .start = new_start, .end = new_end };
                write_idx += 1;
                // Copy remaining
                while (i < self.range_count) : (i += 1) {
                    self.ranges[write_idx] = self.ranges[i];
                    write_idx += 1;
                }
                self.range_count = write_idx;
                return;
            } else {
                // Overlapping or adjacent — merge
                new_start = @min(new_start, r.start);
                new_end = @max(new_end, r.end);
            }
        }

        // Append the merged range
        if (write_idx < MAX_RANGES) {
            self.ranges[write_idx] = .{ .start = new_start, .end = new_end };
            write_idx += 1;
        }
        self.range_count = write_idx;
    }
};

/// Decode a Handshake packet (Long Header type=2) using the provided keys.
/// Returns the decrypted payload.
pub fn decodeHandshakePacket(
    data: []u8,
    server_key: [16]u8,
    server_iv: [12]u8,
    server_hp: [16]u8,
    out_buf: []u8,
) ?DecryptedPacket {
    if (data.len < 7) return null;
    if (data[0] & 0x80 == 0) return null;

    const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
    if (ptype != 2) return null; // not Handshake

    // Parse long header
    const dcid_len: usize = data[5];
    if (data.len < 6 + dcid_len + 1) return null;
    const scid_len: usize = data[6 + dcid_len];
    var pos: usize = 7 + dcid_len + scid_len;

    // Handshake packets have no token field (unlike Initial)
    // Length (varint)
    const length_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
    pos += length_v.consumed;
    const pn_offset = pos;
    const length_val: usize = @intCast(length_v.value);
    const total_packet_len = pos + length_val;

    if (data.len < total_packet_len) return null;

    // Remove header protection
    if (data.len < pn_offset + 4 + 16) return null;
    quic_crypto.removeHeaderProtection(data[0..total_packet_len], pn_offset, server_hp);

    // Read PN
    const pn_length: usize = (data[0] & 0x03) + 1;
    var pn: u64 = 0;
    for (0..pn_length) |i| {
        pn = (pn << 8) | data[pn_offset + i];
    }

    // AAD, ciphertext, tag
    const aad = data[0 .. pn_offset + pn_length];
    const ct_start = pn_offset + pn_length;
    if (length_val < pn_length + 16) return null;
    const ct_len = length_val - pn_length - 16;
    if (data.len < ct_start + ct_len + 16) return null;
    const ciphertext = data[ct_start..][0..ct_len];
    const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

    if (out_buf.len < ct_len) return null;
    const ok = quic_crypto.decryptPayload(
        out_buf[0..ct_len],
        ciphertext,
        tag.*,
        server_key,
        server_iv,
        pn,
        aad,
    );
    if (!ok) return null;

    return .{
        .plaintext = out_buf[0..ct_len],
        .packet_number = pn,
        .total_len = total_packet_len,
    };
}

pub const DecryptedPacket = struct {
    plaintext: []const u8,
    packet_number: u64,
    total_len: usize,
};

/// Extract all CRYPTO frames from a decrypted QUIC payload and insert into reassembler.
/// Also skips CONNECTION_CLOSE frames (0x1c, 0x1d) which are valid in Handshake packets.
pub fn extractCryptoFrames(payload: []const u8, reassembler: *CryptoReassembler) usize {
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < payload.len) {
        const ftype = payload[pos];
        if (ftype == 0x00) {
            pos += 1;
            continue;
        }
        if (ftype == 0x01) {
            pos += 1;
            continue;
        }
        if (ftype == 0x02 or ftype == 0x03) {
            pos += 1;
            const la = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += la.consumed;
            const ad = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += ad.consumed;
            const arc = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += arc.consumed;
            const far_ = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += far_.consumed;
            var i: u64 = 0;
            while (i < arc.value) : (i += 1) {
                const gap = packet_mod.decodeVarint(payload[pos..]) orelse return count;
                pos += gap.consumed;
                const range = packet_mod.decodeVarint(payload[pos..]) orelse return count;
                pos += range.consumed;
            }
            if (ftype == 0x03) {
                for (0..3) |_| {
                    const ecn = packet_mod.decodeVarint(payload[pos..]) orelse return count;
                    pos += ecn.consumed;
                }
            }
            continue;
        }
        if (ftype == 0x06) {
            pos += 1;
            const off = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += off.consumed;
            const length = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += length.consumed;
            const data_len: usize = @intCast(length.value);
            if (pos + data_len > payload.len) break;
            _ = reassembler.insert(off.value, payload[pos..][0..data_len]);
            pos += data_len;
            count += 1;
            continue;
        }
        // CONNECTION_CLOSE (0x1c, 0x1d): error_code(varint) + frame_type(varint) + reason_len(varint) + reason
        if (ftype == 0x1c or ftype == 0x1d) {
            pos += 1;
            const ec = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += ec.consumed;
            if (ftype == 0x1c) {
                const ft = packet_mod.decodeVarint(payload[pos..]) orelse break;
                pos += ft.consumed;
            }
            const rl = packet_mod.decodeVarint(payload[pos..]) orelse break;
            pos += rl.consumed;
            pos += @intCast(rl.value);
            continue;
        }
        break;
    }
    return count;
}

/// Derive 1-RTT (Application) traffic keys from handshake_secret + full transcript hash.
/// RFC 8446 §7.1: master_secret = HKDF-Extract(derive_secret(handshake_secret, "derived", ""), 0)
pub const ApplicationKeys = struct {
    client_key: [16]u8,
    client_iv: [12]u8,
    client_hp: [16]u8,
    server_key: [16]u8,
    server_iv: [12]u8,
    server_hp: [16]u8,
};

/// Application keys plus the traffic secrets needed for Key Update (RFC 9001 §6).
pub const ApplicationKeysWithSecrets = struct {
    keys: ApplicationKeys,
    client_secret: [32]u8,
    server_secret: [32]u8,
    master_secret: [32]u8,
};

pub fn deriveApplicationKeys(
    handshake_secret: [32]u8,
    transcript_hash_handshake: [32]u8,
) ApplicationKeys {
    return deriveApplicationKeysWithSecrets(handshake_secret, transcript_hash_handshake).keys;
}

pub fn deriveApplicationKeysWithSecrets(
    handshake_secret: [32]u8,
    transcript_hash_handshake: [32]u8,
) ApplicationKeysWithSecrets {
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});
    var derived: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&derived, &handshake_secret, "derived", &empty_hash);

    var master_secret: [32]u8 = undefined;
    const zero_ikm = [_]u8{0} ** 32;
    quic_crypto.hkdfExtract(&master_secret, &derived, &zero_ikm);

    var client_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&client_secret, &master_secret, "c ap traffic", &transcript_hash_handshake);

    var server_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&server_secret, &master_secret, "s ap traffic", &transcript_hash_handshake);

    var result: ApplicationKeysWithSecrets = undefined;
    result.master_secret = master_secret;
    result.client_secret = client_secret;
    result.server_secret = server_secret;
    quic_crypto.hkdfExpandLabel(&result.keys.client_key, &client_secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&result.keys.client_iv, &client_secret, "quic iv", "");
    quic_crypto.hkdfExpandLabel(&result.keys.client_hp, &client_secret, "quic hp", "");
    quic_crypto.hkdfExpandLabel(&result.keys.server_key, &server_secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&result.keys.server_iv, &server_secret, "quic iv", "");
    quic_crypto.hkdfExpandLabel(&result.keys.server_hp, &server_secret, "quic hp", "");

    return result;
}

/// Determine the total packet length of a coalesced long-header packet
/// without decrypting it (for skipping non-Initial packets in a datagram).
pub fn coalescedPacketLen(data: []const u8) ?usize {
    if (data.len < 7) return null;
    if (data[0] & 0x80 == 0) return null; // short header

    const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
    const dcid_len: usize = data[5];
    if (data.len < 6 + dcid_len + 1) return null;
    const scid_len: usize = data[6 + dcid_len];
    var pos: usize = 7 + dcid_len + scid_len;

    // Initial has token; Handshake does not
    if (ptype == 0) {
        const token_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += token_v.consumed;
        pos += @intCast(token_v.value);
    }

    // Length varint
    const length_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
    pos += length_v.consumed;

    return pos + @as(usize, @intCast(length_v.value));
}

// ─── Tests ───

test "CryptoReassembler: sequential inserts" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(ra.insert(0, "Hello"));
    try std.testing.expect(ra.insert(5, " World"));
    try std.testing.expectEqual(@as(usize, 11), ra.len());
    try std.testing.expectEqualStrings("Hello World", ra.getData());
    try std.testing.expect(!ra.hasGaps());
}

test "CryptoReassembler: out-of-order inserts with gap" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(ra.insert(10, "World"));
    // Gap exists: [0..10) not received
    try std.testing.expect(ra.hasGaps());
    try std.testing.expectEqual(@as(usize, 0), ra.contiguousLen());

    // Fill the gap
    try std.testing.expect(ra.insert(0, "Hello-----"));
    try std.testing.expect(!ra.hasGaps());
    try std.testing.expectEqual(@as(usize, 15), ra.contiguousLen());
}

test "CryptoReassembler: adjacent inserts merge" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(ra.insert(0, "AB"));
    try std.testing.expect(ra.insert(2, "CD"));
    try std.testing.expect(ra.insert(4, "EF"));
    try std.testing.expectEqual(@as(usize, 1), ra.range_count);
    try std.testing.expectEqual(@as(usize, 6), ra.contiguousLen());
    try std.testing.expectEqualStrings("ABCDEF", ra.getData());
}

test "CryptoReassembler: overlapping inserts" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(ra.insert(0, "ABCDE"));
    try std.testing.expect(ra.insert(3, "DEFGH"));
    try std.testing.expectEqual(@as(usize, 1), ra.range_count);
    try std.testing.expectEqual(@as(usize, 8), ra.contiguousLen());
}

test "CryptoReassembler: isContiguous" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(ra.isContiguous(0));
    try std.testing.expect(!ra.isContiguous(5));

    try std.testing.expect(ra.insert(0, "Hello"));
    try std.testing.expect(ra.isContiguous(5));
    try std.testing.expect(ra.isContiguous(3));
    try std.testing.expect(!ra.isContiguous(10));
}

test "CryptoReassembler: overflow rejected" {
    var ra = CryptoReassembler.init();
    var big: [CryptoReassembler.MAX_CRYPTO_DATA + 1]u8 = undefined;
    try std.testing.expect(!ra.insert(0, &big));
}

test "CryptoReassembler: large offset u64 rejected" {
    var ra = CryptoReassembler.init();
    try std.testing.expect(!ra.insert(std.math.maxInt(u64), "x"));
    try std.testing.expect(!ra.insert(CryptoReassembler.MAX_CRYPTO_DATA + 1, "x"));
}

test "extractCryptoFrames: single CRYPTO frame" {
    var ra = CryptoReassembler.init();
    const payload = [_]u8{ 0x06, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o' };
    const count = extractCryptoFrames(&payload, &ra);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("Hello", ra.getData());
}

test "extractCryptoFrames: padding + ACK + CRYPTO" {
    var ra = CryptoReassembler.init();
    const payload = [_]u8{
        0x00, 0x00, // padding
        0x02, 0x00, 0x00, 0x00, 0x00, // ACK
        0x06, 0x00, 0x03, 0xDE, 0xAD, 0xBE, // CRYPTO offset=0 len=3
    };
    const count = extractCryptoFrames(&payload, &ra);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE }, ra.getData());
}

test "extractCryptoFrames: multiple CRYPTO frames" {
    var ra = CryptoReassembler.init();
    const payload = [_]u8{
        0x06, 0x00, 0x03, 'A', 'B', 'C', // CRYPTO offset=0 len=3
        0x06, 0x03, 0x02, 'D', 'E', // CRYPTO offset=3 len=2
    };
    const count = extractCryptoFrames(&payload, &ra);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("ABCDE", ra.getData());
}

test "extractCryptoFrames: CONNECTION_CLOSE skipped" {
    var ra = CryptoReassembler.init();
    const payload = [_]u8{
        0x06, 0x00, 0x03, 'A', 'B', 'C', // CRYPTO
        0x1c, 0x00, 0x00, 0x00, // CONNECTION_CLOSE: error=0, frame_type=0, reason_len=0
        0x06, 0x03, 0x02, 'D', 'E', // CRYPTO
    };
    const count = extractCryptoFrames(&payload, &ra);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("ABCDE", ra.getData());
}

test "coalescedPacketLen: Initial packet" {
    var buf: [64]u8 = undefined;
    buf[0] = 0xC0; // long header, initial type
    std.mem.writeInt(u32, buf[1..5], 0x00000001, .big);
    buf[5] = 4; // dcid_len
    @memset(buf[6..10], 0xAA);
    buf[10] = 4; // scid_len
    @memset(buf[11..15], 0xBB);
    buf[15] = 0; // token_len = 0
    buf[16] = 20; // Length = 20
    // total = 17 + 20 = 37

    const pkt_len = coalescedPacketLen(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 37), pkt_len);
}

test "coalescedPacketLen: Handshake packet (no token)" {
    var buf: [64]u8 = undefined;
    buf[0] = 0xE0; // long header, handshake type
    std.mem.writeInt(u32, buf[1..5], 0x00000001, .big);
    buf[5] = 4;
    @memset(buf[6..10], 0xAA);
    buf[10] = 4;
    @memset(buf[11..15], 0xBB);
    buf[15] = 30; // Length = 30
    // total = 16 + 30 = 46

    const pkt_len = coalescedPacketLen(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 46), pkt_len);
}

test "deriveApplicationKeys: deterministic" {
    const hs_secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0xAB} ** 32;

    const keys1 = deriveApplicationKeys(hs_secret, transcript);
    const keys2 = deriveApplicationKeys(hs_secret, transcript);

    try std.testing.expectEqualSlices(u8, &keys1.client_key, &keys2.client_key);
    try std.testing.expectEqualSlices(u8, &keys1.server_key, &keys2.server_key);
    try std.testing.expectEqualSlices(u8, &keys1.client_iv, &keys2.client_iv);
    try std.testing.expectEqualSlices(u8, &keys1.server_iv, &keys2.server_iv);
}

test "deriveApplicationKeys: client != server keys" {
    const hs_secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0xAB} ** 32;

    const keys = deriveApplicationKeys(hs_secret, transcript);
    try std.testing.expect(!std.mem.eql(u8, &keys.client_key, &keys.server_key));
    try std.testing.expect(!std.mem.eql(u8, &keys.client_iv, &keys.server_iv));
}

test "deriveApplicationKeys: different transcripts produce different keys" {
    const hs_secret = [_]u8{0x42} ** 32;
    const t1 = [_]u8{0xAB} ** 32;
    const t2 = [_]u8{0xCD} ** 32;

    const keys1 = deriveApplicationKeys(hs_secret, t1);
    const keys2 = deriveApplicationKeys(hs_secret, t2);
    try std.testing.expect(!std.mem.eql(u8, &keys1.client_key, &keys2.client_key));
}

test "decodeHandshakePacket: wrong type rejected" {
    var buf: [64]u8 = undefined;
    buf[0] = 0xC0; // Initial type
    var out: [64]u8 = undefined;
    const result = decodeHandshakePacket(&buf, undefined, undefined, undefined, &out);
    try std.testing.expect(result == null);
}
