const std = @import("std");
const quic_crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");

/// Encode a 1-RTT (short header) packet.
/// Short header format (RFC 9000 §17.3):
///   Form(1)=0 | Fixed(1)=1 | Spin(1) | Reserved(2) | Key Phase(1) | PN Length(2)
///   DCID (variable)
///   Packet Number (1-4 bytes)
///   Payload (encrypted)
///   AEAD Tag (16 bytes)
pub fn encodeShortHeader(
    buf: []u8,
    dcid: []const u8,
    packet_number: u64,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    return encodeShortHeaderWithPhase(buf, dcid, packet_number, payload, key, iv, hp, 0);
}

pub fn encodeShortHeaderWithPhase(
    buf: []u8,
    dcid: []const u8,
    packet_number: u64,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
    key_phase: u1,
) ?usize {
    const pn_len: u8 = if (packet_number < 256) 0 else if (packet_number < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;
    const min_len = 1 + dcid.len + pn_bytes + payload.len + 16;
    if (buf.len < min_len) return null;

    var pos: usize = 0;

    // First byte: 0(form) | 1(fixed) | 0(spin) | 00(reserved) | key_phase(1) | pn_len
    buf[pos] = 0x40 | (@as(u8, key_phase) << 2) | pn_len;
    pos += 1;

    // DCID
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    // Packet Number
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((packet_number >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // AAD = header (first byte + DCID + PN)
    const aad = buf[0..pos];

    // Encrypt payload
    if (payload.len > 4096) return null;
    var ciphertext: [4096]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(
        ciphertext[0..payload.len],
        &tag,
        payload,
        key,
        iv,
        packet_number,
        aad,
    );

    // Append ciphertext + tag
    @memcpy(buf[pos..][0..payload.len], ciphertext[0..payload.len]);
    pos += payload.len;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    // Apply header protection
    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, hp);

    return pos;
}

/// Decode a 1-RTT (short header) packet.
/// `dcid_len` must be known from the connection state (it's not encoded in the packet).
pub fn decodeShortHeader(
    data: []u8,
    dcid_len: usize,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
    out_buf: []u8,
) ?DecodedShortPacket {
    if (data.len < 1 + dcid_len + 4 + 16) return null;
    // Must be short header (form bit = 0)
    if (data[0] & 0x80 != 0) return null;

    const pn_offset = 1 + dcid_len;

    // Remove header protection
    quic_crypto.removeHeaderProtection(data, pn_offset, hp);

    // Read PN length from unmasked first byte
    const pn_length: usize = (data[0] & 0x03) + 1;
    var pn: u64 = 0;
    for (0..pn_length) |i| {
        pn = (pn << 8) | data[pn_offset + i];
    }

    const ct_start = pn_offset + pn_length;
    if (data.len < ct_start + 16) return null;
    const ct_len = data.len - ct_start - 16;
    if (out_buf.len < ct_len) return null;

    const ciphertext = data[ct_start..][0..ct_len];
    const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

    const aad = data[0..ct_start];
    const ok = quic_crypto.decryptPayload(
        out_buf[0..ct_len],
        ciphertext,
        tag.*,
        key,
        iv,
        pn,
        aad,
    );
    if (!ok) return null;

    const phase: u1 = @intCast((data[0] >> 2) & 0x01);

    return .{
        .dcid = data[1..][0..dcid_len],
        .packet_number = pn,
        .plaintext = out_buf[0..ct_len],
        .key_phase = phase,
    };
}

pub const DecodedShortPacket = struct {
    dcid: []const u8,
    packet_number: u64,
    plaintext: []const u8,
    key_phase: u1 = 0,
};

/// Intermediate state after HP removal but before AEAD decryption.
/// Used by key update logic to try multiple keys.
pub const HeaderParsed = struct {
    pn: u64,
    key_phase: u1,
    ct_start: usize,
    ct_len: usize,
    dcid: []const u8,
};

/// Remove header protection and parse the header fields without decrypting.
/// Mutates `data` in-place (HP removal). Returns null if packet is too short or malformed.
pub fn removeHpAndParse(data: []u8, dcid_len: usize, hp: [16]u8) ?HeaderParsed {
    if (data.len < 1 + dcid_len + 4 + 16) return null;
    if (data[0] & 0x80 != 0) return null;

    const pn_offset = 1 + dcid_len;
    quic_crypto.removeHeaderProtection(data, pn_offset, hp);

    const pn_length: usize = (data[0] & 0x03) + 1;
    var pn: u64 = 0;
    for (0..pn_length) |i| {
        pn = (pn << 8) | data[pn_offset + i];
    }

    const ct_start = pn_offset + pn_length;
    if (data.len < ct_start + 16) return null;
    const ct_len = data.len - ct_start - 16;

    const phase: u1 = @intCast((data[0] >> 2) & 0x01);

    return .{
        .pn = pn,
        .key_phase = phase,
        .ct_start = ct_start,
        .ct_len = ct_len,
        .dcid = data[1..][0..dcid_len],
    };
}

/// Decrypt payload after HP has been removed. Returns plaintext length or null on auth failure.
pub fn decryptParsed(data: []const u8, parsed: HeaderParsed, key: [16]u8, iv: [12]u8, out_buf: []u8) ?usize {
    if (out_buf.len < parsed.ct_len) return null;

    const ciphertext = data[parsed.ct_start..][0..parsed.ct_len];
    const tag: *const [16]u8 = data[parsed.ct_start + parsed.ct_len ..][0..16];
    const aad = data[0..parsed.ct_start];

    const ok = quic_crypto.decryptPayload(
        out_buf[0..parsed.ct_len],
        ciphertext,
        tag.*,
        key,
        iv,
        parsed.pn,
        aad,
    );
    if (!ok) return null;
    return parsed.ct_len;
}

// ─── Tests ───

test "encodeShortHeader/decodeShortHeader: roundtrip" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;
    const payload = "Hello 1-RTT!";

    var buf: [256]u8 = undefined;
    const pkt_len = encodeShortHeader(&buf, &dcid, 42, payload, key, iv, hp) orelse unreachable;

    var out: [256]u8 = undefined;
    const decoded = decodeShortHeader(buf[0..pkt_len], dcid.len, key, iv, hp, &out) orelse unreachable;

    try std.testing.expectEqual(@as(u64, 42), decoded.packet_number);
    try std.testing.expectEqualStrings("Hello 1-RTT!", decoded.plaintext);
    try std.testing.expectEqualSlices(u8, &dcid, decoded.dcid);
}

test "encodeShortHeader/decodeShortHeader: large packet number" {
    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const key = [_]u8{0x44} ** 16;
    const iv = [_]u8{0x55} ** 12;
    const hp = [_]u8{0x66} ** 16;
    const payload = "PN test";

    var buf: [256]u8 = undefined;
    const pkt_len = encodeShortHeader(&buf, &dcid, 300, payload, key, iv, hp) orelse unreachable;

    var out: [256]u8 = undefined;
    const decoded = decodeShortHeader(buf[0..pkt_len], dcid.len, key, iv, hp, &out) orelse unreachable;

    try std.testing.expectEqual(@as(u64, 300), decoded.packet_number);
    try std.testing.expectEqualStrings("PN test", decoded.plaintext);
}

test "decodeShortHeader: wrong key fails" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const key = [_]u8{0x11} ** 16;
    const wrong_key = [_]u8{0xFF} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;
    const payload = "secret";

    var buf: [256]u8 = undefined;
    const pkt_len = encodeShortHeader(&buf, &dcid, 0, payload, key, iv, hp) orelse unreachable;

    // Remove HP with correct key, try decrypt with wrong key
    var out: [256]u8 = undefined;
    const result = decodeShortHeader(buf[0..pkt_len], dcid.len, wrong_key, iv, hp, &out);
    try std.testing.expect(result == null);
}

test "decodeShortHeader: long header rejected" {
    var buf = [_]u8{0xC0} ++ [_]u8{0} ** 63; // long header bit set
    var out: [64]u8 = undefined;
    const result = decodeShortHeader(&buf, 8, undefined, undefined, undefined, &out);
    try std.testing.expect(result == null);
}

test "encodeShortHeader: buffer too small" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;

    var buf: [5]u8 = undefined; // way too small
    const result = encodeShortHeader(&buf, &dcid, 0, "data", key, iv, hp);
    try std.testing.expect(result == null);
}
