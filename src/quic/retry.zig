const std = @import("std");
const packet_mod = @import("packet.zig");

/// RFC 9001 §5.8: Retry Integrity Tag fixed key and nonce for QUIC v1.
const RETRY_KEY = [16]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_NONCE = [12]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

/// Decoded Retry packet fields.
pub const RetryPacket = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    integrity_tag: [16]u8,
};

/// Decode a Retry packet from raw bytes.
/// Retry has no Length field and no packet number.
/// Structure: flags(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid + token + tag(16)
pub fn decodeRetryPacket(data: []const u8) ?RetryPacket {
    if (data.len < 1 + 4 + 1 + 1 + 16) return null;

    // Verify long header form bit and Retry type (0b11xx = type 3)
    if (data[0] & 0x80 == 0) return null;
    const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
    if (ptype != 3) return null;

    var pos: usize = 1;

    // Version
    const version = std.mem.readInt(u32, data[pos..][0..4], .big);
    pos += 4;

    // DCID
    const dcid_len: usize = data[pos];
    pos += 1;
    if (pos + dcid_len > data.len) return null;
    const dcid = data[pos..][0..dcid_len];
    pos += dcid_len;

    // SCID
    const scid_len: usize = data[pos];
    pos += 1;
    if (pos + scid_len > data.len) return null;
    const scid = data[pos..][0..scid_len];
    pos += scid_len;

    // Remaining bytes: token + integrity tag (last 16 bytes)
    if (data.len < pos + 16) return null;
    const token_end = data.len - 16;
    const token = data[pos..token_end];
    var tag: [16]u8 = undefined;
    @memcpy(&tag, data[token_end..][0..16]);

    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .integrity_tag = tag,
    };
}

/// Validate the Retry Integrity Tag per RFC 9001 §5.8.
/// AAD = original_dcid_len(1) + original_dcid + retry_packet_without_tag
/// Returns true if the tag is valid.
pub fn validateRetryIntegrityTag(packet_data: []const u8, original_dcid: []const u8) bool {
    if (packet_data.len < 16) return false;

    // AAD: [odcid_len(1)] [odcid] [retry_packet_without_tag]
    const retry_without_tag = packet_data[0 .. packet_data.len - 16];
    const provided_tag = packet_data[packet_data.len - 16 ..][0..16];

    var aad_buf: [1 + 20 + 1500]u8 = undefined;
    if (1 + original_dcid.len + retry_without_tag.len > aad_buf.len) return false;

    aad_buf[0] = @intCast(original_dcid.len);
    @memcpy(aad_buf[1..][0..original_dcid.len], original_dcid);
    @memcpy(aad_buf[1 + original_dcid.len ..][0..retry_without_tag.len], retry_without_tag);
    const aad_len = 1 + original_dcid.len + retry_without_tag.len;
    const aad = aad_buf[0..aad_len];

    // AEAD-AES-128-GCM with empty plaintext — the tag IS the ciphertext output
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    var nonce: [12]u8 = RETRY_NONCE;
    _ = &nonce;

    // Decrypt with empty ciphertext — just validates the tag against AAD
    var empty: [0]u8 = undefined;
    Aes128Gcm.decrypt(&empty, &empty, provided_tag.*, aad, nonce, RETRY_KEY) catch return false;
    return true;
}

// ─── Tests ───

test "decodeRetryPacket: valid retry" {
    // Build a minimal Retry packet: flags + version + dcid_len + dcid + scid_len + scid + token + tag
    var pkt: [64]u8 = undefined;
    var pos: usize = 0;

    pkt[pos] = 0xF0; // Long header, type=3 (0b11), fixed bits
    pos += 1;
    std.mem.writeInt(u32, pkt[pos..][0..4], packet_mod.QUIC_VERSION_1, .big);
    pos += 4;
    pkt[pos] = 4; // dcid_len
    pos += 1;
    @memcpy(pkt[pos..][0..4], &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD });
    pos += 4;
    pkt[pos] = 4; // scid_len
    pos += 1;
    @memcpy(pkt[pos..][0..4], &[_]u8{ 0x11, 0x22, 0x33, 0x44 });
    pos += 4;
    // Token (5 bytes)
    @memcpy(pkt[pos..][0..5], &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01 });
    pos += 5;
    // Fake integrity tag (16 bytes)
    @memset(pkt[pos..][0..16], 0xFF);
    pos += 16;

    const retry = decodeRetryPacket(pkt[0..pos]) orelse unreachable;
    try std.testing.expectEqual(packet_mod.QUIC_VERSION_1, retry.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, retry.dcid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, retry.scid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01 }, retry.token);
    try std.testing.expectEqual([_]u8{0xFF} ** 16, retry.integrity_tag);
}

test "decodeRetryPacket: too short returns null" {
    const short = [_]u8{ 0xF0, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expect(decodeRetryPacket(&short) == null);
}

test "decodeRetryPacket: not long header returns null" {
    var pkt: [40]u8 = [_]u8{0} ** 40;
    pkt[0] = 0x40; // Short header
    try std.testing.expect(decodeRetryPacket(&pkt) == null);
}

test "decodeRetryPacket: wrong type returns null" {
    var pkt: [40]u8 = [_]u8{0} ** 40;
    pkt[0] = 0xC0; // Long header, type=0 (Initial)
    try std.testing.expect(decodeRetryPacket(&pkt) == null);
}

test "validateRetryIntegrityTag: RFC 9001 Appendix A.4 vector" {
    // RFC 9001 §A.4 provides a complete Retry packet example.
    // original_dcid = 0x8394c8f03e515708
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Full Retry packet from RFC 9001 Appendix A.4 (QUIC v1):
    const retry_packet = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    try std.testing.expect(validateRetryIntegrityTag(&retry_packet, &original_dcid));

    // Tamper with the tag — should fail
    var tampered = retry_packet;
    tampered[retry_packet.len - 1] ^= 0x01;
    try std.testing.expect(!validateRetryIntegrityTag(&tampered, &original_dcid));
}

test "validateRetryIntegrityTag: wrong original_dcid fails" {
    const retry_packet = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
        0x0f, 0x24, 0x96, 0xba,
    };

    const wrong_dcid = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expect(!validateRetryIntegrityTag(&retry_packet, &wrong_dcid));
}

test "decodeRetryPacket: empty token is valid" {
    var pkt: [32]u8 = undefined;
    var pos: usize = 0;

    pkt[pos] = 0xF0;
    pos += 1;
    std.mem.writeInt(u32, pkt[pos..][0..4], packet_mod.QUIC_VERSION_1, .big);
    pos += 4;
    pkt[pos] = 0; // dcid_len = 0
    pos += 1;
    pkt[pos] = 0; // scid_len = 0
    pos += 1;
    // No token, just tag
    @memset(pkt[pos..][0..16], 0xAA);
    pos += 16;

    const retry = decodeRetryPacket(pkt[0..pos]) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 0), retry.token.len);
    try std.testing.expectEqual(@as(usize, 0), retry.dcid.len);
    try std.testing.expectEqual(@as(usize, 0), retry.scid.len);
}
