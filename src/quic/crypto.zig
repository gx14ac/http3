// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const crypto = std.crypto;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

/// QUIC v1 Initial salt (RFC 9001 §5.2).
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// Derived key material for Initial packet protection.
pub const InitialKeys = struct {
    client_key: [16]u8,
    client_iv: [12]u8,
    client_hp: [16]u8,
    server_key: [16]u8,
    server_iv: [12]u8,
    server_hp: [16]u8,
};

/// Derive Initial keys from the Destination Connection ID (RFC 9001 §5.2).
pub fn deriveInitialKeys(dcid: []const u8) InitialKeys {
    // initial_secret = HKDF-Extract(initial_salt, dcid)
    var initial_secret: [32]u8 = undefined;
    hkdfExtract(&initial_secret, &initial_salt_v1, dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    var client_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, &initial_secret, "client in", "");

    // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    var server_secret: [32]u8 = undefined;
    hkdfExpandLabel(&server_secret, &initial_secret, "server in", "");

    var keys: InitialKeys = undefined;

    // Client keys
    hkdfExpandLabel(&keys.client_key, &client_secret, "quic key", "");
    hkdfExpandLabel(&keys.client_iv, &client_secret, "quic iv", "");
    hkdfExpandLabel(&keys.client_hp, &client_secret, "quic hp", "");

    // Server keys
    hkdfExpandLabel(&keys.server_key, &server_secret, "quic key", "");
    hkdfExpandLabel(&keys.server_iv, &server_secret, "quic iv", "");
    hkdfExpandLabel(&keys.server_hp, &server_secret, "quic hp", "");

    return keys;
}

/// Apply header protection mask to the first byte and packet number bytes (RFC 9001 §5.4.1).
/// For application: read pn_length BEFORE masking byte[0] (it's still unprotected).
pub fn applyHeaderProtection(pkt: []u8, pn_offset: usize, hp_key: [16]u8) void {
    if (pkt.len < pn_offset + 4 + 16) return;

    const sample = pkt[pn_offset + 4 ..][0..16];
    var mask: [5]u8 = undefined;
    aes128EcbEncrypt(&mask, sample, &hp_key);

    // Read pn_length from unprotected first byte
    const pn_length: usize = (pkt[0] & 0x03) + 1;

    // Mask first byte
    if (pkt[0] & 0x80 != 0) {
        pkt[0] ^= mask[0] & 0x0F;
    } else {
        pkt[0] ^= mask[0] & 0x1F;
    }

    // Mask PN bytes
    for (0..pn_length) |i| {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
}

/// Remove header protection (RFC 9001 §5.4.1).
/// For removal: unmask byte[0] FIRST to recover true pn_length, then unmask PN bytes.
pub fn removeHeaderProtection(pkt: []u8, pn_offset: usize, hp_key: [16]u8) void {
    if (pkt.len < pn_offset + 4 + 16) return;

    const sample = pkt[pn_offset + 4 ..][0..16];
    var mask: [5]u8 = undefined;
    aes128EcbEncrypt(&mask, sample, &hp_key);

    // Unmask first byte to recover pn_length
    if (pkt[0] & 0x80 != 0) {
        pkt[0] ^= mask[0] & 0x0F;
    } else {
        pkt[0] ^= mask[0] & 0x1F;
    }

    // Read pn_length from now-unmasked first byte
    const pn_length: usize = (pkt[0] & 0x03) + 1;

    // Unmask PN bytes
    for (0..pn_length) |i| {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
}

/// Encrypt payload using AES-128-GCM (RFC 9001 §5.3).
/// nonce = iv XOR packet_number (left-padded to 12 bytes).
pub fn encryptPayload(
    ciphertext: []u8,
    tag: *[16]u8,
    plaintext: []const u8,
    key: [16]u8,
    iv: [12]u8,
    packet_number: u64,
    aad: []const u8,
) void {
    var nonce = iv;
    // XOR packet number into the rightmost bytes of IV
    const pn_bytes = std.mem.toBytes(std.mem.nativeTo(u64, packet_number, .big));
    for (0..8) |i| {
        nonce[12 - 8 + i] ^= pn_bytes[i];
    }

    const aes_gcm = crypto.aead.aes_gcm.Aes128Gcm;
    aes_gcm.encrypt(ciphertext, tag, plaintext, aad, nonce, key);
}

/// Decrypt payload using AES-128-GCM.
pub fn decryptPayload(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [16]u8,
    key: [16]u8,
    iv: [12]u8,
    packet_number: u64,
    aad: []const u8,
) bool {
    var nonce = iv;
    const pn_bytes = std.mem.toBytes(std.mem.nativeTo(u64, packet_number, .big));
    for (0..8) |i| {
        nonce[12 - 8 + i] ^= pn_bytes[i];
    }

    const aes_gcm = crypto.aead.aes_gcm.Aes128Gcm;
    aes_gcm.decrypt(plaintext, ciphertext, tag, aad, nonce, key) catch return false;
    return true;
}

// ─── HKDF primitives (TLS 1.3 style, SHA-256) ───

pub fn hkdfExtract(out: *[32]u8, salt: []const u8, ikm: []const u8) void {
    var hmac = HmacSha256.init(salt);
    hmac.update(ikm);
    hmac.final(out);
}

/// HKDF-Expand-Label as defined in RFC 8446 §7.1:
/// HKDF-Expand(secret, HkdfLabel, length)
/// HkdfLabel = length(2) + "tls13 " + label + context
pub fn hkdfExpandLabel(out: anytype, secret: *const [32]u8, label: []const u8, context: []const u8) void {
    const out_len = out.len;
    // Build HkdfLabel
    var hkdf_label: [256]u8 = undefined;
    var pos: usize = 0;

    // length (2 bytes, big-endian)
    std.mem.writeInt(u16, hkdf_label[0..2], @intCast(out_len), .big);
    pos = 2;

    // label with "tls13 " prefix
    const full_label_len: u8 = @intCast(6 + label.len);
    hkdf_label[pos] = full_label_len;
    pos += 1;
    @memcpy(hkdf_label[pos..][0..6], "tls13 ");
    pos += 6;
    @memcpy(hkdf_label[pos..][0..label.len], label);
    pos += label.len;

    // context
    hkdf_label[pos] = @intCast(context.len);
    pos += 1;
    if (context.len > 0) {
        @memcpy(hkdf_label[pos..][0..context.len], context);
        pos += context.len;
    }

    // HKDF-Expand(secret, info=hkdf_label, L=out_len)
    hkdfExpand(out, secret, hkdf_label[0..pos]);
}

pub fn hkdfExpand(out: anytype, prk: *const [32]u8, info: []const u8) void {
    const out_len = out.len;
    var t: [32]u8 = undefined;
    var t_len: usize = 0;
    var offset: usize = 0;
    var counter: u8 = 1;

    while (offset < out_len) {
        var hmac = HmacSha256.init(prk);
        if (t_len > 0) hmac.update(t[0..t_len]);
        hmac.update(info);
        hmac.update(&.{counter});
        hmac.final(&t);
        t_len = 32;

        const remaining = out_len - offset;
        const copy_len = @min(remaining, 32);
        @memcpy(out[offset..][0..copy_len], t[0..copy_len]);
        offset += copy_len;
        counter += 1;
    }
}

/// AES-128 single-block ECB encrypt for header protection.
fn aes128EcbEncrypt(out: *[5]u8, sample: *const [16]u8, key: *const [16]u8) void {
    const aes = crypto.core.aes.Aes128.initEnc(key.*);
    var block: [16]u8 = undefined;
    aes.encrypt(&block, sample);
    @memcpy(out, block[0..5]);
}

// ─── Tests ───

test "deriveInitialKeys: known vector (RFC 9001 §A.1)" {
    // DCID from RFC 9001 Appendix A: 0x8394c8f03e515708
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = deriveInitialKeys(&dcid);

    // Expected client key from RFC 9001 §A.1
    const expected_client_key = [_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_key, &keys.client_key);

    // Expected client IV from RFC 9001 §A.1
    const expected_client_iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_iv, &keys.client_iv);

    // Expected client HP key from RFC 9001 §A.1
    const expected_client_hp = [_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };
    try std.testing.expectEqualSlices(u8, &expected_client_hp, &keys.client_hp);
}

test "encryptPayload/decryptPayload roundtrip" {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const iv = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    const plaintext = "Hello QUIC!";
    const aad = "associated data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encryptPayload(&ciphertext, &tag, plaintext, key, iv, 42, aad);

    var decrypted: [plaintext.len]u8 = undefined;
    const ok = decryptPayload(&decrypted, &ciphertext, tag, key, iv, 42, aad);
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "decryptPayload: wrong key fails" {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const wrong_key = [_]u8{ 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const iv = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    const plaintext = "secret";
    const aad = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encryptPayload(&ciphertext, &tag, plaintext, key, iv, 0, aad);

    var decrypted: [plaintext.len]u8 = undefined;
    const ok = decryptPayload(&decrypted, &ciphertext, tag, wrong_key, iv, 0, aad);
    try std.testing.expect(!ok);
}

test "hkdfExtract: basic operation" {
    var out: [32]u8 = undefined;
    hkdfExtract(&out, "salt", "input key material");
    // Just verify it doesn't crash and produces non-zero output
    var all_zero = true;
    for (out) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
