const std = @import("std");
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const quic_crypto = @import("crypto.zig");

pub const HandshakeError = error{
    InvalidServerHello,
    KeyShareMismatch,
    DhFailed,
    TranscriptError,
};

/// Handshake keys derived from the TLS 1.3 key schedule.
pub const HandshakeKeys = struct {
    client_key: [16]u8,
    client_iv: [12]u8,
    client_hp: [16]u8,
    server_key: [16]u8,
    server_iv: [12]u8,
    server_hp: [16]u8,
    client_handshake_secret: [32]u8,
    server_handshake_secret: [32]u8,
    handshake_secret: [32]u8,
};

/// Parse ServerHello to extract the x25519 key_share.
/// `server_hello` is the raw handshake message (starting with type byte 0x02).
pub fn extractServerKeyShare(server_hello: []const u8) HandshakeError!*const [32]u8 {
    if (server_hello.len < 4) return HandshakeError.InvalidServerHello;
    if (server_hello[0] != 0x02) return HandshakeError.InvalidServerHello;

    const hs_len = (@as(usize, server_hello[1]) << 16) | (@as(usize, server_hello[2]) << 8) | server_hello[3];
    _ = hs_len;

    // Skip: type(1) + length(3) + version(2) + random(32) + session_id_len(1)
    if (server_hello.len < 39) return HandshakeError.InvalidServerHello;
    const session_id_len: usize = server_hello[38];
    var pos: usize = 39 + session_id_len;

    // cipher_suite(2) + compression_method(1)
    if (server_hello.len < pos + 3) return HandshakeError.InvalidServerHello;
    pos += 3;

    // Extensions length
    if (server_hello.len < pos + 2) return HandshakeError.InvalidServerHello;
    const ext_len = std.mem.readInt(u16, server_hello[pos..][0..2], .big);
    pos += 2;

    const ext_end = pos + ext_len;
    if (server_hello.len < ext_end) return HandshakeError.InvalidServerHello;

    // Search for key_share extension (type=0x0033)
    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, server_hello[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, server_hello[pos + 2 ..][0..2], .big);
        pos += 4;

        if (ext_type == 0x0033) {
            // key_share ServerHello: group(2) + key_exchange_length(2) + key_exchange
            if (ext_data_len < 36) return HandshakeError.KeyShareMismatch;
            const group = std.mem.readInt(u16, server_hello[pos..][0..2], .big);
            if (group != 0x001D) return HandshakeError.KeyShareMismatch; // not x25519
            const key_len = std.mem.readInt(u16, server_hello[pos + 2 ..][0..2], .big);
            if (key_len != 32) return HandshakeError.KeyShareMismatch;
            return @ptrCast(server_hello[pos + 4 ..][0..32]);
        }

        pos += ext_data_len;
    }

    return HandshakeError.KeyShareMismatch;
}

/// Derive TLS 1.3 Handshake keys from:
/// - client's x25519 private key
/// - server's x25519 public key (from ServerHello key_share)
/// - transcript hash of ClientHello + ServerHello
pub fn deriveHandshakeKeys(
    client_private_key: [32]u8,
    server_public_key: *const [32]u8,
    transcript_hash: [32]u8,
) HandshakeError!HandshakeKeys {
    // ECDHE shared secret
    const shared_secret = crypto.dh.X25519.scalarmult(client_private_key, server_public_key.*) catch
        return HandshakeError.DhFailed;

    // TLS 1.3 key schedule (RFC 8446 §7.1):
    // early_secret = HKDF-Extract(salt=0, IKM=0...0)
    var early_secret: [32]u8 = undefined;
    const zero_salt = [_]u8{0} ** 32;
    const zero_ikm = [_]u8{0} ** 32;
    quic_crypto.hkdfExtract(&early_secret, &zero_salt, &zero_ikm);

    // derive_secret(early_secret, "derived", empty_hash)
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});

    var derived_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&derived_secret, &early_secret, "derived", &empty_hash);

    // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    var handshake_secret: [32]u8 = undefined;
    quic_crypto.hkdfExtract(&handshake_secret, &derived_secret, &shared_secret);

    // client_handshake_traffic_secret = derive_secret(handshake_secret, "c hs traffic", transcript_hash)
    var client_hs_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&client_hs_secret, &handshake_secret, "c hs traffic", &transcript_hash);

    // server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic", transcript_hash)
    var server_hs_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&server_hs_secret, &handshake_secret, "s hs traffic", &transcript_hash);

    var keys: HandshakeKeys = undefined;
    keys.handshake_secret = handshake_secret;
    keys.client_handshake_secret = client_hs_secret;
    keys.server_handshake_secret = server_hs_secret;

    // Derive traffic keys
    quic_crypto.hkdfExpandLabel(&keys.client_key, &client_hs_secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&keys.client_iv, &client_hs_secret, "quic iv", "");
    quic_crypto.hkdfExpandLabel(&keys.client_hp, &client_hs_secret, "quic hp", "");
    quic_crypto.hkdfExpandLabel(&keys.server_key, &server_hs_secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&keys.server_iv, &server_hs_secret, "quic iv", "");
    quic_crypto.hkdfExpandLabel(&keys.server_hp, &server_hs_secret, "quic hp", "");

    return keys;
}

/// Compute SHA-256 transcript hash of ClientHello + ServerHello handshake messages.
pub fn computeTranscriptHash(client_hello: []const u8, server_hello: []const u8) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(client_hello);
    hasher.update(server_hello);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

// ─── Tests ───

test "extractServerKeyShare: valid ServerHello" {
    // Construct a minimal ServerHello with key_share extension
    var sh: [128]u8 = undefined;
    var pos: usize = 0;

    sh[0] = 0x02; // ServerHello type
    pos = 4; // length filled later

    // version (TLS 1.2)
    std.mem.writeInt(u16, sh[pos..][0..2], 0x0303, .big);
    pos += 2;
    // random (32 bytes)
    @memset(sh[pos..][0..32], 0xAA);
    pos += 32;
    // session_id_len = 0
    sh[pos] = 0;
    pos += 1;
    // cipher suite
    std.mem.writeInt(u16, sh[pos..][0..2], 0x1301, .big);
    pos += 2;
    // compression
    sh[pos] = 0;
    pos += 1;

    // extensions
    const ext_start = pos;
    pos += 2; // extension length placeholder

    // key_share extension (type=0x0033)
    std.mem.writeInt(u16, sh[pos..][0..2], 0x0033, .big);
    pos += 2;
    std.mem.writeInt(u16, sh[pos..][0..2], 36, .big); // ext data len: group(2)+len(2)+key(32)
    pos += 2;
    std.mem.writeInt(u16, sh[pos..][0..2], 0x001D, .big); // x25519
    pos += 2;
    std.mem.writeInt(u16, sh[pos..][0..2], 32, .big); // key len
    pos += 2;
    // fake server public key
    for (0..32) |i| {
        sh[pos + i] = @intCast(i + 1);
    }
    pos += 32;

    // Fill extension length
    const ext_len = pos - ext_start - 2;
    std.mem.writeInt(u16, sh[ext_start..][0..2], @intCast(ext_len), .big);

    // Fill handshake length
    const hs_len = pos - 4;
    sh[1] = @intCast((hs_len >> 16) & 0xFF);
    sh[2] = @intCast((hs_len >> 8) & 0xFF);
    sh[3] = @intCast(hs_len & 0xFF);

    const key_ptr = try extractServerKeyShare(sh[0..pos]);
    try std.testing.expectEqual(@as(u8, 1), key_ptr[0]);
    try std.testing.expectEqual(@as(u8, 32), key_ptr[31]);
}

test "extractServerKeyShare: not ServerHello" {
    const data = [_]u8{ 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const result = extractServerKeyShare(&data);
    try std.testing.expectError(HandshakeError.InvalidServerHello, result);
}

test "deriveHandshakeKeys: deterministic" {
    const private_key = [_]u8{0x42} ** 32;
    // Use a valid point (basepoint * private = public)
    const server_public = crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const transcript_hash = [_]u8{0xAB} ** 32;

    const keys1 = try deriveHandshakeKeys(private_key, &server_public, transcript_hash);
    const keys2 = try deriveHandshakeKeys(private_key, &server_public, transcript_hash);

    try std.testing.expectEqualSlices(u8, &keys1.client_key, &keys2.client_key);
    try std.testing.expectEqualSlices(u8, &keys1.server_key, &keys2.server_key);
}

test "deriveHandshakeKeys: different transcripts produce different keys" {
    const private_key = [_]u8{0x42} ** 32;
    const server_public = crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const hash1 = [_]u8{0xAB} ** 32;
    const hash2 = [_]u8{0xCD} ** 32;

    const keys1 = try deriveHandshakeKeys(private_key, &server_public, hash1);
    const keys2 = try deriveHandshakeKeys(private_key, &server_public, hash2);

    try std.testing.expect(!std.mem.eql(u8, &keys1.client_key, &keys2.client_key));
}

test "computeTranscriptHash: deterministic" {
    const ch = "ClientHello data";
    const sh = "ServerHello data";
    const h1 = computeTranscriptHash(ch, sh);
    const h2 = computeTranscriptHash(ch, sh);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computeTranscriptHash: order matters" {
    const a = "message A";
    const b = "message B";
    const h1 = computeTranscriptHash(a, b);
    const h2 = computeTranscriptHash(b, a);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}
