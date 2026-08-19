const std = @import("std");
const quic_crypto = @import("crypto.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Certificate = std.crypto.Certificate;

/// TLS 1.3 Handshake message types (RFC 8446 §4).
pub const HandshakeType = enum(u8) {
    client_hello = 0x01,
    server_hello = 0x02,
    new_session_ticket = 0x04,
    encrypted_extensions = 0x08,
    certificate = 0x0B,
    certificate_request = 0x0D,
    certificate_verify = 0x0F,
    finished = 0x14,
    key_update = 0x18,
    _,
};

/// Parsed TLS handshake message header.
pub const HandshakeMsg = struct {
    msg_type: HandshakeType,
    length: u24,
    payload: []const u8,
};

/// Parse a TLS handshake message from the CRYPTO stream data.
/// Returns the message and total bytes consumed (4 + length).
pub fn parseHandshakeMsg(data: []const u8) ?ParsedMsg {
    if (data.len < 4) return null;
    const msg_type: HandshakeType = @enumFromInt(data[0]);
    const length: u24 = @intCast((@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3]);
    const total = 4 + @as(usize, length);
    if (data.len < total) return null;
    return .{
        .msg = .{
            .msg_type = msg_type,
            .length = length,
            .payload = data[4..total],
        },
        .consumed = total,
    };
}

pub const ParsedMsg = struct {
    msg: HandshakeMsg,
    consumed: usize,
};

/// State machine for tracking server handshake flight messages.
pub const HandshakeState = enum {
    awaiting_encrypted_extensions,
    awaiting_certificate,
    awaiting_certificate_verify,
    awaiting_finished,
    complete,
};

const transport_params_mod = @import("transport_params.zig");

/// Parsed EncryptedExtensions (RFC 8446 §4.3.1).
/// We extract ALPN and QUIC transport parameters.
pub const EncryptedExtensions = struct {
    alpn: ?[]const u8,
    has_quic_params: bool,
    peer_params: ?transport_params_mod.PeerTransportParams,
    early_data_accepted: bool,
};

/// Parse EncryptedExtensions payload.
pub fn parseEncryptedExtensions(payload: []const u8) ?EncryptedExtensions {
    if (payload.len < 2) return null;
    const ext_len = std.mem.readInt(u16, payload[0..2], .big);
    if (payload.len < 2 + ext_len) return null;

    var result = EncryptedExtensions{ .alpn = null, .has_quic_params = false, .peer_params = null, .early_data_accepted = false };
    var pos: usize = 2;
    const ext_end: usize = 2 + ext_len;

    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, payload[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, payload[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_data_len > ext_end) return null;

        if (ext_type == 0x0010) {
            // ALPN
            if (ext_data_len >= 4) {
                const list_len = std.mem.readInt(u16, payload[pos..][0..2], .big);
                _ = list_len;
                const proto_len: usize = payload[pos + 2];
                if (pos + 3 + proto_len <= ext_end) {
                    result.alpn = payload[pos + 3 ..][0..proto_len];
                }
            }
        } else if (ext_type == 0x0039) {
            // QUIC transport parameters
            result.has_quic_params = true;
            result.peer_params = transport_params_mod.decodePeerParams(payload[pos..][0..ext_data_len]);
        } else if (ext_type == 0x002a) {
            // early_data (RFC 8446 §4.3.1) — presence means server accepted 0-RTT
            result.early_data_accepted = true;
        }

        pos += ext_data_len;
    }

    return result;
}

/// Parsed Certificate message (RFC 8446 §4.4.2).
pub const CertificateMsg = struct {
    certificate_request_context_len: u8,
    cert_count: usize,
    total_certs_len: usize,
};

/// Parse Certificate message payload (extract structure, not validate).
pub fn parseCertificate(payload: []const u8) ?CertificateMsg {
    if (payload.len < 1) return null;
    const ctx_len: usize = payload[0];
    var pos: usize = 1 + ctx_len;

    if (payload.len < pos + 3) return null;
    const certs_len: usize = (@as(usize, payload[pos]) << 16) |
        (@as(usize, payload[pos + 1]) << 8) |
        payload[pos + 2];
    pos += 3;

    // Count certificates (bounds-check against both certs_len and payload.len)
    var cert_count: usize = 0;
    var cpos: usize = 0;
    while (cpos + 3 <= certs_len) {
        if (pos + cpos + 3 > payload.len) break;
        const cert_data_len: usize = (@as(usize, payload[pos + cpos]) << 16) |
            (@as(usize, payload[pos + cpos + 1]) << 8) |
            payload[pos + cpos + 2];
        cpos += 3 + cert_data_len;
        if (cpos + 2 > certs_len) break;
        if (pos + cpos + 2 > payload.len) break;
        const ext_len = std.mem.readInt(u16, payload[pos + cpos ..][0..2], .big);
        cpos += 2 + ext_len;
        cert_count += 1;
    }

    return .{
        .certificate_request_context_len = @intCast(ctx_len),
        .cert_count = cert_count,
        .total_certs_len = certs_len,
    };
}

/// Verify the server's Finished message (RFC 8446 §4.4.4).
/// finished_key = HKDF-Expand-Label(server_handshake_traffic_secret, "finished", "", 32)
/// verify_data = HMAC-SHA256(finished_key, transcript_hash)
pub fn verifyFinished(
    server_handshake_secret: [32]u8,
    transcript_hash: [32]u8,
    received_verify_data: []const u8,
) bool {
    if (received_verify_data.len != 32) return false;

    var finished_key: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&finished_key, &server_handshake_secret, "finished", "");

    var expected: [32]u8 = undefined;
    var hmac = HmacSha256.init(&finished_key);
    hmac.update(&transcript_hash);
    hmac.final(&expected);

    return std.crypto.timing_safe.eql([32]u8, expected, received_verify_data[0..32].*);
}

/// Generate the Client Finished message (RFC 8446 §4.4.4).
/// Returns the 32-byte verify_data.
pub fn generateClientFinished(
    client_handshake_secret: [32]u8,
    transcript_hash: [32]u8,
) [32]u8 {
    var finished_key: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&finished_key, &client_handshake_secret, "finished", "");

    var verify_data: [32]u8 = undefined;
    var hmac = HmacSha256.init(&finished_key);
    hmac.update(&transcript_hash);
    hmac.final(&verify_data);

    return verify_data;
}

/// Build the Client Finished TLS handshake message (type + length + verify_data).
pub fn buildClientFinishedMsg(verify_data: [32]u8, buf: []u8) ?usize {
    if (buf.len < 36) return null; // 1(type) + 3(length) + 32(verify_data)
    buf[0] = @intFromEnum(HandshakeType.finished);
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 32;
    @memcpy(buf[4..36], &verify_data);
    return 36;
}

/// TLS 1.3 SignatureScheme (RFC 8446 §4.2.3).
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    _,
};

/// Parsed CertificateVerify payload.
pub const CertificateVerifyMsg = struct {
    scheme: SignatureScheme,
    signature: []const u8,
};

/// Parse CertificateVerify message payload (RFC 8446 §4.4.3).
/// Payload layout: signature_scheme(2) + signature_length(2) + signature(N).
pub fn parseCertificateVerify(payload: []const u8) ?CertificateVerifyMsg {
    if (payload.len < 4) return null;
    const scheme: SignatureScheme = @enumFromInt(std.mem.readInt(u16, payload[0..2], .big));
    const sig_len: usize = std.mem.readInt(u16, payload[2..4], .big);
    if (payload.len < 4 + sig_len) return null;
    return .{
        .scheme = scheme,
        .signature = payload[4..][0..sig_len],
    };
}

/// Extract the first certificate's DER bytes from a Certificate message payload.
/// Returns null if the payload is malformed or has no certificates.
pub fn extractFirstCertDer(payload: []const u8) ?[]const u8 {
    if (payload.len < 1) return null;
    const ctx_len: usize = payload[0];
    var pos: usize = 1 + ctx_len;
    if (payload.len < pos + 3) return null;
    // certificate list length
    pos += 3;
    // first cert entry: cert_data_len(3) + cert_data
    if (payload.len < pos + 3) return null;
    const cert_data_len: usize = (@as(usize, payload[pos]) << 16) |
        (@as(usize, payload[pos + 1]) << 8) |
        payload[pos + 2];
    pos += 3;
    if (payload.len < pos + cert_data_len) return null;
    return payload[pos..][0..cert_data_len];
}

pub const CertificateVerifyError = error{
    InvalidSignature,
    UnsupportedScheme,
    InvalidCertificate,
    CertificatePublicKeyInvalid,
};

/// Verify the server's CertificateVerify signature (RFC 8446 §4.4.3).
/// transcript_hash: SHA-256 hash of all handshake messages up to (but not including) CertificateVerify.
/// cert_der: DER-encoded X.509 certificate (first cert from the Certificate message).
/// cv: parsed CertificateVerify message.
pub fn verifyCertificateVerify(
    transcript_hash: [32]u8,
    cert_der: []const u8,
    cv: CertificateVerifyMsg,
) CertificateVerifyError!void {
    // Parse X.509 certificate to extract public key
    const cert = Certificate{ .buffer = cert_der, .index = @intCast(0) };
    const parsed = cert.parse() catch return CertificateVerifyError.InvalidCertificate;
    const pub_key = parsed.pubKey();
    const pub_key_algo = parsed.pub_key_algo;

    // Construct the content that was signed: 64 spaces + context string + 0x00 + transcript_hash
    const context = "TLS 1.3, server CertificateVerify";
    const content_len = 64 + context.len + 1 + 32;
    var sign_content: [content_len]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    @memcpy(sign_content[64..][0..context.len], context);
    sign_content[64 + context.len] = 0x00;
    @memcpy(sign_content[64 + context.len + 1 ..][0..32], &transcript_hash);

    switch (cv.scheme) {
        .ed25519 => {
            if (pub_key_algo != .curveEd25519) return CertificateVerifyError.InvalidSignature;
            const Ed25519 = std.crypto.sign.Ed25519;
            if (cv.signature.len != Ed25519.Signature.encoded_length) return CertificateVerifyError.InvalidSignature;
            if (pub_key.len != Ed25519.PublicKey.encoded_length) return CertificateVerifyError.CertificatePublicKeyInvalid;
            const sig = Ed25519.Signature.fromBytes(cv.signature[0..Ed25519.Signature.encoded_length].*);
            const key = Ed25519.PublicKey.fromBytes(pub_key[0..Ed25519.PublicKey.encoded_length].*) catch
                return CertificateVerifyError.CertificatePublicKeyInvalid;
            sig.verify(&sign_content, key) catch return CertificateVerifyError.InvalidSignature;
        },
        .ecdsa_secp256r1_sha256 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return CertificateVerifyError.InvalidSignature;
            const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const sig = EcdsaP256Sha256.Signature.fromDer(cv.signature) catch
                return CertificateVerifyError.InvalidSignature;
            const key = EcdsaP256Sha256.PublicKey.fromSec1(pub_key) catch
                return CertificateVerifyError.CertificatePublicKeyInvalid;
            sig.verify(&sign_content, key) catch return CertificateVerifyError.InvalidSignature;
        },
        .ecdsa_secp384r1_sha384 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return CertificateVerifyError.InvalidSignature;
            const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
            const sig = EcdsaP384Sha384.Signature.fromDer(cv.signature) catch
                return CertificateVerifyError.InvalidSignature;
            const key = EcdsaP384Sha384.PublicKey.fromSec1(pub_key) catch
                return CertificateVerifyError.CertificatePublicKeyInvalid;
            sig.verify(&sign_content, key) catch return CertificateVerifyError.InvalidSignature;
        },
        .rsa_pss_rsae_sha256 => {
            if (pub_key_algo != .rsaEncryption) return CertificateVerifyError.InvalidSignature;
            verifyRsaPss(pub_key, cv.signature, &sign_content, .sha256) catch
                return CertificateVerifyError.InvalidSignature;
        },
        .rsa_pss_rsae_sha384 => {
            if (pub_key_algo != .rsaEncryption) return CertificateVerifyError.InvalidSignature;
            verifyRsaPss(pub_key, cv.signature, &sign_content, .sha384) catch
                return CertificateVerifyError.InvalidSignature;
        },
        .rsa_pss_rsae_sha512 => {
            if (pub_key_algo != .rsaEncryption) return CertificateVerifyError.InvalidSignature;
            verifyRsaPss(pub_key, cv.signature, &sign_content, .sha512) catch
                return CertificateVerifyError.InvalidSignature;
        },
        else => return CertificateVerifyError.UnsupportedScheme,
    }
}

const RsaHashType = enum { sha256, sha384, sha512 };

fn verifyRsaPss(pub_key_der: []const u8, sig_bytes: []const u8, message: []const u8, hash_type: RsaHashType) !void {
    const rsa = Certificate.rsa;
    const components = try rsa.PublicKey.parseDer(pub_key_der);
    const modulus = components.modulus;

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const key: rsa.PublicKey = try .fromBytes(components.exponent, modulus);
            switch (hash_type) {
                .sha256 => {
                    const sig = rsa.PSSSignature.fromBytes(modulus_len, sig_bytes);
                    try rsa.PSSSignature.verify(modulus_len, sig, message, key, Sha256);
                },
                .sha384 => {
                    const sig = rsa.PSSSignature.fromBytes(modulus_len, sig_bytes);
                    try rsa.PSSSignature.verify(modulus_len, sig, message, key, Sha384);
                },
                .sha512 => {
                    const sig = rsa.PSSSignature.fromBytes(modulus_len, sig_bytes);
                    try rsa.PSSSignature.verify(modulus_len, sig, message, key, std.crypto.hash.sha2.Sha512);
                },
            }
        },
        else => return error.TlsBadRsaSignatureBitCount,
    }
}

/// Incremental transcript hash computation.
/// Tracks SHA-256 state across multiple handshake messages.
pub const TranscriptHash = struct {
    hasher: Sha256,

    pub fn init() TranscriptHash {
        return .{ .hasher = Sha256.init(.{}) };
    }

    /// Feed a complete TLS handshake message (including type+length header).
    pub fn update(self: *TranscriptHash, msg: []const u8) void {
        self.hasher.update(msg);
    }

    /// Get the current transcript hash without consuming the state.
    pub fn current(self: *const TranscriptHash) [32]u8 {
        // Clone the hasher to get intermediate value
        var clone = self.hasher;
        var result: [32]u8 = undefined;
        clone.final(&result);
        return result;
    }
};

// ─── Tests ───

test "parseHandshakeMsg: EncryptedExtensions" {
    // type(0x08) + length(3 bytes, = 4) + 4 bytes payload
    const data = [_]u8{ 0x08, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
    const result = parseHandshakeMsg(&data) orelse unreachable;
    try std.testing.expectEqual(HandshakeType.encrypted_extensions, result.msg.msg_type);
    try std.testing.expectEqual(@as(u24, 4), result.msg.length);
    try std.testing.expectEqual(@as(usize, 8), result.consumed);
    try std.testing.expectEqual(@as(usize, 4), result.msg.payload.len);
}

test "parseHandshakeMsg: Finished" {
    var data: [36]u8 = undefined;
    data[0] = 0x14; // Finished
    data[1] = 0;
    data[2] = 0;
    data[3] = 32; // length = 32
    @memset(data[4..36], 0xAB);

    const result = parseHandshakeMsg(&data) orelse unreachable;
    try std.testing.expectEqual(HandshakeType.finished, result.msg.msg_type);
    try std.testing.expectEqual(@as(u24, 32), result.msg.length);
    try std.testing.expectEqual(@as(usize, 36), result.consumed);
}

test "parseHandshakeMsg: truncated" {
    const data = [_]u8{ 0x08, 0x00, 0x00, 0x10 }; // says 16 bytes but only header
    try std.testing.expect(parseHandshakeMsg(&data) == null);
}

test "verifyFinished/generateClientFinished: symmetric" {
    const secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0xAB} ** 32;

    // Generate using same logic
    const verify_data = generateClientFinished(secret, transcript);

    // Verify should pass with same inputs
    try std.testing.expect(verifyFinished(secret, transcript, &verify_data));
}

test "verifyFinished: wrong data rejected" {
    const secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0xAB} ** 32;

    var bad_data = [_]u8{0xFF} ** 32;
    try std.testing.expect(!verifyFinished(secret, transcript, &bad_data));
}

test "verifyFinished: wrong transcript rejected" {
    const secret = [_]u8{0x42} ** 32;
    const transcript1 = [_]u8{0xAB} ** 32;
    const transcript2 = [_]u8{0xCD} ** 32;

    const verify_data = generateClientFinished(secret, transcript1);
    try std.testing.expect(!verifyFinished(secret, transcript2, &verify_data));
}

test "verifyFinished: wrong length rejected" {
    const secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0xAB} ** 32;
    const short = [_]u8{0x00} ** 16;
    try std.testing.expect(!verifyFinished(secret, transcript, &short));
}

test "buildClientFinishedMsg" {
    const verify_data = [_]u8{0xDE} ** 32;
    var buf: [64]u8 = undefined;
    const len = buildClientFinishedMsg(verify_data, &buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 36), len);
    try std.testing.expectEqual(@as(u8, 0x14), buf[0]); // Finished type
    try std.testing.expectEqual(@as(u8, 32), buf[3]); // length
    try std.testing.expectEqualSlices(u8, &verify_data, buf[4..36]);
}

test "TranscriptHash: incremental updates" {
    var th = TranscriptHash.init();
    th.update("ClientHello");
    const h1 = th.current();
    th.update("ServerHello");
    const h2 = th.current();

    // h1 != h2
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));

    // h2 should equal hash(ClientHello || ServerHello)
    var direct = Sha256.init(.{});
    direct.update("ClientHello");
    direct.update("ServerHello");
    var expected: [32]u8 = undefined;
    direct.final(&expected);
    try std.testing.expectEqualSlices(u8, &expected, &h2);
}

test "TranscriptHash: current() does not consume state" {
    var th = TranscriptHash.init();
    th.update("message");
    const h1 = th.current();
    const h2 = th.current();
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "parseEncryptedExtensions: with ALPN" {
    // extensions_len(2) + extension(type=0x0010, ALPN with "h3")
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    // extensions total length
    std.mem.writeInt(u16, buf[pos..][0..2], 9, .big); // ext list = 9 bytes
    pos += 2;
    // ALPN extension
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0010, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 5, .big); // ext data len = 5
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big); // ALPN list len = 3
    pos += 2;
    buf[pos] = 2; // protocol name len
    pos += 1;
    buf[pos] = 'h';
    buf[pos + 1] = '3';
    pos += 2;

    const ee = parseEncryptedExtensions(buf[0..pos]) orelse unreachable;
    try std.testing.expect(ee.alpn != null);
    try std.testing.expectEqualStrings("h3", ee.alpn.?);
}

test "parseEncryptedExtensions: with QUIC transport params" {
    var buf: [16]u8 = undefined;
    // extensions total length = 8
    std.mem.writeInt(u16, buf[0..2], 8, .big);
    // QUIC transport params (0x0039)
    std.mem.writeInt(u16, buf[2..4], 0x0039, .big);
    std.mem.writeInt(u16, buf[4..6], 4, .big); // ext data len
    buf[6] = 0x04;
    buf[7] = 0x01;
    buf[8] = 0x00;
    buf[9] = 0x00; // some param

    const ee = parseEncryptedExtensions(buf[0..10]) orelse unreachable;
    try std.testing.expect(ee.has_quic_params);
}

test "parseEncryptedExtensions: with early_data accepted" {
    var buf: [12]u8 = undefined;
    // extensions total length = 8 (ALPN not needed; just early_data 0x002a)
    std.mem.writeInt(u16, buf[0..2], 4, .big); // total ext len = 4
    std.mem.writeInt(u16, buf[2..4], 0x002a, .big); // early_data type
    std.mem.writeInt(u16, buf[4..6], 0, .big); // ext data len = 0 (empty in EE)

    const ee = parseEncryptedExtensions(buf[0..6]) orelse unreachable;
    try std.testing.expect(ee.early_data_accepted);
}

test "parseEncryptedExtensions: no early_data means rejected" {
    var buf: [16]u8 = undefined;
    // Only QUIC transport params, no early_data
    std.mem.writeInt(u16, buf[0..2], 8, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0039, .big);
    std.mem.writeInt(u16, buf[4..6], 4, .big);
    buf[6] = 0x04;
    buf[7] = 0x01;
    buf[8] = 0x00;
    buf[9] = 0x00;

    const ee = parseEncryptedExtensions(buf[0..10]) orelse unreachable;
    try std.testing.expect(!ee.early_data_accepted);
}

test "parseCertificate: single cert" {
    // cert_request_context_len(1=0) + certs_len(3) + cert_data_len(3) + cert(3 bytes) + ext_len(2=0)
    const payload = [_]u8{
        0x00, // context len = 0
        0x00, 0x00, 0x08, // certs_len = 8
        0x00, 0x00, 0x03, // cert_data_len = 3
        0xDE, 0xAD, 0xBE, // cert data
        0x00, 0x00, // extensions len = 0
    };
    const cert = parseCertificate(&payload) orelse unreachable;
    try std.testing.expectEqual(@as(u8, 0), cert.certificate_request_context_len);
    try std.testing.expectEqual(@as(usize, 1), cert.cert_count);
}

test "parseCertificateVerify: valid parse" {
    var payload: [68]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x0807, .big); // ed25519
    std.mem.writeInt(u16, payload[2..4], 64, .big); // sig_len = 64
    @memset(payload[4..68], 0xAB); // fake signature

    const cv = parseCertificateVerify(&payload) orelse unreachable;
    try std.testing.expectEqual(SignatureScheme.ed25519, cv.scheme);
    try std.testing.expectEqual(@as(usize, 64), cv.signature.len);
}

test "verifyCertificateVerify: Ed25519 roundtrip" {
    const server_hs = @import("server_handshake.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    // Generate a key pair and build a valid self-signed cert
    const kp = Ed25519.KeyPair.generate();
    var cert_buf: [1024]u8 = undefined;
    const cert_len = server_hs.buildSelfSignedCertDer(&cert_buf, kp) orelse unreachable;
    const cert_der = cert_buf[0..cert_len];

    // Build CertificateVerify (same as server would)
    const transcript_hash = [_]u8{0x42} ** 32;
    var cv_buf: [256]u8 = undefined;
    const cv_total = server_hs.buildCertificateVerify(&cv_buf, transcript_hash, kp) orelse unreachable;

    // Parse the CertificateVerify payload (skip type+length header = 4 bytes)
    const cv_payload = cv_buf[4..cv_total];
    const cv_msg = parseCertificateVerify(cv_payload) orelse unreachable;

    // Verify should succeed
    try verifyCertificateVerify(transcript_hash, cert_der, cv_msg);
}

test "verifyCertificateVerify: wrong transcript rejected" {
    const server_hs = @import("server_handshake.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    const kp = Ed25519.KeyPair.generate();
    var cert_buf: [1024]u8 = undefined;
    const cert_len = server_hs.buildSelfSignedCertDer(&cert_buf, kp) orelse unreachable;
    const cert_der = cert_buf[0..cert_len];

    const transcript_hash = [_]u8{0x42} ** 32;
    var cv_buf: [256]u8 = undefined;
    const cv_total = server_hs.buildCertificateVerify(&cv_buf, transcript_hash, kp) orelse unreachable;

    const cv_payload = cv_buf[4..cv_total];
    const cv_msg = parseCertificateVerify(cv_payload) orelse unreachable;

    // Use wrong transcript — should fail
    const wrong_transcript = [_]u8{0xFF} ** 32;
    const result = verifyCertificateVerify(wrong_transcript, cert_der, cv_msg);
    try std.testing.expectError(CertificateVerifyError.InvalidSignature, result);
}
