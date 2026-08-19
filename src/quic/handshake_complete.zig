const std = @import("std");
const quic_crypto = @import("crypto.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const tls_messages = @import("tls_messages.zig");
const packet_mod = @import("packet.zig");
const transport_params_mod = @import("transport_params.zig");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HandshakeCompleteError = error{
    MissingServerHello,
    MissingEncryptedExtensions,
    MissingCertificate,
    MissingCertificateVerify,
    MissingFinished,
    FinishedVerificationFailed,
    CertificateVerifyFailed,
    UnexpectedMessage,
    AlpnMismatch,
    TruncatedData,
};

/// Result of a completed handshake.
pub const HandshakeResult = struct {
    application_keys: handshake_flight.ApplicationKeys,
    client_traffic_secret: [32]u8,
    server_traffic_secret: [32]u8,
    master_secret: [32]u8,
    client_finished_msg: [36]u8,
    client_finished_msg_len: usize,
    transcript_after_server_finished: [32]u8,
    transcript_after_client_finished: [32]u8,
    peer_transport_params: ?transport_params_mod.PeerTransportParams,
    early_data_accepted: bool,
};

/// Orchestrates the full TLS 1.3 handshake message processing.
/// Input: reassembled CRYPTO data from Handshake-level packets.
/// Assumes ServerHello was already processed (at Initial level) and handshake keys derived.
///
/// The handshake CRYPTO stream contains (in order):
/// 1. EncryptedExtensions
/// 2. Certificate (or CertificateRequest + Certificate)
/// 3. CertificateVerify
/// 4. Finished
pub fn processServerHandshakeFlight(
    crypto_data: []const u8,
    handshake_keys: handshake_mod.HandshakeKeys,
    transcript: *tls_messages.TranscriptHash,
) HandshakeCompleteError!HandshakeResult {
    var pos: usize = 0;

    // 1. EncryptedExtensions
    const ee_parsed = tls_messages.parseHandshakeMsg(crypto_data[pos..]) orelse
        return HandshakeCompleteError.MissingEncryptedExtensions;
    if (ee_parsed.msg.msg_type != .encrypted_extensions)
        return HandshakeCompleteError.UnexpectedMessage;

    const ee = tls_messages.parseEncryptedExtensions(ee_parsed.msg.payload) orelse
        return HandshakeCompleteError.MissingEncryptedExtensions;

    // ALPN is mandatory in QUIC (RFC 9001 §8.1)
    const alpn = ee.alpn orelse return HandshakeCompleteError.AlpnMismatch;
    if (!std.mem.eql(u8, alpn, "h3")) return HandshakeCompleteError.AlpnMismatch;

    transcript.update(crypto_data[pos..][0..ee_parsed.consumed]);
    pos += ee_parsed.consumed;

    // 2. Certificate (may be preceded by CertificateRequest, which we skip)
    if (pos >= crypto_data.len) return HandshakeCompleteError.MissingCertificate;
    var next = tls_messages.parseHandshakeMsg(crypto_data[pos..]) orelse
        return HandshakeCompleteError.TruncatedData;

    if (next.msg.msg_type == .certificate_request) {
        transcript.update(crypto_data[pos..][0..next.consumed]);
        pos += next.consumed;
        next = tls_messages.parseHandshakeMsg(crypto_data[pos..]) orelse
            return HandshakeCompleteError.MissingCertificate;
    }

    if (next.msg.msg_type != .certificate)
        return HandshakeCompleteError.MissingCertificate;

    // Extract first certificate DER for CertificateVerify validation
    const cert_der = tls_messages.extractFirstCertDer(next.msg.payload);

    transcript.update(crypto_data[pos..][0..next.consumed]);
    pos += next.consumed;

    // 3. CertificateVerify
    const cv_parsed = tls_messages.parseHandshakeMsg(crypto_data[pos..]) orelse
        return HandshakeCompleteError.MissingCertificateVerify;
    if (cv_parsed.msg.msg_type != .certificate_verify)
        return HandshakeCompleteError.MissingCertificateVerify;

    // Verify CertificateVerify signature (RFC 8446 §4.4.3)
    const der = cert_der orelse return HandshakeCompleteError.MissingCertificate;
    const cv_msg = tls_messages.parseCertificateVerify(cv_parsed.msg.payload) orelse
        return HandshakeCompleteError.MissingCertificateVerify;
    const transcript_before_cv = transcript.current();
    tls_messages.verifyCertificateVerify(transcript_before_cv, der, cv_msg) catch
        return HandshakeCompleteError.CertificateVerifyFailed;

    transcript.update(crypto_data[pos..][0..cv_parsed.consumed]);
    pos += cv_parsed.consumed;

    // 4. Finished
    const fin_parsed = tls_messages.parseHandshakeMsg(crypto_data[pos..]) orelse
        return HandshakeCompleteError.MissingFinished;
    if (fin_parsed.msg.msg_type != .finished)
        return HandshakeCompleteError.MissingFinished;

    // Compute transcript hash up to (but not including) server Finished
    // — that's the current state right before we add server Finished.
    const transcript_before_finished = transcript.current();

    // Verify server Finished
    if (!tls_messages.verifyFinished(
        handshake_keys.server_handshake_secret,
        transcript_before_finished,
        fin_parsed.msg.payload,
    )) {
        return HandshakeCompleteError.FinishedVerificationFailed;
    }

    // Add server Finished to transcript
    transcript.update(crypto_data[pos..][0..fin_parsed.consumed]);
    const transcript_after_server_finished = transcript.current();

    // Generate Client Finished
    const client_verify_data = tls_messages.generateClientFinished(
        handshake_keys.client_handshake_secret,
        transcript_after_server_finished,
    );

    var client_finished_msg: [36]u8 = undefined;
    const cfm_len = tls_messages.buildClientFinishedMsg(client_verify_data, &client_finished_msg) orelse
        return HandshakeCompleteError.TruncatedData;

    // Add Client Finished to transcript for 1-RTT key derivation
    transcript.update(client_finished_msg[0..cfm_len]);
    const transcript_after_client_finished = transcript.current();

    // Derive 1-RTT application keys (RFC 8446 §7.1: uses transcript up to server Finished only)
    const app = handshake_flight.deriveApplicationKeysWithSecrets(
        handshake_keys.handshake_secret,
        transcript_after_server_finished,
    );

    return .{
        .application_keys = app.keys,
        .client_traffic_secret = app.client_secret,
        .server_traffic_secret = app.server_secret,
        .master_secret = app.master_secret,
        .client_finished_msg = client_finished_msg,
        .client_finished_msg_len = cfm_len,
        .transcript_after_server_finished = transcript_after_server_finished,
        .transcript_after_client_finished = transcript_after_client_finished,
        .peer_transport_params = ee.peer_params,
        .early_data_accepted = ee.early_data_accepted,
    };
}

/// Build a QUIC Handshake packet containing the Client Finished CRYPTO frame.
/// Returns bytes written to buf.
pub fn buildClientFinishedPacket(
    buf: []u8,
    client_finished_msg: []const u8,
    packet_number: u64,
    dcid: []const u8,
    scid: []const u8,
    client_key: [16]u8,
    client_iv: [12]u8,
    client_hp: [16]u8,
) ?usize {
    // Build CRYPTO frame: type(0x06) + offset(varint=0) + length(varint) + data
    var crypto_frame: [128]u8 = undefined;
    var cpos: usize = 0;
    crypto_frame[cpos] = 0x06;
    cpos += 1;
    cpos += packet_mod.encodeVarint(crypto_frame[cpos..], 0) orelse return null;
    cpos += packet_mod.encodeVarint(crypto_frame[cpos..], client_finished_msg.len) orelse return null;
    @memcpy(crypto_frame[cpos..][0..client_finished_msg.len], client_finished_msg);
    cpos += client_finished_msg.len;

    // Encode Handshake packet header (unprotected)
    var pos: usize = 0;
    // First byte: 1(form) 1(fixed) 10(handshake) RRKK where KK = pn_length - 1
    const pn_len: u8 = if (packet_number < 256) 0 else if (packet_number < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;
    buf[pos] = 0xE0 | pn_len; // Long header, Handshake type, pn_length
    pos += 1;
    // Version
    std.mem.writeInt(u32, buf[pos..][0..4], packet_mod.QUIC_VERSION_1, .big);
    pos += 4;
    // DCID
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    // SCID
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos..][0..scid.len], scid);
    pos += scid.len;
    // Length: pn_bytes + cpos(payload) + 16(AEAD tag)
    const length_field: u64 = @as(u64, pn_bytes) + cpos + 16;
    pos += packet_mod.encodeVarint(buf[pos..], @intCast(length_field)) orelse return null;
    // Packet number
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((packet_number >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // AAD = everything up to (and including) packet number
    const aad = buf[0..pos];

    // Encrypt payload (CRYPTO frame)
    var ciphertext: [128]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(
        ciphertext[0..cpos],
        &tag,
        crypto_frame[0..cpos],
        client_key,
        client_iv,
        packet_number,
        aad,
    );

    // Append ciphertext + tag
    @memcpy(buf[pos..][0..cpos], ciphertext[0..cpos]);
    pos += cpos;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    // Apply header protection
    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, client_hp);

    return pos;
}

// ─── Tests ───

test "processServerHandshakeFlight: full valid flight with CertificateVerify" {
    const server_hs = @import("server_handshake.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    // Generate server signing key and certificate
    const signing_kp = Ed25519.KeyPair.generate();
    var cert_der_buf: [1024]u8 = undefined;
    const cert_der_len = server_hs.buildSelfSignedCertDer(&cert_der_buf, signing_kp) orelse unreachable;
    const cert_der = cert_der_buf[0..cert_der_len];

    // Set up handshake keys (deterministic values)
    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript_ch_sh = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript_ch_sh) catch unreachable;

    // Build the server's handshake CRYPTO data
    var flight_buf: [2048]u8 = undefined;
    var fpos: usize = 0;

    // EncryptedExtensions with ALPN "h3"
    flight_buf[fpos] = 0x08;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 13;
    std.mem.writeInt(u16, flight_buf[fpos + 4 ..][0..2], 11, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 6 ..][0..2], 0x0010, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 8 ..][0..2], 5, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 10 ..][0..2], 3, .big);
    flight_buf[fpos + 12] = 2;
    flight_buf[fpos + 13] = 'h';
    flight_buf[fpos + 14] = '3';
    const ee_len: usize = 17;
    fpos += ee_len;

    // Certificate with real self-signed cert
    const cert_msg_len = server_hs.buildCertificateMsg(flight_buf[fpos..], cert_der) orelse unreachable;
    fpos += cert_msg_len;

    // Compute transcript hash before CertificateVerify (EE + Cert fed so far)
    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(&fake_transcript_ch_sh);
    transcript.update(flight_buf[0..ee_len]);
    transcript.update(flight_buf[ee_len..][0..cert_msg_len]);
    const transcript_before_cv = transcript.current();

    // CertificateVerify with real Ed25519 signature
    const cv_len = server_hs.buildCertificateVerify(flight_buf[fpos..], transcript_before_cv, signing_kp) orelse unreachable;
    fpos += cv_len;

    // Feed CV to transcript for Finished computation
    transcript.update(flight_buf[ee_len + cert_msg_len ..][0..cv_len]);
    const th_before_fin = transcript.current();

    // Generate correct server Finished
    const server_verify = tls_messages.generateClientFinished(hs_keys.server_handshake_secret, th_before_fin);
    flight_buf[fpos] = 0x14;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 32;
    @memcpy(flight_buf[fpos + 4 ..][0..32], &server_verify);
    fpos += 36;

    // Now process using the function under test
    var test_transcript = tls_messages.TranscriptHash.init();
    test_transcript.update(&fake_transcript_ch_sh);

    const result = try processServerHandshakeFlight(
        flight_buf[0..fpos],
        hs_keys,
        &test_transcript,
    );

    // Verify we got application keys
    var all_zero = true;
    for (result.application_keys.server_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Client and server app keys should differ
    try std.testing.expect(!std.mem.eql(u8, &result.application_keys.client_key, &result.application_keys.server_key));

    // Client finished msg should be 36 bytes
    try std.testing.expectEqual(@as(usize, 36), result.client_finished_msg_len);
    try std.testing.expectEqual(@as(u8, 0x14), result.client_finished_msg[0]);
}

test "processServerHandshakeFlight: empty certificate rejected" {
    // Verify that empty Certificate (certs_len=0) is now rejected
    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript_ch_sh = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript_ch_sh) catch unreachable;

    var flight_buf: [256]u8 = undefined;
    var fpos: usize = 0;

    // EncryptedExtensions with ALPN "h3"
    flight_buf[fpos] = 0x08;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 13;
    std.mem.writeInt(u16, flight_buf[fpos + 4 ..][0..2], 11, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 6 ..][0..2], 0x0010, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 8 ..][0..2], 5, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 10 ..][0..2], 3, .big);
    flight_buf[fpos + 12] = 2;
    flight_buf[fpos + 13] = 'h';
    flight_buf[fpos + 14] = '3';
    fpos += 17;

    // Empty Certificate: certs_len = 0
    flight_buf[fpos] = 0x0B;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 4;
    flight_buf[fpos + 4] = 0; // ctx_len = 0
    flight_buf[fpos + 5] = 0;
    flight_buf[fpos + 6] = 0;
    flight_buf[fpos + 7] = 0; // certs_len = 0
    fpos += 8;

    // CertificateVerify (dummy, should never be reached)
    flight_buf[fpos] = 0x0F;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 4;
    flight_buf[fpos + 4] = 0x08;
    flight_buf[fpos + 5] = 0x07; // ed25519
    flight_buf[fpos + 6] = 0;
    flight_buf[fpos + 7] = 0; // sig_len = 0
    fpos += 8;

    var test_transcript = tls_messages.TranscriptHash.init();
    test_transcript.update(&fake_transcript_ch_sh);

    const result = processServerHandshakeFlight(flight_buf[0..fpos], hs_keys, &test_transcript);
    try std.testing.expectError(HandshakeCompleteError.MissingCertificate, result);
}

test "processServerHandshakeFlight: wrong Finished rejected" {
    const server_hs = @import("server_handshake.zig");
    const Ed25519 = std.crypto.sign.Ed25519;

    const signing_kp = Ed25519.KeyPair.generate();
    var cert_der_buf: [1024]u8 = undefined;
    const cert_der_len = server_hs.buildSelfSignedCertDer(&cert_der_buf, signing_kp) orelse unreachable;
    const cert_der = cert_der_buf[0..cert_der_len];

    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript) catch unreachable;

    var flight_buf: [2048]u8 = undefined;
    var fpos: usize = 0;

    // EE with ALPN "h3"
    flight_buf[fpos] = 0x08;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 13;
    std.mem.writeInt(u16, flight_buf[fpos + 4 ..][0..2], 11, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 6 ..][0..2], 0x0010, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 8 ..][0..2], 5, .big);
    std.mem.writeInt(u16, flight_buf[fpos + 10 ..][0..2], 3, .big);
    flight_buf[fpos + 12] = 2;
    flight_buf[fpos + 13] = 'h';
    flight_buf[fpos + 14] = '3';
    const ee_len: usize = 17;
    fpos += ee_len;

    // Real Certificate
    const cert_msg_len = server_hs.buildCertificateMsg(flight_buf[fpos..], cert_der) orelse unreachable;
    fpos += cert_msg_len;

    // Real CertificateVerify
    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(&fake_transcript);
    transcript.update(flight_buf[0..ee_len]);
    transcript.update(flight_buf[ee_len..][0..cert_msg_len]);
    const transcript_before_cv = transcript.current();
    const cv_len = server_hs.buildCertificateVerify(flight_buf[fpos..], transcript_before_cv, signing_kp) orelse unreachable;
    fpos += cv_len;

    // Bad Finished (wrong verify_data)
    flight_buf[fpos] = 0x14;
    flight_buf[fpos + 1] = 0;
    flight_buf[fpos + 2] = 0;
    flight_buf[fpos + 3] = 32;
    @memset(flight_buf[fpos + 4 ..][0..32], 0xFF);
    fpos += 36;

    var test_transcript = tls_messages.TranscriptHash.init();
    test_transcript.update(&fake_transcript);

    const result = processServerHandshakeFlight(flight_buf[0..fpos], hs_keys, &test_transcript);
    try std.testing.expectError(HandshakeCompleteError.FinishedVerificationFailed, result);
}

test "processServerHandshakeFlight: missing messages" {
    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript) catch unreachable;

    // Empty data
    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(&fake_transcript);
    const result = processServerHandshakeFlight("", hs_keys, &transcript);
    try std.testing.expectError(HandshakeCompleteError.MissingEncryptedExtensions, result);
}

test "processServerHandshakeFlight: ALPN mismatch rejected" {
    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript) catch unreachable;

    // EE with ALPN = "h2" (not h3)
    var flight_buf: [64]u8 = undefined;
    flight_buf[0] = 0x08; // EncryptedExtensions
    flight_buf[1] = 0;
    flight_buf[2] = 0;
    flight_buf[3] = 11; // payload len
    // Extensions list len = 9
    std.mem.writeInt(u16, flight_buf[4..6], 9, .big);
    // ALPN extension
    std.mem.writeInt(u16, flight_buf[6..8], 0x0010, .big);
    std.mem.writeInt(u16, flight_buf[8..10], 5, .big);
    std.mem.writeInt(u16, flight_buf[10..12], 3, .big);
    flight_buf[12] = 2; // "h2" len
    flight_buf[13] = 'h';
    flight_buf[14] = '2';

    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(&fake_transcript);
    const result = processServerHandshakeFlight(flight_buf[0..15], hs_keys, &transcript);
    try std.testing.expectError(HandshakeCompleteError.AlpnMismatch, result);
}

test "processServerHandshakeFlight: ALPN null rejected" {
    const private_key = [_]u8{0x42} ** 32;
    const server_public = std.crypto.dh.X25519.recoverPublicKey([_]u8{0x77} ** 32) catch unreachable;
    const fake_transcript = [_]u8{0xAB} ** 32;
    const hs_keys = handshake_mod.deriveHandshakeKeys(private_key, &server_public, fake_transcript) catch unreachable;

    // EE with no ALPN extension (extensions_len=0)
    var flight_buf: [64]u8 = undefined;
    flight_buf[0] = 0x08;
    flight_buf[1] = 0;
    flight_buf[2] = 0;
    flight_buf[3] = 2;
    flight_buf[4] = 0;
    flight_buf[5] = 0;

    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(&fake_transcript);
    const result = processServerHandshakeFlight(flight_buf[0..6], hs_keys, &transcript);
    try std.testing.expectError(HandshakeCompleteError.AlpnMismatch, result);
}

test "buildClientFinishedPacket: produces valid packet" {
    const finished_msg = [_]u8{0x14} ++ [_]u8{ 0, 0, 32 } ++ [_]u8{0xAB} ** 32;
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;

    var buf: [256]u8 = undefined;
    const pkt_len = buildClientFinishedPacket(&buf, &finished_msg, 0, &dcid, &scid, key, iv, hp) orelse unreachable;

    // Should be a long header Handshake packet
    // After HP, first byte is masked, but form bit is preserved
    try std.testing.expect(pkt_len > 0);
    // Verify it's longer than just the header
    try std.testing.expect(pkt_len > 20);
}
