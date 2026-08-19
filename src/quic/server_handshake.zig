const std = @import("std");
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const quic_crypto = @import("crypto.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const tls_messages = @import("tls_messages.zig");
const transport_params_mod = @import("transport_params.zig");
const packet_mod = @import("packet.zig");

pub const ServerHandshakeError = error{
    InvalidClientHello,
    KeyShareMissing,
    DhFailed,
    BufferTooSmall,
    EncodingFailed,
};

/// Parsed ClientHello fields needed for server handshake.
pub const ParsedClientHello = struct {
    random: [32]u8,
    client_public_key: [32]u8,
    server_name: [256]u8,
    server_name_len: u8,
    alpn: [16]u8,
    alpn_len: u8,
};

/// Parse a TLS 1.3 ClientHello to extract key_share and SNI.
/// `ch` is the full handshake message starting with type byte 0x01.
pub fn parseClientHello(ch: []const u8) ServerHandshakeError!ParsedClientHello {
    if (ch.len < 4) return ServerHandshakeError.InvalidClientHello;
    if (ch[0] != 0x01) return ServerHandshakeError.InvalidClientHello;

    const hs_len = (@as(usize, ch[1]) << 16) | (@as(usize, ch[2]) << 8) | ch[3];
    if (ch.len < 4 + hs_len) return ServerHandshakeError.InvalidClientHello;

    var result: ParsedClientHello = .{
        .random = undefined,
        .client_public_key = undefined,
        .server_name = undefined,
        .server_name_len = 0,
        .alpn = undefined,
        .alpn_len = 0,
    };

    // Skip type(1) + length(3) + version(2) = offset 6
    if (ch.len < 38) return ServerHandshakeError.InvalidClientHello;
    @memcpy(&result.random, ch[6..38]);

    // session_id
    var pos: usize = 38;
    if (pos >= ch.len) return ServerHandshakeError.InvalidClientHello;
    const session_id_len: usize = ch[pos];
    pos += 1 + session_id_len;

    // cipher suites
    if (pos + 2 > ch.len) return ServerHandshakeError.InvalidClientHello;
    const suites_len = std.mem.readInt(u16, ch[pos..][0..2], .big);
    pos += 2 + suites_len;

    // compression methods
    if (pos >= ch.len) return ServerHandshakeError.InvalidClientHello;
    const comp_len: usize = ch[pos];
    pos += 1 + comp_len;

    // extensions
    if (pos + 2 > ch.len) return ServerHandshakeError.InvalidClientHello;
    const ext_total = std.mem.readInt(u16, ch[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total;
    if (ext_end > ch.len) return ServerHandshakeError.InvalidClientHello;

    var found_key_share = false;

    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, ch[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, ch[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_data_len > ext_end) break;

        switch (ext_type) {
            0x0000 => {
                // SNI
                if (ext_data_len >= 5) {
                    const name_list_len = std.mem.readInt(u16, ch[pos..][0..2], .big);
                    _ = name_list_len;
                    if (ch[pos + 2] == 0x00) { // host_name type
                        const name_len = std.mem.readInt(u16, ch[pos + 3 ..][0..2], .big);
                        if (pos + 5 + name_len <= ext_end) {
                            const len: u8 = @intCast(@min(name_len, 256));
                            @memcpy(result.server_name[0..len], ch[pos + 5 ..][0..len]);
                            result.server_name_len = len;
                        }
                    }
                }
            },
            0x0033 => {
                // key_share: client_shares_len(2) + entries
                if (ext_data_len >= 4) {
                    var kpos: usize = 0;
                    const shares_len = std.mem.readInt(u16, ch[pos..][0..2], .big);
                    kpos = 2;
                    const shares_end = @min(kpos + shares_len, ext_data_len);
                    while (kpos + 4 <= shares_end) {
                        const group = std.mem.readInt(u16, ch[pos + kpos ..][0..2], .big);
                        const key_len = std.mem.readInt(u16, ch[pos + kpos + 2 ..][0..2], .big);
                        kpos += 4;
                        if (group == 0x001D and key_len == 32 and kpos + 32 <= ext_data_len) {
                            @memcpy(&result.client_public_key, ch[pos + kpos ..][0..32]);
                            found_key_share = true;
                        }
                        kpos += key_len;
                    }
                }
            },
            0x0010 => {
                // ALPN
                if (ext_data_len >= 4) {
                    const proto_len: u8 = ch[pos + 2];
                    if (proto_len <= 16 and pos + 3 + proto_len <= ext_end) {
                        @memcpy(result.alpn[0..proto_len], ch[pos + 3 ..][0..proto_len]);
                        result.alpn_len = proto_len;
                    }
                }
            },
            else => {},
        }
        pos += ext_data_len;
    }

    if (!found_key_share) return ServerHandshakeError.KeyShareMissing;
    return result;
}

/// Server's ephemeral key pair for the handshake.
pub const ServerKeyPair = struct {
    private_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() ServerKeyPair {
        var kp: ServerKeyPair = undefined;
        crypto.random.bytes(&kp.private_key);
        kp.public_key = crypto.dh.X25519.recoverPublicKey(kp.private_key) catch unreachable;
        return kp;
    }
};

/// Build ServerHello TLS handshake message.
/// Returns bytes written to buf (includes type + length header).
pub fn buildServerHello(buf: []u8, server_random: [32]u8, server_public_key: [32]u8) ?usize {
    var pos: usize = 0;

    // type(1) + length(3) — fill length later
    if (buf.len < 4) return null;
    buf[0] = 0x02; // ServerHello
    pos = 4;

    // version: TLS 1.2
    if (buf.len < pos + 2) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0303, .big);
    pos += 2;

    // random
    if (buf.len < pos + 32) return null;
    @memcpy(buf[pos..][0..32], &server_random);
    pos += 32;

    // session_id_len = 0
    if (buf.len < pos + 1) return null;
    buf[pos] = 0;
    pos += 1;

    // cipher suite: TLS_AES_128_GCM_SHA256 (0x1301)
    if (buf.len < pos + 2) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x1301, .big);
    pos += 2;

    // compression method: null
    if (buf.len < pos + 1) return null;
    buf[pos] = 0;
    pos += 1;

    // extensions
    const ext_start = pos;
    if (buf.len < pos + 2) return null;
    pos += 2; // placeholder for extensions length

    // supported_versions extension (0x002B): TLS 1.3
    if (buf.len < pos + 6) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x002B, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2, .big); // ext data len
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0304, .big); // TLS 1.3
    pos += 2;

    // key_share extension (0x0033): x25519 server share
    if (buf.len < pos + 40) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0033, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 36, .big); // ext data len = 2+2+32
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x001D, .big); // x25519 group
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 32, .big); // key length
    pos += 2;
    @memcpy(buf[pos..][0..32], &server_public_key);
    pos += 32;

    // fill extensions length
    std.mem.writeInt(u16, buf[ext_start..][0..2], @intCast(pos - ext_start - 2), .big);

    // fill handshake length
    const body_len = pos - 4;
    buf[1] = @intCast((body_len >> 16) & 0xFF);
    buf[2] = @intCast((body_len >> 8) & 0xFF);
    buf[3] = @intCast(body_len & 0xFF);

    return pos;
}

/// Build EncryptedExtensions with ALPN=h3 and QUIC transport parameters.
pub fn buildEncryptedExtensions(buf: []u8, scid: []const u8) ?usize {
    var pos: usize = 0;

    // type(1) + length(3)
    if (buf.len < 4) return null;
    buf[0] = 0x08; // EncryptedExtensions
    pos = 4;

    // extensions list length placeholder
    const ext_list_start = pos;
    if (buf.len < pos + 2) return null;
    pos += 2;

    // ALPN extension (0x0010): "h3"
    if (buf.len < pos + 11) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0010, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 5, .big); // ext data len
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big); // ALPN list len
    pos += 2;
    buf[pos] = 2; // "h3" length
    pos += 1;
    buf[pos] = 'h';
    buf[pos + 1] = '3';
    pos += 2;

    // QUIC transport params (0x0039)
    var tp_buf: [256]u8 = undefined;
    const tp_len = encodeServerTransportParams(&tp_buf, scid) orelse return null;
    if (buf.len < pos + 4 + tp_len) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0039, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(tp_len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..tp_len], tp_buf[0..tp_len]);
    pos += tp_len;

    // fill extensions list length
    std.mem.writeInt(u16, buf[ext_list_start..][0..2], @intCast(pos - ext_list_start - 2), .big);

    // fill handshake length
    const body_len = pos - 4;
    buf[1] = @intCast((body_len >> 16) & 0xFF);
    buf[2] = @intCast((body_len >> 8) & 0xFF);
    buf[3] = @intCast(body_len & 0xFF);

    return pos;
}

/// Encode minimal server QUIC transport parameters.
fn encodeServerTransportParams(buf: []u8, scid: []const u8) ?usize {
    var pos: usize = 0;

    // initial_max_data (0x04)
    pos += writeTransportParam(buf[pos..], 0x04, 1_048_576) orelse return null;
    // initial_max_stream_data_bidi_local (0x05)
    pos += writeTransportParam(buf[pos..], 0x05, 262_144) orelse return null;
    // initial_max_stream_data_bidi_remote (0x06)
    pos += writeTransportParam(buf[pos..], 0x06, 262_144) orelse return null;
    // initial_max_stream_data_uni (0x07)
    pos += writeTransportParam(buf[pos..], 0x07, 262_144) orelse return null;
    // initial_max_streams_bidi (0x08)
    pos += writeTransportParam(buf[pos..], 0x08, 100) orelse return null;
    // initial_max_streams_uni (0x09)
    pos += writeTransportParam(buf[pos..], 0x09, 100) orelse return null;

    // initial_source_connection_id (0x0f)
    if (scid.len > 0) {
        if (buf.len < pos + 2 + scid.len) return null;
        pos += packet_mod.encodeVarint(buf[pos..], 0x0f) orelse return null;
        pos += packet_mod.encodeVarint(buf[pos..], scid.len) orelse return null;
        @memcpy(buf[pos..][0..scid.len], scid);
        pos += scid.len;
    }

    return pos;
}

fn writeTransportParam(buf: []u8, param_id: u64, value: u64) ?usize {
    var pos: usize = 0;
    pos += packet_mod.encodeVarint(buf[pos..], param_id) orelse return null;
    var val_buf: [8]u8 = undefined;
    const val_len = packet_mod.encodeVarint(&val_buf, value) orelse return null;
    pos += packet_mod.encodeVarint(buf[pos..], val_len) orelse return null;
    @memcpy(buf[pos..][0..val_len], val_buf[0..val_len]);
    pos += val_len;
    return pos;
}

/// Build a minimal Certificate message (self-signed Ed25519 certificate).
/// For testing purposes — uses a raw public key in a minimal X.509-like wrapper.
pub fn buildCertificateMsg(buf: []u8, cert_der: []const u8) ?usize {
    // Certificate message: type(0x0B) + length(3) + cert_request_context_len(1=0) + certs_len(3) + cert_entry
    // cert_entry: cert_data_len(3) + cert_data + extensions_len(2=0)
    const cert_entry_len = 3 + cert_der.len + 2;
    const certs_len = cert_entry_len;
    const body_len = 1 + 3 + certs_len;
    const total = 4 + body_len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    buf[pos] = 0x0B; // Certificate
    pos += 1;
    buf[pos] = @intCast((body_len >> 16) & 0xFF);
    buf[pos + 1] = @intCast((body_len >> 8) & 0xFF);
    buf[pos + 2] = @intCast(body_len & 0xFF);
    pos += 3;

    buf[pos] = 0; // cert_request_context_len = 0
    pos += 1;

    buf[pos] = @intCast((certs_len >> 16) & 0xFF);
    buf[pos + 1] = @intCast((certs_len >> 8) & 0xFF);
    buf[pos + 2] = @intCast(certs_len & 0xFF);
    pos += 3;

    // cert_data_len
    buf[pos] = @intCast((cert_der.len >> 16) & 0xFF);
    buf[pos + 1] = @intCast((cert_der.len >> 8) & 0xFF);
    buf[pos + 2] = @intCast(cert_der.len & 0xFF);
    pos += 3;
    @memcpy(buf[pos..][0..cert_der.len], cert_der);
    pos += cert_der.len;

    // extensions_len = 0
    std.mem.writeInt(u16, buf[pos..][0..2], 0, .big);
    pos += 2;

    return pos;
}

/// Build CertificateVerify message using Ed25519.
/// Signs the transcript hash with the server's Ed25519 private key.
pub fn buildCertificateVerify(buf: []u8, transcript_hash: [32]u8, signing_key: crypto.sign.Ed25519.KeyPair) ?usize {
    // Construct the content to sign per RFC 8446 §4.4.3:
    // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    var sign_content: [130]u8 = undefined;
    @memset(sign_content[0..64], 0x20); // 64 spaces
    const context = "TLS 1.3, server CertificateVerify";
    @memcpy(sign_content[64..][0..context.len], context);
    sign_content[64 + context.len] = 0x00;
    @memcpy(sign_content[64 + context.len + 1 ..][0..32], &transcript_hash);
    const content_len = 64 + context.len + 1 + 32;

    const sig = signing_key.sign(sign_content[0..content_len], null) catch return null;
    const sig_bytes = sig.toBytes();

    // CertificateVerify: type(0x0F) + length(3) + sig_algorithm(2) + sig_len(2) + signature(64)
    const body_len: usize = 2 + 2 + 64;
    const total: usize = 4 + body_len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    buf[pos] = 0x0F; // CertificateVerify
    pos += 1;
    buf[pos] = @intCast((body_len >> 16) & 0xFF);
    buf[pos + 1] = @intCast((body_len >> 8) & 0xFF);
    buf[pos + 2] = @intCast(body_len & 0xFF);
    pos += 3;

    // signature algorithm: ed25519 (0x0807)
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0807, .big);
    pos += 2;
    // signature length
    std.mem.writeInt(u16, buf[pos..][0..2], 64, .big);
    pos += 2;
    // signature
    @memcpy(buf[pos..][0..64], &sig_bytes);
    pos += 64;

    return pos;
}

/// Build server Finished message (RFC 8446 §4.4.4).
pub fn buildServerFinished(buf: []u8, server_handshake_secret: [32]u8, transcript_hash: [32]u8) ?usize {
    const verify_data = tls_messages.generateClientFinished(server_handshake_secret, transcript_hash);
    return tls_messages.buildClientFinishedMsg(verify_data, buf);
}

/// Complete server handshake state: takes parsed CH, produces all keys + flight messages.
pub const ServerHandshakeState = struct {
    server_kp: ServerKeyPair,
    handshake_keys: handshake_mod.HandshakeKeys,
    transcript: tls_messages.TranscriptHash,
    transcript_after_server_finished: [32]u8,
    app_keys: handshake_flight.ApplicationKeysWithSecrets,

    /// Run the server-side handshake from a parsed ClientHello.
    /// `ch_raw` is the full ClientHello message bytes (including type+length).
    /// `cert_der` is the server's certificate in DER format.
    /// `signing_key` is the server's Ed25519 key pair.
    /// Returns: ServerHello in `sh_buf`, handshake flight in `hs_buf`.
    pub fn init(
        ch_raw: []const u8,
        parsed_ch: ParsedClientHello,
        scid: []const u8,
        cert_der: []const u8,
        signing_key: crypto.sign.Ed25519.KeyPair,
        sh_buf: []u8,
        sh_len: *usize,
        hs_buf: []u8,
        hs_len: *usize,
    ) ServerHandshakeError!ServerHandshakeState {
        var state: ServerHandshakeState = undefined;

        // Generate server ephemeral key
        state.server_kp = ServerKeyPair.generate();

        // Build ServerHello
        var server_random: [32]u8 = undefined;
        crypto.random.bytes(&server_random);
        sh_len.* = buildServerHello(sh_buf, server_random, state.server_kp.public_key) orelse
            return ServerHandshakeError.BufferTooSmall;

        // Compute transcript hash(CH + SH) for handshake key derivation
        state.transcript = tls_messages.TranscriptHash.init();
        state.transcript.update(ch_raw);
        state.transcript.update(sh_buf[0..sh_len.*]);
        const transcript_ch_sh = state.transcript.current();

        // Derive handshake keys using server's private + client's public
        state.handshake_keys = handshake_mod.deriveHandshakeKeys(
            state.server_kp.private_key,
            &parsed_ch.client_public_key,
            transcript_ch_sh,
        ) catch return ServerHandshakeError.DhFailed;

        // Build handshake flight: EE + Certificate + CertificateVerify + Finished
        var hpos: usize = 0;

        // EncryptedExtensions
        const ee_len = buildEncryptedExtensions(hs_buf[hpos..], scid) orelse
            return ServerHandshakeError.BufferTooSmall;
        state.transcript.update(hs_buf[hpos..][0..ee_len]);
        hpos += ee_len;

        // Certificate
        const cert_len = buildCertificateMsg(hs_buf[hpos..], cert_der) orelse
            return ServerHandshakeError.BufferTooSmall;
        state.transcript.update(hs_buf[hpos..][0..cert_len]);
        hpos += cert_len;

        // CertificateVerify
        const transcript_before_cv = state.transcript.current();
        const cv_len = buildCertificateVerify(hs_buf[hpos..], transcript_before_cv, signing_key) orelse
            return ServerHandshakeError.BufferTooSmall;
        state.transcript.update(hs_buf[hpos..][0..cv_len]);
        hpos += cv_len;

        // Finished
        const transcript_before_fin = state.transcript.current();
        const fin_len = buildServerFinished(hs_buf[hpos..], state.handshake_keys.server_handshake_secret, transcript_before_fin) orelse
            return ServerHandshakeError.BufferTooSmall;
        state.transcript.update(hs_buf[hpos..][0..fin_len]);
        hpos += fin_len;

        state.transcript_after_server_finished = state.transcript.current();

        // Derive application keys
        state.app_keys = handshake_flight.deriveApplicationKeysWithSecrets(
            state.handshake_keys.handshake_secret,
            state.transcript_after_server_finished,
        );

        hs_len.* = hpos;
        return state;
    }
};

// ─── Tests ───

test "parseClientHello: extract key_share and SNI" {
    const tls_mod = @import("tls.zig");
    const builder = tls_mod.ClientHelloBuilder.init("example.com");
    var ch_buf: [2048]u8 = undefined;
    const ch_len = builder.build(&ch_buf) orelse unreachable;

    const parsed = try parseClientHello(ch_buf[0..ch_len]);
    try std.testing.expectEqualSlices(u8, "example.com", parsed.server_name[0..parsed.server_name_len]);
    try std.testing.expectEqualSlices(u8, &builder.public_key, &parsed.client_public_key);
    try std.testing.expectEqualSlices(u8, "h3", parsed.alpn[0..parsed.alpn_len]);
}

test "buildServerHello: valid encoding" {
    var buf: [256]u8 = undefined;
    const random = [_]u8{0xAA} ** 32;
    const pubkey = [_]u8{0xBB} ** 32;
    const len = buildServerHello(&buf, random, pubkey) orelse unreachable;

    try std.testing.expectEqual(@as(u8, 0x02), buf[0]); // ServerHello type
    // version
    try std.testing.expectEqual(@as(u16, 0x0303), std.mem.readInt(u16, buf[4..6], .big));
    // random
    try std.testing.expectEqualSlices(u8, &random, buf[6..38]);
    try std.testing.expect(len > 40);
}

test "buildEncryptedExtensions: contains ALPN h3" {
    var buf: [512]u8 = undefined;
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const len = buildEncryptedExtensions(&buf, &scid) orelse unreachable;

    try std.testing.expectEqual(@as(u8, 0x08), buf[0]); // EncryptedExtensions type
    // Should contain "h3" somewhere in the payload
    var found_h3 = false;
    for (0..len - 1) |i| {
        if (buf[i] == 'h' and buf[i + 1] == '3') {
            found_h3 = true;
            break;
        }
    }
    try std.testing.expect(found_h3);
}

test "buildCertificateMsg: minimal cert" {
    var buf: [256]u8 = undefined;
    const fake_cert = "FAKECERT";
    const len = buildCertificateMsg(&buf, fake_cert) orelse unreachable;

    try std.testing.expectEqual(@as(u8, 0x0B), buf[0]); // Certificate type
    try std.testing.expect(len == 4 + 1 + 3 + 3 + fake_cert.len + 2);
}

test "buildCertificateVerify: produces valid message" {
    var buf: [256]u8 = undefined;
    const transcript = [_]u8{0xAA} ** 32;
    const kp = crypto.sign.Ed25519.KeyPair.generate();
    const len = buildCertificateVerify(&buf, transcript, kp) orelse unreachable;

    try std.testing.expectEqual(@as(u8, 0x0F), buf[0]); // CertificateVerify type
    try std.testing.expectEqual(@as(usize, 72), len); // 4 header + 2 sig_alg + 2 sig_len + 64 sig
    // sig_algorithm = ed25519 (0x0807)
    try std.testing.expectEqual(@as(u16, 0x0807), std.mem.readInt(u16, buf[4..6], .big));
}

test "ServerHandshakeState: full handshake produces keys" {
    const tls_mod = @import("tls.zig");
    const builder = tls_mod.ClientHelloBuilder.init("test.example.com");
    var ch_buf: [2048]u8 = undefined;
    const ch_len = builder.build(&ch_buf) orelse unreachable;

    const parsed_ch = try parseClientHello(ch_buf[0..ch_len]);
    const signing_kp = crypto.sign.Ed25519.KeyPair.generate();
    const fake_cert = "TESTCERT";
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var sh_buf: [512]u8 = undefined;
    var sh_len: usize = 0;
    var hs_buf: [2048]u8 = undefined;
    var hs_len: usize = 0;

    const state = try ServerHandshakeState.init(
        ch_buf[0..ch_len],
        parsed_ch,
        &scid,
        fake_cert,
        signing_kp,
        &sh_buf,
        &sh_len,
        &hs_buf,
        &hs_len,
    );

    // ServerHello should be valid
    try std.testing.expectEqual(@as(u8, 0x02), sh_buf[0]);
    try std.testing.expect(sh_len > 0);

    // Handshake flight should be non-empty
    try std.testing.expect(hs_len > 0);

    // Application keys should be non-zero
    var all_zero = true;
    for (state.app_keys.keys.server_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
