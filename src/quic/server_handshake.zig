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
    // PSK extension (0x0029) for 0-RTT resumption
    has_psk: bool,
    psk_identity: [256]u8,
    psk_identity_len: u16,
    psk_binder: [32]u8,
    obfuscated_ticket_age: u32,
    // early_data extension (0x002a) present
    has_early_data: bool,
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
        .has_psk = false,
        .psk_identity = undefined,
        .psk_identity_len = 0,
        .psk_binder = undefined,
        .obfuscated_ticket_age = 0,
        .has_early_data = false,
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
            0x0029 => {
                // pre_shared_key (RFC 8446 §4.2.11)
                // identities_len(2) + [identity_len(2) + identity + obfuscated_ticket_age(4)] + binders_len(2) + [binder_len(1) + binder]
                if (ext_data_len >= 6) {
                    const identities_len = std.mem.readInt(u16, ch[pos..][0..2], .big);
                    if (identities_len >= 6 and 2 + identities_len <= ext_data_len) {
                        const id_len = std.mem.readInt(u16, ch[pos + 2 ..][0..2], .big);
                        if (id_len <= 256 and 2 + 2 + id_len + 4 <= 2 + identities_len) {
                            const id_start = pos + 4;
                            @memcpy(result.psk_identity[0..id_len], ch[id_start..][0..id_len]);
                            result.psk_identity_len = id_len;
                            result.obfuscated_ticket_age = std.mem.readInt(u32, ch[id_start + id_len ..][0..4], .big);
                            // Parse first binder
                            const binders_offset = pos + 2 + identities_len;
                            if (binders_offset + 2 <= pos + ext_data_len) {
                                const binders_len = std.mem.readInt(u16, ch[binders_offset..][0..2], .big);
                                _ = binders_len;
                                if (binders_offset + 3 <= pos + ext_data_len) {
                                    const binder_len = ch[binders_offset + 2];
                                    if (binder_len == 32 and binders_offset + 3 + 32 <= pos + ext_data_len) {
                                        @memcpy(&result.psk_binder, ch[binders_offset + 3 ..][0..32]);
                                        result.has_psk = true;
                                    }
                                }
                            }
                        }
                    }
                }
            },
            0x002a => {
                // early_data indication (empty in ClientHello)
                result.has_early_data = true;
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

/// Build a minimal self-signed X.509 DER certificate for Ed25519.
/// Returns the DER bytes written to `out`. This certificate is minimal but parseable
/// by std.crypto.Certificate.parse(), containing the Ed25519 public key.
pub fn buildSelfSignedCertDer(out: []u8, key_pair: crypto.sign.Ed25519.KeyPair) ?usize {
    const pub_key = key_pair.public_key.bytes;

    // Minimal X.509 v3 structure (DER encoded):
    // SEQUENCE (Certificate) {
    //   SEQUENCE (TBSCertificate) {
    //     [0] EXPLICIT INTEGER 2 (version v3)
    //     INTEGER 1 (serialNumber)
    //     SEQUENCE { OID 1.3.101.112 (Ed25519) } (signature algorithm)
    //     SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "localhost" } } } (issuer)
    //     SEQUENCE { UTCTime "250101000000Z", UTCTime "350101000000Z" } (validity)
    //     SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "localhost" } } } (subject)
    //     SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING <pub_key> } (subjectPublicKeyInfo)
    //   }
    //   SEQUENCE { OID 1.3.101.112 } (signatureAlgorithm)
    //   BIT STRING <signature>
    // }

    // Pre-built DER fragments (everything except the public key and signature)
    const ed25519_oid = [_]u8{ 0x06, 0x03, 0x2B, 0x65, 0x70 }; // OID 1.3.101.112
    const cn_oid = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 }; // OID 2.5.4.3 (commonName)
    const cn_value = [_]u8{ 0x0C, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't' }; // UTF8String "localhost"

    // Build issuer/subject: SEQUENCE { SET { SEQUENCE { cn_oid, cn_value } } }
    const cn_seq_len = cn_oid.len + cn_value.len;
    const cn_seq = [_]u8{ 0x30, cn_seq_len } ++ cn_oid ++ cn_value;
    const cn_set = [_]u8{ 0x31, cn_seq.len } ++ cn_seq;
    const name = [_]u8{ 0x30, cn_set.len } ++ cn_set;

    // Validity: SEQUENCE { UTCTime "250101000000Z", UTCTime "350101000000Z" }
    const not_before = [_]u8{ 0x17, 0x0D } ++ "250101000000Z".*;
    const not_after = [_]u8{ 0x17, 0x0D } ++ "350101000000Z".*;
    const validity = [_]u8{ 0x30, not_before.len + not_after.len } ++ not_before ++ not_after;

    // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { ed25519_oid }, BIT STRING(pub_key) }
    const algo_seq = [_]u8{ 0x30, ed25519_oid.len } ++ ed25519_oid;
    const bit_string_hdr = [_]u8{ 0x03, 33, 0x00 }; // BIT STRING: 33 bytes (1 unused_bits + 32 pub_key)
    const spki_inner_len = algo_seq.len + bit_string_hdr.len + 32;
    const spki_hdr = [_]u8{ 0x30, @intCast(spki_inner_len) };

    // Version: [0] EXPLICIT { INTEGER 2 }
    const version = [_]u8{ 0xA0, 0x03, 0x02, 0x01, 0x02 };
    // Serial number: INTEGER 1
    const serial = [_]u8{ 0x02, 0x01, 0x01 };
    // Signature algorithm in TBS: SEQUENCE { ed25519_oid }
    const sig_algo = [_]u8{ 0x30, ed25519_oid.len } ++ ed25519_oid;

    // TBSCertificate length
    const tbs_content_len = version.len + serial.len + sig_algo.len + name.len + validity.len + name.len + spki_hdr.len + algo_seq.len + bit_string_hdr.len + 32;

    // Build TBS
    var pos: usize = 0;
    if (out.len < 4 + tbs_content_len + 200) return null; // rough check

    // Outer SEQUENCE placeholder (fill length later)
    const outer_start = pos;
    out[pos] = 0x30;
    pos += 1;
    // We'll use 2-byte length encoding (0x82 + 2 bytes)
    out[pos] = 0x82;
    pos += 3; // skip 2 bytes for length, fill later

    // TBSCertificate SEQUENCE
    const tbs_start = pos;
    out[pos] = 0x30;
    pos += 1;
    if (tbs_content_len < 128) {
        out[pos] = @intCast(tbs_content_len);
        pos += 1;
    } else {
        out[pos] = 0x81;
        pos += 1;
        out[pos] = @intCast(tbs_content_len);
        pos += 1;
    }
    const tbs_body_start = pos;

    @memcpy(out[pos..][0..version.len], &version);
    pos += version.len;
    @memcpy(out[pos..][0..serial.len], &serial);
    pos += serial.len;
    @memcpy(out[pos..][0..sig_algo.len], &sig_algo);
    pos += sig_algo.len;
    @memcpy(out[pos..][0..name.len], &name);
    pos += name.len;
    @memcpy(out[pos..][0..validity.len], &validity);
    pos += validity.len;
    @memcpy(out[pos..][0..name.len], &name);
    pos += name.len;
    @memcpy(out[pos..][0..spki_hdr.len], &spki_hdr);
    pos += spki_hdr.len;
    @memcpy(out[pos..][0..algo_seq.len], &algo_seq);
    pos += algo_seq.len;
    @memcpy(out[pos..][0..bit_string_hdr.len], &bit_string_hdr);
    pos += bit_string_hdr.len;
    @memcpy(out[pos..][0..32], &pub_key);
    pos += 32;

    _ = tbs_body_start;
    const tbs_end = pos;
    const tbs_bytes = out[tbs_start..tbs_end];

    // signatureAlgorithm SEQUENCE { ed25519_oid }
    @memcpy(out[pos..][0..sig_algo.len], &sig_algo);
    pos += sig_algo.len;

    // Sign the TBS
    const sig = key_pair.sign(tbs_bytes, null) catch return null;
    const sig_bytes = sig.toBytes();

    // BIT STRING for signature: 0x03 + length + 0x00 (unused bits) + signature
    out[pos] = 0x03;
    pos += 1;
    out[pos] = 65; // 1 + 64
    pos += 1;
    out[pos] = 0x00; // unused bits
    pos += 1;
    @memcpy(out[pos..][0..64], &sig_bytes);
    pos += 64;

    // Fill outer SEQUENCE length
    const outer_content_len = pos - (outer_start + 4); // content after the 4-byte header (0x30, 0x82, HI, LO)
    out[outer_start + 2] = @intCast((outer_content_len >> 8) & 0xFF);
    out[outer_start + 3] = @intCast(outer_content_len & 0xFF);

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

// ─── NewSessionTicket (RFC 8446 §4.6.1) ───

/// Build a NewSessionTicket TLS message for 0-RTT resumption.
/// Returns the message bytes (handshake type + length + body).
/// The ticket value is a random opaque blob; the server must remember
/// the mapping from ticket → PSK externally (via TicketStore or equivalent).
pub fn buildNewSessionTicket(
    buf: []u8,
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket_value: []const u8,
    max_early_data_size: u32,
) ?usize {
    // Handshake type (0x04 = NewSessionTicket) + 3-byte length
    if (buf.len < 4) return null;
    buf[0] = 0x04;
    var pos: usize = 4; // length filled later

    // ticket_lifetime (4)
    if (buf.len < pos + 4) return null;
    std.mem.writeInt(u32, buf[pos..][0..4], ticket_lifetime, .big);
    pos += 4;

    // ticket_age_add (4)
    if (buf.len < pos + 4) return null;
    std.mem.writeInt(u32, buf[pos..][0..4], ticket_age_add, .big);
    pos += 4;

    // ticket_nonce_len (1) + ticket_nonce
    if (buf.len < pos + 1 + ticket_nonce.len) return null;
    buf[pos] = @intCast(ticket_nonce.len);
    pos += 1;
    @memcpy(buf[pos..][0..ticket_nonce.len], ticket_nonce);
    pos += ticket_nonce.len;

    // ticket_len (2) + ticket
    if (buf.len < pos + 2 + ticket_value.len) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ticket_value.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..ticket_value.len], ticket_value);
    pos += ticket_value.len;

    // extensions: early_data (0x002a) with max_early_data_size
    const ext_data: usize = if (max_early_data_size > 0) 8 else 0;
    if (buf.len < pos + 2 + ext_data) return null;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data), .big);
    pos += 2;
    if (max_early_data_size > 0) {
        std.mem.writeInt(u16, buf[pos..][0..2], 0x002a, .big);
        pos += 2;
        std.mem.writeInt(u16, buf[pos..][0..2], 4, .big);
        pos += 2;
        std.mem.writeInt(u32, buf[pos..][0..4], max_early_data_size, .big);
        pos += 4;
    }

    // Fill handshake length (3 bytes big-endian)
    const body_len = pos - 4;
    buf[1] = @intCast((body_len >> 16) & 0xFF);
    buf[2] = @intCast((body_len >> 8) & 0xFF);
    buf[3] = @intCast(body_len & 0xFF);

    return pos;
}

/// Server-side ticket store for 0-RTT validation.
/// Maps opaque ticket values to the PSK needed to derive early keys.
pub const ServerTicketStore = struct {
    entries: [MAX_ENTRIES]?TicketEntry,
    count: usize,

    const MAX_ENTRIES = 16;

    pub const TicketEntry = struct {
        ticket: [256]u8,
        ticket_len: u16,
        psk: [32]u8,
        issued_at_ms: i64,
        lifetime_s: u32,
        used_for_0rtt: bool,
    };

    pub fn init() ServerTicketStore {
        return .{
            .entries = [_]?TicketEntry{null} ** MAX_ENTRIES,
            .count = 0,
        };
    }

    /// Store a ticket → PSK mapping. Evicts expired entries first, then oldest.
    pub fn store(self: *ServerTicketStore, ticket_value: []const u8, psk: [32]u8, issued_at_ms: i64, lifetime_s: u32) void {
        var target: usize = 0;
        var oldest_time: i64 = std.math.maxInt(i64);
        var found_slot = false;
        for (&self.entries, 0..) |*e, i| {
            if (e.* == null) {
                target = i;
                found_slot = true;
                break;
            }
            // Prefer evicting expired entries
            const age_ms = issued_at_ms - e.*.?.issued_at_ms;
            if (age_ms > @as(i64, e.*.?.lifetime_s) * 1000) {
                target = i;
                found_slot = true;
                break;
            }
            // Track oldest for LRU eviction
            if (e.*.?.issued_at_ms < oldest_time) {
                oldest_time = e.*.?.issued_at_ms;
                target = i;
            }
        }
        if (!found_slot) {
            // All slots occupied and none expired — evict the oldest (target set above)
        }
        var entry: TicketEntry = undefined;
        entry.ticket_len = @intCast(@min(ticket_value.len, 256));
        @memcpy(entry.ticket[0..entry.ticket_len], ticket_value[0..entry.ticket_len]);
        entry.psk = psk;
        entry.issued_at_ms = issued_at_ms;
        entry.lifetime_s = lifetime_s;
        entry.used_for_0rtt = false;
        const was_empty = self.entries[target] == null;
        self.entries[target] = entry;
        if (was_empty and self.count < MAX_ENTRIES) self.count += 1;
    }

    /// Look up a PSK by ticket value. Returns null if not found or expired.
    pub fn lookup(self: *const ServerTicketStore, ticket_value: []const u8, now_ms: i64) ?[32]u8 {
        for (&self.entries) |*slot| {
            if (slot.*) |entry| {
                if (entry.ticket_len != ticket_value.len) continue;
                if (!std.mem.eql(u8, entry.ticket[0..entry.ticket_len], ticket_value)) continue;
                const age_ms = now_ms - entry.issued_at_ms;
                if (age_ms < 0 or age_ms > @as(i64, entry.lifetime_s) * 1000) continue;
                return entry.psk;
            }
        }
        return null;
    }

    /// Look up a PSK for 0-RTT and mark it as consumed (single-use anti-replay).
    /// Returns null if not found, expired, or already used for 0-RTT.
    pub fn consumeForZeroRtt(self: *ServerTicketStore, ticket_value: []const u8, now_ms: i64) ?[32]u8 {
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                if (entry.ticket_len != ticket_value.len) continue;
                if (!std.mem.eql(u8, entry.ticket[0..entry.ticket_len], ticket_value)) continue;
                const age_ms = now_ms - entry.issued_at_ms;
                if (age_ms < 0 or age_ms > @as(i64, entry.lifetime_s) * 1000) continue;
                if (entry.used_for_0rtt) return null;
                entry.used_for_0rtt = true;
                return entry.psk;
            }
        }
        return null;
    }
};

/// Issue a NewSessionTicket after handshake completes.
/// Derives the PSK from the master_secret + transcript, builds the ticket message,
/// and stores the ticket → PSK mapping in the ticket store.
/// Returns the number of bytes written to `out_buf`, or null on failure.
pub fn issueNewSessionTicket(
    master_secret: [32]u8,
    transcript_hash_full: [32]u8,
    ticket_store: *ServerTicketStore,
    out_buf: []u8,
    issued_at_ms: i64,
) ?usize {
    const resumption = @import("resumption.zig");

    const rms = resumption.deriveResumptionMasterSecret(
        master_secret,
        transcript_hash_full,
    );

    var ticket_nonce: [8]u8 = undefined;
    crypto.random.bytes(&ticket_nonce);
    var ticket_value: [32]u8 = undefined;
    crypto.random.bytes(&ticket_value);

    const psk = resumption.computePsk(rms, &ticket_nonce);

    const lifetime: u32 = 7200; // 2 hours
    var ticket_age_add: [4]u8 = undefined;
    crypto.random.bytes(&ticket_age_add);
    const age_add = std.mem.readInt(u32, &ticket_age_add, .big);

    ticket_store.store(&ticket_value, psk, issued_at_ms, lifetime);

    return buildNewSessionTicket(
        out_buf,
        lifetime,
        age_add,
        &ticket_nonce,
        &ticket_value,
        0x4000, // max_early_data_size = 16KB
    );
}

/// Validate a 0-RTT attempt: look up the PSK from the ticket store and derive early keys.
/// Marks the ticket as consumed for anti-replay (single-use 0-RTT).
/// Returns the early keys for decrypting 0-RTT data, or null if ticket is invalid/expired/replayed.
pub fn validate0Rtt(
    parsed_ch: *const ParsedClientHello,
    ch_raw: []const u8,
    ticket_store: *ServerTicketStore,
    now_ms: i64,
) ?@import("resumption.zig").EarlyKeys {
    const resump = @import("resumption.zig");

    if (!parsed_ch.has_psk or !parsed_ch.has_early_data) return null;

    // Look up and consume PSK (anti-replay: single-use for 0-RTT)
    const psk = ticket_store.consumeForZeroRtt(
        parsed_ch.psk_identity[0..parsed_ch.psk_identity_len],
        now_ms,
    ) orelse return null;

    // Derive early keys from PSK and ClientHello hash
    const early_secret = resump.deriveEarlySecret(psk);
    var ch_hash: [32]u8 = undefined;
    Sha256.hash(ch_raw, &ch_hash, .{});

    return resump.deriveEarlyKeys(early_secret, ch_hash);
}

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

test "buildNewSessionTicket: valid encoding" {
    var buf: [512]u8 = undefined;
    const nonce = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const ticket = [_]u8{0xAA} ** 32;
    const len = buildNewSessionTicket(&buf, 7200, 0x12345678, &nonce, &ticket, 0x4000) orelse unreachable;

    // Type = NewSessionTicket (0x04)
    try std.testing.expectEqual(@as(u8, 0x04), buf[0]);
    // ticket_lifetime
    try std.testing.expectEqual(@as(u32, 7200), std.mem.readInt(u32, buf[4..8], .big));
    // ticket_age_add
    try std.testing.expectEqual(@as(u32, 0x12345678), std.mem.readInt(u32, buf[8..12], .big));
    // nonce length
    try std.testing.expectEqual(@as(u8, 4), buf[12]);
    // ticket length
    try std.testing.expectEqual(@as(u16, 32), std.mem.readInt(u16, buf[17..19], .big));
    try std.testing.expect(len > 50);
}

test "ServerTicketStore: store and lookup" {
    var store = ServerTicketStore.init();
    const ticket = [_]u8{0xBB} ** 32;
    const psk = [_]u8{0xCC} ** 32;
    store.store(&ticket, psk, 1000, 3600);

    // Lookup within lifetime
    const found = store.lookup(&ticket, 2000);
    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, &psk, &found.?);

    // Lookup after expiry
    const expired = store.lookup(&ticket, 1000 + 3600 * 1000 + 1);
    try std.testing.expect(expired == null);

    // Lookup with wrong ticket
    const wrong = [_]u8{0xDD} ** 32;
    try std.testing.expect(store.lookup(&wrong, 2000) == null);
}

test "ServerTicketStore: consumeForZeroRtt single-use anti-replay" {
    var store = ServerTicketStore.init();
    const ticket = [_]u8{0xEE} ** 32;
    const psk = [_]u8{0xFF} ** 32;
    store.store(&ticket, psk, 1000, 3600);

    // First consume succeeds
    const first = store.consumeForZeroRtt(&ticket, 2000);
    try std.testing.expect(first != null);
    try std.testing.expectEqualSlices(u8, &psk, &first.?);

    // Second consume is rejected (replay)
    const replay = store.consumeForZeroRtt(&ticket, 2001);
    try std.testing.expect(replay == null);

    // Regular lookup still works (1-RTT resumption unaffected)
    const regular = store.lookup(&ticket, 2002);
    try std.testing.expect(regular != null);
}

test "ServerTicketStore: consumeForZeroRtt rejects expired" {
    var store = ServerTicketStore.init();
    const ticket = [_]u8{0xAA} ** 32;
    const psk = [_]u8{0xBB} ** 32;
    store.store(&ticket, psk, 1000, 1); // 1 second lifetime

    // Expired — should be rejected
    const result = store.consumeForZeroRtt(&ticket, 1000 + 1001);
    try std.testing.expect(result == null);
}

test "parseClientHello: PSK fields default to false" {
    const tls_mod = @import("tls.zig");
    const builder = tls_mod.ClientHelloBuilder.init("example.com");
    var ch_buf: [2048]u8 = undefined;
    const ch_len = builder.build(&ch_buf) orelse unreachable;

    const parsed = try parseClientHello(ch_buf[0..ch_len]);
    try std.testing.expect(!parsed.has_psk);
    try std.testing.expect(!parsed.has_early_data);
    try std.testing.expectEqual(@as(u16, 0), parsed.psk_identity_len);
}
