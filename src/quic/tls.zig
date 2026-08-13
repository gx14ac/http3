const std = @import("std");
const crypto = std.crypto;

/// Build a TLS 1.3 ClientHello for QUIC (RFC 9001).
/// Includes: supported_versions (TLS 1.3), key_share (x25519),
/// signature_algorithms, supported_groups, ALPN (h3), QUIC transport params.
pub const ClientHelloBuilder = struct {
    /// x25519 private key (ephemeral)
    private_key: [32]u8,
    /// x25519 public key (derived from private)
    public_key: [32]u8,
    /// Client random (32 bytes)
    random: [32]u8,
    /// Server name for SNI
    server_name: []const u8,
    /// Source Connection ID (for initial_source_connection_id TP)
    scid: [20]u8,
    scid_len: u8,

    pub fn init(server_name: []const u8) ClientHelloBuilder {
        return initWithScid(server_name, &[_]u8{});
    }

    pub fn initWithScid(server_name: []const u8, scid: []const u8) ClientHelloBuilder {
        var self: ClientHelloBuilder = .{
            .private_key = undefined,
            .public_key = undefined,
            .random = undefined,
            .server_name = server_name,
            .scid = [_]u8{0} ** 20,
            .scid_len = @intCast(@min(scid.len, 20)),
        };
        const len: usize = @min(scid.len, 20);
        if (len > 0) {
            @memcpy(self.scid[0..len], scid[0..len]);
        }
        crypto.random.bytes(&self.private_key);
        self.public_key = crypto.dh.X25519.recoverPublicKey(self.private_key) catch unreachable;
        crypto.random.bytes(&self.random);
        return self;
    }

    /// Build the full ClientHello handshake message (including handshake header).
    /// Returns bytes written to buf.
    pub fn build(self: *const ClientHelloBuilder, buf: []u8) ?usize {
        var pos: usize = 0;

        // Handshake header: type(1) + length(3) — length filled in later
        if (buf.len < 4) return null;
        buf[0] = 0x01; // ClientHello
        pos = 4; // skip length for now

        // Client version: TLS 1.2 (for compatibility, real version in extension)
        if (buf.len < pos + 2) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], 0x0303, .big);
        pos += 2;

        // Random (32 bytes)
        if (buf.len < pos + 32) return null;
        @memcpy(buf[pos..][0..32], &self.random);
        pos += 32;

        // Session ID length: 0 (QUIC doesn't use legacy session ID)
        if (buf.len < pos + 1) return null;
        buf[pos] = 0;
        pos += 1;

        // Cipher suites
        const cipher_suites = [_]u16{
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
        };
        if (buf.len < pos + 2 + cipher_suites.len * 2) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(cipher_suites.len * 2), .big);
        pos += 2;
        for (cipher_suites) |suite| {
            std.mem.writeInt(u16, buf[pos..][0..2], suite, .big);
            pos += 2;
        }

        // Compression methods: 1 method, null compression
        if (buf.len < pos + 2) return null;
        buf[pos] = 1; // length
        buf[pos + 1] = 0; // null
        pos += 2;

        // Extensions — build in a temporary buffer then write with length prefix
        var ext_buf: [1024]u8 = undefined;
        var ext_pos: usize = 0;

        // SNI extension (type=0x0000)
        ext_pos += writeSniExtension(ext_buf[ext_pos..], self.server_name) orelse return null;

        // Supported versions extension (type=0x002B) — TLS 1.3 only
        ext_pos += writeSupportedVersions(ext_buf[ext_pos..]) orelse return null;

        // Signature algorithms (type=0x000D)
        ext_pos += writeSignatureAlgorithms(ext_buf[ext_pos..]) orelse return null;

        // Supported groups (type=0x000A)
        ext_pos += writeSupportedGroups(ext_buf[ext_pos..]) orelse return null;

        // Key share (type=0x0033) — x25519
        ext_pos += writeKeyShare(ext_buf[ext_pos..], &self.public_key) orelse return null;

        // ALPN (type=0x0010) — h3
        ext_pos += writeAlpn(ext_buf[ext_pos..]) orelse return null;

        // QUIC transport parameters (type=0x0039)
        ext_pos += writeQuicTransportParams(ext_buf[ext_pos..], self.scid[0..self.scid_len]) orelse return null;

        // Write extensions to main buffer
        if (buf.len < pos + 2 + ext_pos) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_pos), .big);
        pos += 2;
        @memcpy(buf[pos..][0..ext_pos], ext_buf[0..ext_pos]);
        pos += ext_pos;

        // Fill in handshake length (3 bytes, big-endian)
        const body_len = pos - 4;
        buf[1] = @intCast((body_len >> 16) & 0xFF);
        buf[2] = @intCast((body_len >> 8) & 0xFF);
        buf[3] = @intCast(body_len & 0xFF);

        return pos;
    }
};

// ─── Extension builders ───

fn writeSniExtension(buf: []u8, server_name: []const u8) ?usize {
    // type(2) + ext_len(2) + sni_list_len(2) + type(1) + name_len(2) + name
    const ext_data_len = 2 + 1 + 2 + server_name.len;
    const total = 2 + 2 + ext_data_len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0000, .big); // SNI type
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data_len), .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data_len - 2), .big); // server name list length
    pos += 2;
    buf[pos] = 0x00; // host name type
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(server_name.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..server_name.len], server_name);
    pos += server_name.len;

    return pos;
}

fn writeSupportedVersions(buf: []u8) ?usize {
    // type(2) + ext_len(2) + list_len(1) + version(2)
    const total: usize = 7;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x002B, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big); // ext data len
    pos += 2;
    buf[pos] = 2; // list len (1 version * 2 bytes)
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0304, .big); // TLS 1.3
    pos += 2;

    return pos;
}

fn writeSignatureAlgorithms(buf: []u8) ?usize {
    const algorithms = [_]u16{
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0807, // ed25519
    };
    const list_len = algorithms.len * 2;
    const total = 2 + 2 + 2 + list_len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x000D, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(2 + list_len), .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(list_len), .big);
    pos += 2;
    for (algorithms) |alg| {
        std.mem.writeInt(u16, buf[pos..][0..2], alg, .big);
        pos += 2;
    }

    return pos;
}

fn writeSupportedGroups(buf: []u8) ?usize {
    const groups = [_]u16{
        0x001D, // x25519
        0x0017, // secp256r1
        0x0018, // secp384r1
    };
    const list_len = groups.len * 2;
    const total = 2 + 2 + 2 + list_len;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x000A, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(2 + list_len), .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(list_len), .big);
    pos += 2;
    for (groups) |g| {
        std.mem.writeInt(u16, buf[pos..][0..2], g, .big);
        pos += 2;
    }

    return pos;
}

fn writeKeyShare(buf: []u8, public_key: *const [32]u8) ?usize {
    // type(2) + ext_len(2) + client_shares_len(2) + group(2) + key_len(2) + key(32)
    const total: usize = 2 + 2 + 2 + 2 + 2 + 32;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0033, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2 + 2 + 2 + 32, .big); // ext data len
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2 + 2 + 32, .big); // client shares len
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x001D, .big); // x25519
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 32, .big); // key len
    pos += 2;
    @memcpy(buf[pos..][0..32], public_key);
    pos += 32;

    return pos;
}

fn writeAlpn(buf: []u8) ?usize {
    // type(2) + ext_len(2) + protocols_len(2) + proto_len(1) + "h3"(2)
    const total: usize = 2 + 2 + 2 + 1 + 2;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0010, .big); // ALPN
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 5, .big); // ext data len
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big); // protocols list len
    pos += 2;
    buf[pos] = 2; // protocol name len
    pos += 1;
    buf[pos] = 'h';
    buf[pos + 1] = '3';
    pos += 2;

    return pos;
}

fn writeQuicTransportParams(buf: []u8, scid: []const u8) ?usize {
    const transport_params = @import("transport_params.zig");

    var client_params = transport_params.ClientParams{};
    if (scid.len > 0) {
        const len: u8 = @intCast(@min(scid.len, 20));
        @memcpy(client_params.initial_source_cid[0..len], scid[0..len]);
        client_params.initial_source_cid_len = len;
    }

    var params_buf: [256]u8 = undefined;
    const ppos = transport_params.encodeClientParams(&params_buf, client_params) orelse return null;

    // type(2) + ext_len(2) + params
    const total = 2 + 2 + ppos;
    if (buf.len < total) return null;

    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0039, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ppos), .big);
    pos += 2;
    @memcpy(buf[pos..][0..ppos], params_buf[0..ppos]);
    pos += ppos;

    return pos;
}

// ─── Tests ───

test "ClientHelloBuilder: produces valid handshake message" {
    const builder = ClientHelloBuilder.init("example.com");
    var buf: [2048]u8 = undefined;
    const len = builder.build(&buf) orelse unreachable;

    // Minimum reasonable ClientHello size
    try std.testing.expect(len > 200);

    // Handshake type = ClientHello (0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);

    // Handshake length matches
    const hs_len = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | buf[3];
    try std.testing.expectEqual(len - 4, hs_len);

    // Version = TLS 1.2 (0x0303)
    try std.testing.expectEqual(@as(u16, 0x0303), std.mem.readInt(u16, buf[4..6], .big));
}

test "ClientHelloBuilder: different instances have different randoms" {
    const b1 = ClientHelloBuilder.init("a.com");
    const b2 = ClientHelloBuilder.init("b.com");
    try std.testing.expect(!std.mem.eql(u8, &b1.random, &b2.random));
}

test "ClientHelloBuilder: public key is valid x25519 point" {
    const builder = ClientHelloBuilder.init("test.com");
    // Public key should not be all zeros
    var all_zero = true;
    for (builder.public_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "writeSniExtension: correct encoding" {
    var buf: [256]u8 = undefined;
    const len = writeSniExtension(&buf, "example.com") orelse unreachable;
    // type(2) + ext_len(2) + list_len(2) + type(1) + name_len(2) + "example.com"(11) = 20
    try std.testing.expectEqual(@as(usize, 20), len);
    // Extension type = SNI (0x0000)
    try std.testing.expectEqual(@as(u16, 0x0000), std.mem.readInt(u16, buf[0..2], .big));
}

test "writeAlpn: h3 protocol" {
    var buf: [64]u8 = undefined;
    const len = writeAlpn(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 9), len);
    // Verify "h3" is in the output
    var found = false;
    for (0..len - 1) |i| {
        if (buf[i] == 'h' and buf[i + 1] == '3') {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}
