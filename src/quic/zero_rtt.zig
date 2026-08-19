const std = @import("std");
const crypto = std.crypto;
const tls_mod = @import("tls.zig");
const resumption_mod = @import("resumption.zig");
const quic_crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Build a TLS 1.3 ClientHello with PSK extension for 0-RTT resumption.
/// The PSK binder is computed over the truncated transcript (ClientHello up to binders list).
pub const ZeroRttClientHelloBuilder = struct {
    private_key: [32]u8,
    public_key: [32]u8,
    random: [32]u8,
    server_name: []const u8,
    scid: [20]u8,
    scid_len: u8,

    pub fn init(server_name: []const u8, scid: []const u8) ZeroRttClientHelloBuilder {
        var self: ZeroRttClientHelloBuilder = .{
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

    /// Build ClientHello with PSK and early_data extensions.
    /// Returns total bytes written. The binder is computed and patched in-place.
    pub fn build(self: *const ZeroRttClientHelloBuilder, buf: []u8, ticket: *const resumption_mod.SessionTicket, now_ms: i64) ?usize {
        var pos: usize = 0;

        // Handshake header: type(1) + length(3)
        if (buf.len < 4) return null;
        buf[0] = 0x01;
        pos = 4;

        // Client version: TLS 1.2
        if (buf.len < pos + 2) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], 0x0303, .big);
        pos += 2;

        // Random
        if (buf.len < pos + 32) return null;
        @memcpy(buf[pos..][0..32], &self.random);
        pos += 32;

        // Session ID length: 0
        if (buf.len < pos + 1) return null;
        buf[pos] = 0;
        pos += 1;

        // Cipher suites
        const cipher_suites = [_]u16{ 0x1301, 0x1302, 0x1303 };
        if (buf.len < pos + 2 + cipher_suites.len * 2) return null;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(cipher_suites.len * 2), .big);
        pos += 2;
        for (cipher_suites) |suite| {
            std.mem.writeInt(u16, buf[pos..][0..2], suite, .big);
            pos += 2;
        }

        // Compression methods: null
        if (buf.len < pos + 2) return null;
        buf[pos] = 1;
        buf[pos + 1] = 0;
        pos += 2;

        // Extensions
        const ext_len_pos = pos;
        if (buf.len < pos + 2) return null;
        pos += 2; // placeholder for extensions length

        // SNI
        pos += writeSniExtension(buf[pos..], self.server_name) orelse return null;
        // Supported versions
        pos += writeSupportedVersions(buf[pos..]) orelse return null;
        // Signature algorithms
        pos += writeSignatureAlgorithms(buf[pos..]) orelse return null;
        // Supported groups
        pos += writeSupportedGroups(buf[pos..]) orelse return null;
        // Key share
        pos += writeKeyShare(buf[pos..], &self.public_key) orelse return null;
        // ALPN
        pos += writeAlpn(buf[pos..]) orelse return null;
        // QUIC transport params
        pos += writeQuicTransportParams(buf[pos..], self.scid[0..self.scid_len]) orelse return null;
        // early_data extension (empty, signals 0-RTT intent)
        pos += resumption_mod.buildEarlyDataExtension(buf[pos..]) orelse return null;
        // PSK modes (RFC 8446 §4.2.9) — psk_dhe_ke(1)
        pos += writePskKeyExchangeModes(buf[pos..]) orelse return null;

        // pre_shared_key extension MUST be last (RFC 8446 §4.2.11)
        const obfuscated_age = resumption_mod.obfuscatedTicketAge(
            ticket.received_at_ms,
            now_ms,
            ticket.ticket_age_add,
        );
        // Write PSK extension with placeholder binder (zeros)
        const placeholder_binder = [_]u8{0} ** 32;
        const psk_len = resumption_mod.buildPskExtension(
            buf[pos..],
            ticket.ticket[0..ticket.ticket_len],
            obfuscated_age,
            placeholder_binder,
        ) orelse return null;
        pos += psk_len;

        // Fill extensions length
        const ext_total = pos - ext_len_pos - 2;
        std.mem.writeInt(u16, buf[ext_len_pos..][0..2], @intCast(ext_total), .big);

        // Fill handshake length
        const body_len = pos - 4;
        buf[1] = @intCast((body_len >> 16) & 0xFF);
        buf[2] = @intCast((body_len >> 8) & 0xFF);
        buf[3] = @intCast(body_len & 0xFF);

        // Compute binder:
        // transcript_hash_truncated = Hash(ClientHello[0 .. end - binders_length - 2])
        // binders_length = 1 (binder_len) + 32 (binder) = 33
        // The 2 bytes before binders is the binders_list_length field
        const binders_with_len = 2 + 33; // binders_list_length(2) + binder_entry(1+32)
        const truncated_len = pos - binders_with_len;

        const early_secret = resumption_mod.deriveEarlySecret(ticket.psk);
        var truncated_hash: [32]u8 = undefined;
        Sha256.hash(buf[0..truncated_len], &truncated_hash, .{});
        const binder = resumption_mod.computeBinder(early_secret, truncated_hash);

        // Patch binder into the buffer (last 32 bytes)
        @memcpy(buf[pos - 32 ..][0..32], &binder);

        return pos;
    }

    /// Derive 0-RTT keys from the ticket's PSK and the ClientHello hash.
    pub fn deriveKeys(self: *const ZeroRttClientHelloBuilder, ch_buf: []const u8, ch_len: usize, psk: [32]u8) resumption_mod.EarlyKeys {
        _ = self;
        const early_secret = resumption_mod.deriveEarlySecret(psk);
        var ch_hash: [32]u8 = undefined;
        Sha256.hash(ch_buf[0..ch_len], &ch_hash, .{});
        return resumption_mod.deriveEarlyKeys(early_secret, ch_hash);
    }
};

/// Encode a 0-RTT QUIC packet carrying application data.
/// Uses Long Header with type=0x01 (0-RTT).
pub fn encode0RttPacket(
    buf: []u8,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    payload: []const u8,
    keys: resumption_mod.EarlyKeys,
) ?usize {
    return resumption_mod.encode0RttPacket(
        buf,
        dcid,
        scid,
        packet_number,
        payload,
        keys.key,
        keys.iv,
        keys.hp,
    );
}

// ─── Extension builders (duplicated from tls.zig to keep 0-RTT self-contained) ───

fn writeSniExtension(buf: []u8, server_name: []const u8) ?usize {
    const ext_data_len = 2 + 1 + 2 + server_name.len;
    const total = 2 + 2 + ext_data_len;
    if (buf.len < total) return null;
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0000, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data_len), .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data_len - 2), .big);
    pos += 2;
    buf[pos] = 0x00;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(server_name.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..server_name.len], server_name);
    pos += server_name.len;
    return pos;
}

fn writeSupportedVersions(buf: []u8) ?usize {
    const total: usize = 7;
    if (buf.len < total) return null;
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x002B, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big);
    pos += 2;
    buf[pos] = 2;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0304, .big);
    pos += 2;
    return pos;
}

fn writeSignatureAlgorithms(buf: []u8) ?usize {
    const algorithms = [_]u16{ 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0807 };
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
    const groups = [_]u16{ 0x001D, 0x0017, 0x0018 };
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
    const total: usize = 2 + 2 + 2 + 2 + 2 + 32;
    if (buf.len < total) return null;
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0033, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2 + 2 + 2 + 32, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2 + 2 + 32, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x001D, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 32, .big);
    pos += 2;
    @memcpy(buf[pos..][0..32], public_key);
    pos += 32;
    return pos;
}

fn writeAlpn(buf: []u8) ?usize {
    const total: usize = 2 + 2 + 2 + 1 + 2;
    if (buf.len < total) return null;
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0010, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 5, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 3, .big);
    pos += 2;
    buf[pos] = 2;
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

/// psk_key_exchange_modes extension (RFC 8446 §4.2.9)
/// Required when offering PSK. Advertises psk_dhe_ke(1).
fn writePskKeyExchangeModes(buf: []u8) ?usize {
    // type(2) + ext_len(2) + modes_len(1) + mode(1)
    const total: usize = 6;
    if (buf.len < total) return null;
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], 0x002D, .big); // psk_key_exchange_modes
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 2, .big); // ext data len
    pos += 2;
    buf[pos] = 1; // modes_len
    pos += 1;
    buf[pos] = 1; // psk_dhe_ke
    pos += 1;
    return pos;
}

// ─── Tests ───

test "ZeroRttClientHelloBuilder: produces valid ClientHello with PSK" {
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 7200;
    ticket.ticket_age_add = 0x12345678;
    ticket.ticket_nonce_len = 2;
    ticket.ticket_nonce[0] = 0x01;
    ticket.ticket_nonce[1] = 0x02;
    ticket.ticket_len = 8;
    @memcpy(ticket.ticket[0..8], "TESTTKTS");
    ticket.max_early_data_size = 16384;
    ticket.psk = [_]u8{0xAA} ** 32;
    ticket.server_name_len = 11;
    @memcpy(ticket.server_name[0..11], "example.com");
    ticket.received_at_ms = 1000;

    const builder = ZeroRttClientHelloBuilder.init("example.com", &[_]u8{});
    var buf: [2048]u8 = undefined;
    const len = builder.build(&buf, &ticket, 2000) orelse unreachable;

    // Handshake type = ClientHello
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    // Length matches
    const hs_len = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | buf[3];
    try std.testing.expectEqual(len - 4, hs_len);
    // Version
    try std.testing.expectEqual(@as(u16, 0x0303), std.mem.readInt(u16, buf[4..6], .big));
    // Should be longer than regular ClientHello (PSK adds ~50+ bytes)
    try std.testing.expect(len > 250);
}

test "ZeroRttClientHelloBuilder: PSK extension is last" {
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 3600;
    ticket.ticket_age_add = 0;
    ticket.ticket_nonce_len = 0;
    ticket.ticket_len = 4;
    @memcpy(ticket.ticket[0..4], "TICK");
    ticket.max_early_data_size = 0;
    ticket.psk = [_]u8{0xBB} ** 32;
    ticket.server_name_len = 4;
    @memcpy(ticket.server_name[0..4], "test");
    ticket.received_at_ms = 0;

    const builder = ZeroRttClientHelloBuilder.init("test", &[_]u8{});
    var buf: [2048]u8 = undefined;
    const len = builder.build(&buf, &ticket, 1000) orelse unreachable;

    // The last extension should be pre_shared_key (0x0029)
    // Find it by scanning backwards from end: last 32 bytes = binder, before that = binder_len(1)
    // before that = binders_list_len(2), before that = ticket_age(4), before that = ticket data...
    // Easier: scan extensions forward and verify last is 0x0029
    // Skip to extensions: pos=4(header) + 2(version) + 32(random) + 1(sessid_len) + 2(suites_len) + 6(suites) + 2(comp)
    var pos: usize = 4 + 2 + 32 + 1 + 2 + 6 + 2;
    const ext_total_len = std.mem.readInt(u16, buf[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total_len;
    var last_ext_type: u16 = 0;
    while (pos + 4 <= ext_end) {
        last_ext_type = std.mem.readInt(u16, buf[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, buf[pos + 2 ..][0..2], .big);
        pos += 4 + ext_data_len;
    }
    try std.testing.expectEqual(@as(u16, 0x0029), last_ext_type);
    try std.testing.expectEqual(ext_end, pos);
    try std.testing.expectEqual(len, ext_end);
}

test "ZeroRttClientHelloBuilder: binder is non-zero" {
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 3600;
    ticket.ticket_age_add = 100;
    ticket.ticket_nonce_len = 1;
    ticket.ticket_nonce[0] = 0x42;
    ticket.ticket_len = 4;
    @memcpy(ticket.ticket[0..4], "ABCD");
    ticket.max_early_data_size = 4096;
    ticket.psk = [_]u8{0xCC} ** 32;
    ticket.server_name_len = 3;
    @memcpy(ticket.server_name[0..3], "srv");
    ticket.received_at_ms = 500;

    const builder = ZeroRttClientHelloBuilder.init("srv", &[_]u8{});
    var buf: [2048]u8 = undefined;
    const len = builder.build(&buf, &ticket, 1500) orelse unreachable;

    // Last 32 bytes should be the binder (non-zero)
    const binder = buf[len - 32 .. len];
    try std.testing.expect(!std.mem.eql(u8, binder, &([_]u8{0} ** 32)));
}

test "ZeroRttClientHelloBuilder: deriveKeys produces non-zero keys" {
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 3600;
    ticket.ticket_age_add = 0;
    ticket.ticket_nonce_len = 0;
    ticket.ticket_len = 4;
    @memcpy(ticket.ticket[0..4], "TICK");
    ticket.max_early_data_size = 0;
    ticket.psk = [_]u8{0xDD} ** 32;
    ticket.server_name_len = 4;
    @memcpy(ticket.server_name[0..4], "test");
    ticket.received_at_ms = 0;

    const builder = ZeroRttClientHelloBuilder.init("test", &[_]u8{});
    var ch_buf: [2048]u8 = undefined;
    const ch_len = builder.build(&ch_buf, &ticket, 1000) orelse unreachable;

    const keys = builder.deriveKeys(&ch_buf, ch_len, ticket.psk);
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &([_]u8{0} ** 16)));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &([_]u8{0} ** 12)));
    try std.testing.expect(!std.mem.eql(u8, &keys.hp, &([_]u8{0} ** 16)));
}

test "ZeroRttClientHelloBuilder: psk_key_exchange_modes present" {
    var ticket: resumption_mod.SessionTicket = undefined;
    ticket.ticket_lifetime = 3600;
    ticket.ticket_age_add = 0;
    ticket.ticket_nonce_len = 0;
    ticket.ticket_len = 4;
    @memcpy(ticket.ticket[0..4], "TICK");
    ticket.max_early_data_size = 0;
    ticket.psk = [_]u8{0xEE} ** 32;
    ticket.server_name_len = 4;
    @memcpy(ticket.server_name[0..4], "test");
    ticket.received_at_ms = 0;

    const builder = ZeroRttClientHelloBuilder.init("test", &[_]u8{});
    var buf: [2048]u8 = undefined;
    const len = builder.build(&buf, &ticket, 0) orelse unreachable;

    // Scan for psk_key_exchange_modes extension type (0x002D)
    var found = false;
    var pos: usize = 4 + 2 + 32 + 1 + 2 + 6 + 2;
    const ext_total_len = std.mem.readInt(u16, buf[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total_len;
    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, buf[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, buf[pos + 2 ..][0..2], .big);
        if (ext_type == 0x002D) {
            found = true;
            // Verify content: modes_len=1, mode=1 (psk_dhe_ke)
            try std.testing.expectEqual(@as(u16, 2), ext_data_len);
            try std.testing.expectEqual(@as(u8, 1), buf[pos + 4]);
            try std.testing.expectEqual(@as(u8, 1), buf[pos + 5]);
        }
        pos += 4 + ext_data_len;
    }
    try std.testing.expect(found);
    _ = len;
}

test "encode0RttPacket: produces valid long header" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06 };
    const keys = resumption_mod.EarlyKeys{
        .key = [_]u8{0xAA} ** 16,
        .iv = [_]u8{0xBB} ** 12,
        .hp = [_]u8{0xCC} ** 16,
    };

    var buf: [256]u8 = undefined;
    const len = encode0RttPacket(&buf, &dcid, &scid, 0, "early data", keys) orelse unreachable;
    try std.testing.expect(len > 0);
    // Long header bit set
    try std.testing.expect(buf[0] & 0x80 != 0);
}

test "writePskKeyExchangeModes: correct encoding" {
    var buf: [16]u8 = undefined;
    const len = writePskKeyExchangeModes(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 6), len);
    try std.testing.expectEqual(@as(u16, 0x002D), std.mem.readInt(u16, buf[0..2], .big));
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, buf[2..4], .big));
    try std.testing.expectEqual(@as(u8, 1), buf[4]);
    try std.testing.expectEqual(@as(u8, 1), buf[5]);
}
