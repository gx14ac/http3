const std = @import("std");
const packet = @import("packet.zig");
const quic_crypto = @import("crypto.zig");
const socket_mod = @import("socket.zig");

pub const InitialError = error{
    PacketTooLarge,
    EncodingFailed,
    SendFailed,
    RecvFailed,
    Timeout,
    InvalidResponse,
    VersionNotSupported,
};

/// Result of sending an Initial packet and receiving the server's response.
pub const InitialResult = struct {
    /// Raw response packet bytes.
    response: []const u8,
    /// Whether it was a Version Negotiation packet.
    is_version_negotiation: bool,
    /// Number of bytes in the response.
    response_len: usize,
};

/// QUIC Initial packet builder and sender.
/// Phase 1: send a minimal Initial packet (with CRYPTO frame containing ClientHello placeholder)
/// and receive the server's response (Initial or Version Negotiation).
pub const InitialSender = struct {
    dcid: [20]u8,
    dcid_len: u8,
    scid: [20]u8,
    scid_len: u8,
    version: u32,

    pub fn init(dcid: []const u8, scid: []const u8) InitialSender {
        var self: InitialSender = .{
            .dcid = undefined,
            .dcid_len = @intCast(@min(dcid.len, 20)),
            .scid = undefined,
            .scid_len = @intCast(@min(scid.len, 20)),
            .version = packet.QUIC_VERSION_1,
        };
        @memcpy(self.dcid[0..self.dcid_len], dcid[0..self.dcid_len]);
        @memcpy(self.scid[0..self.scid_len], scid[0..self.scid_len]);
        return self;
    }

    /// Build a protected Initial packet with the given CRYPTO frame payload.
    /// The packet is padded to at least 1200 bytes (RFC 9000 §14.1).
    pub fn buildPacket(self: *const InitialSender, crypto_payload: []const u8, buf: []u8) InitialError!usize {
        if (buf.len < 1200) return InitialError.PacketTooLarge;

        const dcid = self.dcid[0..self.dcid_len];
        const scid = self.scid[0..self.scid_len];
        const keys = quic_crypto.deriveInitialKeys(dcid);

        // Build CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
        var crypto_frame: [1280]u8 = undefined;
        var cpos: usize = 0;
        crypto_frame[cpos] = 0x06; // CRYPTO frame type
        cpos += 1;
        cpos += packet.encodeVarint(crypto_frame[cpos..], 0) orelse return InitialError.EncodingFailed; // offset = 0
        cpos += packet.encodeVarint(crypto_frame[cpos..], crypto_payload.len) orelse return InitialError.EncodingFailed;
        if (cpos + crypto_payload.len > crypto_frame.len) return InitialError.PacketTooLarge;
        @memcpy(crypto_frame[cpos..][0..crypto_payload.len], crypto_payload);
        cpos += crypto_payload.len;

        // We need to pad to 1200 bytes minimum for Initial packets.
        // Add PADDING frames (0x00) to reach minimum size after encryption overhead.
        // Header size estimate: 7 + dcid_len + scid_len + 1(token_len) + 2(length varint) + 4(pn) = ~30
        const header_estimate: usize = 7 + dcid.len + scid.len + 1 + 2 + 4;
        const min_payload = 1200 - header_estimate - 16; // 16 for AEAD tag
        if (cpos < min_payload) {
            @memset(crypto_frame[cpos..min_payload], 0x00); // PADDING
            cpos = min_payload;
        }

        // Encode Initial packet (unprotected)
        const pkt = packet.InitialPacket{
            .header = .{
                .packet_type = .initial,
                .version = self.version,
                .dcid = dcid,
                .scid = scid,
            },
            .token = &.{},
            .packet_number = 0,
            .pn_length = 3, // 4-byte packet number
            .payload = crypto_frame[0..cpos],
        };

        // First, encode to get the header for AAD
        var unprotected: [1500]u8 = undefined;
        const unprotected_len = pkt.encode(&unprotected) orelse return InitialError.EncodingFailed;

        // Find packet number offset (right before the 4 PN bytes which are right before payload)
        const pn_offset = unprotected_len - cpos - 4;

        // AAD = everything from start of packet to end of packet number
        const aad = unprotected[0 .. pn_offset + 4];

        // Encrypt payload
        var ciphertext: [1500]u8 = undefined;
        var tag: [16]u8 = undefined;
        quic_crypto.encryptPayload(
            ciphertext[0..cpos],
            &tag,
            crypto_frame[0..cpos],
            keys.client_key,
            keys.client_iv,
            0,
            aad,
        );

        // Assemble final packet: header + ciphertext + tag
        @memcpy(buf[0..aad.len], aad);
        @memcpy(buf[aad.len..][0..cpos], ciphertext[0..cpos]);
        @memcpy(buf[aad.len + cpos ..][0..16], &tag);
        const total_before_hp = aad.len + cpos + 16;

        // Apply header protection
        quic_crypto.applyHeaderProtection(buf[0..total_before_hp], pn_offset, keys.client_hp);

        // Verify minimum 1200 bytes — pad with zeros if needed (shouldn't happen with our calc above)
        if (total_before_hp < 1200) {
            @memset(buf[total_before_hp..1200], 0);
            return 1200;
        }

        return total_before_hp;
    }

    /// Send an Initial packet and wait for a response.
    pub fn sendAndRecv(
        self: *const InitialSender,
        sock: *socket_mod.UdpSocket,
        crypto_payload: []const u8,
        response_buf: []u8,
    ) InitialError!InitialResult {
        var send_buf: [1500]u8 = undefined;
        const pkt_len = try self.buildPacket(crypto_payload, &send_buf);

        _ = sock.send(send_buf[0..pkt_len]) catch return InitialError.SendFailed;

        const n = sock.recv(response_buf) catch |e| {
            return switch (e) {
                socket_mod.UdpSocketError.Timeout => InitialError.Timeout,
                else => InitialError.RecvFailed,
            };
        };

        if (n == 0) return InitialError.InvalidResponse;

        // Check if it's a Version Negotiation packet (version field = 0)
        if (n >= 5) {
            const version = std.mem.readInt(u32, response_buf[1..5], .big);
            if (version == 0 and response_buf[0] & 0x80 != 0) {
                return .{
                    .response = response_buf[0..n],
                    .is_version_negotiation = true,
                    .response_len = n,
                };
            }
        }

        return .{
            .response = response_buf[0..n],
            .is_version_negotiation = false,
            .response_len = n,
        };
    }
};

/// Generate a random connection ID.
pub fn generateConnectionId(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

// ─── Tests ───

test "InitialSender: buildPacket produces >= 1200 bytes" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const sender = InitialSender.init(&dcid, &scid);

    // Minimal CRYPTO payload (empty ClientHello placeholder)
    const crypto_payload = [_]u8{ 0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00 };

    var buf: [1500]u8 = undefined;
    const pkt_len = try sender.buildPacket(&crypto_payload, &buf);

    // Must be at least 1200 bytes (RFC 9000 §14.1)
    try std.testing.expect(pkt_len >= 1200);
    // First byte must have form bit set (long header)
    try std.testing.expect(buf[0] & 0x80 != 0);
}

test "InitialSender: different DCIDs produce different packets" {
    const dcid1 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const dcid2 = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const scid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const payload = [_]u8{0x00} ** 8;

    const sender1 = InitialSender.init(&dcid1, &scid);
    const sender2 = InitialSender.init(&dcid2, &scid);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const len1 = try sender1.buildPacket(&payload, &buf1);
    const len2 = try sender2.buildPacket(&payload, &buf2);

    try std.testing.expect(!std.mem.eql(u8, buf1[0..len1], buf2[0..len2]));
}

test "generateConnectionId: produces random bytes" {
    var id1: [8]u8 = undefined;
    var id2: [8]u8 = undefined;
    generateConnectionId(&id1);
    generateConnectionId(&id2);
    // Extremely unlikely to be equal
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}
