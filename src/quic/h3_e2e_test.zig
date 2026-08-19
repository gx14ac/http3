const std = @import("std");
const server_mod = @import("server.zig");
const h3_server_mod = @import("h3_server.zig");
const h3_frame = @import("h3_frame.zig");
const qpack = @import("qpack.zig");
const packet_mod = @import("packet.zig");
const tls_mod = @import("tls.zig");
const initial_mod = @import("initial.zig");
const decode_mod = @import("decode.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const handshake_complete_mod = @import("handshake_complete.zig");
const tls_messages = @import("tls_messages.zig");
const socket_mod = @import("socket.zig");
const short_header = @import("short_header.zig");

const H3Server = h3_server_mod.H3Server;

const HandshakeResult = struct {
    app_keys: handshake_flight.ApplicationKeys,
    client_scid: [8]u8,
    client_dcid: [8]u8,
    server_scid: [20]u8,
    server_scid_len: u8,
    sock: socket_mod.UdpSocket,
    recv_buf: [4096]u8,
    plain_buf: [4096]u8,

    fn deinit(self: *HandshakeResult) void {
        self.sock.close();
    }

    fn sendStream(self: *HandshakeResult, stream_id: u62, data: []const u8, fin: bool, pn: u64) !void {
        var frame_buf: [4096]u8 = undefined;
        var fpos: usize = 0;

        var frame_type: u8 = 0x08 | 0x02; // STREAM + LEN
        if (fin) frame_type |= 0x01;
        frame_buf[fpos] = frame_type;
        fpos += 1;

        fpos += packet_mod.encodeVarint(frame_buf[fpos..], stream_id) orelse return error.EncodeFailed;
        fpos += packet_mod.encodeVarint(frame_buf[fpos..], data.len) orelse return error.EncodeFailed;
        @memcpy(frame_buf[fpos..][0..data.len], data);
        fpos += data.len;

        var pkt_buf: [4096]u8 = undefined;
        const pkt_len = short_header.encodeShortHeader(
            &pkt_buf,
            self.server_scid[0..self.server_scid_len],
            pn,
            frame_buf[0..fpos],
            self.app_keys.client_key,
            self.app_keys.client_iv,
            self.app_keys.client_hp,
        ) orelse return error.EncodeFailed;

        _ = try self.sock.send(pkt_buf[0..pkt_len]);
    }

    fn recvAndDecrypt(self: *HandshakeResult) ![]const u8 {
        return self.recvAndDecryptOnStream(null);
    }

    /// Receive packets until we get one with a STREAM frame for the expected stream_id.
    /// If expected_stream_id is null, returns the first successfully decrypted payload.
    fn recvAndDecryptOnStream(self: *HandshakeResult, expected_stream_id: ?u62) ![]const u8 {
        var attempts: usize = 0;
        while (attempts < 5) : (attempts += 1) {
            const recv_len = self.sock.recv(&self.recv_buf) catch return error.RecvFailed;
            if (recv_len == 0) continue;

            var pkt_data: [4096]u8 = undefined;
            @memcpy(pkt_data[0..recv_len], self.recv_buf[0..recv_len]);
            const parsed = short_header.removeHpAndParse(
                pkt_data[0..recv_len],
                self.client_scid.len,
                self.app_keys.server_hp,
            ) orelse continue;

            const plain_len = short_header.decryptParsed(
                pkt_data[0..recv_len],
                parsed,
                self.app_keys.server_key,
                self.app_keys.server_iv,
                &self.plain_buf,
            ) orelse continue;

            const plaintext = self.plain_buf[0..plain_len];

            if (expected_stream_id) |sid| {
                const got_sid = extractStreamId(plaintext) orelse continue;
                if (got_sid != sid) continue;
            }

            return plaintext;
        }
        return error.RecvFailed;
    }
};

fn doClientHandshake(server: *H3Server, server_port: u16) !HandshakeResult {
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server_port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);

    var sock = try socket_mod.UdpSocket.init(server_addr);
    errdefer sock.close();
    sock.setTimeout(3000);

    // 1. Client sends Initial (ClientHello)
    const ch_builder = tls_mod.ClientHelloBuilder.initWithScid("localhost", &scid);
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf) orelse return error.BuildFailed;

    const sender_inst = initial_mod.InitialSender.init(&dcid, &scid);
    var initial_buf: [1500]u8 = undefined;
    const pkt_len = sender_inst.buildPacket(ch_buf[0..ch_len], &initial_buf) catch return error.BuildFailed;
    _ = try sock.send(initial_buf[0..pkt_len]);

    // 2. Server polls → processes Initial, sends SH + handshake flight
    _ = server.poll();

    // 3. Client receives server response (Initial + Handshake coalesced)
    var response_buf: [8192]u8 = undefined;
    const resp_len = sock.recv(&response_buf) catch return error.RecvFailed;
    if (resp_len == 0) return error.RecvFailed;

    // Decode server Initial → ServerHello
    var decode_buf: [4096]u8 = undefined;
    const decoded = decode_mod.decodeServerInitial(response_buf[0..resp_len], &dcid, &decode_buf) catch
        return error.DecodeFailed;

    // Derive handshake keys
    const server_pub_key = handshake_mod.extractServerKeyShare(decoded.crypto_data) catch
        return error.HandshakeFailed;
    const transcript_hash = handshake_mod.computeTranscriptHash(ch_buf[0..ch_len], decoded.crypto_data);
    const hs_keys = handshake_mod.deriveHandshakeKeys(ch_builder.private_key, server_pub_key, transcript_hash) catch
        return error.HandshakeFailed;

    // Build TranscriptHash
    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(ch_buf[0..ch_len]);
    transcript.update(decoded.crypto_data);

    // Decrypt coalesced Handshake packet
    const initial_pkt_len = handshake_flight.coalescedPacketLen(response_buf[0..resp_len]) orelse
        return error.DecodeFailed;

    var hs_pkt_data: [4096]u8 = undefined;
    const hs_pkt_size = resp_len - initial_pkt_len;
    @memcpy(hs_pkt_data[0..hs_pkt_size], response_buf[initial_pkt_len..resp_len]);
    var hs_out: [4096]u8 = undefined;
    const decrypted = handshake_flight.decodeHandshakePacket(
        hs_pkt_data[0..hs_pkt_size],
        hs_keys.server_key,
        hs_keys.server_iv,
        hs_keys.server_hp,
        &hs_out,
    ) orelse return error.DecodeFailed;

    // Extract CRYPTO frames
    var crypto_reassembler = handshake_flight.CryptoReassembler.init();
    _ = handshake_flight.extractCryptoFrames(decrypted.plaintext, &crypto_reassembler);
    const hs_crypto_data = crypto_reassembler.getData();
    if (hs_crypto_data.len == 0) return error.DecodeFailed;

    // Process handshake flight → app keys
    const hs_result = handshake_complete_mod.processServerHandshakeFlight(
        hs_crypto_data,
        hs_keys,
        &transcript,
    ) catch return error.HandshakeFailed;

    // 4. Client sends Finished
    var fin_buf: [256]u8 = undefined;
    const fin_len = handshake_complete_mod.buildClientFinishedPacket(
        &fin_buf,
        &hs_result.client_finished_msg,
        0,
        decoded.scid,
        &scid,
        hs_keys.client_key,
        hs_keys.client_iv,
        hs_keys.client_hp,
    ) orelse return error.BuildFailed;
    _ = try sock.send(fin_buf[0..fin_len]);

    // 5. Server polls → processes Client Finished → must be connected
    const event = server.poll();
    if (event != .connected) return error.HandshakeFailed;

    var result = HandshakeResult{
        .app_keys = hs_result.application_keys,
        .client_scid = scid,
        .client_dcid = dcid,
        .server_scid = undefined,
        .server_scid_len = @intCast(decoded.scid.len),
        .sock = sock,
        .recv_buf = undefined,
        .plain_buf = undefined,
    };
    @memcpy(result.server_scid[0..decoded.scid.len], decoded.scid);
    return result;
}

/// Extract stream ID from a STREAM frame.
fn extractStreamId(plaintext: []const u8) ?u62 {
    if (plaintext.len == 0) return null;
    const frame_type = plaintext[0];
    if (frame_type & 0xF8 != 0x08) return null;
    const sid_result = packet_mod.decodeVarint(plaintext[1..]) orelse return null;
    return @intCast(sid_result.value);
}

/// Extract STREAM frame payload from decrypted QUIC packet plaintext.
fn extractStreamPayload(plaintext: []const u8) ?[]const u8 {
    if (plaintext.len == 0) return null;
    const frame_type = plaintext[0];
    if (frame_type & 0xF8 != 0x08) return null; // Not a STREAM frame

    const has_offset = (frame_type & 0x04) != 0;
    const has_length = (frame_type & 0x02) != 0;

    var pos: usize = 1;

    // Stream ID (varint)
    const sid_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
    pos += sid_result.consumed;

    // Offset (varint, optional)
    if (has_offset) {
        const off_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
        pos += off_result.consumed;
    }

    // Length (varint, optional)
    if (has_length) {
        const len_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
        const data_len: usize = @intCast(len_result.value);
        pos += len_result.consumed;
        if (pos + data_len > plaintext.len) return null;
        return plaintext[pos..][0..data_len];
    }

    // No length field — rest of packet is data
    return plaintext[pos..];
}

// ─── Tests ───

test "H3 E2E: full handshake + GET request + response" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(bind_addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    const port = server.getPort();

    // Client: QUIC handshake (interleaved with server polls)
    var hs = try doClientHandshake(&server, port);
    defer hs.deinit();

    // Client: build and send H3 GET request on stream 0
    var h3_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &h3_headers) orelse return error.TestUnexpectedResult;

    var frame_buf: [1024]u8 = undefined;
    const frame_len = h3_frame.encodeHeadersFrame(&frame_buf, qpack_buf[0..qpack_len]) orelse return error.TestUnexpectedResult;

    try hs.sendStream(0, frame_buf[0..frame_len], true, 0);

    // Server: poll until request
    var req_event: h3_server_mod.H3ServerEvent = .none;
    for (0..10) |_| {
        req_event = server.poll();
        if (req_event == .request) break;
    }

    const req = switch (req_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "GET", req.methodSlice());
    try std.testing.expectEqualSlices(u8, "/hello", req.pathSlice());

    // Server: send response
    const resp_headers = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "text/plain" },
    };
    try server.sendResponse(req.conn_idx, req.stream_id, 200, &resp_headers, "Hello, World!");

    // Client: receive and decrypt response on stream 0
    const plaintext = try hs.recvAndDecryptOnStream(0);

    // Extract STREAM frame payload (H3 frames)
    const stream_payload = extractStreamPayload(plaintext) orelse return error.TestUnexpectedResult;

    // Parse H3 HEADERS frame → verify :status = 200
    const hdr = h3_frame.decodeFrameHeader(stream_payload) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type); // HEADERS

    const hdr_payload = stream_payload[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_decoded: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_decoded) orelse return error.TestUnexpectedResult;
    try std.testing.expect(hcount >= 1);
    try std.testing.expectEqualSlices(u8, ":status", resp_decoded[0].name);
    try std.testing.expectEqualSlices(u8, "200", resp_decoded[0].value);

    // Parse DATA frame → verify body
    const after_headers = stream_payload[hdr.header_len + @as(usize, @intCast(hdr.length)) ..];
    const data_hdr = h3_frame.decodeFrameHeader(after_headers) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x00), data_hdr.frame_type); // DATA
    const resp_body = after_headers[data_hdr.header_len..][0..@intCast(data_hdr.length)];
    try std.testing.expectEqualSlices(u8, "Hello, World!", resp_body);
}

test "H3 E2E: POST with body" {
    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try H3Server.init(bind_addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    const port = server.getPort();

    var hs = try doClientHandshake(&server, port);
    defer hs.deinit();

    // Client: build and send POST with body on stream 4 (second client bidi stream)
    var h3_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/json" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &h3_headers) orelse return error.TestUnexpectedResult;

    var frame_buf: [2048]u8 = undefined;
    var pos: usize = 0;

    pos += h3_frame.encodeHeadersFrame(frame_buf[pos..], qpack_buf[0..qpack_len]) orelse return error.TestUnexpectedResult;

    const body = "{\"msg\":\"hello\"}";
    pos += h3_frame.encodeDataFrame(frame_buf[pos..], body) orelse return error.TestUnexpectedResult;

    // Stream ID 4 = second client-initiated bidi stream
    try hs.sendStream(4, frame_buf[0..pos], true, 0);

    // Server: poll until request
    var req_event: h3_server_mod.H3ServerEvent = .none;
    for (0..10) |_| {
        req_event = server.poll();
        if (req_event == .request) break;
    }

    const req = switch (req_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "POST", req.methodSlice());
    try std.testing.expectEqualSlices(u8, "/echo", req.pathSlice());
    try std.testing.expectEqualSlices(u8, "application/json", req.contentTypeSlice());
    try std.testing.expectEqualSlices(u8, body, req.bodySlice());
    try std.testing.expect(req.fin);

    // Server: echo response
    const resp_hdrs = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "application/json" },
    };
    try server.sendResponse(req.conn_idx, req.stream_id, 200, &resp_hdrs, req.bodySlice());

    // Client: receive, decrypt, and verify response on stream 4
    const plaintext = try hs.recvAndDecryptOnStream(4);
    const stream_payload = extractStreamPayload(plaintext) orelse return error.TestUnexpectedResult;

    // Verify :status = 200
    const hdr = h3_frame.decodeFrameHeader(stream_payload) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);
    const hdr_payload = stream_payload[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_decoded: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_decoded) orelse return error.TestUnexpectedResult;
    try std.testing.expect(hcount >= 1);
    try std.testing.expectEqualSlices(u8, ":status", resp_decoded[0].name);
    try std.testing.expectEqualSlices(u8, "200", resp_decoded[0].value);

    // Verify echoed body
    const after_headers = stream_payload[hdr.header_len + @as(usize, @intCast(hdr.length)) ..];
    const data_hdr = h3_frame.decodeFrameHeader(after_headers) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x00), data_hdr.frame_type);
    const resp_body = after_headers[data_hdr.header_len..][0..@intCast(data_hdr.length)];
    try std.testing.expectEqualSlices(u8, body, resp_body);
}
