const std = @import("std");
const grpc_server_mod = @import("server.zig");
const message_mod = @import("message.zig");
const status_mod = @import("status.zig");
const qpack = @import("../quic/qpack.zig");
const h3_frame = @import("../quic/h3_frame.zig");
const packet_mod = @import("../quic/packet.zig");
const tls_mod = @import("../quic/tls.zig");
const initial_mod = @import("../quic/initial.zig");
const decode_mod = @import("../quic/decode.zig");
const handshake_mod = @import("../quic/handshake.zig");
const handshake_flight = @import("../quic/handshake_flight.zig");
const handshake_complete_mod = @import("../quic/handshake_complete.zig");
const tls_messages = @import("../quic/tls_messages.zig");
const socket_mod = @import("../quic/socket.zig");
const short_header = @import("../quic/short_header.zig");

const GrpcServer = grpc_server_mod.GrpcServer;
const GrpcRequest = grpc_server_mod.GrpcRequest;
const GrpcResponse = grpc_server_mod.GrpcResponse;
const ServiceHandler = grpc_server_mod.ServiceHandler;

const HandshakeResult = struct {
    app_keys: handshake_flight.ApplicationKeys,
    client_scid: [8]u8,
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

        var frame_type: u8 = 0x08 | 0x02;
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

fn extractStreamId(plaintext: []const u8) ?u62 {
    if (plaintext.len == 0) return null;
    if (plaintext[0] & 0xF8 != 0x08) return null;
    const sid_result = packet_mod.decodeVarint(plaintext[1..]) orelse return null;
    return @intCast(sid_result.value);
}

fn extractStreamPayload(plaintext: []const u8) ?[]const u8 {
    if (plaintext.len == 0) return null;
    const frame_type = plaintext[0];
    if (frame_type & 0xF8 != 0x08) return null;

    const has_offset = (frame_type & 0x04) != 0;
    const has_length = (frame_type & 0x02) != 0;

    var pos: usize = 1;
    const sid_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
    pos += sid_result.consumed;

    if (has_offset) {
        const off_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
        pos += off_result.consumed;
    }

    if (has_length) {
        const len_result = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
        const data_len: usize = @intCast(len_result.value);
        pos += len_result.consumed;
        if (pos + data_len > plaintext.len) return null;
        return plaintext[pos..][0..data_len];
    }

    return plaintext[pos..];
}

fn doHandshake(server: *GrpcServer, server_port: u16) !HandshakeResult {
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server_port);
    var dcid: [8]u8 = undefined;
    var scid: [8]u8 = undefined;
    std.crypto.random.bytes(&dcid);
    std.crypto.random.bytes(&scid);

    var sock = try socket_mod.UdpSocket.init(server_addr);
    errdefer sock.close();
    sock.setTimeout(3000);

    const ch_builder = tls_mod.ClientHelloBuilder.initWithScid("localhost", &scid);
    var ch_buf: [2048]u8 = undefined;
    const ch_len = ch_builder.build(&ch_buf) orelse return error.BuildFailed;

    const sender_inst = initial_mod.InitialSender.init(&dcid, &scid);
    var initial_buf: [1500]u8 = undefined;
    const pkt_len = sender_inst.buildPacket(ch_buf[0..ch_len], &initial_buf) catch return error.BuildFailed;
    _ = try sock.send(initial_buf[0..pkt_len]);

    // Server poll: process Initial
    _ = server.poll();

    var response_buf: [8192]u8 = undefined;
    const resp_len = sock.recv(&response_buf) catch return error.RecvFailed;
    if (resp_len == 0) return error.RecvFailed;

    var decode_buf: [4096]u8 = undefined;
    const decoded = decode_mod.decodeServerInitial(response_buf[0..resp_len], &dcid, &decode_buf) catch
        return error.DecodeFailed;

    const server_pub_key = handshake_mod.extractServerKeyShare(decoded.crypto_data) catch
        return error.HandshakeFailed;
    const transcript_hash = handshake_mod.computeTranscriptHash(ch_buf[0..ch_len], decoded.crypto_data);
    const hs_keys = handshake_mod.deriveHandshakeKeys(ch_builder.private_key, server_pub_key, transcript_hash) catch
        return error.HandshakeFailed;

    var transcript = tls_messages.TranscriptHash.init();
    transcript.update(ch_buf[0..ch_len]);
    transcript.update(decoded.crypto_data);

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

    var crypto_reassembler = handshake_flight.CryptoReassembler.init();
    _ = handshake_flight.extractCryptoFrames(decrypted.plaintext, &crypto_reassembler);
    const hs_crypto_data = crypto_reassembler.getData();
    if (hs_crypto_data.len == 0) return error.DecodeFailed;

    const hs_result = handshake_complete_mod.processServerHandshakeFlight(
        hs_crypto_data,
        hs_keys,
        &transcript,
    ) catch return error.HandshakeFailed;

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

    // Server poll: process Client Finished
    const event = server.poll();
    if (event != .connected) return error.HandshakeFailed;

    var result = HandshakeResult{
        .app_keys = hs_result.application_keys,
        .client_scid = scid,
        .server_scid = undefined,
        .server_scid_len = @intCast(decoded.scid.len),
        .sock = sock,
        .recv_buf = undefined,
        .plain_buf = undefined,
    };
    @memcpy(result.server_scid[0..decoded.scid.len], decoded.scid);
    return result;
}

/// Build a gRPC request (H3 HEADERS + DATA frame with length-prefixed message).
fn buildGrpcRequest(
    out: []u8,
    method_path: []const u8,
    payload: []const u8,
) ?usize {
    var headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = method_path },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers) orelse return null;

    var pos: usize = 0;
    pos += h3_frame.encodeHeadersFrame(out[pos..], qpack_buf[0..qpack_len]) orelse return null;

    // gRPC length-prefixed message as DATA frame
    var grpc_buf: [GrpcRequest.MAX_PAYLOAD + 5]u8 = undefined;
    const grpc_msg = message_mod.encodeMessage(&grpc_buf, payload, false) catch return null;
    pos += h3_frame.encodeDataFrame(out[pos..], grpc_msg) orelse return null;

    return pos;
}

// ─── Echo handler ───

const EchoHandler = struct {
    fn handle(_: *const anyopaque, req: *const GrpcRequest, response_buf: []u8) ?GrpcResponse {
        const p = req.payload();
        @memcpy(response_buf[0..p.len], p);
        return .{
            .status_code = .ok,
            .message = "",
            .payload = response_buf[0..p.len],
        };
    }

    fn serviceHandler() ServiceHandler {
        return .{
            .context = @ptrCast(&struct {
                const x: u8 = 0;
            }.x),
            .handleFn = handle,
        };
    }
};

// ─── Tests ───

test "gRPC Server E2E: unary echo" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    try std.testing.expect(server.addRoute("/test.Echo/", EchoHandler.serviceHandler()));
    const port = server.getPort();

    var hs = try doHandshake(&server, port);
    defer hs.deinit();

    // Build and send gRPC request
    const payload = "hello gRPC server";
    var req_buf: [2048]u8 = undefined;
    const req_len = buildGrpcRequest(&req_buf, "/test.Echo/Echo", payload) orelse
        return error.TestUnexpectedResult;

    try hs.sendStream(0, req_buf[0..req_len], true, 0);

    // Server: poll until gRPC request
    var grpc_event = server.poll();
    for (0..10) |_| {
        if (grpc_event == .request) break;
        grpc_event = server.poll();
    }

    const req = switch (grpc_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "test.Echo", req.service());
    try std.testing.expectEqualSlices(u8, "Echo", req.method());
    try std.testing.expectEqualSlices(u8, payload, req.payload());

    // Server responds with handler
    try server.handleAndRespond(&req);

    // Client: receive response on stream 0
    const plaintext = try hs.recvAndDecryptOnStream(0);
    const stream_payload = extractStreamPayload(plaintext) orelse return error.TestUnexpectedResult;

    // Parse H3 response: HEADERS frame
    const hdr = h3_frame.decodeFrameHeader(stream_payload) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);

    const hdr_payload = stream_payload[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_headers: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_headers) orelse return error.TestUnexpectedResult;

    // Check :status = 200 and grpc-status = 0
    var found_status = false;
    var found_grpc_status = false;
    for (resp_headers[0..hcount]) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            try std.testing.expectEqualSlices(u8, "200", h.value);
            found_status = true;
        }
        if (std.mem.eql(u8, h.name, "grpc-status")) {
            try std.testing.expectEqualSlices(u8, "0", h.value);
            found_grpc_status = true;
        }
    }
    try std.testing.expect(found_status);
    try std.testing.expect(found_grpc_status);

    // Parse DATA frame → decode gRPC message → verify echoed payload
    const after_headers = stream_payload[hdr.header_len + @as(usize, @intCast(hdr.length)) ..];
    const data_hdr = h3_frame.decodeFrameHeader(after_headers) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x00), data_hdr.frame_type);
    const data_payload = after_headers[data_hdr.header_len..][0..@intCast(data_hdr.length)];

    // Decode gRPC length-prefixed message
    const grpc_decoded = message_mod.decodeMessage(data_payload, 16384) catch return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, payload, grpc_decoded.payload);
}

test "gRPC Server E2E: unimplemented method" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    // No routes registered
    const port = server.getPort();

    var hs = try doHandshake(&server, port);
    defer hs.deinit();

    var req_buf: [2048]u8 = undefined;
    const req_len = buildGrpcRequest(&req_buf, "/unknown.Service/Method", "") orelse
        return error.TestUnexpectedResult;

    try hs.sendStream(0, req_buf[0..req_len], true, 0);

    var grpc_event = server.poll();
    for (0..10) |_| {
        if (grpc_event == .request) break;
        grpc_event = server.poll();
    }

    const req = switch (grpc_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    // handleAndRespond should send UNIMPLEMENTED
    try server.handleAndRespond(&req);

    // Client: verify grpc-status = 12 (UNIMPLEMENTED)
    const plaintext = try hs.recvAndDecryptOnStream(0);
    const stream_payload = extractStreamPayload(plaintext) orelse return error.TestUnexpectedResult;

    const hdr = h3_frame.decodeFrameHeader(stream_payload) orelse return error.TestUnexpectedResult;
    const hdr_payload = stream_payload[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_headers: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_headers) orelse return error.TestUnexpectedResult;

    var found_grpc_status = false;
    for (resp_headers[0..hcount]) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status")) {
            try std.testing.expectEqualSlices(u8, "12", h.value);
            found_grpc_status = true;
        }
    }
    try std.testing.expect(found_grpc_status);
}

/// Build only gRPC H3 HEADERS frame (no DATA). Used for streaming where HEADERS are sent first.
fn buildGrpcHeaders(out: []u8, method_path: []const u8) ?usize {
    var headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = method_path },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };
    var qpack_buf: [512]u8 = undefined;
    const qpack_len = qpack.Encoder.encode(&qpack_buf, &headers) orelse return null;

    return h3_frame.encodeHeadersFrame(out, qpack_buf[0..qpack_len]);
}

/// Build a gRPC DATA frame containing a length-prefixed message.
fn buildGrpcDataFrame(out: []u8, payload: []const u8) ?usize {
    var grpc_buf: [GrpcRequest.MAX_PAYLOAD + 5]u8 = undefined;
    const grpc_msg = message_mod.encodeMessage(&grpc_buf, payload, false) catch return null;
    return h3_frame.encodeDataFrame(out, grpc_msg);
}

test "gRPC Server E2E: server streaming" {
    const ServerStream = grpc_server_mod.ServerStream;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    try std.testing.expect(server.addRoute("/test.Stream/", EchoHandler.serviceHandler()));
    const port = server.getPort();

    var hs = try doHandshake(&server, port);
    defer hs.deinit();

    // Send gRPC request
    var req_buf: [2048]u8 = undefined;
    const req_len = buildGrpcRequest(&req_buf, "/test.Stream/ServerStream", "start") orelse
        return error.TestUnexpectedResult;
    try hs.sendStream(0, req_buf[0..req_len], true, 0);

    // Server: poll until gRPC request arrives
    var grpc_event = server.poll();
    for (0..10) |_| {
        if (grpc_event == .request) break;
        grpc_event = server.poll();
    }
    const req = switch (grpc_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    // Server: open stream and send 3 messages
    var stream: ServerStream = server.openStream(&req);
    const messages = [_][]const u8{ "msg-1", "msg-2", "msg-3" };
    for (messages) |msg| {
        try stream.send(msg);
    }
    try stream.close(.ok, "");

    // Client: receive first packet (headers + possibly first DATA frames)
    var all_data: [8192]u8 = undefined;
    var all_len: usize = 0;

    // Collect all packets on stream 0
    var recv_attempts: usize = 0;
    while (recv_attempts < 10) : (recv_attempts += 1) {
        const plaintext = hs.recvAndDecryptOnStream(0) catch break;
        const sp = extractStreamPayload(plaintext) orelse continue;
        if (all_len + sp.len > all_data.len) break;
        @memcpy(all_data[all_len..][0..sp.len], sp);
        all_len += sp.len;
    }

    if (all_len == 0) return error.TestUnexpectedResult;
    const stream_data = all_data[0..all_len];

    // Parse initial HEADERS frame (HTTP 200 + content-type)
    const hdr = h3_frame.decodeFrameHeader(stream_data) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);

    const hdr_payload = stream_data[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_headers: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_headers) orelse return error.TestUnexpectedResult;

    var found_status = false;
    for (resp_headers[0..hcount]) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            try std.testing.expectEqualSlices(u8, "200", h.value);
            found_status = true;
        }
    }
    try std.testing.expect(found_status);

    // Parse DATA frames containing the 3 gRPC messages
    var pos: usize = hdr.header_len + @as(usize, @intCast(hdr.length));
    var msg_count: usize = 0;

    while (pos < stream_data.len) {
        const frame_hdr = h3_frame.decodeFrameHeader(stream_data[pos..]) orelse break;
        const frame_payload = stream_data[pos + frame_hdr.header_len ..][0..@intCast(frame_hdr.length)];
        pos += frame_hdr.header_len + @as(usize, @intCast(frame_hdr.length));

        if (frame_hdr.frame_type == 0x00) {
            // DATA frame → decode gRPC length-prefixed message
            const grpc_decoded = message_mod.decodeMessage(frame_payload, 16384) catch continue;
            if (msg_count < messages.len) {
                try std.testing.expectEqualSlices(u8, messages[msg_count], grpc_decoded.payload);
            }
            msg_count += 1;
        } else if (frame_hdr.frame_type == 0x01) {
            // Trailing HEADERS (grpc-status)
            var trailer_headers: [32]qpack.HeaderField = undefined;
            const thcount = qpack.Decoder.decode(frame_payload, &trailer_headers) orelse continue;
            var found_grpc_status = false;
            for (trailer_headers[0..thcount]) |h| {
                if (std.mem.eql(u8, h.name, "grpc-status")) {
                    try std.testing.expectEqualSlices(u8, "0", h.value);
                    found_grpc_status = true;
                }
            }
            try std.testing.expect(found_grpc_status);
        }
    }

    try std.testing.expectEqual(@as(usize, 3), msg_count);
}

test "gRPC Server E2E: client streaming" {
    const ServerStream = grpc_server_mod.ServerStream;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    try std.testing.expect(server.addRoute("/test.Collect/", EchoHandler.serviceHandler()));
    const port = server.getPort();

    var hs = try doHandshake(&server, port);
    defer hs.deinit();

    // Client sends HEADERS + first DATA (no FIN)
    var req_buf: [2048]u8 = undefined;
    var req_pos: usize = 0;
    req_pos += buildGrpcHeaders(req_buf[req_pos..], "/test.Collect/Aggregate") orelse
        return error.TestUnexpectedResult;
    req_pos += buildGrpcDataFrame(req_buf[req_pos..], "chunk-1") orelse
        return error.TestUnexpectedResult;
    try hs.sendStream(0, req_buf[0..req_pos], false, 0);

    // Server: poll until initial request arrives
    var grpc_event = server.poll();
    for (0..10) |_| {
        if (grpc_event == .request) break;
        grpc_event = server.poll();
    }
    const req = switch (grpc_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "test.Collect", req.service());
    try std.testing.expectEqualSlices(u8, "Aggregate", req.method());
    try std.testing.expectEqualSlices(u8, "chunk-1", req.payload());

    // Server opens stream for receiving remaining client messages
    var stream: ServerStream = server.openStream(&req);

    // Client sends second message (no FIN)
    var data_buf: [512]u8 = undefined;
    const data_len2 = buildGrpcDataFrame(&data_buf, "chunk-2") orelse return error.TestUnexpectedResult;
    try hs.sendStream(0, data_buf[0..data_len2], false, 1);

    // Server receives second message
    const msg2 = try stream.recv() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "chunk-2", msg2.payload());
    try std.testing.expect(!msg2.fin);

    // Client sends third (final) message WITH FIN
    const data_len3 = buildGrpcDataFrame(&data_buf, "chunk-3") orelse return error.TestUnexpectedResult;
    try hs.sendStream(0, data_buf[0..data_len3], true, 2);

    // Server receives third message (fin=true)
    const msg3 = try stream.recv() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "chunk-3", msg3.payload());
    try std.testing.expect(msg3.fin);

    // Server: all client messages received. Send single aggregated response.
    try stream.send("chunk-1+chunk-2+chunk-3");
    try stream.close(.ok, "");

    // Client: receive response
    var all_data: [8192]u8 = undefined;
    var all_len: usize = 0;
    var recv_attempts: usize = 0;
    while (recv_attempts < 10) : (recv_attempts += 1) {
        const plaintext = hs.recvAndDecryptOnStream(0) catch break;
        const sp = extractStreamPayload(plaintext) orelse continue;
        if (all_len + sp.len > all_data.len) break;
        @memcpy(all_data[all_len..][0..sp.len], sp);
        all_len += sp.len;
    }

    if (all_len == 0) return error.TestUnexpectedResult;
    const stream_data = all_data[0..all_len];

    // Parse: HEADERS (200) + DATA (aggregated payload) + trailing HEADERS (grpc-status)
    const hdr = h3_frame.decodeFrameHeader(stream_data) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);

    // Verify :status = 200
    const hdr_payload = stream_data[hdr.header_len..][0..@intCast(hdr.length)];
    var resp_headers: [32]qpack.HeaderField = undefined;
    const hcount = qpack.Decoder.decode(hdr_payload, &resp_headers) orelse return error.TestUnexpectedResult;
    var found_status = false;
    for (resp_headers[0..hcount]) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            try std.testing.expectEqualSlices(u8, "200", h.value);
            found_status = true;
        }
    }
    try std.testing.expect(found_status);

    // Parse DATA frame → verify aggregated response
    var pos: usize = hdr.header_len + @as(usize, @intCast(hdr.length));
    var found_payload = false;
    var found_grpc_status = false;

    while (pos < stream_data.len) {
        const frame_hdr = h3_frame.decodeFrameHeader(stream_data[pos..]) orelse break;
        const frame_payload = stream_data[pos + frame_hdr.header_len ..][0..@intCast(frame_hdr.length)];
        pos += frame_hdr.header_len + @as(usize, @intCast(frame_hdr.length));

        if (frame_hdr.frame_type == 0x00) {
            const grpc_decoded = message_mod.decodeMessage(frame_payload, 16384) catch continue;
            try std.testing.expectEqualSlices(u8, "chunk-1+chunk-2+chunk-3", grpc_decoded.payload);
            found_payload = true;
        } else if (frame_hdr.frame_type == 0x01) {
            var trailer_headers: [32]qpack.HeaderField = undefined;
            const thcount = qpack.Decoder.decode(frame_payload, &trailer_headers) orelse continue;
            for (trailer_headers[0..thcount]) |h| {
                if (std.mem.eql(u8, h.name, "grpc-status")) {
                    try std.testing.expectEqualSlices(u8, "0", h.value);
                    found_grpc_status = true;
                }
            }
        }
    }

    try std.testing.expect(found_payload);
    try std.testing.expect(found_grpc_status);
}

test "gRPC Server E2E: bidi streaming" {
    const ServerStream = grpc_server_mod.ServerStream;

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(3000);
    try std.testing.expect(server.addRoute("/test.BiDi/", EchoHandler.serviceHandler()));
    const port = server.getPort();

    var hs = try doHandshake(&server, port);
    defer hs.deinit();

    // Client sends HEADERS + first DATA frame (no FIN) on stream 0
    var req_buf: [2048]u8 = undefined;
    var req_pos: usize = 0;
    req_pos += buildGrpcHeaders(req_buf[req_pos..], "/test.BiDi/Chat") orelse
        return error.TestUnexpectedResult;
    req_pos += buildGrpcDataFrame(req_buf[req_pos..], "msg-1") orelse
        return error.TestUnexpectedResult;

    // Send without FIN (streaming — client will send more)
    try hs.sendStream(0, req_buf[0..req_pos], false, 0);

    // Server: poll until request arrives (headers_emitted, fin=false)
    var grpc_event = server.poll();
    for (0..10) |_| {
        if (grpc_event == .request) break;
        grpc_event = server.poll();
    }
    const req = switch (grpc_event) {
        .request => |r| r,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "test.BiDi", req.service());
    try std.testing.expectEqualSlices(u8, "Chat", req.method());
    try std.testing.expectEqualSlices(u8, "msg-1", req.payload());
    try std.testing.expect(req.payload_len > 0);

    // Server: open stream and send first response
    var stream: ServerStream = server.openStream(&req);
    try stream.send("reply-1");

    // Client: send second message (still no FIN)
    var data_buf: [512]u8 = undefined;
    const data_len = buildGrpcDataFrame(&data_buf, "msg-2") orelse return error.TestUnexpectedResult;
    try hs.sendStream(0, data_buf[0..data_len], false, 1);

    // Server: recv the next client message
    const msg2 = try stream.recv() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "msg-2", msg2.payload());

    // Server: reply to second message
    try stream.send("reply-2");

    // Client: send third message with FIN (closes client side)
    const data_len3 = buildGrpcDataFrame(&data_buf, "msg-3") orelse return error.TestUnexpectedResult;
    try hs.sendStream(0, data_buf[0..data_len3], true, 2);

    // Server: recv the final client message (with fin)
    const msg3 = try stream.recv() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "msg-3", msg3.payload());
    try std.testing.expect(msg3.fin);

    // Server: send final response and close
    try stream.send("reply-3");
    try stream.close(.ok, "");

    // Client: receive all server messages
    var all_data: [8192]u8 = undefined;
    var all_len: usize = 0;
    var recv_attempts: usize = 0;
    while (recv_attempts < 10) : (recv_attempts += 1) {
        const plaintext = hs.recvAndDecryptOnStream(0) catch break;
        const sp = extractStreamPayload(plaintext) orelse continue;
        if (all_len + sp.len > all_data.len) break;
        @memcpy(all_data[all_len..][0..sp.len], sp);
        all_len += sp.len;
    }

    if (all_len == 0) return error.TestUnexpectedResult;
    const stream_data = all_data[0..all_len];

    // Parse response: HEADERS + 3 DATA frames + trailing HEADERS
    const hdr = h3_frame.decodeFrameHeader(stream_data) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), hdr.frame_type);

    var pos: usize = hdr.header_len + @as(usize, @intCast(hdr.length));
    var reply_count: usize = 0;
    const expected_replies = [_][]const u8{ "reply-1", "reply-2", "reply-3" };

    while (pos < stream_data.len) {
        const frame_hdr = h3_frame.decodeFrameHeader(stream_data[pos..]) orelse break;
        const frame_payload = stream_data[pos + frame_hdr.header_len ..][0..@intCast(frame_hdr.length)];
        pos += frame_hdr.header_len + @as(usize, @intCast(frame_hdr.length));

        if (frame_hdr.frame_type == 0x00) {
            const grpc_decoded = message_mod.decodeMessage(frame_payload, 16384) catch continue;
            if (reply_count < expected_replies.len) {
                try std.testing.expectEqualSlices(u8, expected_replies[reply_count], grpc_decoded.payload);
            }
            reply_count += 1;
        } else if (frame_hdr.frame_type == 0x01) {
            // Trailing HEADERS — verify grpc-status = 0
            var trailer_headers: [32]qpack.HeaderField = undefined;
            const thcount = qpack.Decoder.decode(frame_payload, &trailer_headers) orelse continue;
            for (trailer_headers[0..thcount]) |h| {
                if (std.mem.eql(u8, h.name, "grpc-status")) {
                    try std.testing.expectEqualSlices(u8, "0", h.value);
                }
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 3), reply_count);
}
