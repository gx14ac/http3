const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;
const quic_crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const handshake_mod = @import("handshake.zig");
const handshake_flight = @import("handshake_flight.zig");
const handshake_complete_mod = @import("handshake_complete.zig");
const tls_messages = @import("tls_messages.zig");
const server_hs = @import("server_handshake.zig");
const flow_control_mod = @import("flow_control.zig");

pub const ServerError = error{
    BindFailed,
    SocketError,
    InvalidPacket,
    HandshakeFailed,
    BufferTooSmall,
    DecryptFailed,
    Timeout,
};

/// Server connection state.
pub const ServerConn = struct {
    state: ConnState,
    dcid: [20]u8,
    dcid_len: u8,
    scid: [20]u8,
    scid_len: u8,
    client_dcid: [20]u8,
    client_dcid_len: u8,
    handshake_keys: ?handshake_mod.HandshakeKeys,
    app_keys: ?handshake_flight.ApplicationKeys,
    client_traffic_secret: ?[32]u8,
    server_traffic_secret: ?[32]u8,
    initial_send_pn: u64,
    handshake_send_pn: u64,
    app_send_pn: u64,
    app_recv_pn: u64,
    client_addr: ?std.net.Address,
    transcript_after_server_finished: ?[32]u8,
    initial_crypto: handshake_flight.CryptoReassembler,
    handshake_crypto: handshake_flight.CryptoReassembler,
    flow: flow_control_mod.FlowController,
    active: bool,

    pub const ConnState = enum {
        awaiting_initial,
        handshake_sent,
        connected,
        closed,
    };

    pub fn init(scid: []const u8) ServerConn {
        var conn: ServerConn = .{
            .state = .awaiting_initial,
            .dcid = undefined,
            .dcid_len = 0,
            .scid = undefined,
            .scid_len = @intCast(@min(scid.len, 20)),
            .client_dcid = undefined,
            .client_dcid_len = 0,
            .handshake_keys = null,
            .app_keys = null,
            .client_traffic_secret = null,
            .server_traffic_secret = null,
            .initial_send_pn = 0,
            .handshake_send_pn = 0,
            .app_send_pn = 0,
            .app_recv_pn = 0,
            .client_addr = null,
            .transcript_after_server_finished = null,
            .initial_crypto = handshake_flight.CryptoReassembler.init(),
            .handshake_crypto = handshake_flight.CryptoReassembler.init(),
            .flow = flow_control_mod.FlowController.init(.{}),
            .active = true,
        };
        @memcpy(conn.scid[0..conn.scid_len], scid[0..conn.scid_len]);
        return conn;
    }

    pub fn scidSlice(self: *const ServerConn) []const u8 {
        return self.scid[0..self.scid_len];
    }

    pub fn dcidSlice(self: *const ServerConn) []const u8 {
        return self.dcid[0..self.dcid_len];
    }
};

/// QUIC server supporting multiple concurrent connections.
/// Connection table is fixed-size (no allocator needed).
pub const QuicServer = struct {
    fd: posix.socket_t,
    bind_addr: std.net.Address,
    conns: [MAX_CONNS]ServerConn,
    conn_count: usize,
    signing_key: crypto.sign.Ed25519.KeyPair,
    cert_der: [1024]u8,
    cert_der_len: usize,
    recv_stream_buf: [4096]u8,
    recv_stream_len: usize,

    pub const MAX_CONNS = 16;

    pub const Config = struct {
        cert_der: []const u8 = "QUIC-TEST-CERT",
    };

    pub fn init(bind_addr: std.net.Address, config: Config) ServerError!QuicServer {
        const family: u32 = switch (bind_addr.any.family) {
            posix.AF.INET => posix.AF.INET,
            posix.AF.INET6 => posix.AF.INET6,
            else => return ServerError.BindFailed,
        };

        const fd = posix.socket(family, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch
            return ServerError.SocketError;
        errdefer posix.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};

        posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen()) catch
            return ServerError.BindFailed;

        var cert_buf: [1024]u8 = undefined;
        const cert_len = @min(config.cert_der.len, 1024);
        @memcpy(cert_buf[0..cert_len], config.cert_der[0..cert_len]);

        return .{
            .fd = fd,
            .bind_addr = bind_addr,
            .conns = undefined,
            .conn_count = 0,
            .signing_key = crypto.sign.Ed25519.KeyPair.generate(),
            .cert_der = cert_buf,
            .cert_der_len = cert_len,
            .recv_stream_buf = undefined,
            .recv_stream_len = 0,
        };
    }

    /// Get the primary connection (backward-compat accessor).
    pub fn conn(self: *QuicServer) *ServerConn {
        return &self.conns[0];
    }

    pub fn deinit(self: *QuicServer) void {
        posix.close(self.fd);
    }

    /// Get the bound port (useful when binding to port 0).
    pub fn getPort(self: *const QuicServer) u16 {
        var addr: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        posix.getsockname(self.fd, @ptrCast(&addr), &addr_len) catch return 0;
        const sa: *const posix.sockaddr.in = @ptrCast(@alignCast(&addr));
        return std.mem.bigToNative(u16, sa.port);
    }

    /// Set receive timeout.
    pub fn setTimeout(self: *QuicServer, timeout_ms: u64) void {
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }

    /// Wait for and process one client datagram. Returns an event.
    pub fn poll(self: *QuicServer, buf: []u8) ServerError!ServerEvent {
        var src_addr: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

        const n = posix.recvfrom(self.fd, buf, 0, @ptrCast(&src_addr), &addr_len) catch |e| {
            return switch (e) {
                error.WouldBlock => ServerError.Timeout,
                else => ServerError.SocketError,
            };
        };
        if (n == 0) return ServerError.SocketError;

        const data = buf[0..n];

        // Route by DCID: extract from packet header
        const conn_idx = self.routePacket(data) orelse {
            // New connection — find a free slot or use slot 0 for Initial
            if (data.len >= 1 and data[0] & 0x80 != 0) {
                return self.handleInitial(data, &src_addr);
            }
            return ServerError.InvalidPacket;
        };

        return switch (self.conns[conn_idx].state) {
            .awaiting_initial => self.handleInitial(data, &src_addr),
            .handshake_sent => self.handleHandshakeResponse(data),
            .connected => self.handleAppDataForConn(data, conn_idx),
            .closed => .closed,
        };
    }

    /// Route a packet to an existing connection by matching DCID against conn SCIDs.
    fn routePacket(self: *const QuicServer, data: []const u8) ?usize {
        if (data.len < 1) return null;

        if (data[0] & 0x80 != 0) {
            // Long header: DCID at offset 6, length at offset 5
            if (data.len < 7) return null;
            const dcid_len: usize = data[5];
            if (data.len < 6 + dcid_len) return null;
            const dcid = data[6..][0..dcid_len];
            return self.findConnByScid(dcid);
        } else {
            // Short header: DCID starts at offset 1, length matches conn's scid_len
            for (0..self.conn_count) |i| {
                if (!self.conns[i].active) continue;
                const scid_len = self.conns[i].scid_len;
                if (data.len < 1 + scid_len) continue;
                if (std.mem.eql(u8, data[1..][0..scid_len], self.conns[i].scid[0..scid_len])) {
                    return i;
                }
            }
            return null;
        }
    }

    fn findConnByScid(self: *const QuicServer, dcid: []const u8) ?usize {
        for (0..self.conn_count) |i| {
            if (!self.conns[i].active) continue;
            if (dcid.len == self.conns[i].scid_len and
                std.mem.eql(u8, dcid, self.conns[i].scid[0..self.conns[i].scid_len]))
            {
                return i;
            }
        }
        return null;
    }

    /// Allocate a new connection slot. Returns index or null if full.
    fn allocConn(self: *QuicServer) ?usize {
        if (self.conn_count < MAX_CONNS) {
            const idx = self.conn_count;
            var scid: [8]u8 = undefined;
            crypto.random.bytes(&scid);
            self.conns[idx] = ServerConn.init(&scid);
            self.conn_count += 1;
            return idx;
        }
        // Look for an inactive slot to recycle
        for (0..self.conn_count) |i| {
            if (!self.conns[i].active) {
                var scid: [8]u8 = undefined;
                crypto.random.bytes(&scid);
                self.conns[i] = ServerConn.init(&scid);
                return i;
            }
        }
        return null;
    }

    /// Handle a client Initial packet: decrypt, parse CH, send SH + handshake flight.
    fn handleInitial(self: *QuicServer, data: []u8, src_addr: *const posix.sockaddr.storage) ServerError!ServerEvent {
        if (data.len < 1200) return ServerError.InvalidPacket; // RFC 9000 §14.1

        // Parse long header
        if (data[0] & 0x80 == 0) return ServerError.InvalidPacket;
        const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
        if (ptype != @intFromEnum(packet_mod.PacketType.initial)) return ServerError.InvalidPacket;

        if (data.len < 7) return ServerError.InvalidPacket;
        const dcid_len: usize = data[5];
        if (data.len < 6 + dcid_len + 1) return ServerError.InvalidPacket;
        const dcid = data[6..][0..dcid_len];
        const scid_len: usize = data[6 + dcid_len];
        if (data.len < 7 + dcid_len + scid_len) return ServerError.InvalidPacket;
        const client_scid = data[7 + dcid_len ..][0..scid_len];

        var pos: usize = 7 + dcid_len + scid_len;

        // Token
        const token_varint = packet_mod.decodeVarint(data[pos..]) orelse return ServerError.InvalidPacket;
        pos += token_varint.consumed;
        pos += @intCast(token_varint.value);

        // Length
        const length_varint = packet_mod.decodeVarint(data[pos..]) orelse return ServerError.InvalidPacket;
        pos += length_varint.consumed;
        const length: usize = @intCast(length_varint.value);
        if (data.len < pos + length) return ServerError.InvalidPacket;

        const pn_offset = pos;

        // Derive Initial keys from DCID (which is what the client used as destination)
        const keys = quic_crypto.deriveInitialKeys(dcid);

        // Remove header protection (client HP key)
        if (data.len < pn_offset + 4 + 16) return ServerError.DecryptFailed;
        quic_crypto.removeHeaderProtection(data, pn_offset, keys.client_hp);

        const pn_length: usize = (data[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_length) |i| {
            pn = (pn << 8) | data[pn_offset + i];
        }

        // AAD
        const aad = data[0 .. pn_offset + pn_length];
        const ct_start = pn_offset + pn_length;
        const ct_len = length - pn_length - 16;
        if (data.len < ct_start + ct_len + 16) return ServerError.DecryptFailed;
        const ciphertext = data[ct_start..][0..ct_len];
        const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

        // Decrypt
        var plaintext: [4096]u8 = undefined;
        if (ct_len > plaintext.len) return ServerError.BufferTooSmall;
        const ok = quic_crypto.decryptPayload(
            plaintext[0..ct_len],
            ciphertext,
            tag.*,
            keys.client_key,
            keys.client_iv,
            pn,
            aad,
        );
        if (!ok) return ServerError.DecryptFailed;

        // Allocate a new connection slot for this client
        const ci = self.allocConn() orelse return ServerError.BufferTooSmall;

        // Feed CRYPTO frames through the reassembler
        if (!feedCryptoFrames(&self.conns[ci].initial_crypto, plaintext[0..ct_len]))
            return ServerError.InvalidPacket;

        const crypto_data = self.conns[ci].initial_crypto.getData();
        if (crypto_data.len == 0) return ServerError.InvalidPacket;

        // Parse ClientHello
        const parsed_ch = server_hs.parseClientHello(crypto_data) catch
            return ServerError.HandshakeFailed;

        // Store client connection info
        const client_dcid_len: u8 = @intCast(@min(dcid_len, 20));
        @memcpy(self.conns[ci].client_dcid[0..client_dcid_len], dcid[0..client_dcid_len]);
        self.conns[ci].client_dcid_len = client_dcid_len;

        // Client's SCID becomes our DCID
        const conn_dcid_len: u8 = @intCast(@min(scid_len, 20));
        @memcpy(self.conns[ci].dcid[0..conn_dcid_len], client_scid[0..conn_dcid_len]);
        self.conns[ci].dcid_len = conn_dcid_len;

        self.conns[ci].client_addr = addrFromStorage(src_addr);

        // Run server handshake
        var sh_buf: [512]u8 = undefined;
        var sh_len: usize = 0;
        var hs_buf: [4096]u8 = undefined;
        var hs_len: usize = 0;

        const hs_state = server_hs.ServerHandshakeState.init(
            crypto_data,
            parsed_ch,
            self.conns[ci].scid[0..self.conns[ci].scid_len],
            self.cert_der[0..self.cert_der_len],
            self.signing_key,
            &sh_buf,
            &sh_len,
            &hs_buf,
            &hs_len,
        ) catch return ServerError.HandshakeFailed;

        // Store keys
        self.conns[ci].handshake_keys = hs_state.handshake_keys;
        self.conns[ci].app_keys = hs_state.app_keys.keys;
        self.conns[ci].client_traffic_secret = hs_state.app_keys.client_secret;
        self.conns[ci].server_traffic_secret = hs_state.app_keys.server_secret;
        self.conns[ci].transcript_after_server_finished = hs_state.transcript_after_server_finished;

        // Send Initial packet with ServerHello + Handshake packet with EE+Cert+CV+Finished
        var send_buf: [4096]u8 = undefined;
        const send_len = self.buildServerResponseForConn(
            &send_buf,
            sh_buf[0..sh_len],
            hs_buf[0..hs_len],
            dcid,
            ci,
        ) orelse return ServerError.BufferTooSmall;

        const dst = self.conns[ci].client_addr orelse return ServerError.SocketError;
        self.sendToAddr(send_buf[0..send_len], dst) catch return ServerError.SocketError;

        self.conns[ci].state = .handshake_sent;
        return .handshake_started;
    }

    /// Build the server's Initial (containing ServerHello) + Handshake packet.
    fn buildServerResponseForConn(self: *QuicServer, buf: []u8, server_hello: []const u8, hs_flight: []const u8, original_dcid: []const u8, ci: usize) ?usize {
        var total: usize = 0;

        // 1. Server Initial packet containing ServerHello in CRYPTO frame
        const initial_len = self.buildServerInitialForConn(buf, server_hello, original_dcid, ci) orelse return null;
        total += initial_len;

        // 2. Handshake packet containing EE+Cert+CV+Finished in CRYPTO frame (Handshake PN space)
        const hs_keys = self.conns[ci].handshake_keys orelse return null;
        const hs_pn = self.conns[ci].handshake_send_pn;
        self.conns[ci].handshake_send_pn += 1;
        const hs_pkt_len = buildHandshakePacket(
            buf[total..],
            hs_flight,
            hs_pn,
            self.conns[ci].scid[0..self.conns[ci].scid_len],
            self.conns[ci].dcid[0..self.conns[ci].dcid_len],
            hs_keys.server_key,
            hs_keys.server_iv,
            hs_keys.server_hp,
        ) orelse return null;
        total += hs_pkt_len;

        return total;
    }

    /// Build server Initial packet with CRYPTO frame.
    fn buildServerInitialForConn(self: *QuicServer, buf: []u8, server_hello: []const u8, original_dcid: []const u8, ci: usize) ?usize {
        // Derive Initial keys from the client's original DCID
        const keys = quic_crypto.deriveInitialKeys(original_dcid);

        // CRYPTO frame
        var crypto_frame: [1024]u8 = undefined;
        var cpos: usize = 0;
        crypto_frame[cpos] = 0x06;
        cpos += 1;
        cpos += packet_mod.encodeVarint(crypto_frame[cpos..], 0) orelse return null;
        cpos += packet_mod.encodeVarint(crypto_frame[cpos..], server_hello.len) orelse return null;
        @memcpy(crypto_frame[cpos..][0..server_hello.len], server_hello);
        cpos += server_hello.len;

        // Build long header (Initial PN space)
        const scid = self.conns[ci].scid[0..self.conns[ci].scid_len];
        const dcid = self.conns[ci].dcid[0..self.conns[ci].dcid_len];
        const pn: u64 = self.conns[ci].initial_send_pn;
        self.conns[ci].initial_send_pn += 1;

        return encodeAndProtectLongHeader(
            buf,
            .initial,
            scid,
            dcid,
            pn,
            crypto_frame[0..cpos],
            keys.server_key,
            keys.server_iv,
            keys.server_hp,
        );
    }

    /// Handle client's Handshake packet containing Client Finished.
    fn handleHandshakeResponse(self: *QuicServer, data: []u8) ServerError!ServerEvent {
        if (data.len < 7) return ServerError.InvalidPacket;
        if (data[0] & 0x80 == 0) return ServerError.InvalidPacket;

        const ptype: u2 = @intCast((data[0] >> 4) & 0x03);
        if (ptype != @intFromEnum(packet_mod.PacketType.handshake)) return ServerError.InvalidPacket;

        // Find which connection this belongs to
        const dcid_len: usize = data[5];
        if (data.len < 6 + dcid_len + 1) return ServerError.InvalidPacket;
        const ci = self.findConnByScid(data[6..][0..dcid_len]) orelse return ServerError.InvalidPacket;

        const hs_keys = self.conns[ci].handshake_keys orelse return ServerError.HandshakeFailed;

        // Parse header
        const scid_len: usize = data[6 + dcid_len];
        var hpos: usize = 7 + dcid_len + scid_len;

        // Length
        const length_varint = packet_mod.decodeVarint(data[hpos..]) orelse return ServerError.InvalidPacket;
        hpos += length_varint.consumed;
        const length: usize = @intCast(length_varint.value);
        if (data.len < hpos + length) return ServerError.InvalidPacket;

        const pn_offset = hpos;

        // Remove HP
        if (data.len < pn_offset + 4 + 16) return ServerError.DecryptFailed;
        quic_crypto.removeHeaderProtection(data, pn_offset, hs_keys.client_hp);

        const pn_length: usize = (data[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_length) |i| {
            pn = (pn << 8) | data[pn_offset + i];
        }

        const aad = data[0 .. pn_offset + pn_length];
        const ct_start = pn_offset + pn_length;
        const ct_len = length - pn_length - 16;
        if (data.len < ct_start + ct_len + 16) return ServerError.DecryptFailed;
        const ciphertext = data[ct_start..][0..ct_len];
        const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

        var plaintext: [1024]u8 = undefined;
        if (ct_len > plaintext.len) return ServerError.BufferTooSmall;
        const ok = quic_crypto.decryptPayload(
            plaintext[0..ct_len],
            ciphertext,
            tag.*,
            hs_keys.client_key,
            hs_keys.client_iv,
            pn,
            aad,
        );
        if (!ok) return ServerError.DecryptFailed;

        // Feed CRYPTO frames through the handshake reassembler
        if (!feedCryptoFrames(&self.conns[ci].handshake_crypto, plaintext[0..ct_len]))
            return ServerError.InvalidPacket;

        const crypto_data = self.conns[ci].handshake_crypto.getData();
        if (crypto_data.len == 0) return ServerError.InvalidPacket;

        // Validate: type(1) + length(3) + verify_data(32) = 36 bytes minimum
        if (crypto_data.len < 36) return ServerError.InvalidPacket;
        if (crypto_data[0] != @intFromEnum(tls_messages.HandshakeType.finished)) return ServerError.InvalidPacket;

        // Verify Client Finished
        const transcript_sf = self.conns[ci].transcript_after_server_finished orelse return ServerError.HandshakeFailed;
        if (!tls_messages.verifyFinished(hs_keys.client_handshake_secret, transcript_sf, crypto_data[4..36])) {
            return ServerError.HandshakeFailed;
        }

        self.conns[ci].state = .connected;
        self.conns[ci].app_recv_pn = 0;

        // Initialize flow control: assume peer advertises standard defaults
        // (In production, this should come from parsing client transport params)
        self.conns[ci].flow.setPeerParams(.{});

        // RFC 9000 §7.3: Server MUST send HANDSHAKE_DONE in a 1-RTT packet
        self.sendHandshakeDone(ci);

        return .{ .connected = ci };
    }

    /// Handle 1-RTT (short header) application data.
    fn handleAppDataForConn(self: *QuicServer, data: []u8, ci: usize) ServerError!ServerEvent {
        if (data.len < 1) return ServerError.InvalidPacket;
        if (data[0] & 0x80 != 0) {
            return .none;
        }

        const app_keys = self.conns[ci].app_keys orelse return ServerError.HandshakeFailed;
        const dcid_len = self.conns[ci].scid_len;

        if (data.len < 1 + dcid_len + 4 + 16) return ServerError.InvalidPacket;

        const pn_offset: usize = 1 + dcid_len;
        quic_crypto.removeHeaderProtection(data, pn_offset, app_keys.client_hp);

        const pn_length: usize = (data[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_length) |i| {
            pn = (pn << 8) | data[pn_offset + i];
        }

        const aad = data[0 .. pn_offset + pn_length];
        const ct_start = pn_offset + pn_length;
        if (data.len < ct_start + 16) return ServerError.DecryptFailed;
        const ct_len = data.len - ct_start - 16;
        const ciphertext = data[ct_start..][0..ct_len];
        const tag: *const [16]u8 = data[ct_start + ct_len ..][0..16];

        var plaintext: [4096]u8 = undefined;
        if (ct_len > plaintext.len) return ServerError.BufferTooSmall;
        const ok = quic_crypto.decryptPayload(
            plaintext[0..ct_len],
            ciphertext,
            tag.*,
            app_keys.client_key,
            app_keys.client_iv,
            pn,
            aad,
        );
        if (!ok) return ServerError.DecryptFailed;

        // Process flow control frames (MAX_DATA, MAX_STREAM_DATA) from client
        self.processFlowControlFrames(ci, plaintext[0..ct_len]);

        // Parse all STREAM frames and concatenate payload into recv buffer
        var total_len: usize = 0;
        var result_stream_id: u62 = 0;
        var result_offset: u64 = 0;
        var result_fin: bool = false;
        var found_any: bool = false;

        var scan_pos: usize = 0;
        while (scan_pos < ct_len) {
            const sf = extractStreamFrameAt(plaintext[0..ct_len], scan_pos) orelse break;
            if (!found_any) {
                result_stream_id = sf.stream_id;
                result_offset = sf.offset;
                found_any = true;
            }
            if (sf.fin) result_fin = true;
            const copy_len = @min(sf.data_len, self.recv_stream_buf.len - total_len);
            @memcpy(self.recv_stream_buf[total_len..][0..copy_len], plaintext[sf.data_start..][0..copy_len]);
            total_len += copy_len;
            scan_pos = sf.frame_end;
        }

        if (!found_any) return .none;

        // Track received bytes in flow controller
        _ = self.conns[ci].flow.openStream(result_stream_id);
        self.conns[ci].flow.onRecv(result_stream_id, total_len);

        // Send MAX_DATA / MAX_STREAM_DATA if thresholds exceeded
        self.sendFlowControlUpdates(ci);

        self.recv_stream_len = total_len;
        return .{ .data_received = .{
            .stream_id = result_stream_id,
            .conn_idx = ci,
            .offset = result_offset,
            .data = self.recv_stream_buf[0..total_len],
            .fin = result_fin,
        } };
    }

    /// Send data on a stream for connection at the given index.
    pub fn sendStreamDataOn(self: *QuicServer, ci: usize, stream_id: u62, data: []const u8, fin: bool) ServerError!void {
        const app_keys = self.conns[ci].app_keys orelse return ServerError.HandshakeFailed;
        const client_addr = self.conns[ci].client_addr orelse return ServerError.SocketError;

        // Ensure stream is registered in flow controller
        _ = self.conns[ci].flow.openStream(stream_id);

        // Track send offset for flow control
        self.conns[ci].flow.onSend(stream_id, data.len);

        // Build STREAM frame
        var frame_buf: [4096]u8 = undefined;
        var fpos: usize = 0;

        var frame_type: u8 = 0x08 | 0x02;
        if (fin) frame_type |= 0x01;
        frame_buf[fpos] = frame_type;
        fpos += 1;

        fpos += packet_mod.encodeVarint(frame_buf[fpos..], stream_id) orelse return ServerError.BufferTooSmall;
        fpos += packet_mod.encodeVarint(frame_buf[fpos..], data.len) orelse return ServerError.BufferTooSmall;
        if (fpos + data.len > frame_buf.len) return ServerError.BufferTooSmall;
        @memcpy(frame_buf[fpos..][0..data.len], data);
        fpos += data.len;

        var pkt_buf: [4096]u8 = undefined;
        const pn = self.conns[ci].app_send_pn;
        self.conns[ci].app_send_pn += 1;

        const pkt_len = encodeShortHeaderPacket(
            &pkt_buf,
            self.conns[ci].dcid[0..self.conns[ci].dcid_len],
            pn,
            frame_buf[0..fpos],
            app_keys.server_key,
            app_keys.server_iv,
            app_keys.server_hp,
        ) orelse return ServerError.BufferTooSmall;

        self.sendToAddr(pkt_buf[0..pkt_len], client_addr) catch return ServerError.SocketError;
    }

    /// Send data on a stream (backward-compat: uses first connection).
    pub fn sendStreamData(self: *QuicServer, stream_id: u62, data: []const u8, fin: bool) ServerError!void {
        return self.sendStreamDataOn(0, stream_id, data, fin);
    }

    /// Send MAX_DATA / MAX_STREAM_DATA frames if flow control thresholds are exceeded.
    fn sendFlowControlUpdates(self: *QuicServer, ci: usize) void {
        var fc_buf: [256]u8 = undefined;
        const fc_len = self.conns[ci].flow.buildFlowControlFrames(&fc_buf);
        if (fc_len == 0) return;

        const app_keys = self.conns[ci].app_keys orelse return;
        const client_addr = self.conns[ci].client_addr orelse return;

        var pkt_buf: [512]u8 = undefined;
        const pn = self.conns[ci].app_send_pn;
        self.conns[ci].app_send_pn += 1;

        const pkt_len = encodeShortHeaderPacket(
            &pkt_buf,
            self.conns[ci].dcid[0..self.conns[ci].dcid_len],
            pn,
            fc_buf[0..fc_len],
            app_keys.server_key,
            app_keys.server_iv,
            app_keys.server_hp,
        ) orelse return;

        self.sendToAddr(pkt_buf[0..pkt_len], client_addr) catch {};
    }

    /// Process MAX_DATA and MAX_STREAM_DATA frames from plaintext.
    fn processFlowControlFrames(self: *QuicServer, ci: usize, plaintext: []const u8) void {
        var pos: usize = 0;
        while (pos < plaintext.len) {
            if (pos >= plaintext.len) break;
            const ft = plaintext[pos];
            switch (ft) {
                0x00 => {
                    pos += 1; // PADDING
                },
                0x10 => {
                    // MAX_DATA
                    pos += 1;
                    const v = packet_mod.decodeVarint(plaintext[pos..]) orelse return;
                    pos += v.consumed;
                    self.conns[ci].flow.onMaxData(v.value);
                },
                0x11 => {
                    // MAX_STREAM_DATA
                    pos += 1;
                    const sid_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return;
                    pos += sid_v.consumed;
                    const max_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return;
                    pos += max_v.consumed;
                    self.conns[ci].flow.onMaxStreamData(@intCast(sid_v.value), max_v.value);
                },
                else => return,
            }
        }
    }

    /// Send HANDSHAKE_DONE frame (type 0x1e) in a 1-RTT packet (RFC 9000 §7.3).
    fn sendHandshakeDone(self: *QuicServer, ci: usize) void {
        const app_keys = self.conns[ci].app_keys orelse return;
        const client_addr = self.conns[ci].client_addr orelse return;

        // HANDSHAKE_DONE is a single byte: frame type 0x1e
        const frame = [_]u8{0x1e};

        var pkt_buf: [128]u8 = undefined;
        const pn = self.conns[ci].app_send_pn;
        self.conns[ci].app_send_pn += 1;

        const pkt_len = encodeShortHeaderPacket(
            &pkt_buf,
            self.conns[ci].dcid[0..self.conns[ci].dcid_len],
            pn,
            &frame,
            app_keys.server_key,
            app_keys.server_iv,
            app_keys.server_hp,
        ) orelse return;

        self.sendToAddr(pkt_buf[0..pkt_len], client_addr) catch {};
    }

    fn sendToAddr(self: *QuicServer, data: []const u8, addr: std.net.Address) !void {
        _ = posix.sendto(self.fd, data, 0, &addr.any, addr.getOsSockLen()) catch
            return error.SocketError;
    }
};

fn addrFromStorage(storage: *const posix.sockaddr.storage) ?std.net.Address {
    const sa: *align(4) const posix.sockaddr = @ptrCast(@alignCast(storage));
    return std.net.Address.initPosix(sa);
}

pub const ServerEvent = union(enum) {
    none,
    handshake_started,
    connected: usize,
    data_received: StreamData,
    closed,
};

pub const StreamData = struct {
    stream_id: u62,
    conn_idx: usize,
    offset: u64,
    data: []const u8,
    fin: bool,
};

// ─── Packet encoding helpers ───

fn encodeAndProtectLongHeader(
    buf: []u8,
    ptype: packet_mod.PacketType,
    scid: []const u8,
    dcid: []const u8,
    pn: u64,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    const pn_len: u8 = if (pn < 256) 0 else if (pn < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;

    var pos: usize = 0;

    // First byte
    const ptype_bits: u8 = @intCast(@intFromEnum(ptype));
    buf[pos] = 0xC0 | (ptype_bits << 4) | pn_len;
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

    // For Initial packets: token length = 0
    if (ptype == .initial) {
        buf[pos] = 0;
        pos += 1;
    }

    // Length field (varint): pn_bytes + payload + 16 (tag)
    const length_val: usize = @as(usize, pn_bytes) + payload.len + 16;
    pos += packet_mod.encodeVarint(buf[pos..], length_val) orelse return null;

    // Packet number
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((pn >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // AAD
    const aad = buf[0..pos];

    // Encrypt
    var ciphertext: [4096]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(
        ciphertext[0..payload.len],
        &tag,
        payload,
        key,
        iv,
        pn,
        aad,
    );

    @memcpy(buf[pos..][0..payload.len], ciphertext[0..payload.len]);
    pos += payload.len;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    // Header protection
    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, hp);

    return pos;
}

fn buildHandshakePacket(
    buf: []u8,
    crypto_payload: []const u8,
    pn: u64,
    scid: []const u8,
    dcid: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    // Build CRYPTO frame
    var crypto_frame: [4096]u8 = undefined;
    var cpos: usize = 0;
    crypto_frame[cpos] = 0x06;
    cpos += 1;
    cpos += packet_mod.encodeVarint(crypto_frame[cpos..], 0) orelse return null;
    cpos += packet_mod.encodeVarint(crypto_frame[cpos..], crypto_payload.len) orelse return null;
    if (cpos + crypto_payload.len > crypto_frame.len) return null;
    @memcpy(crypto_frame[cpos..][0..crypto_payload.len], crypto_payload);
    cpos += crypto_payload.len;

    return encodeAndProtectLongHeader(buf, .handshake, scid, dcid, pn, crypto_frame[0..cpos], key, iv, hp);
}

fn encodeShortHeaderPacket(
    buf: []u8,
    dcid: []const u8,
    pn: u64,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    const pn_len: u8 = if (pn < 256) 0 else if (pn < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;

    var pos: usize = 0;

    // First byte: form=0, fixed=1, spin=0, reserved=00, key_phase=0, pn_len
    buf[pos] = 0x40 | pn_len;
    pos += 1;

    // DCID
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    // PN
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((pn >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // AAD
    const aad = buf[0..pos];

    // Encrypt
    var ciphertext: [4096]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(
        ciphertext[0..payload.len],
        &tag,
        payload,
        key,
        iv,
        pn,
        aad,
    );

    @memcpy(buf[pos..][0..payload.len], ciphertext[0..payload.len]);
    pos += payload.len;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, hp);

    return pos;
}

// ─── Frame parsing helpers ───

/// Feed all CRYPTO frames from a decrypted packet into a CryptoReassembler.
/// Returns false if the packet is malformed.
fn feedCryptoFrames(reassembler: *handshake_flight.CryptoReassembler, plaintext: []const u8) bool {
    var pos: usize = 0;
    var found_crypto = false;
    while (pos < plaintext.len) {
        const frame_type = plaintext[pos];
        if (frame_type == 0x00) {
            pos += 1;
            continue;
        }
        if (frame_type == 0x02 or frame_type == 0x03) {
            // ACK frame — skip
            pos += 1;
            const v1 = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += v1.consumed;
            const v2 = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += v2.consumed;
            const v3 = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += v3.consumed;
            const range_count: usize = @intCast(v3.value);
            const v4 = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += v4.consumed;
            for (0..range_count) |_| {
                const g = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
                pos += g.consumed;
                const a = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
                pos += a.consumed;
            }
            continue;
        }
        if (frame_type == 0x06) {
            pos += 1;
            const offset_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += offset_v.consumed;
            const len_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return false;
            pos += len_v.consumed;
            const data_len: usize = @intCast(len_v.value);
            if (pos + data_len > plaintext.len) return false;
            if (!reassembler.insert(offset_v.value, plaintext[pos..][0..data_len])) return false;
            pos += data_len;
            found_crypto = true;
            continue;
        }
        // Unknown frame type in Initial/Handshake — skip remaining
        break;
    }
    return found_crypto;
}

const StreamFrameInfo = struct {
    stream_id: u62,
    offset: u64,
    data_start: usize,
    data_len: usize,
    fin: bool,
    frame_end: usize,
};

/// Extract the next STREAM frame starting at `start_pos`, skipping PADDING and non-STREAM frames.
fn extractStreamFrameAt(plaintext: []const u8, start_pos: usize) ?StreamFrameInfo {
    var pos: usize = start_pos;
    while (pos < plaintext.len) {
        const frame_type = plaintext[pos];
        if (frame_type == 0x00) {
            pos += 1;
            continue;
        }
        if (frame_type & 0xF8 == 0x08) {
            const has_off = (frame_type & 0x04) != 0;
            const has_len = (frame_type & 0x02) != 0;
            const has_fin = (frame_type & 0x01) != 0;
            pos += 1;

            const sid_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
            pos += sid_v.consumed;
            const stream_id: u62 = @intCast(sid_v.value);

            var offset: u64 = 0;
            if (has_off) {
                const off_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
                pos += off_v.consumed;
                offset = off_v.value;
            }

            var data_len: usize = 0;
            if (has_len) {
                const len_v = packet_mod.decodeVarint(plaintext[pos..]) orelse return null;
                pos += len_v.consumed;
                data_len = @intCast(len_v.value);
            } else {
                data_len = plaintext.len - pos;
            }

            if (pos + data_len > plaintext.len) return null;

            return .{
                .stream_id = stream_id,
                .offset = offset,
                .data_start = pos,
                .data_len = data_len,
                .fin = has_fin,
                .frame_end = pos + data_len,
            };
        }
        // Non-STREAM, non-PADDING frame — skip past it
        break;
    }
    return null;
}

fn extractStreamFrame(plaintext: []const u8) ?StreamFrameInfo {
    return extractStreamFrameAt(plaintext, 0);
}

// ─── Tests ───

test "QuicServer: create and close" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try QuicServer.init(addr, .{});
    defer server.deinit();
    try std.testing.expect(server.getPort() > 0);
}

test "encodeAndProtectLongHeader: produces valid packet" {
    const keys = quic_crypto.deriveInitialKeys(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    var buf: [1500]u8 = undefined;
    const payload = "test CRYPTO data";
    const len = encodeAndProtectLongHeader(
        &buf,
        .initial,
        &[_]u8{ 0x05, 0x06, 0x07, 0x08 },
        &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
        0,
        payload,
        keys.server_key,
        keys.server_iv,
        keys.server_hp,
    ) orelse unreachable;

    try std.testing.expect(len > 0);
    // Long header bit should be set (even after HP)
    try std.testing.expect(buf[0] & 0x80 != 0);
}

test "encodeShortHeaderPacket: produces valid packet" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12;
    const hp = [_]u8{0x33} ** 16;
    var buf: [256]u8 = undefined;
    const payload = "hello";
    const len = encodeShortHeaderPacket(&buf, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, 0, payload, key, iv, hp) orelse unreachable;
    try std.testing.expect(len > 0);
    // Short header: form bit = 0, but fixed bit = 1
    try std.testing.expect(buf[0] & 0x80 == 0);
    try std.testing.expect(buf[0] & 0x40 != 0);
}

test "feedCryptoFrames: single CRYPTO frame" {
    var reassembler = handshake_flight.CryptoReassembler.init();
    var buf: [64]u8 = undefined;
    buf[0] = 0x06; // CRYPTO frame
    buf[1] = 0x00; // offset = 0
    buf[2] = 0x04; // length = 4
    buf[3] = 'T';
    buf[4] = 'E';
    buf[5] = 'S';
    buf[6] = 'T';

    try std.testing.expect(feedCryptoFrames(&reassembler, buf[0..7]));
    try std.testing.expectEqualSlices(u8, "TEST", reassembler.getData());
}

test "feedCryptoFrames: padding before CRYPTO" {
    var reassembler = handshake_flight.CryptoReassembler.init();
    var buf: [64]u8 = undefined;
    buf[0] = 0x00; // PADDING
    buf[1] = 0x00; // PADDING
    buf[2] = 0x06; // CRYPTO frame
    buf[3] = 0x00; // offset = 0
    buf[4] = 0x02; // length = 2
    buf[5] = 'O';
    buf[6] = 'K';

    try std.testing.expect(feedCryptoFrames(&reassembler, buf[0..7]));
    try std.testing.expectEqualSlices(u8, "OK", reassembler.getData());
}
