const std = @import("std");
const packet_mod = @import("packet.zig");
const flow_control_mod = @import("flow_control.zig");

/// RFC 9000 §18: Transport Parameter IDs.
const ParamId = struct {
    const original_destination_connection_id: u64 = 0x00;
    const max_idle_timeout: u64 = 0x01;
    const stateless_reset_token: u64 = 0x02;
    const max_udp_payload_size: u64 = 0x03;
    const initial_max_data: u64 = 0x04;
    const initial_max_stream_data_bidi_local: u64 = 0x05;
    const initial_max_stream_data_bidi_remote: u64 = 0x06;
    const initial_max_stream_data_uni: u64 = 0x07;
    const initial_max_streams_bidi: u64 = 0x08;
    const initial_max_streams_uni: u64 = 0x09;
    const ack_delay_exponent: u64 = 0x0a;
    const max_ack_delay: u64 = 0x0b;
    const disable_active_migration: u64 = 0x0c;
    const active_connection_id_limit: u64 = 0x0e;
    const initial_source_connection_id: u64 = 0x0f;
    const retry_source_connection_id: u64 = 0x10;
};

/// Decoded transport parameters from peer (superset of flow_control.TransportParams).
pub const PeerTransportParams = struct {
    max_idle_timeout_ms: u64 = 0,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay_ms: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,

    /// Convert to the flow_control.TransportParams used by stream/flow modules.
    pub fn toFlowParams(self: *const PeerTransportParams) flow_control_mod.TransportParams {
        return .{
            .initial_max_data = self.initial_max_data,
            .initial_max_stream_data_bidi_local = self.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = self.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = self.initial_max_stream_data_uni,
            .initial_max_streams_bidi = self.initial_max_streams_bidi,
            .initial_max_streams_uni = self.initial_max_streams_uni,
            .max_idle_timeout_ms = self.max_idle_timeout_ms,
        };
    }
};

/// Encode client transport parameters for the ClientHello extension.
/// RFC 9000 §18.2: each param = id(varint) + length(varint) + value.
/// Returns bytes written to buf.
pub fn encodeClientParams(buf: []u8, params: ClientParams) ?usize {
    var pos: usize = 0;

    // initial_max_data (0x04)
    pos += writeParam(buf[pos..], ParamId.initial_max_data, params.initial_max_data) orelse return null;
    // initial_max_stream_data_bidi_local (0x05)
    pos += writeParam(buf[pos..], ParamId.initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local) orelse return null;
    // initial_max_stream_data_bidi_remote (0x06)
    pos += writeParam(buf[pos..], ParamId.initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote) orelse return null;
    // initial_max_stream_data_uni (0x07)
    pos += writeParam(buf[pos..], ParamId.initial_max_stream_data_uni, params.initial_max_stream_data_uni) orelse return null;
    // initial_max_streams_bidi (0x08)
    pos += writeParam(buf[pos..], ParamId.initial_max_streams_bidi, params.initial_max_streams_bidi) orelse return null;
    // initial_max_streams_uni (0x09)
    pos += writeParam(buf[pos..], ParamId.initial_max_streams_uni, params.initial_max_streams_uni) orelse return null;
    // max_idle_timeout (0x01) — in milliseconds
    if (params.max_idle_timeout_ms > 0) {
        pos += writeParam(buf[pos..], ParamId.max_idle_timeout, params.max_idle_timeout_ms) orelse return null;
    }
    // active_connection_id_limit (0x0e)
    pos += writeParam(buf[pos..], ParamId.active_connection_id_limit, params.active_connection_id_limit) orelse return null;
    // initial_source_connection_id (0x0f) — variable-length opaque
    if (params.initial_source_cid_len > 0) {
        pos += writeParamBytes(buf[pos..], ParamId.initial_source_connection_id, params.initial_source_cid[0..params.initial_source_cid_len]) orelse return null;
    }

    return pos;
}

/// Decode peer transport parameters from the EncryptedExtensions payload.
/// `data` is the raw content of the quic_transport_parameters extension (after ext type+length).
/// Returns null on malformed data or RFC 9000 §18.2 validation failure.
pub fn decodePeerParams(data: []const u8) ?PeerTransportParams {
    var params = PeerTransportParams{};
    var pos: usize = 0;

    while (pos < data.len) {
        const id_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += id_v.consumed;

        const len_v = packet_mod.decodeVarint(data[pos..]) orelse return null;
        pos += len_v.consumed;

        const param_end = pos + @as(usize, @intCast(len_v.value));
        if (param_end > data.len) return null;

        const param_data = data[pos..param_end];

        switch (id_v.value) {
            ParamId.max_idle_timeout => {
                params.max_idle_timeout_ms = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.max_udp_payload_size => {
                params.max_udp_payload_size = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_data => {
                params.initial_max_data = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_stream_data_bidi_local => {
                params.initial_max_stream_data_bidi_local = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_stream_data_bidi_remote => {
                params.initial_max_stream_data_bidi_remote = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_stream_data_uni => {
                params.initial_max_stream_data_uni = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_streams_bidi => {
                params.initial_max_streams_bidi = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.initial_max_streams_uni => {
                params.initial_max_streams_uni = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.ack_delay_exponent => {
                params.ack_delay_exponent = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.max_ack_delay => {
                params.max_ack_delay_ms = decodeParamVarint(param_data) orelse return null;
            },
            ParamId.disable_active_migration => {
                params.disable_active_migration = true;
            },
            ParamId.active_connection_id_limit => {
                params.active_connection_id_limit = decodeParamVarint(param_data) orelse return null;
            },
            else => {}, // Unknown params are ignored (RFC 9000 §18)
        }

        pos = param_end;
    }

    // RFC 9000 §18.2 validation
    if (params.ack_delay_exponent > 20) return null;
    if (params.max_ack_delay_ms >= 16384) return null; // 2^14
    if (params.max_udp_payload_size < 1200) return null;
    if (params.active_connection_id_limit < 2) return null;

    return params;
}

/// Client-side transport parameters to advertise in ClientHello.
pub const ClientParams = struct {
    initial_max_data: u64 = 1_048_576,
    initial_max_stream_data_bidi_local: u64 = 262_144,
    initial_max_stream_data_bidi_remote: u64 = 262_144,
    initial_max_stream_data_uni: u64 = 262_144,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    max_idle_timeout_ms: u64 = 30_000,
    active_connection_id_limit: u64 = 8,
    initial_source_cid: [20]u8 = [_]u8{0} ** 20,
    initial_source_cid_len: u8 = 0,
};

// ─── Internal helpers ───

fn writeParam(buf: []u8, id: u64, value: u64) ?usize {
    var pos: usize = 0;

    // Encode value to determine length
    var val_buf: [8]u8 = undefined;
    const val_len = packet_mod.encodeVarint(&val_buf, @intCast(value)) orelse return null;

    // id (varint)
    pos += packet_mod.encodeVarint(buf[pos..], @intCast(id)) orelse return null;
    // length (varint)
    pos += packet_mod.encodeVarint(buf[pos..], val_len) orelse return null;
    // value
    if (buf.len < pos + val_len) return null;
    @memcpy(buf[pos..][0..val_len], val_buf[0..val_len]);
    pos += val_len;

    return pos;
}

fn writeParamBytes(buf: []u8, id: u64, value: []const u8) ?usize {
    var pos: usize = 0;

    // id (varint)
    pos += packet_mod.encodeVarint(buf[pos..], @intCast(id)) orelse return null;
    // length (varint)
    pos += packet_mod.encodeVarint(buf[pos..], value.len) orelse return null;
    // raw bytes
    if (buf.len < pos + value.len) return null;
    @memcpy(buf[pos..][0..value.len], value);
    pos += value.len;

    return pos;
}

fn decodeParamVarint(data: []const u8) ?u64 {
    if (data.len == 0) return null;
    const v = packet_mod.decodeVarint(data) orelse return null;
    return v.value;
}

// ─── Tests ───

test "encodeClientParams: produces valid output" {
    var buf: [256]u8 = undefined;
    const len = encodeClientParams(&buf, .{}) orelse unreachable;
    try std.testing.expect(len > 0);
}

test "encodeClientParams/decodePeerParams roundtrip" {
    var buf: [256]u8 = undefined;
    const len = encodeClientParams(&buf, .{
        .initial_max_data = 2_000_000,
        .initial_max_stream_data_bidi_local = 500_000,
        .initial_max_stream_data_bidi_remote = 500_000,
        .initial_max_stream_data_uni = 100_000,
        .initial_max_streams_bidi = 50,
        .initial_max_streams_uni = 10,
        .max_idle_timeout_ms = 60_000,
        .active_connection_id_limit = 4,
    }) orelse unreachable;

    const params = decodePeerParams(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 2_000_000), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 500_000), params.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u64, 500_000), params.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 100_000), params.initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 50), params.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 10), params.initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 60_000), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 4), params.active_connection_id_limit);
}

test "decodePeerParams: unknown params are skipped" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Write a known param: max_idle_timeout = 5000
    pos += writeParam(buf[pos..], ParamId.max_idle_timeout, 5000) orelse unreachable;
    // Write unknown param id=0xFF with 2 bytes of data
    pos += packet_mod.encodeVarint(buf[pos..], 0xFF) orelse unreachable;
    pos += packet_mod.encodeVarint(buf[pos..], 2) orelse unreachable;
    buf[pos] = 0xDE;
    buf[pos + 1] = 0xAD;
    pos += 2;
    // Write another known param: initial_max_data = 1000
    pos += writeParam(buf[pos..], ParamId.initial_max_data, 1000) orelse unreachable;

    const params = decodePeerParams(buf[0..pos]) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 5000), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 1000), params.initial_max_data);
}

test "decodePeerParams: empty input returns defaults" {
    const params = decodePeerParams(&[_]u8{}) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 0), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 2), params.active_connection_id_limit);
}

test "decodePeerParams: disable_active_migration (zero-length param)" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    // id = 0x0c, length = 0
    pos += packet_mod.encodeVarint(buf[pos..], ParamId.disable_active_migration) orelse unreachable;
    pos += packet_mod.encodeVarint(buf[pos..], 0) orelse unreachable;

    const params = decodePeerParams(buf[0..pos]) orelse unreachable;
    try std.testing.expect(params.disable_active_migration);
}

test "decodePeerParams: truncated data returns null" {
    // id only, no length
    var buf: [2]u8 = undefined;
    _ = packet_mod.encodeVarint(&buf, 0x04) orelse unreachable;
    try std.testing.expect(decodePeerParams(buf[0..1]) == null);
}

test "decodePeerParams: RFC validation rejects invalid values" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // ack_delay_exponent = 21 (> 20 is invalid)
    pos = 0;
    pos += writeParam(buf[pos..], ParamId.ack_delay_exponent, 21) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.max_udp_payload_size, 1200) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.active_connection_id_limit, 2) orelse unreachable;
    try std.testing.expect(decodePeerParams(buf[0..pos]) == null);

    // max_ack_delay = 16384 (>= 2^14 is invalid)
    pos = 0;
    pos += writeParam(buf[pos..], ParamId.max_ack_delay, 16384) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.max_udp_payload_size, 1200) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.active_connection_id_limit, 2) orelse unreachable;
    try std.testing.expect(decodePeerParams(buf[0..pos]) == null);

    // max_udp_payload_size = 1199 (< 1200 is invalid)
    pos = 0;
    pos += writeParam(buf[pos..], ParamId.max_udp_payload_size, 1199) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.active_connection_id_limit, 2) orelse unreachable;
    try std.testing.expect(decodePeerParams(buf[0..pos]) == null);

    // active_connection_id_limit = 1 (< 2 is invalid)
    pos = 0;
    pos += writeParam(buf[pos..], ParamId.max_udp_payload_size, 1200) orelse unreachable;
    pos += writeParam(buf[pos..], ParamId.active_connection_id_limit, 1) orelse unreachable;
    try std.testing.expect(decodePeerParams(buf[0..pos]) == null);
}

test "decodePeerParams: empty varint param data returns null" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    // max_idle_timeout with length 0 (no varint data)
    pos += packet_mod.encodeVarint(buf[pos..], ParamId.max_idle_timeout) orelse unreachable;
    pos += packet_mod.encodeVarint(buf[pos..], 0) orelse unreachable; // length = 0
    try std.testing.expect(decodePeerParams(buf[0..pos]) == null);
}

test "PeerTransportParams: toFlowParams" {
    const peer = PeerTransportParams{
        .initial_max_data = 5_000_000,
        .initial_max_stream_data_bidi_local = 1_000_000,
        .initial_max_stream_data_bidi_remote = 800_000,
        .initial_max_stream_data_uni = 200_000,
        .initial_max_streams_bidi = 128,
        .initial_max_streams_uni = 32,
        .max_idle_timeout_ms = 45_000,
    };
    const fp = peer.toFlowParams();
    try std.testing.expectEqual(@as(u64, 5_000_000), fp.initial_max_data);
    try std.testing.expectEqual(@as(u64, 128), fp.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 45_000), fp.max_idle_timeout_ms);
}

test "encodeClientParams: with initial_source_cid" {
    var buf: [256]u8 = undefined;
    var client_params = ClientParams{};
    client_params.initial_source_cid[0] = 0xAA;
    client_params.initial_source_cid[1] = 0xBB;
    client_params.initial_source_cid[2] = 0xCC;
    client_params.initial_source_cid_len = 3;

    const len = encodeClientParams(&buf, client_params) orelse unreachable;

    // Decode and verify the CID param is present (it won't map to PeerTransportParams fields,
    // but we can verify the encoding doesn't fail)
    const params = decodePeerParams(buf[0..len]) orelse unreachable;
    // Verify other params decoded correctly
    try std.testing.expectEqual(@as(u64, 1_048_576), params.initial_max_data);
}
