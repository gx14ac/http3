const std = @import("std");
const channel_mod = @import("channel.zig");

const Channel = channel_mod.Channel;
const ChannelError = channel_mod.ChannelError;

/// gRPC health check serving status (grpc.health.v1.HealthCheckResponse.ServingStatus).
pub const ServingStatus = enum(u8) {
    unknown = 0,
    serving = 1,
    not_serving = 2,
    service_unknown = 3,

    pub fn fromInt(v: u64) ServingStatus {
        return switch (v) {
            0 => .unknown,
            1 => .serving,
            2 => .not_serving,
            3 => .service_unknown,
            else => .unknown,
        };
    }
};

pub const HealthCheckResult = struct {
    status: ServingStatus,
};

pub const HealthError = error{
    RpcFailed,
    InvalidResponse,
};

/// Client for the grpc.health.v1.Health service.
/// Performs health checks over an existing gRPC Channel.
pub const HealthClient = struct {
    channel: *Channel,

    pub fn init(channel: *Channel) HealthClient {
        return .{ .channel = channel };
    }

    /// Perform a unary health check for the given service name.
    /// Empty string checks the overall server health.
    pub fn check(self: *HealthClient, service: []const u8) HealthError!HealthCheckResult {
        var request_buf: [256]u8 = undefined;
        const request = encodeHealthCheckRequest(service, &request_buf) orelse
            return HealthError.InvalidResponse;

        var response_buf: [64]u8 = undefined;
        const result = self.channel.unary(
            "/grpc.health.v1.Health/Check",
            request,
            .{ .timeout_ms = 5000 },
            &response_buf,
        ) catch return HealthError.RpcFailed;

        if (!result.status.isOk()) {
            return HealthError.RpcFailed;
        }

        const status = decodeHealthCheckResponse(result.data) orelse
            return HealthError.InvalidResponse;

        return .{ .status = status };
    }

    /// Convenience: returns true if the service is SERVING.
    pub fn isServing(self: *HealthClient, service: []const u8) bool {
        const result = self.check(service) catch return false;
        return result.status == .serving;
    }
};

// ─── Protobuf wire format (grpc.health.v1) ───

/// Encode HealthCheckRequest: field 1 (string service).
/// Wire format: tag(0x0A) + varint(len) + bytes.
/// Empty service → empty message (0 bytes).
fn encodeHealthCheckRequest(service: []const u8, buf: []u8) ?[]const u8 {
    if (service.len == 0) {
        return buf[0..0];
    }
    // tag (1 byte) + varint length + service bytes
    const varint_len = varintSize(service.len);
    const total = 1 + varint_len + service.len;
    if (total > buf.len) return null;

    buf[0] = 0x0A; // field 1, wire type 2 (length-delimited)
    const written = encodeVarint(buf[1..], service.len);
    @memcpy(buf[1 + written ..][0..service.len], service);
    return buf[0..total];
}

/// Decode HealthCheckResponse: field 1 (enum ServingStatus).
/// Wire format: tag(0x08) + varint(value).
/// Empty response → UNKNOWN (default value).
fn decodeHealthCheckResponse(data: []const u8) ?ServingStatus {
    if (data.len == 0) return .unknown;

    var pos: usize = 0;
    while (pos < data.len) {
        const tag_byte = data[pos];
        pos += 1;
        const field_number = tag_byte >> 3;
        const wire_type: u3 = @intCast(tag_byte & 0x07);

        if (field_number == 1 and wire_type == 0) {
            // Varint field: ServingStatus
            const value = decodeVarint(data[pos..]) orelse return null;
            return ServingStatus.fromInt(value.value);
        }

        // Skip unknown fields
        switch (wire_type) {
            0 => { // varint
                const v = decodeVarint(data[pos..]) orelse return null;
                pos += v.consumed;
            },
            1 => pos += 8, // 64-bit
            2 => { // length-delimited
                const v = decodeVarint(data[pos..]) orelse return null;
                pos += v.consumed + @as(usize, @intCast(v.value));
            },
            5 => pos += 4, // 32-bit
            else => return null,
        }
    }

    // Field 1 not found → default value (UNKNOWN)
    return .unknown;
}

const VarintResult = struct {
    value: u64,
    consumed: usize,
};

fn decodeVarint(data: []const u8) ?VarintResult {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (data, 0..) |byte, i| {
        if (i >= 10) return null; // varint too long
        value |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) {
            return .{ .value = value, .consumed = i + 1 };
        }
        shift +%= 7;
    }
    return null;
}

fn encodeVarint(buf: []u8, value: usize) usize {
    var v = value;
    var i: usize = 0;
    while (true) {
        if (v < 0x80) {
            buf[i] = @intCast(v);
            return i + 1;
        }
        buf[i] = @intCast((v & 0x7F) | 0x80);
        v >>= 7;
        i += 1;
    }
}

fn varintSize(value: usize) usize {
    var v = value;
    var size: usize = 0;
    while (true) {
        size += 1;
        v >>= 7;
        if (v == 0) return size;
    }
}

// ─── Tests ───

test "encodeHealthCheckRequest: empty service" {
    var buf: [64]u8 = undefined;
    const result = encodeHealthCheckRequest("", &buf);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 0), result.?.len);
}

test "encodeHealthCheckRequest: non-empty service" {
    var buf: [64]u8 = undefined;
    const result = encodeHealthCheckRequest("myservice", &buf);
    try std.testing.expect(result != null);
    // tag(1) + varint(1, len=9) + "myservice"(9) = 11
    try std.testing.expectEqual(@as(usize, 11), result.?.len);
    try std.testing.expectEqual(@as(u8, 0x0A), result.?[0]);
    try std.testing.expectEqual(@as(u8, 9), result.?[1]);
    try std.testing.expectEqualStrings("myservice", result.?[2..11]);
}

test "decodeHealthCheckResponse: empty → UNKNOWN" {
    const result = decodeHealthCheckResponse("");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.unknown, result.?);
}

test "decodeHealthCheckResponse: SERVING" {
    // field 1, wire type 0 (varint), value 1
    const data = [_]u8{ 0x08, 0x01 };
    const result = decodeHealthCheckResponse(&data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.serving, result.?);
}

test "decodeHealthCheckResponse: NOT_SERVING" {
    const data = [_]u8{ 0x08, 0x02 };
    const result = decodeHealthCheckResponse(&data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.not_serving, result.?);
}

test "decodeHealthCheckResponse: SERVICE_UNKNOWN" {
    const data = [_]u8{ 0x08, 0x03 };
    const result = decodeHealthCheckResponse(&data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.service_unknown, result.?);
}

test "decodeHealthCheckResponse: unknown field skipped" {
    // field 2 (varint, value 42), then field 1 (varint, value 1)
    const data = [_]u8{ 0x10, 0x2A, 0x08, 0x01 };
    const result = decodeHealthCheckResponse(&data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.serving, result.?);
}

test "varint roundtrip" {
    var buf: [10]u8 = undefined;
    const cases = [_]usize{ 0, 1, 127, 128, 300, 16383, 16384, 1_000_000 };
    for (cases) |v| {
        const written = encodeVarint(&buf, v);
        const decoded = decodeVarint(buf[0..written]);
        try std.testing.expect(decoded != null);
        try std.testing.expectEqual(v, @as(usize, @intCast(decoded.?.value)));
        try std.testing.expectEqual(written, decoded.?.consumed);
    }
}
