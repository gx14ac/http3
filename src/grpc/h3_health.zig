const std = @import("std");
const h3_channel_mod = @import("h3_channel.zig");
const health_mod = @import("health.zig");

const H3Channel = h3_channel_mod.H3Channel;
const H3ChannelError = h3_channel_mod.H3ChannelError;
const H3GrpcStream = h3_channel_mod.H3GrpcStream;

pub const ServingStatus = health_mod.ServingStatus;
pub const HealthCheckResult = health_mod.HealthCheckResult;
pub const encodeHealthCheckRequest = health_mod.encodeHealthCheckRequest;
pub const decodeHealthCheckResponse = health_mod.decodeHealthCheckResponse;

pub const HealthError = error{
    RpcFailed,
    InvalidResponse,
    StreamEnded,
};

/// Client for the grpc.health.v1.Health service over HTTP/3.
pub const H3HealthClient = struct {
    channel: *H3Channel,

    pub fn init(channel: *H3Channel) H3HealthClient {
        return .{ .channel = channel };
    }

    /// Perform a unary health check for the given service name.
    /// Empty string checks the overall server health.
    pub fn check(self: *const H3HealthClient, service: []const u8) HealthError!HealthCheckResult {
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
    pub fn isServing(self: *const H3HealthClient, service: []const u8) bool {
        const result = self.check(service) catch return false;
        return result.status == .serving;
    }

    /// Start a server-streaming Watch RPC for health status changes.
    /// Returns an H3HealthWatcher that yields ServingStatus updates.
    pub fn watch(self: *const H3HealthClient, service: []const u8) HealthError!H3HealthWatcher {
        var request_buf: [256]u8 = undefined;
        const request = encodeHealthCheckRequest(service, &request_buf) orelse
            return HealthError.InvalidResponse;

        const stream = self.channel.serverStream(
            "/grpc.health.v1.Health/Watch",
            request,
            .{},
        ) catch return HealthError.RpcFailed;

        return H3HealthWatcher{ .stream = stream };
    }
};

/// Server-streaming watcher for health status changes over HTTP/3.
/// Call next() to receive the next status update.
pub const H3HealthWatcher = struct {
    stream: H3GrpcStream,

    /// Receive the next health status update.
    /// Returns null when the stream ends normally.
    pub fn next(self: *H3HealthWatcher) HealthError!?ServingStatus {
        var buf: [256]u8 = undefined;
        const data = self.stream.recv(&buf) catch return HealthError.RpcFailed;
        if (data == null) return null;

        return decodeHealthCheckResponse(data.?) orelse HealthError.InvalidResponse;
    }

    /// Close the watcher and release resources.
    pub fn deinit(self: *H3HealthWatcher) void {
        self.stream.deinit();
    }
};

// ─── Tests ───

test "H3HealthClient: init" {
    // Verify struct layout compiles — actual RPC needs a live server
    try std.testing.expect(@sizeOf(H3HealthClient) > 0);
}

test "encodeHealthCheckRequest via health_mod" {
    var buf: [64]u8 = undefined;
    const result = encodeHealthCheckRequest("test.svc", &buf);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 0x0A), result.?[0]);
    try std.testing.expectEqual(@as(u8, 8), result.?[1]);
    try std.testing.expectEqualStrings("test.svc", result.?[2..10]);
}

test "decodeHealthCheckResponse via health_mod" {
    const data = [_]u8{ 0x08, 0x01 };
    const result = decodeHealthCheckResponse(&data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(ServingStatus.serving, result.?);
}
