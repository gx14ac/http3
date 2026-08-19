const std = @import("std");
const h3_server_mod = @import("../quic/h3_server.zig");
const server_mod = @import("../quic/server.zig");
const qpack = @import("../quic/qpack.zig");
const h3_frame = @import("../quic/h3_frame.zig");
const message_mod = @import("message.zig");
const status_mod = @import("status.zig");

const H3Server = h3_server_mod.H3Server;
const H3Request = h3_server_mod.H3Request;
const H3ServerEvent = h3_server_mod.H3ServerEvent;
const QuicServer = server_mod.QuicServer;
const ServerError = server_mod.ServerError;

pub const GrpcServerError = error{
    BindFailed,
    EncodeFailed,
    WriteFailed,
    InvalidRequest,
    HandlerFailed,
    MessageTooLarge,
    DeadlineExceeded,
};

pub const RequestMetadata = struct {
    key: []const u8,
    value: []const u8,
};

pub const GrpcRequest = struct {
    path_buf: [1024]u8,
    path_len: usize,
    content_type_buf: [128]u8,
    content_type_len: usize,
    payload_buf: [MAX_PAYLOAD]u8,
    payload_len: usize,
    service_start: usize,
    service_len: usize,
    method_start: usize,
    method_len: usize,
    conn_idx: usize,
    stream_id: u62,
    deadline_ns: ?i128,
    headers: [MAX_METADATA]qpack.HeaderField,
    header_count: usize,

    pub const MAX_PAYLOAD = 16384;
    pub const MAX_METADATA = 16;

    pub fn path(self: *const GrpcRequest) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    pub fn service(self: *const GrpcRequest) []const u8 {
        return self.path_buf[self.service_start..][0..self.service_len];
    }

    pub fn method(self: *const GrpcRequest) []const u8 {
        return self.path_buf[self.method_start..][0..self.method_len];
    }

    pub fn contentType(self: *const GrpcRequest) []const u8 {
        return self.content_type_buf[0..self.content_type_len];
    }

    pub fn payload(self: *const GrpcRequest) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }

    pub fn isExpired(self: *const GrpcRequest) bool {
        return isDeadlineExceeded(self.deadline_ns);
    }

    /// Returns remaining time in milliseconds, or null if no deadline is set.
    pub fn remainingMs(self: *const GrpcRequest) ?u64 {
        const dl = self.deadline_ns orelse return null;
        const now: i128 = std.time.nanoTimestamp();
        if (now >= dl) return 0;
        return @intCast(@divFloor(dl - now, 1_000_000));
    }

    /// Get all application metadata headers (excludes pseudo-headers and well-known gRPC headers).
    pub fn metadata(self: *const GrpcRequest) []const qpack.HeaderField {
        return self.headers[0..self.header_count];
    }

    /// Look up a specific metadata header by key. Returns the value or null.
    pub fn getHeader(self: *const GrpcRequest, key: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |h| {
            if (std.mem.eql(u8, h.name, key)) return h.value;
        }
        return null;
    }
};

pub const GrpcResponse = struct {
    status_code: status_mod.Code,
    message: []const u8,
    payload: []const u8,
};

pub const GrpcStreamMessage = struct {
    conn_idx: usize,
    stream_id: u62,
    payload_buf: [GrpcRequest.MAX_PAYLOAD]u8,
    payload_len: usize,
    fin: bool,

    pub fn payload(self: *const GrpcStreamMessage) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
};

pub const GrpcServerEvent = union(enum) {
    none,
    request: GrpcRequest,
    data: GrpcStreamMessage,
    connected,
    timeout,
};

pub const ServiceHandler = struct {
    context: *const anyopaque,
    handleFn: *const fn (ctx: *const anyopaque, req: *const GrpcRequest, response_buf: []u8) ?GrpcResponse,

    pub fn handle(self: ServiceHandler, req: *const GrpcRequest, response_buf: []u8) ?GrpcResponse {
        return self.handleFn(self.context, req, response_buf);
    }
};

pub const ServiceRoute = struct {
    path_prefix: []const u8,
    handler: ServiceHandler,
};

/// Handle for sending streaming responses on a gRPC server stream.
pub const ServerStream = struct {
    server: *GrpcServer,
    conn_idx: usize,
    stream_id: u62,
    headers_sent: bool,
    deadline_ns: ?i128,

    /// Send initial response headers (HTTP 200 + content-type). Called automatically on first send.
    pub fn sendHeaders(self: *ServerStream) GrpcServerError!void {
        if (self.headers_sent) return;
        var headers = [_]qpack.HeaderField{
            .{ .name = "content-type", .value = "application/grpc" },
        };
        self.server.h3.sendHeaders(self.conn_idx, self.stream_id, 200, &headers) catch
            return GrpcServerError.WriteFailed;
        self.headers_sent = true;
    }

    /// Send a gRPC message (length-prefixed) without closing the stream.
    pub fn send(self: *ServerStream, payload: []const u8) GrpcServerError!void {
        if (!self.headers_sent) try self.sendHeaders();

        var grpc_buf: [GrpcRequest.MAX_PAYLOAD + 5]u8 = undefined;
        const grpc_msg = message_mod.encodeMessage(&grpc_buf, payload, false) catch
            return GrpcServerError.EncodeFailed;

        self.server.h3.sendData(self.conn_idx, self.stream_id, grpc_msg, false) catch
            return GrpcServerError.WriteFailed;
    }

    /// Receive the next client message on this stream (for BiDi streaming).
    /// Returns the payload, or null if the stream has been closed (FIN received with no data).
    /// Non-matching events are enqueued back into the server for later retrieval.
    pub fn recv(self: *ServerStream) GrpcServerError!?GrpcStreamMessage {
        var attempts: usize = 0;
        while (attempts < 20) : (attempts += 1) {
            if (isDeadlineExceeded(self.deadline_ns)) return GrpcServerError.DeadlineExceeded;

            const event = self.server.poll();
            switch (event) {
                .data => |msg| {
                    if (msg.conn_idx == self.conn_idx and msg.stream_id == self.stream_id) {
                        if (msg.payload_len == 0 and msg.fin) return null;
                        return msg;
                    }
                    _ = self.server.enqueue(.{ .data = msg });
                },
                .timeout => return GrpcServerError.InvalidRequest,
                .none => {},
                .request => |req| {
                    _ = self.server.enqueue(.{ .request = req });
                },
                .connected => {
                    _ = self.server.enqueue(.connected);
                },
            }
        }
        return GrpcServerError.InvalidRequest;
    }

    pub fn isExpired(self: *const ServerStream) bool {
        return isDeadlineExceeded(self.deadline_ns);
    }

    /// Close the stream with a gRPC status (trailers-only HEADERS frame + FIN).
    pub fn close(self: *ServerStream, code: status_mod.Code, msg: []const u8) GrpcServerError!void {
        if (!self.headers_sent) try self.sendHeaders();

        var trailer_headers: [2]qpack.HeaderField = undefined;
        var hcount: usize = 0;
        var status_buf: [3]u8 = undefined;
        const status_str = grpcStatusToStr(code, &status_buf);
        trailer_headers[hcount] = .{ .name = "grpc-status", .value = status_str };
        hcount += 1;
        if (msg.len > 0) {
            trailer_headers[hcount] = .{ .name = "grpc-message", .value = msg };
            hcount += 1;
        }

        self.server.h3.sendTrailers(self.conn_idx, self.stream_id, trailer_headers[0..hcount]) catch
            return GrpcServerError.WriteFailed;
    }
};

pub const GrpcServer = struct {
    h3: H3Server,
    routes: [MAX_ROUTES]ServiceRoute,
    route_count: usize,
    event_queue: [EVENT_QUEUE_SIZE]GrpcServerEvent,
    eq_head: usize,
    eq_tail: usize,

    const MAX_ROUTES = 16;
    const EVENT_QUEUE_SIZE = 32;

    pub fn init(bind_addr: std.net.Address, config: QuicServer.Config) ServerError!GrpcServer {
        return .{
            .h3 = try H3Server.init(bind_addr, config),
            .routes = undefined,
            .route_count = 0,
            .event_queue = undefined,
            .eq_head = 0,
            .eq_tail = 0,
        };
    }

    pub fn deinit(self: *GrpcServer) void {
        self.h3.deinit();
    }

    pub fn getPort(self: *const GrpcServer) u16 {
        return self.h3.getPort();
    }

    pub fn setTimeout(self: *GrpcServer, ms: u64) void {
        self.h3.setTimeout(ms);
    }

    /// Initiate graceful shutdown (RFC 9114 §5.2 + gRPC GOAWAY semantics).
    /// Sends GOAWAY to all clients with the given last_stream_id.
    /// After calling this, new requests on streams >= last_stream_id are silently dropped.
    /// Existing in-flight requests continue to completion.
    /// Call `forceClose()` after a drain period to terminate connections.
    pub fn shutdown(self: *GrpcServer, last_stream_id: u62) void {
        self.h3.gracefulShutdown(last_stream_id);
    }

    /// Force-close all connections after the drain period.
    /// Call this after shutdown() + drain to terminate remaining connections.
    pub fn forceClose(self: *GrpcServer) void {
        self.h3.forceClose();
    }

    pub fn isShuttingDown(self: *const GrpcServer) bool {
        return self.h3.isShuttingDown();
    }

    pub fn activeConnectionCount(self: *const GrpcServer) usize {
        return self.h3.activeConnectionCount();
    }

    /// Create a ServerStream handle for sending streaming responses on a request's stream.
    pub fn openStream(self: *GrpcServer, req: *const GrpcRequest) ServerStream {
        return .{
            .server = self,
            .conn_idx = req.conn_idx,
            .stream_id = req.stream_id,
            .headers_sent = false,
            .deadline_ns = req.deadline_ns,
        };
    }

    pub fn addRoute(self: *GrpcServer, path_prefix: []const u8, handler: ServiceHandler) bool {
        if (self.route_count >= MAX_ROUTES) return false;
        self.routes[self.route_count] = .{ .path_prefix = path_prefix, .handler = handler };
        self.route_count += 1;
        return true;
    }

    pub fn poll(self: *GrpcServer) GrpcServerEvent {
        // Drain queued events first (re-queued by recv() for other streams)
        if (self.dequeue()) |queued| return queued;

        const event = self.h3.poll();
        switch (event) {
            .none => return .none,
            .timeout => return .timeout,
            .connected => return .connected,
            .request => |h3_req| {
                return self.processRequest(&h3_req);
            },
            .data => |h3_data| {
                return self.processStreamData(&h3_data);
            },
        }
    }

    fn enqueue(self: *GrpcServer, event: GrpcServerEvent) bool {
        const next_tail = (self.eq_tail + 1) % EVENT_QUEUE_SIZE;
        if (next_tail == self.eq_head) return false; // queue full
        self.event_queue[self.eq_tail] = event;
        self.eq_tail = next_tail;
        return true;
    }

    fn dequeue(self: *GrpcServer) ?GrpcServerEvent {
        if (self.eq_head == self.eq_tail) return null;
        const event = self.event_queue[self.eq_head];
        self.eq_head = (self.eq_head + 1) % EVENT_QUEUE_SIZE;
        return event;
    }

    pub fn sendResponse(
        self: *GrpcServer,
        conn_idx: usize,
        stream_id: u62,
        response: GrpcResponse,
    ) GrpcServerError!void {
        // Encode gRPC length-prefixed message
        var grpc_buf: [GrpcRequest.MAX_PAYLOAD + 5]u8 = undefined;
        const grpc_msg = message_mod.encodeMessage(&grpc_buf, response.payload, false) catch
            return GrpcServerError.EncodeFailed;

        // Build H3 response: HEADERS (200 + content-type + grpc-status) + DATA
        var resp_headers: [3]qpack.HeaderField = undefined;
        var hcount: usize = 0;
        resp_headers[hcount] = .{ .name = "content-type", .value = "application/grpc" };
        hcount += 1;

        var status_buf: [3]u8 = undefined;
        const status_str = grpcStatusToStr(response.status_code, &status_buf);
        resp_headers[hcount] = .{ .name = "grpc-status", .value = status_str };
        hcount += 1;

        if (response.message.len > 0) {
            resp_headers[hcount] = .{ .name = "grpc-message", .value = response.message };
            hcount += 1;
        }

        // Use H3 sendResponse with grpc_msg as body
        self.h3.sendResponse(
            conn_idx,
            stream_id,
            200,
            resp_headers[0..hcount],
            grpc_msg,
        ) catch return GrpcServerError.WriteFailed;
    }

    pub fn sendError(
        self: *GrpcServer,
        conn_idx: usize,
        stream_id: u62,
        code: status_mod.Code,
        msg: []const u8,
    ) GrpcServerError!void {
        var resp_headers: [3]qpack.HeaderField = undefined;
        var hcount: usize = 0;
        resp_headers[hcount] = .{ .name = "content-type", .value = "application/grpc" };
        hcount += 1;

        var status_buf: [3]u8 = undefined;
        const status_str = grpcStatusToStr(code, &status_buf);
        resp_headers[hcount] = .{ .name = "grpc-status", .value = status_str };
        hcount += 1;

        if (msg.len > 0) {
            resp_headers[hcount] = .{ .name = "grpc-message", .value = msg };
            hcount += 1;
        }

        self.h3.sendResponse(conn_idx, stream_id, 200, resp_headers[0..hcount], "") catch
            return GrpcServerError.WriteFailed;
    }

    /// Dispatch request to matching handler and send response automatically.
    pub fn handleAndRespond(self: *GrpcServer, req: *const GrpcRequest) GrpcServerError!void {
        if (isDeadlineExceeded(req.deadline_ns)) {
            return self.sendError(req.conn_idx, req.stream_id, .deadline_exceeded, "deadline exceeded");
        }

        const handler = self.findHandler(req.path()) orelse {
            return self.sendError(req.conn_idx, req.stream_id, .unimplemented, "method not found");
        };

        var response_buf: [GrpcRequest.MAX_PAYLOAD]u8 = undefined;
        const response = handler.handle(req, &response_buf) orelse {
            return self.sendError(req.conn_idx, req.stream_id, .internal, "handler error");
        };

        if (isDeadlineExceeded(req.deadline_ns)) {
            return self.sendError(req.conn_idx, req.stream_id, .deadline_exceeded, "deadline exceeded");
        }

        return self.sendResponse(req.conn_idx, req.stream_id, response);
    }

    fn processRequest(self: *GrpcServer, h3_req: *const H3Request) GrpcServerEvent {
        _ = self;
        const path = h3_req.path[0..h3_req.path_len];
        const ct = h3_req.content_type[0..h3_req.content_type_len];

        if (!isGrpcContentType(ct)) return .none;

        // Decode gRPC message from body
        var decoded_payload: []const u8 = &.{};
        if (h3_req.body_len >= 5) {
            const decoded = message_mod.decodeMessage(
                h3_req.body[0..h3_req.body_len],
                GrpcRequest.MAX_PAYLOAD,
            ) catch {
                return .none;
            };
            decoded_payload = decoded.payload;
        }

        // Copy all data into owned buffers
        var req: GrpcRequest = undefined;
        req.path_len = path.len;
        @memcpy(req.path_buf[0..path.len], path);
        req.content_type_len = ct.len;
        @memcpy(req.content_type_buf[0..ct.len], ct);
        req.payload_len = decoded_payload.len;
        if (decoded_payload.len > 0) {
            @memcpy(req.payload_buf[0..decoded_payload.len], decoded_payload);
        }
        req.conn_idx = h3_req.conn_idx;
        req.stream_id = h3_req.stream_id;

        // Parse grpc-timeout header and copy application metadata
        req.deadline_ns = null;
        req.header_count = 0;
        for (h3_req.headers[0..h3_req.header_count]) |h| {
            if (std.mem.eql(u8, h.name, "grpc-timeout")) {
                req.deadline_ns = computeDeadlineFromTimeout(h.value);
            }
            // Copy non-pseudo, non-well-known headers as metadata
            if (h.name.len > 0 and h.name[0] != ':' and
                !std.mem.eql(u8, h.name, "content-type") and
                !std.mem.eql(u8, h.name, "te") and
                !std.mem.eql(u8, h.name, "grpc-timeout") and
                !std.mem.eql(u8, h.name, "grpc-encoding"))
            {
                if (req.header_count < GrpcRequest.MAX_METADATA) {
                    req.headers[req.header_count] = h;
                    req.header_count += 1;
                }
            }
        }

        // Compute service/method offsets from the owned path_buf
        // path: /Service/Method → skip leading '/'
        if (path.len >= 3 and path[0] == '/') {
            if (std.mem.indexOfScalar(u8, path[1..], '/')) |slash_pos| {
                req.service_start = 1;
                req.service_len = slash_pos;
                req.method_start = 1 + slash_pos + 1;
                req.method_len = path.len - req.method_start;
            } else {
                req.service_start = 1;
                req.service_len = path.len - 1;
                req.method_start = 0;
                req.method_len = 0;
            }
        } else {
            req.service_start = 0;
            req.service_len = path.len;
            req.method_start = 0;
            req.method_len = 0;
        }

        return .{ .request = req };
    }

    fn processStreamData(self: *GrpcServer, h3_data: *const h3_server_mod.H3StreamData) GrpcServerEvent {
        _ = self;
        var msg: GrpcStreamMessage = undefined;
        msg.conn_idx = h3_data.conn_idx;
        msg.stream_id = h3_data.stream_id;
        msg.fin = h3_data.fin;

        const body = h3_data.bodySlice();
        if (body.len >= 5) {
            const decoded = message_mod.decodeMessage(body, GrpcRequest.MAX_PAYLOAD) catch {
                return .none;
            };
            msg.payload_len = decoded.payload.len;
            if (decoded.payload.len > 0) {
                @memcpy(msg.payload_buf[0..decoded.payload.len], decoded.payload);
            }
        } else if (h3_data.fin) {
            // FIN with no/insufficient body — signal stream end
            msg.payload_len = 0;
        } else {
            return .none;
        }

        return .{ .data = msg };
    }

    fn findHandler(self: *GrpcServer, path_slice: []const u8) ?ServiceHandler {
        for (self.routes[0..self.route_count]) |route| {
            if (std.mem.startsWith(u8, path_slice, route.path_prefix)) {
                return route.handler;
            }
        }
        return null;
    }
};

const ServiceMethodParts = struct {
    service: []const u8,
    method: []const u8,
};

fn parseServiceMethod(path: []const u8) ServiceMethodParts {
    // path: /package.Service/Method
    if (path.len < 3 or path[0] != '/') return .{ .service = path, .method = "" };

    const rest = path[1..];
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash_pos| {
        return .{
            .service = rest[0..slash_pos],
            .method = rest[slash_pos + 1 ..],
        };
    }
    return .{ .service = rest, .method = "" };
}

fn isGrpcContentType(ct: []const u8) bool {
    return std.mem.startsWith(u8, ct, "application/grpc");
}

/// Parse gRPC timeout value (e.g. "100m", "5S", "1H") into an absolute deadline (ns).
/// Format: <digits><unit> where unit is H/M/S/m/u/n.
fn computeDeadlineFromTimeout(value: []const u8) ?i128 {
    if (value.len < 2) return null;
    const unit = value[value.len - 1];
    const digits = value[0 .. value.len - 1];
    const num = std.fmt.parseInt(u64, digits, 10) catch return null;

    const ns_per_unit: u64 = switch (unit) {
        'H' => 3_600_000_000_000,
        'M' => 60_000_000_000,
        'S' => 1_000_000_000,
        'm' => 1_000_000,
        'u' => 1_000,
        'n' => 1,
        else => return null,
    };

    const now: i128 = std.time.nanoTimestamp();
    return now + @as(i128, num) * @as(i128, ns_per_unit);
}

fn isDeadlineExceeded(deadline_ns: ?i128) bool {
    const dl = deadline_ns orelse return false;
    return std.time.nanoTimestamp() >= dl;
}

fn grpcStatusToStr(code: status_mod.Code, buf: *[3]u8) []const u8 {
    const v: u8 = @intFromEnum(code);
    if (v < 10) {
        buf[0] = '0' + v;
        return buf[0..1];
    }
    buf[0] = '0' + (v / 10);
    buf[1] = '0' + (v % 10);
    return buf[0..2];
}

// ─── Tests ───

test "parseServiceMethod" {
    const r1 = parseServiceMethod("/grpc.health.v1.Health/Check");
    try std.testing.expectEqualSlices(u8, "grpc.health.v1.Health", r1.service);
    try std.testing.expectEqualSlices(u8, "Check", r1.method);

    const r2 = parseServiceMethod("/MyService/DoThing");
    try std.testing.expectEqualSlices(u8, "MyService", r2.service);
    try std.testing.expectEqualSlices(u8, "DoThing", r2.method);
}

test "isGrpcContentType" {
    try std.testing.expect(isGrpcContentType("application/grpc"));
    try std.testing.expect(isGrpcContentType("application/grpc+proto"));
    try std.testing.expect(!isGrpcContentType("text/plain"));
    try std.testing.expect(!isGrpcContentType(""));
}

test "grpcStatusToStr" {
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "0", grpcStatusToStr(.ok, &buf));
    try std.testing.expectEqualSlices(u8, "12", grpcStatusToStr(.unimplemented, &buf));
    try std.testing.expectEqualSlices(u8, "13", grpcStatusToStr(.internal, &buf));
}

test "GrpcServer: create and close" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    try std.testing.expect(server.getPort() > 0);
}

test "GrpcServer: add routes" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();

    const DummyHandler = struct {
        fn handle(_: *const anyopaque, _: *const GrpcRequest, _: []u8) ?GrpcResponse {
            return .{ .status_code = .ok, .message = "", .payload = "" };
        }
    };

    try std.testing.expect(server.addRoute("/grpc.health.v1.Health/", .{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .handleFn = DummyHandler.handle,
    }));

    try std.testing.expectEqual(@as(usize, 1), server.route_count);
}

test "GrpcServer: poll timeout" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    server.setTimeout(10);
    const event = server.poll();
    try std.testing.expect(event == .timeout);
}

test "computeDeadlineFromTimeout: valid formats" {
    // 5 seconds should produce a deadline ~5s in the future
    const dl_5s = computeDeadlineFromTimeout("5S").?;
    const now: i128 = std.time.nanoTimestamp();
    try std.testing.expect(dl_5s > now);
    try std.testing.expect(dl_5s - now < 6_000_000_000); // less than 6s

    // 100 milliseconds
    const dl_100m = computeDeadlineFromTimeout("100m").?;
    try std.testing.expect(dl_100m > now);
    try std.testing.expect(dl_100m - now < 200_000_000); // less than 200ms

    // 1 hour
    const dl_1h = computeDeadlineFromTimeout("1H").?;
    try std.testing.expect(dl_1h - now > 3_500_000_000_000); // > 3500s

    // 2 minutes
    const dl_2m = computeDeadlineFromTimeout("2M").?;
    try std.testing.expect(dl_2m - now > 100_000_000_000); // > 100s
}

test "computeDeadlineFromTimeout: invalid formats" {
    try std.testing.expect(computeDeadlineFromTimeout("") == null);
    try std.testing.expect(computeDeadlineFromTimeout("X") == null);
    try std.testing.expect(computeDeadlineFromTimeout("5x") == null);
    try std.testing.expect(computeDeadlineFromTimeout("abcS") == null);
}

test "isDeadlineExceeded: null is never exceeded" {
    try std.testing.expect(!isDeadlineExceeded(null));
}

test "isDeadlineExceeded: past deadline is exceeded" {
    try std.testing.expect(isDeadlineExceeded(0));
}

test "isDeadlineExceeded: future deadline is not exceeded" {
    const future: i128 = std.time.nanoTimestamp() + 10_000_000_000;
    try std.testing.expect(!isDeadlineExceeded(future));
}

test "GrpcServer: shutdown sets state" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();

    try std.testing.expect(!server.isShuttingDown());
    server.shutdown(4);
    try std.testing.expect(server.isShuttingDown());
}

test "GrpcServer: activeConnectionCount initially zero" {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = try GrpcServer.init(addr, .{});
    defer server.deinit();
    try std.testing.expectEqual(@as(usize, 0), server.activeConnectionCount());
}

test "GrpcRequest: getHeader returns metadata value" {
    var req: GrpcRequest = undefined;
    req.header_count = 2;
    req.headers[0] = .{ .name = "authorization", .value = "Bearer token123" };
    req.headers[1] = .{ .name = "x-request-id", .value = "abc-def" };

    try std.testing.expectEqualStrings("Bearer token123", req.getHeader("authorization").?);
    try std.testing.expectEqualStrings("abc-def", req.getHeader("x-request-id").?);
    try std.testing.expect(req.getHeader("missing") == null);
}

test "GrpcRequest: metadata returns all headers" {
    var req: GrpcRequest = undefined;
    req.header_count = 3;
    req.headers[0] = .{ .name = "x-trace-id", .value = "trace-1" };
    req.headers[1] = .{ .name = "x-user-id", .value = "user-42" };
    req.headers[2] = .{ .name = "authorization", .value = "Bearer xyz" };

    const md = req.metadata();
    try std.testing.expectEqual(@as(usize, 3), md.len);
    try std.testing.expectEqualStrings("x-trace-id", md[0].name);
    try std.testing.expectEqualStrings("trace-1", md[0].value);
}
