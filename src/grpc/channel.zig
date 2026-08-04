const std = @import("std");
const message = @import("message.zig");
const grpc_status = @import("status.zig");
const interceptor = @import("interceptor.zig");
const stream_interceptor = @import("stream_interceptor.zig");
const resolver_mod = @import("resolver.zig");
const balancer_mod = @import("balancer.zig");
const dialer_mod = @import("dialer.zig");

const h2_client = @import("../h2/client.zig");
const h2_frame = @import("../h2/frame.zig");
const h2_hpack = @import("../h2/hpack.zig");
const h2_connection = @import("../h2/connection.zig");

pub const ChannelError = error{
    ConnectionFailed,
    HandshakeFailed,
    StreamExhausted,
    MaxConcurrentStreams,
    EncodingError,
    IoError,
    ProtocolError,
    InvalidResponse,
    BufferTooSmall,
    MessageTooLarge,
    RpcFailed,
    ConnectionClosed,
    GoawayReceived,
    TooManyHeaders,
    OutOfMemory,
    DeadlineExceeded,
};

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    initial_backoff_ms: u64 = 100,
    max_backoff_ms: u64 = 10_000,
    backoff_multiplier: u32 = 2,
    retryable_status_codes: []const grpc_status.Code = &default_retryable_codes,

    const default_retryable_codes = [_]grpc_status.Code{ .unavailable, .resource_exhausted, .aborted };

    fn isRetryable(self: *const RetryPolicy, code: grpc_status.Code) bool {
        for (self.retryable_status_codes) |c| {
            if (c == code) return true;
        }
        return false;
    }

    fn computeBackoffMs(self: *const RetryPolicy, attempt: u32) u64 {
        var backoff = self.initial_backoff_ms;
        var i: u32 = 0;
        while (i < attempt) : (i += 1) {
            backoff = @min(backoff * self.backoff_multiplier, self.max_backoff_ms);
        }
        return backoff;
    }
};

pub const KeepaliveConfig = struct {
    /// Interval between keepalive pings (0 = disabled).
    interval_ms: u64 = 30_000,
    /// How long to wait for a ping ack before declaring connection dead.
    timeout_ms: u64 = 10_000,
};

pub const CallOptions = struct {
    timeout_ms: u64 = 0,
    retry_policy: ?RetryPolicy = null,
    metadata: []const Metadata = &.{},
    max_recv_message_size: u32 = 4 * 1024 * 1024,
    max_send_message_size: u32 = 4 * 1024 * 1024,
};

/// Encodes a timeout in milliseconds as a gRPC Timeout header value.
/// Format: integer + unit char (H=hours, M=minutes, S=seconds, m=millis, u=micros, n=nanos)
/// Returns the formatted slice within the provided buffer.
pub fn encodeGrpcTimeout(timeout_ms: u64, buf: *[32]u8) []const u8 {
    if (timeout_ms == 0) return "0m";

    // Use largest unit that doesn't lose precision and fits in 8 digits
    if (timeout_ms >= 3_600_000 and timeout_ms % 3_600_000 == 0) {
        const hours = timeout_ms / 3_600_000;
        if (hours <= 99_999_999) {
            return std.fmt.bufPrint(buf, "{d}H", .{hours}) catch "0m";
        }
    }
    if (timeout_ms >= 60_000 and timeout_ms % 60_000 == 0) {
        const minutes = timeout_ms / 60_000;
        if (minutes <= 99_999_999) {
            return std.fmt.bufPrint(buf, "{d}M", .{minutes}) catch "0m";
        }
    }
    if (timeout_ms >= 1000 and timeout_ms % 1000 == 0) {
        const seconds = timeout_ms / 1000;
        if (seconds <= 99_999_999) {
            return std.fmt.bufPrint(buf, "{d}S", .{seconds}) catch "0m";
        }
    }
    if (timeout_ms <= 99_999_999) {
        return std.fmt.bufPrint(buf, "{d}m", .{timeout_ms}) catch "0m";
    }
    // Fallback: seconds (loses sub-second precision for very large timeouts)
    const seconds = timeout_ms / 1000;
    return std.fmt.bufPrint(buf, "{d}S", .{seconds}) catch "0m";
}

/// Compute a deadline timestamp (nanoseconds from timer start) from timeout_ms.
/// Returns null if timeout_ms is 0 (no deadline).
fn computeDeadlineNs(timeout_ms: u64) ?i128 {
    if (timeout_ms == 0) return null;
    const now = std.time.nanoTimestamp();
    return now + @as(i128, timeout_ms) * 1_000_000;
}

/// Check if a deadline has been exceeded. Returns true if expired.
fn isDeadlineExceeded(deadline_ns: ?i128) bool {
    const dl = deadline_ns orelse return false;
    return std.time.nanoTimestamp() >= dl;
}

/// Sleep for the retry backoff duration. Single point of sleep for future async swap.
fn retryBackoff(backoff_ms: u64) void {
    const ns: u64 = backoff_ms * 1_000_000;
    std.Thread.sleep(ns);
}

/// Check if there's enough remaining time before the deadline for a backoff + attempt.
fn hasTimeForRetry(deadline_ns: ?i128, backoff_ms: u64) bool {
    const dl = deadline_ns orelse return true;
    const now = std.time.nanoTimestamp();
    const needed: i128 = @as(i128, backoff_ms) * 1_000_000;
    return (dl - now) > needed;
}

pub const Metadata = struct {
    key: []const u8,
    value: []const u8,
};

pub const UnaryResult = struct {
    status: grpc_status.Status,
    data: []const u8,
};

pub const ChannelState = enum {
    idle,
    connected,
    disconnected,
    shutdown,
};

pub const Channel = struct {
    client: h2_client.Client,
    authority: []const u8,
    allocator: std.mem.Allocator,
    config: h2_client.Config,
    channel_state: ChannelState,
    unary_interceptors: []const interceptor.UnaryInterceptor,
    stream_interceptors: []const stream_interceptor.StreamInterceptor,
    current_method: []const u8 = "",
    current_stream_type: stream_interceptor.StreamType = .server_streaming,

    // Keepalive state
    keepalive: KeepaliveConfig = .{},
    last_activity_ns: i128 = 0,
    ping_sent_ns: i128 = 0,
    ping_outstanding: bool = false,

    // Optional resolver + balancer + dialer for managed connections
    resolver_instance: ?resolver_mod.Resolver = null,
    balancer_instance: ?balancer_mod.Balancer = null,
    dialer_instance: ?dialer_mod.Dialer = null,
    active_dial: ?dialer_mod.DialResult = null,
    last_endpoint: ?resolver_mod.Endpoint = null,

    pub fn init(
        allocator: std.mem.Allocator,
        reader: std.io.AnyReader,
        writer: std.io.AnyWriter,
        authority: []const u8,
        config: h2_client.Config,
    ) Channel {
        return .{
            .client = h2_client.Client.init(allocator, reader, writer, config),
            .authority = authority,
            .allocator = allocator,
            .config = config,
            .channel_state = .idle,
            .unary_interceptors = &.{},
            .stream_interceptors = &.{},
            .current_method = "",
        };
    }

    /// Create a channel with managed connection lifecycle.
    /// The channel resolves, picks, and dials automatically.
    pub fn initManaged(
        allocator: std.mem.Allocator,
        authority: []const u8,
        config: h2_client.Config,
        r: resolver_mod.Resolver,
        b: balancer_mod.Balancer,
        d: dialer_mod.Dialer,
    ) Channel {
        // Initialize client with dummy reader/writer — connect() will set real ones
        const dummy_reader = std.io.AnyReader{ .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x), .readFn = dummyRead };
        const dummy_writer = std.io.AnyWriter{ .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x), .writeFn = dummyWrite };

        return .{
            .client = h2_client.Client.init(allocator, dummy_reader, dummy_writer, config),
            .authority = authority,
            .allocator = allocator,
            .config = config,
            .channel_state = .idle,
            .unary_interceptors = &.{},
            .stream_interceptors = &.{},
            .current_method = "",
            .resolver_instance = r,
            .balancer_instance = b,
            .dialer_instance = d,
        };
    }

    /// Set unary interceptors. Interceptors execute in order before the retry loop.
    pub fn withUnaryInterceptors(self: *Channel, interceptors: []const interceptor.UnaryInterceptor) void {
        self.unary_interceptors = interceptors;
    }

    /// Set stream interceptors. Interceptors execute in order before stream creation.
    pub fn withStreamInterceptors(self: *Channel, interceptors: []const stream_interceptor.StreamInterceptor) void {
        self.stream_interceptors = interceptors;
    }

    /// Configure keepalive parameters.
    pub fn withKeepalive(self: *Channel, config: KeepaliveConfig) void {
        self.keepalive = config;
    }

    /// Resolve target, pick endpoint via balancer, dial, and perform H2 handshake.
    /// For managed channels (created with initManaged).
    pub fn connect(self: *Channel) ChannelError!void {
        const r = self.resolver_instance orelse return ChannelError.ConnectionFailed;
        const b = self.balancer_instance orelse return ChannelError.ConnectionFailed;
        const d = self.dialer_instance orelse return ChannelError.ConnectionFailed;

        var result = r.resolve(self.authority, self.allocator) catch return ChannelError.ConnectionFailed;
        defer result.deinit();

        if (result.endpoints.len == 0) return ChannelError.ConnectionFailed;

        const endpoint = b.pick(result.endpoints) catch return ChannelError.ConnectionFailed;
        self.last_endpoint = endpoint;

        const dial_result = d.dial(endpoint) catch return ChannelError.ConnectionFailed;

        // Close previous connection if any
        if (self.active_dial) |prev| {
            prev.close();
        }
        self.active_dial = dial_result;

        self.client.conn.replaceTransport(dial_result.reader, dial_result.writer);
        self.client.encoder = h2_hpack.Encoder.init(self.config.header_table_size);
        self.client.decoder = h2_hpack.Decoder.init(self.config.header_table_size);
        self.channel_state = .idle;
        self.handshake() catch |e| {
            self.active_dial.?.close();
            self.active_dial = null;
            return e;
        };
    }

    pub fn handshake(self: *Channel) ChannelError!void {
        self.client.handshake() catch |e| {
            self.channel_state = .disconnected;
            return mapClientError(e);
        };
        self.channel_state = .connected;
        self.recordActivity();
    }

    /// Reconnect with new transport after a disconnect or GOAWAY.
    /// Caller must provide fresh reader/writer (e.g. from a new TCP connection).
    pub fn reconnect(self: *Channel, reader: std.io.AnyReader, writer: std.io.AnyWriter) ChannelError!void {
        if (self.channel_state == .shutdown) return ChannelError.ConnectionClosed;
        self.client.conn.replaceTransport(reader, writer);
        self.client.encoder = h2_hpack.Encoder.init(self.config.header_table_size);
        self.client.decoder = h2_hpack.Decoder.init(self.config.header_table_size);
        self.channel_state = .idle;
        self.handshake() catch |e| return e;
    }

    /// Returns whether the channel is in a state that requires reconnection.
    pub fn needsReconnect(self: *const Channel) bool {
        return self.channel_state == .disconnected or
            self.client.conn.state == .goaway_received or
            self.client.conn.state == .closed;
    }

    pub fn getState(self: *const Channel) ChannelState {
        return self.channel_state;
    }

    /// Unary RPC: send one message, receive one message. Supports retry with backoff.
    /// If unary_interceptors are configured, they execute before the retry loop.
    pub fn unary(
        self: *Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult {
        if (self.unary_interceptors.len > 0) {
            self.current_method = method;
            const info = interceptor.UnaryCallInfo{
                .method = method,
                .authority = self.authority,
            };
            const final_inv = self.unaryInvoker(method);
            const chain = interceptor.InterceptorChain.init(
                self.unary_interceptors,
                info,
                final_inv,
            );
            return chain.proceed(0, request_data, opts, response_buf);
        }
        return self.unaryWithRetry(method, request_data, opts, response_buf);
    }

    fn unaryInvoker(self: *Channel, method: []const u8) interceptor.Invoker {
        _ = method;
        return .{
            .context = @ptrCast(self),
            .invokeFn = unaryInvokerFn,
        };
    }

    fn unaryInvokerFn(
        ctx: *const anyopaque,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult {
        const self: *Channel = @constCast(@alignCast(@ptrCast(ctx)));
        return self.unaryWithRetry(self.current_method, request_data, opts, response_buf);
    }

    fn unaryWithRetry(
        self: *Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult {
        const deadline = computeDeadlineNs(opts.timeout_ms);
        const max_attempts: u32 = if (opts.retry_policy) |rp| rp.max_attempts else 1;

        var attempt: u32 = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            if (attempt > 0) {
                const policy = opts.retry_policy.?;
                const backoff = policy.computeBackoffMs(attempt - 1);
                if (!hasTimeForRetry(deadline, backoff)) return ChannelError.DeadlineExceeded;
                retryBackoff(backoff);
            }

            const result = self.unaryAttempt(method, request_data, opts, response_buf, deadline);
            const unary_result = result catch |e| {
                self.reportBalancerFailure();
                return e;
            };

            if (!unary_result.status.isOk()) {
                self.reportBalancerFailure();
                if (opts.retry_policy) |policy| {
                    if (policy.isRetryable(unary_result.status.code) and attempt + 1 < max_attempts) continue;
                }
            } else {
                self.reportBalancerSuccess();
            }

            return unary_result;
        }
        unreachable;
    }

    fn reportBalancerSuccess(self: *Channel) void {
        if (self.balancer_instance) |b| {
            if (self.last_endpoint) |ep| b.reportSuccess(ep);
        }
    }

    fn reportBalancerFailure(self: *Channel) void {
        if (self.balancer_instance) |b| {
            if (self.last_endpoint) |ep| b.reportFailure(ep);
        }
    }

    pub fn isManaged(self: *const Channel) bool {
        return self.resolver_instance != null and
            self.balancer_instance != null and
            self.dialer_instance != null;
    }

    fn autoConnect(self: *Channel) ChannelError!void {
        if (self.channel_state != .connected and self.isManaged()) {
            try self.connect();
        }
    }

    /// Check keepalive state before an RPC. If a ping is outstanding and timed out,
    /// mark connection as disconnected (auto-reconnect will handle it on next attempt).
    /// If interval has elapsed since last activity, send a keepalive ping.
    fn keepaliveCheck(self: *Channel) void {
        if (self.keepalive.interval_ms == 0) return;
        if (self.channel_state != .connected) return;

        const now = std.time.nanoTimestamp();

        // Check if outstanding ping has timed out
        if (self.ping_outstanding) {
            const elapsed_ns = now - self.ping_sent_ns;
            const timeout_ns: i128 = @as(i128, self.keepalive.timeout_ms) * 1_000_000;
            if (elapsed_ns >= timeout_ns) {
                self.channel_state = .disconnected;
                self.ping_outstanding = false;
                return;
            }
            // Ping still in flight, don't send another
            return;
        }

        // Check if it's time to send a keepalive ping
        const since_activity = now - self.last_activity_ns;
        const interval_ns: i128 = @as(i128, self.keepalive.interval_ms) * 1_000_000;
        if (since_activity >= interval_ns) {
            const ping_data: [8]u8 = .{ 'k', 'e', 'e', 'p', 'a', 'l', 'v', 'e' };
            self.client.conn.sendPing(ping_data) catch {
                self.channel_state = .disconnected;
                return;
            };
            self.ping_sent_ns = now;
            self.ping_outstanding = true;
        }
    }

    /// Record activity (successful data exchange). Resets keepalive timer.
    fn recordActivity(self: *Channel) void {
        self.last_activity_ns = std.time.nanoTimestamp();
        self.ping_outstanding = false;
    }

    fn unaryAttempt(
        self: *Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        deadline: ?i128,
    ) ChannelError!UnaryResult {
        try self.autoConnect();
        self.keepaliveCheck();
        if (self.channel_state == .disconnected) {
            try self.autoConnect();
        }

        const framed = try self.frameMessage(request_data, opts.max_send_message_size);
        defer self.allocator.free(framed);

        const headers = try buildGrpcHeaders(opts.metadata, opts.timeout_ms);

        if (isDeadlineExceeded(deadline)) return ChannelError.DeadlineExceeded;

        const handle = self.client.request(
            .POST,
            method,
            self.authority,
            framed,
            .{ .extra_headers = headers.slice(), .end_stream = true },
        ) catch |e| return self.mapAndTrackError(e);

        if (isDeadlineExceeded(deadline)) return ChannelError.DeadlineExceeded;

        var resp_headers: [32]h2_hpack.HeaderField = undefined;
        var decode_buf: [8192]u8 = undefined;

        const resp = self.client.recvResponse(
            handle,
            &resp_headers,
            &decode_buf,
            response_buf,
        ) catch |e| return self.mapAndTrackError(e);

        const resp_status = parseGrpcStatus(resp.headers[0..resp.header_count]);

        self.recordActivity();

        if (!resp_status.isOk()) {
            return UnaryResult{ .status = resp_status, .data = &.{} };
        }

        if (resp.body.len == 0) {
            return UnaryResult{ .status = resp_status, .data = &.{} };
        }

        const decoded = message.decodeMessage(resp.body, opts.max_recv_message_size) catch |e| return switch (e) {
            error.MessageTooLarge => ChannelError.MessageTooLarge,
            error.IncompleteMessage => ChannelError.ProtocolError,
            error.BufferTooSmall => ChannelError.BufferTooSmall,
        };

        return UnaryResult{ .status = resp_status, .data = decoded.payload };
    }

    /// Start a server-streaming RPC: send one message, receive a stream of messages.
    pub fn serverStream(
        self: *Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        self.current_method = method;
        self.current_stream_type = .server_streaming;
        if (self.stream_interceptors.len > 0) {
            const info = stream_interceptor.StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .server_streaming,
            };
            const final_inv = self.streamInvoker();
            const chain = stream_interceptor.StreamInterceptorChain.init(
                self.stream_interceptors,
                info,
                final_inv,
            );
            return chain.proceed(0, request_data, opts);
        }
        return self.serverStreamInternal(request_data, opts);
    }

    fn serverStreamInternal(self: *Channel, request_data: ?[]const u8, opts: CallOptions) ChannelError!StreamHandle {
        try self.autoConnect();
        self.keepaliveCheck();
        if (self.channel_state == .disconnected) try self.autoConnect();
        const payload = request_data orelse return ChannelError.ProtocolError;
        const framed = try self.frameMessage(payload, opts.max_send_message_size);
        defer self.allocator.free(framed);

        const headers = try buildGrpcHeaders(opts.metadata, opts.timeout_ms);

        const handle = self.client.request(
            .POST,
            self.current_method,
            self.authority,
            framed,
            .{ .extra_headers = headers.slice(), .end_stream = true },
        ) catch |e| return self.mapAndTrackError(e);

        return StreamHandle{
            .client = &self.client,
            .handle = handle,
            .max_recv_message_size = opts.max_recv_message_size,
            .max_send_message_size = opts.max_send_message_size,
            .allocator = self.allocator,
            .recv_buf = .{},
            .recv_buf_pos = 0,
            .final_status = null,
            .send_closed = true,
            .recv_closed = false,
            .deadline_ns = computeDeadlineNs(opts.timeout_ms),
        };
    }

    /// Start a client-streaming RPC: send a stream of messages, receive one response.
    pub fn clientStream(
        self: *Channel,
        method: []const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        self.current_method = method;
        self.current_stream_type = .client_streaming;
        if (self.stream_interceptors.len > 0) {
            const info = stream_interceptor.StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .client_streaming,
            };
            const final_inv = self.streamInvoker();
            const chain = stream_interceptor.StreamInterceptorChain.init(
                self.stream_interceptors,
                info,
                final_inv,
            );
            return chain.proceed(0, null, opts);
        }
        return self.clientStreamInternal(null, opts);
    }

    fn clientStreamInternal(self: *Channel, _: ?[]const u8, opts: CallOptions) ChannelError!StreamHandle {
        try self.autoConnect();
        self.keepaliveCheck();
        if (self.channel_state == .disconnected) try self.autoConnect();
        const headers = try buildGrpcHeaders(opts.metadata, opts.timeout_ms);

        const handle = self.client.request(
            .POST,
            self.current_method,
            self.authority,
            null,
            .{ .extra_headers = headers.slice(), .end_stream = false },
        ) catch |e| return self.mapAndTrackError(e);

        return StreamHandle{
            .client = &self.client,
            .handle = handle,
            .max_recv_message_size = opts.max_recv_message_size,
            .max_send_message_size = opts.max_send_message_size,
            .allocator = self.allocator,
            .recv_buf = .{},
            .recv_buf_pos = 0,
            .final_status = null,
            .send_closed = false,
            .recv_closed = false,
            .deadline_ns = computeDeadlineNs(opts.timeout_ms),
        };
    }

    /// Start a bidi-streaming RPC: send and receive streams of messages.
    pub fn bidiStream(
        self: *Channel,
        method: []const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        self.current_method = method;
        self.current_stream_type = .bidi_streaming;
        if (self.stream_interceptors.len > 0) {
            const info = stream_interceptor.StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .bidi_streaming,
            };
            const final_inv = self.streamInvoker();
            const chain = stream_interceptor.StreamInterceptorChain.init(
                self.stream_interceptors,
                info,
                final_inv,
            );
            return chain.proceed(0, null, opts);
        }
        return self.clientStreamInternal(null, opts);
    }

    fn streamInvoker(self: *Channel) stream_interceptor.StreamInvoker {
        return .{
            .context = @ptrCast(self),
            .invokeFn = streamInvokerFn,
        };
    }

    fn streamInvokerFn(
        ctx: *const anyopaque,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        const self: *Channel = @constCast(@alignCast(@ptrCast(ctx)));
        return switch (self.current_stream_type) {
            .server_streaming => self.serverStreamInternal(request_data, opts),
            .client_streaming, .bidi_streaming => self.clientStreamInternal(request_data, opts),
        };
    }

    pub fn close(self: *Channel) void {
        self.client.close();
        self.client.deinit();
        if (self.active_dial) |ad| {
            ad.close();
            self.active_dial = null;
        }
        self.channel_state = .shutdown;
    }

    fn frameMessage(self: *Channel, payload: []const u8, max_size: u32) ChannelError![]u8 {
        if (payload.len > max_size) return ChannelError.MessageTooLarge;
        const total = message.FrameHeader.encoded_size + payload.len;
        const buf = self.allocator.alloc(u8, total) catch return ChannelError.OutOfMemory;
        _ = message.encodeMessage(buf, payload, false) catch {
            self.allocator.free(buf);
            return ChannelError.MessageTooLarge;
        };
        return buf;
    }

    const max_grpc_headers = 32;

    const GrpcHeaders = struct {
        buf: [max_grpc_headers]h2_client.Header,
        count: usize,
        timeout_buf: [32]u8,

        fn slice(self: *const GrpcHeaders) []const h2_client.Header {
            return self.buf[0..self.count];
        }
    };

    fn buildGrpcHeaders(metadata: []const Metadata, timeout_ms: u64) ChannelError!GrpcHeaders {
        var result = GrpcHeaders{ .buf = undefined, .count = 0, .timeout_buf = undefined };

        const required = [_]h2_client.Header{
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "grpc-encoding", .value = "identity" },
        };

        for (required) |h| {
            result.buf[result.count] = h;
            result.count += 1;
        }

        if (timeout_ms > 0) {
            const timeout_val = encodeGrpcTimeout(timeout_ms, &result.timeout_buf);
            result.buf[result.count] = .{ .name = "grpc-timeout", .value = timeout_val };
            result.count += 1;
        }

        for (metadata) |m| {
            if (result.count >= max_grpc_headers) return ChannelError.TooManyHeaders;
            result.buf[result.count] = .{ .name = m.key, .value = m.value };
            result.count += 1;
        }

        return result;
    }

    fn mapClientError(e: h2_client.ClientError) ChannelError {
        return switch (e) {
            error.ConnectionNotOpen => ChannelError.ConnectionFailed,
            error.StreamExhausted => ChannelError.StreamExhausted,
            error.MaxConcurrentStreams => ChannelError.MaxConcurrentStreams,
            error.FlowControlError => ChannelError.ProtocolError,
            error.EncodingError => ChannelError.EncodingError,
            error.IoError => ChannelError.IoError,
            error.ProtocolError => ChannelError.ProtocolError,
            error.InvalidResponse => ChannelError.InvalidResponse,
            error.BufferTooSmall => ChannelError.BufferTooSmall,
            error.FrameSizeError => ChannelError.ProtocolError,
            error.ConnectionClosed => ChannelError.ConnectionClosed,
            error.GoawayReceived => ChannelError.GoawayReceived,
        };
    }

    fn mapAndTrackError(self: *Channel, e: h2_client.ClientError) ChannelError {
        const err = mapClientError(e);
        switch (err) {
            ChannelError.IoError, ChannelError.ConnectionClosed, ChannelError.GoawayReceived, ChannelError.ConnectionFailed => {
                self.channel_state = .disconnected;
            },
            else => {},
        }
        return err;
    }
};

fn dummyRead(_: *const anyopaque, _: []u8) anyerror!usize {
    return 0;
}

fn dummyWrite(_: *const anyopaque, data: []const u8) anyerror!usize {
    return data.len;
}

/// Unified stream handle for server-streaming, client-streaming, and bidi-streaming RPCs.
pub const StreamHandle = struct {
    client: *h2_client.Client,
    handle: h2_client.RequestHandle,
    max_recv_message_size: u32,
    max_send_message_size: u32,
    allocator: std.mem.Allocator,
    recv_buf: std.ArrayListUnmanaged(u8),
    recv_buf_pos: usize,
    final_status: ?grpc_status.Status,
    send_closed: bool,
    recv_closed: bool,
    deadline_ns: ?i128,

    /// Send a message on the stream (client-streaming or bidi).
    pub fn send(self: *StreamHandle, payload: []const u8) ChannelError!void {
        if (isDeadlineExceeded(self.deadline_ns)) return ChannelError.DeadlineExceeded;
        if (self.send_closed) return ChannelError.ProtocolError;
        if (payload.len > self.max_send_message_size) return ChannelError.MessageTooLarge;

        const total = message.FrameHeader.encoded_size + payload.len;
        const buf = self.allocator.alloc(u8, total) catch return ChannelError.OutOfMemory;
        defer self.allocator.free(buf);

        _ = message.encodeMessage(buf, payload, false) catch return ChannelError.MessageTooLarge;
        self.client.sendStreamData(self.handle, buf, false) catch |e| return Channel.mapClientError(e);
    }

    /// Close the send side of the stream.
    pub fn closeSend(self: *StreamHandle) ChannelError!void {
        if (self.send_closed) return;
        self.send_closed = true;
        self.client.sendStreamData(self.handle, &.{}, true) catch |e| return Channel.mapClientError(e);
    }

    /// Receive the next message from the stream. Returns null when the stream ends.
    pub fn recv(self: *StreamHandle, buf: []u8) ChannelError!?[]const u8 {
        if (isDeadlineExceeded(self.deadline_ns)) return ChannelError.DeadlineExceeded;
        if (self.recv_closed) return null;

        while (true) {
            // Try to decode a message from buffered data
            const buffered = self.recv_buf.items[self.recv_buf_pos..];
            if (buffered.len >= message.FrameHeader.encoded_size) {
                const result = message.decodeMessage(buffered, self.max_recv_message_size) catch |e| return switch (e) {
                    error.MessageTooLarge => ChannelError.MessageTooLarge,
                    error.IncompleteMessage => {
                        // Need more data, fall through to read next frame
                        break;
                    },
                    error.BufferTooSmall => ChannelError.BufferTooSmall,
                };
                if (result.payload.len > buf.len) return ChannelError.BufferTooSmall;
                @memcpy(buf[0..result.payload.len], result.payload);
                self.recv_buf_pos += result.consumed;
                return buf[0..result.payload.len];
            }
            break;
        }

        // Read frames from the connection until we get enough data or stream ends
        while (true) {
            const event = self.client.recvEvent() catch |e| return Channel.mapClientError(e);
            switch (event) {
                .data => |d| {
                    if (d.stream_id != self.handle.stream_id) {
                        self.client.skipFramePayload(d.payload_len) catch return ChannelError.IoError;
                        self.client.conn.payloadConsumed(d.payload_len);
                        continue;
                    }

                    const payload_len: usize = d.payload_len;
                    if (payload_len > 0) {
                        const old_len = self.recv_buf.items.len;
                        if (old_len + payload_len > self.max_recv_message_size + message.FrameHeader.encoded_size) {
                            return ChannelError.MessageTooLarge;
                        }
                        self.recv_buf.resize(self.allocator, old_len + payload_len) catch
                            return ChannelError.OutOfMemory;
                        self.client.readPayload(self.recv_buf.items[old_len..]) catch
                            return ChannelError.IoError;
                    }
                    self.client.conn.payloadConsumed(d.payload_len);

                    // Update stream state and send WINDOW_UPDATEs
                    {
                        const stream = self.client.conn.streams.get(self.handle.stream_id);
                        if (stream) |s| s.recvData(@intCast(payload_len), d.end_stream) catch {};
                    }
                    self.client.conn.maybeUpdateConnectionWindow() catch {};
                    self.client.conn.maybeUpdateStreamWindow(self.handle.stream_id) catch {};

                    if (d.end_stream) {
                        self.recv_closed = true;
                    }

                    // Try to decode
                    const buffered = self.recv_buf.items[self.recv_buf_pos..];
                    if (buffered.len >= message.FrameHeader.encoded_size) {
                        const result = message.decodeMessage(buffered, self.max_recv_message_size) catch |e| return switch (e) {
                            error.MessageTooLarge => ChannelError.MessageTooLarge,
                            error.IncompleteMessage => {
                                if (self.recv_closed) return null;
                                continue;
                            },
                            error.BufferTooSmall => ChannelError.BufferTooSmall,
                        };
                        if (result.payload.len > buf.len) return ChannelError.BufferTooSmall;
                        @memcpy(buf[0..result.payload.len], result.payload);
                        self.recv_buf_pos += result.consumed;
                        return buf[0..result.payload.len];
                    }

                    if (self.recv_closed) return null;
                },
                .headers => |h| {
                    if (h.stream_id != self.handle.stream_id) {
                        self.client.skipFramePayload(h.payload_len) catch return ChannelError.IoError;
                        self.client.conn.payloadConsumed(h.payload_len);
                        continue;
                    }

                    var hdr_payload: [16384]u8 = undefined;
                    var total_len: usize = h.payload_len;
                    if (total_len > hdr_payload.len) return ChannelError.BufferTooSmall;
                    self.client.readPayload(hdr_payload[0..total_len]) catch return ChannelError.IoError;
                    self.client.conn.payloadConsumed(h.payload_len);

                    if (self.client.conn.expecting_continuation != null) {
                        while (self.client.conn.expecting_continuation != null) {
                            const cont_event = self.client.recvEvent() catch |e| return switch (e) {
                                h2_client.ClientError.ProtocolError => ChannelError.ProtocolError,
                                h2_client.ClientError.IoError => ChannelError.IoError,
                                h2_client.ClientError.ConnectionClosed => ChannelError.ConnectionClosed,
                                h2_client.ClientError.GoawayReceived => ChannelError.GoawayReceived,
                                h2_client.ClientError.FrameSizeError => ChannelError.ProtocolError,
                                else => ChannelError.ProtocolError,
                            };
                            switch (cont_event) {
                                .continuation => |c| {
                                    const clen: usize = c.payload_len;
                                    if (total_len + clen > hdr_payload.len) return ChannelError.BufferTooSmall;
                                    self.client.readPayload(hdr_payload[total_len..][0..clen]) catch return ChannelError.IoError;
                                    self.client.conn.payloadConsumed(c.payload_len);
                                    total_len += clen;
                                },
                                else => return ChannelError.ProtocolError,
                            }
                        }
                    }

                    var headers: [32]h2_hpack.HeaderField = undefined;
                    var decode_buf: [8192]u8 = undefined;
                    const count = self.client.decoder.decode(
                        hdr_payload[0..total_len],
                        &headers,
                        &decode_buf,
                    ) catch return ChannelError.InvalidResponse;

                    // Check if this has grpc-status (trailers)
                    const parsed = parseGrpcStatus(headers[0..count]);
                    if (parsed.code != .ok or hasGrpcStatusHeader(headers[0..count])) {
                        self.final_status = parsed;
                    }

                    if (h.end_stream) {
                        self.recv_closed = true;
                        return null;
                    }
                },
                .rst_stream => |r| {
                    if (r.stream_id == self.handle.stream_id) {
                        self.recv_closed = true;
                        self.final_status = .{ .code = .internal, .message = "stream reset" };
                        return null;
                    }
                },
                .goaway => {
                    self.recv_closed = true;
                    return ChannelError.GoawayReceived;
                },
                .settings_ack, .ping_ack, .window_update => continue,
                .continuation => |c| {
                    self.client.skipFramePayload(c.payload_len) catch return ChannelError.IoError;
                    self.client.conn.payloadConsumed(c.payload_len);
                    continue;
                },
            }
        }
    }

    /// Close send and receive the final response as a single message (client-streaming pattern).
    pub fn closeAndRecv(self: *StreamHandle, buf: []u8) ChannelError!UnaryResult {
        try self.closeSend();
        const data = try self.recv(buf);
        const s = self.getStatus();
        if (data) |d| {
            return UnaryResult{ .status = s, .data = d };
        }
        return UnaryResult{ .status = s, .data = &.{} };
    }

    /// Get the final gRPC status (available after recv returns null).
    pub fn getStatus(self: *StreamHandle) grpc_status.Status {
        return self.final_status orelse grpc_status.Status.ok;
    }

    pub fn deinit(self: *StreamHandle) void {
        self.recv_buf.deinit(self.allocator);
    }
};

fn parseGrpcStatus(headers: []const h2_hpack.HeaderField) grpc_status.Status {
    var code: grpc_status.Code = .ok;
    var msg: []const u8 = "";

    for (headers) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status")) {
            const v = std.fmt.parseInt(u32, h.value, 10) catch 2;
            code = grpc_status.Code.fromInt(v);
        } else if (std.mem.eql(u8, h.name, "grpc-message")) {
            msg = h.value;
        }
    }

    return .{ .code = code, .message = msg };
}

fn hasGrpcStatusHeader(headers: []const h2_hpack.HeaderField) bool {
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status")) return true;
    }
    return false;
}

// ─── Tests ───

const TestPipe = struct {
    read_buf: []const u8,
    read_pos: usize,
    write_buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, input: []const u8) TestPipe {
        return .{
            .read_buf = input,
            .read_pos = 0,
            .write_buf = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestPipe) void {
        self.write_buf.deinit(self.allocator);
    }

    fn reader(self: *TestPipe) std.io.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }

    fn writer(self: *TestPipe) std.io.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
    }

    fn readFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
        const self: *TestPipe = @constCast(@alignCast(@ptrCast(ctx)));
        if (self.read_pos >= self.read_buf.len) return 0;
        const available = self.read_buf[self.read_pos..];
        const len = @min(buf.len, available.len);
        @memcpy(buf[0..len], available[0..len]);
        self.read_pos += len;
        return len;
    }

    fn writeFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
        const self: *TestPipe = @constCast(@alignCast(@ptrCast(ctx)));
        try self.write_buf.appendSlice(self.allocator, data);
        return data.len;
    }
};

fn buildServerPreface(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) !void {
    var settings_hdr: [9]u8 = undefined;
    const sh = h2_frame.FrameHeader{ .length = 0, .frame_type = .settings, .flags = .{}, .stream_id = 0 };
    sh.encode(&settings_hdr);
    try buf.appendSlice(allocator, &settings_hdr);

    var ack_buf: [9]u8 = undefined;
    _ = h2_frame.buildSettingsAck(&ack_buf);
    try buf.appendSlice(allocator, &ack_buf);
}

fn buildGrpcResponse(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), stream_id: u31, response_payload: []const u8, grpc_code: u8) !void {
    var enc = h2_hpack.Encoder.init(4096);

    // Response HEADERS
    var hdr_block: [512]u8 = undefined;
    var offset: usize = 0;
    offset += enc.encodeHeader(hdr_block[offset..], ":status", "200", .without_indexing);
    offset += enc.encodeHeader(hdr_block[offset..], "content-type", "application/grpc", .without_indexing);

    const hdr_fh = h2_frame.FrameHeader{
        .length = @intCast(offset),
        .frame_type = .headers,
        .flags = h2_frame.Flags.END_HEADERS,
        .stream_id = stream_id,
    };
    var frame_buf: [9]u8 = undefined;
    hdr_fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, hdr_block[0..offset]);

    // DATA frame with gRPC-framed message
    if (response_payload.len > 0) {
        var msg_frame: [1024]u8 = undefined;
        const framed = try message.encodeMessage(&msg_frame, response_payload, false);

        const data_fh = h2_frame.FrameHeader{
            .length = @intCast(framed.len),
            .frame_type = .data,
            .flags = .{},
            .stream_id = stream_id,
        };
        data_fh.encode(&frame_buf);
        try buf.appendSlice(allocator, &frame_buf);
        try buf.appendSlice(allocator, framed);
    }

    // Trailers with grpc-status
    var trailer_block: [256]u8 = undefined;
    var toffset: usize = 0;
    var status_str: [3]u8 = undefined;
    const status_slice = std.fmt.bufPrint(&status_str, "{d}", .{grpc_code}) catch "0";
    toffset += enc.encodeHeader(trailer_block[toffset..], "grpc-status", status_slice, .without_indexing);

    const trailer_fh = h2_frame.FrameHeader{
        .length = @intCast(toffset),
        .frame_type = .headers,
        .flags = h2_frame.Flags.END_HEADERS.combine(h2_frame.Flags.END_STREAM),
        .stream_id = stream_id,
    };
    trailer_fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, trailer_block[0..toffset]);
}

fn buildStreamingResponse(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), stream_id: u31, messages: []const []const u8, grpc_code: u8) !void {
    var enc = h2_hpack.Encoder.init(4096);

    // Response HEADERS
    var hdr_block: [512]u8 = undefined;
    var offset: usize = 0;
    offset += enc.encodeHeader(hdr_block[offset..], ":status", "200", .without_indexing);
    offset += enc.encodeHeader(hdr_block[offset..], "content-type", "application/grpc", .without_indexing);

    const hdr_fh = h2_frame.FrameHeader{
        .length = @intCast(offset),
        .frame_type = .headers,
        .flags = h2_frame.Flags.END_HEADERS,
        .stream_id = stream_id,
    };
    var frame_buf: [9]u8 = undefined;
    hdr_fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, hdr_block[0..offset]);

    // Multiple DATA frames, each with a gRPC-framed message
    for (messages) |msg| {
        var msg_frame: [1024]u8 = undefined;
        const framed = try message.encodeMessage(&msg_frame, msg, false);

        const data_fh = h2_frame.FrameHeader{
            .length = @intCast(framed.len),
            .frame_type = .data,
            .flags = .{},
            .stream_id = stream_id,
        };
        data_fh.encode(&frame_buf);
        try buf.appendSlice(allocator, &frame_buf);
        try buf.appendSlice(allocator, framed);
    }

    // Trailers
    var trailer_block: [256]u8 = undefined;
    var toffset: usize = 0;
    var status_str: [3]u8 = undefined;
    const status_slice = std.fmt.bufPrint(&status_str, "{d}", .{grpc_code}) catch "0";
    toffset += enc.encodeHeader(trailer_block[toffset..], "grpc-status", status_slice, .without_indexing);

    const trailer_fh = h2_frame.FrameHeader{
        .length = @intCast(toffset),
        .frame_type = .headers,
        .flags = h2_frame.Flags.END_HEADERS.combine(h2_frame.Flags.END_STREAM),
        .stream_id = stream_id,
    };
    trailer_fh.encode(&frame_buf);
    try buf.appendSlice(allocator, &frame_buf);
    try buf.appendSlice(allocator, trailer_block[0..toffset]);
}

test "channel unary RPC success" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "response_data", 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "request_data", .{}, &response_buf);

    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("response_data", result.data);
}

test "channel unary RPC with grpc error" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "", 5); // NOT_FOUND

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "request_data", .{}, &response_buf);

    try std.testing.expectEqual(grpc_status.Code.not_found, result.status.code);
}

test "channel unary RPC with metadata" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "ok", 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "conductor.runetale.com", .{});
    try ch.handshake();

    const metadata = [_]Metadata{
        .{ .key = "authorization", .value = "Bearer token123" },
    };

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/runetale.v1.NodeService/LoginNode", "login_request", .{ .metadata = &metadata }, &response_buf);

    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("ok", result.data);
}

test "server streaming multiple messages" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };
    try buildStreamingResponse(allocator, &server_data, 1, &messages, 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var stream = try ch.serverStream("/test.Service/StreamMethod", "request", .{});
    defer stream.deinit();

    var buf: [256]u8 = undefined;

    const m1 = try stream.recv(&buf);
    try std.testing.expectEqualStrings("msg1", m1.?);

    const m2 = try stream.recv(&buf);
    try std.testing.expectEqualStrings("msg2", m2.?);

    const m3 = try stream.recv(&buf);
    try std.testing.expectEqualStrings("msg3", m3.?);

    const m4 = try stream.recv(&buf);
    try std.testing.expect(m4 == null);

    try std.testing.expect(stream.getStatus().isOk());
}

test "server streaming with error status" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    try buildServerPreface(allocator, &server_data);

    const messages = [_][]const u8{"partial"};
    try buildStreamingResponse(allocator, &server_data, 1, &messages, 13); // INTERNAL

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var stream = try ch.serverStream("/test.Service/StreamMethod", "request", .{});
    defer stream.deinit();

    var buf: [256]u8 = undefined;
    const m1 = try stream.recv(&buf);
    try std.testing.expectEqualStrings("partial", m1.?);

    const m2 = try stream.recv(&buf);
    try std.testing.expect(m2 == null);

    try std.testing.expectEqual(grpc_status.Code.internal, stream.getStatus().code);
}

test "too many headers returns error" {
    const allocator = std.testing.allocator;

    var big_metadata: [30]Metadata = undefined;
    for (&big_metadata) |*m| {
        m.* = .{ .key = "x-custom", .value = "val" };
    }

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = ch.unary("/test.Service/Method", "data", .{ .metadata = &big_metadata }, &response_buf);
    try std.testing.expectError(ChannelError.TooManyHeaders, result);
}

test "message too large returns error" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    const big_payload = try allocator.alloc(u8, 5 * 1024 * 1024);
    defer allocator.free(big_payload);
    @memset(big_payload, 'A');

    var response_buf: [1024]u8 = undefined;
    const result = ch.unary("/test.Service/Method", big_payload, .{}, &response_buf);
    try std.testing.expectError(ChannelError.MessageTooLarge, result);
}

test "channel reconnect after disconnect" {
    const allocator = std.testing.allocator;

    // First connection
    var server_data1 = std.ArrayListUnmanaged(u8){};
    defer server_data1.deinit(allocator);
    try buildServerPreface(allocator, &server_data1);

    var pipe1 = TestPipe.init(allocator, server_data1.items);
    defer pipe1.deinit();

    var ch = Channel.init(allocator, pipe1.reader(), pipe1.writer(), "test.example.com", .{});
    try ch.handshake();
    try std.testing.expectEqual(ChannelState.connected, ch.getState());

    // Simulate disconnect
    ch.channel_state = .disconnected;
    try std.testing.expect(ch.needsReconnect());

    // Reconnect with new transport
    var server_data2 = std.ArrayListUnmanaged(u8){};
    defer server_data2.deinit(allocator);
    try buildServerPreface(allocator, &server_data2);
    try buildGrpcResponse(allocator, &server_data2, 1, "reconnected", 0);

    var pipe2 = TestPipe.init(allocator, server_data2.items);
    defer pipe2.deinit();

    try ch.reconnect(pipe2.reader(), pipe2.writer());
    try std.testing.expectEqual(ChannelState.connected, ch.getState());

    // Verify RPC works on new connection
    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "test", .{}, &response_buf);
    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("reconnected", result.data);
}

test "channel reconnect after shutdown fails" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();
    ch.close();

    try std.testing.expectEqual(ChannelState.shutdown, ch.getState());
    try std.testing.expectError(ChannelError.ConnectionClosed, ch.reconnect(pipe.reader(), pipe.writer()));
}

test "channel needsReconnect after goaway" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    // Simulate server sending GOAWAY
    ch.client.conn.state = .goaway_received;
    try std.testing.expect(ch.needsReconnect());
}

test "encodeGrpcTimeout milliseconds" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("500m", encodeGrpcTimeout(500, &buf));
    try std.testing.expectEqualStrings("100m", encodeGrpcTimeout(100, &buf));
    try std.testing.expectEqualStrings("1m", encodeGrpcTimeout(1, &buf));
}

test "encodeGrpcTimeout seconds" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("5S", encodeGrpcTimeout(5000, &buf));
    try std.testing.expectEqualStrings("30S", encodeGrpcTimeout(30000, &buf));
}

test "encodeGrpcTimeout minutes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2M", encodeGrpcTimeout(120_000, &buf));
    try std.testing.expectEqualStrings("10M", encodeGrpcTimeout(600_000, &buf));
}

test "encodeGrpcTimeout hours" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1H", encodeGrpcTimeout(3_600_000, &buf));
    try std.testing.expectEqualStrings("24H", encodeGrpcTimeout(86_400_000, &buf));
}

test "encodeGrpcTimeout zero" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("0m", encodeGrpcTimeout(0, &buf));
}

test "computeDeadlineNs returns null for zero timeout" {
    try std.testing.expect(computeDeadlineNs(0) == null);
}

test "computeDeadlineNs returns future timestamp" {
    const deadline = computeDeadlineNs(1000).?;
    const now = std.time.nanoTimestamp();
    try std.testing.expect(deadline > now);
}

test "isDeadlineExceeded null deadline never expires" {
    try std.testing.expect(!isDeadlineExceeded(null));
}

test "isDeadlineExceeded past deadline" {
    const past: i128 = std.time.nanoTimestamp() - 1_000_000_000;
    try std.testing.expect(isDeadlineExceeded(past));
}

test "isDeadlineExceeded future deadline" {
    const future: i128 = std.time.nanoTimestamp() + 60_000_000_000;
    try std.testing.expect(!isDeadlineExceeded(future));
}

test "isDeadlineExceeded works with computeDeadlineNs" {
    // A deadline computed with timeout_ms=1 should not be immediately expired
    const deadline = computeDeadlineNs(1);
    try std.testing.expect(deadline != null);
    // Right after computing, it should not yet be expired (1ms in the future)
    try std.testing.expect(!isDeadlineExceeded(deadline));
}

test "grpc-timeout header included in request" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    // Send a unary RPC with a long timeout (won't expire)
    var response_buf: [1024]u8 = undefined;
    _ = ch.unary("/test.Service/Method", "hello", .{ .timeout_ms = 60_000 }, &response_buf) catch {};

    // Verify the output contains "grpc-timeout" header by scanning written bytes
    const written = pipe.write_buf.items;
    var found_timeout = false;
    // The HPACK-encoded header will contain the literal "grpc-timeout" string
    if (std.mem.indexOf(u8, written, "grpc-timeout")) |_| {
        found_timeout = true;
    }
    try std.testing.expect(found_timeout);
}

test "retry policy retries on UNAVAILABLE then succeeds" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    // First attempt: stream 1 returns UNAVAILABLE (14)
    try buildGrpcResponse(allocator, &server_data, 1, "", 14);
    // Second attempt: stream 3 returns OK with payload
    try buildGrpcResponse(allocator, &server_data, 3, "success", 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "hello", .{
        .retry_policy = .{ .max_attempts = 3, .initial_backoff_ms = 1, .max_backoff_ms = 10, .backoff_multiplier = 2 },
    }, &response_buf);

    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("success", result.data);
}

test "retry policy exhausts max_attempts" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    // All 3 attempts return UNAVAILABLE
    try buildGrpcResponse(allocator, &server_data, 1, "", 14);
    try buildGrpcResponse(allocator, &server_data, 3, "", 14);
    try buildGrpcResponse(allocator, &server_data, 5, "", 14);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "hello", .{
        .retry_policy = .{ .max_attempts = 3, .initial_backoff_ms = 1, .max_backoff_ms = 10, .backoff_multiplier = 2 },
    }, &response_buf);

    try std.testing.expect(!result.status.isOk());
    try std.testing.expectEqual(grpc_status.Code.unavailable, result.status.code);
}

test "retry policy does not retry non-retryable status" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    // Returns INVALID_ARGUMENT (3) — not retryable
    try buildGrpcResponse(allocator, &server_data, 1, "", 3);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "hello", .{
        .retry_policy = .{ .max_attempts = 3, .initial_backoff_ms = 1, .max_backoff_ms = 10, .backoff_multiplier = 2 },
    }, &response_buf);

    try std.testing.expect(!result.status.isOk());
    try std.testing.expectEqual(grpc_status.Code.invalid_argument, result.status.code);
}

test "retry policy no retry without policy" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    // Returns UNAVAILABLE but no retry policy
    try buildGrpcResponse(allocator, &server_data, 1, "", 14);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "hello", .{}, &response_buf);

    try std.testing.expect(!result.status.isOk());
    try std.testing.expectEqual(grpc_status.Code.unavailable, result.status.code);
}

test "RetryPolicy.computeBackoffMs exponential" {
    const policy = RetryPolicy{ .initial_backoff_ms = 100, .max_backoff_ms = 5000, .backoff_multiplier = 2 };
    // attempt=0: initial * multiplier^0 = 100
    try std.testing.expectEqual(@as(u64, 100), policy.computeBackoffMs(0));
    // attempt=1: 100 * 2 = 200
    try std.testing.expectEqual(@as(u64, 200), policy.computeBackoffMs(1));
    // attempt=2: 200 * 2 = 400
    try std.testing.expectEqual(@as(u64, 400), policy.computeBackoffMs(2));
    // attempt=3: 400 * 2 = 800
    try std.testing.expectEqual(@as(u64, 800), policy.computeBackoffMs(3));
    // attempt=4: 800 * 2 = 1600
    try std.testing.expectEqual(@as(u64, 1600), policy.computeBackoffMs(4));
    // attempt=5: 1600 * 2 = 3200
    try std.testing.expectEqual(@as(u64, 3200), policy.computeBackoffMs(5));
    // attempt=6: 3200 * 2 = 5000 (capped)
    try std.testing.expectEqual(@as(u64, 5000), policy.computeBackoffMs(6));
}

test "RetryPolicy.isRetryable" {
    const policy = RetryPolicy{};
    try std.testing.expect(policy.isRetryable(.unavailable));
    try std.testing.expect(policy.isRetryable(.resource_exhausted));
    try std.testing.expect(policy.isRetryable(.aborted));
    try std.testing.expect(!policy.isRetryable(.invalid_argument));
    try std.testing.expect(!policy.isRetryable(.not_found));
    try std.testing.expect(!policy.isRetryable(.ok));
}

test "initManaged creates channel with resolver/balancer/dialer" {
    const allocator = std.testing.allocator;

    const endpoints = [_]resolver_mod.Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
    };
    const static = resolver_mod.StaticResolver.init(&endpoints);
    var pf = balancer_mod.PickFirst.init();

    const ch = Channel.initManaged(
        allocator,
        "localhost:50051",
        .{},
        static.resolver(),
        pf.balancer(),
        .{ .context = undefined, .dialFn = testDialFn },
    );

    try std.testing.expectEqual(ChannelState.idle, ch.channel_state);
    try std.testing.expect(ch.resolver_instance != null);
    try std.testing.expect(ch.balancer_instance != null);
    try std.testing.expect(ch.dialer_instance != null);
}

test "connect resolves picks and dials" {
    const allocator = std.testing.allocator;

    // Build server preface + response for after handshake
    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "managed_response", 0);

    // Create a fake dialer that returns a pipe backed by server_data
    var fake_dialer = FakeDialer{ .server_data = server_data.items, .allocator = allocator };

    const endpoints = [_]resolver_mod.Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
    };
    const static = resolver_mod.StaticResolver.init(&endpoints);
    var pf = balancer_mod.PickFirst.init();

    var ch = Channel.initManaged(
        allocator,
        "localhost:50051",
        .{},
        static.resolver(),
        pf.balancer(),
        fake_dialer.dialer(),
    );
    defer ch.close();

    try ch.connect();
    try std.testing.expectEqual(ChannelState.connected, ch.channel_state);

    // Verify RPC works through managed connection
    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqualStrings("managed_response", result.data);
}

test "connect with empty endpoints fails" {
    const allocator = std.testing.allocator;

    const static = resolver_mod.StaticResolver.init(&.{});
    var pf = balancer_mod.PickFirst.init();

    var ch = Channel.initManaged(
        allocator,
        "empty:50051",
        .{},
        static.resolver(),
        pf.balancer(),
        .{ .context = undefined, .dialFn = testDialFn },
    );

    try std.testing.expectError(ChannelError.ConnectionFailed, ch.connect());
}

fn testDialFn(_: *anyopaque, _: resolver_mod.Endpoint) dialer_mod.DialError!dialer_mod.DialResult {
    return dialer_mod.DialError.ConnectionRefused;
}

const FakeDialer = struct {
    server_data: []const u8,
    allocator: std.mem.Allocator,
    shared_pos: usize = 0,

    fn dialer(self: *FakeDialer) dialer_mod.Dialer {
        return .{
            .context = @ptrCast(self),
            .dialFn = fakeDialFn,
        };
    }

    fn fakeDialFn(ctx: *anyopaque, _: resolver_mod.Endpoint) dialer_mod.DialError!dialer_mod.DialResult {
        const self: *FakeDialer = @alignCast(@ptrCast(ctx));
        const conn = self.allocator.create(FakeConn) catch return dialer_mod.DialError.IoError;
        conn.* = .{ .data = self.server_data, .shared_pos = &self.shared_pos, .write_buf = .{}, .allocator = self.allocator };
        return .{
            .reader = .{ .context = @ptrCast(conn), .readFn = fakeReadFn },
            .writer = .{ .context = @ptrCast(conn), .writeFn = fakeWriteFn },
            .closeFn = fakeCloseFn,
            .close_ctx = @ptrCast(conn),
        };
    }
};

const FakeConn = struct {
    data: []const u8,
    shared_pos: *usize,
    write_buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
};

fn fakeReadFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
    const conn: *FakeConn = @constCast(@alignCast(@ptrCast(ctx)));
    if (conn.shared_pos.* >= conn.data.len) return 0;
    const available = conn.data[conn.shared_pos.*..];
    const len = @min(buf.len, available.len);
    @memcpy(buf[0..len], available[0..len]);
    conn.shared_pos.* += len;
    return len;
}

fn fakeWriteFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
    const conn: *FakeConn = @constCast(@alignCast(@ptrCast(ctx)));
    conn.write_buf.appendSlice(conn.allocator, data) catch return error.IoError;
    return data.len;
}

fn fakeCloseFn(ctx: *anyopaque) void {
    const conn: *FakeConn = @alignCast(@ptrCast(ctx));
    conn.write_buf.deinit(conn.allocator);
    conn.allocator.destroy(conn);
}

test "auto-reconnect on managed channel" {
    const allocator = std.testing.allocator;

    // Build server data for two handshakes + two RPCs
    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);

    // First connection: handshake + RPC
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "first", 0);
    // Second connection (after reconnect): handshake + RPC
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "reconnected", 0);

    var fake_dialer = FakeDialer{ .server_data = server_data.items, .allocator = allocator };

    const endpoints = [_]resolver_mod.Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
    };
    const static = resolver_mod.StaticResolver.init(&endpoints);
    var pf = balancer_mod.PickFirst.init();

    var ch = Channel.initManaged(
        allocator,
        "localhost:50051",
        .{},
        static.resolver(),
        pf.balancer(),
        fake_dialer.dialer(),
    );

    // First RPC: auto-connects (channel starts as idle)
    var response_buf: [1024]u8 = undefined;
    const r1 = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(r1.status.isOk());
    try std.testing.expectEqualStrings("first", r1.data);
    try std.testing.expectEqual(ChannelState.connected, ch.channel_state);

    // Simulate disconnect
    ch.channel_state = .disconnected;

    // Second RPC: auto-reconnects
    const r2 = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(r2.status.isOk());
    try std.testing.expectEqualStrings("reconnected", r2.data);
    try std.testing.expectEqual(ChannelState.connected, ch.channel_state);

    ch.close();
}

test "balancer feedback: reportSuccess on OK" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "ok", 0);

    var fake_dialer = FakeDialer{ .server_data = server_data.items, .allocator = allocator };
    const endpoints = [_]resolver_mod.Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
    };
    const static = resolver_mod.StaticResolver.init(&endpoints);
    var counting_bal = CountingBalancer.init();

    var ch = Channel.initManaged(
        allocator,
        "localhost:50051",
        .{},
        static.resolver(),
        counting_bal.balancer(),
        fake_dialer.dialer(),
    );
    defer ch.close();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(result.status.isOk());
    try std.testing.expectEqual(@as(u32, 1), counting_bal.success_count);
    try std.testing.expectEqual(@as(u32, 0), counting_bal.failure_count);
}

test "balancer feedback: reportFailure on error status" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "", 14); // UNAVAILABLE

    var fake_dialer = FakeDialer{ .server_data = server_data.items, .allocator = allocator };
    const endpoints = [_]resolver_mod.Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
    };
    const static = resolver_mod.StaticResolver.init(&endpoints);
    var counting_bal = CountingBalancer.init();

    var ch = Channel.initManaged(
        allocator,
        "localhost:50051",
        .{},
        static.resolver(),
        counting_bal.balancer(),
        fake_dialer.dialer(),
    );
    defer ch.close();

    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(!result.status.isOk());
    try std.testing.expectEqual(@as(u32, 0), counting_bal.success_count);
    try std.testing.expectEqual(@as(u32, 1), counting_bal.failure_count);
}

const CountingBalancer = struct {
    success_count: u32,
    failure_count: u32,

    fn init() CountingBalancer {
        return .{ .success_count = 0, .failure_count = 0 };
    }

    fn balancer(self: *CountingBalancer) balancer_mod.Balancer {
        return .{
            .context = @ptrCast(self),
            .pickFn = pickFn,
            .reportSuccessFn = reportSuccessFn,
            .reportFailureFn = reportFailureFn,
        };
    }

    fn pickFn(_: *anyopaque, endpoints: []const resolver_mod.Endpoint) balancer_mod.PickError!resolver_mod.Endpoint {
        if (endpoints.len == 0) return balancer_mod.PickError.NoEndpoints;
        return endpoints[0];
    }

    fn reportSuccessFn(ctx: *anyopaque, _: resolver_mod.Endpoint) void {
        const self: *CountingBalancer = @alignCast(@ptrCast(ctx));
        self.success_count += 1;
    }

    fn reportFailureFn(ctx: *anyopaque, _: resolver_mod.Endpoint) void {
        const self: *CountingBalancer = @alignCast(@ptrCast(ctx));
        self.failure_count += 1;
    }
};

test "auto-reconnect not triggered on non-managed channel" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "ok", 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    // Works normally
    var response_buf: [1024]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "req", .{}, &response_buf);
    try std.testing.expect(result.status.isOk());

    // After disconnect, non-managed channel does NOT auto-reconnect
    ch.channel_state = .disconnected;
    try std.testing.expect(!ch.isManaged());
}

test "keepalive: disabled by default (interval_ms=0 does nothing)" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);
    try buildGrpcResponse(allocator, &server_data, 1, "resp", 0);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    // Default keepalive interval is 30s — no ping should be sent for a fresh connection
    ch.keepaliveCheck();
    try std.testing.expectEqual(ChannelState.connected, ch.channel_state);
    try std.testing.expect(!ch.ping_outstanding);
}

test "keepalive: sends ping after interval elapsed" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();
    ch.withKeepalive(.{ .interval_ms = 1, .timeout_ms = 5000 });

    // Simulate elapsed time by backdating last_activity
    ch.last_activity_ns = std.time.nanoTimestamp() - 10_000_000; // 10ms ago

    ch.keepaliveCheck();
    // Ping should be sent (or fail due to pipe — either way, state is set)
    // On success: ping_outstanding = true
    // On IoError from sendPing: channel_state = disconnected
    try std.testing.expect(ch.ping_outstanding or ch.channel_state == .disconnected);
}

test "keepalive: timeout triggers disconnect" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();
    ch.withKeepalive(.{ .interval_ms = 1, .timeout_ms = 1 });

    // Simulate: ping was sent 10ms ago, no ack received
    ch.ping_outstanding = true;
    ch.ping_sent_ns = std.time.nanoTimestamp() - 10_000_000; // 10ms ago, timeout is 1ms

    ch.keepaliveCheck();
    try std.testing.expectEqual(ChannelState.disconnected, ch.channel_state);
    try std.testing.expect(!ch.ping_outstanding);
}

test "keepalive: recordActivity resets state" {
    const allocator = std.testing.allocator;

    var server_data = std.ArrayListUnmanaged(u8){};
    defer server_data.deinit(allocator);
    try buildServerPreface(allocator, &server_data);

    var pipe = TestPipe.init(allocator, server_data.items);
    defer pipe.deinit();

    var ch = Channel.init(allocator, pipe.reader(), pipe.writer(), "test.example.com", .{});
    try ch.handshake();

    ch.ping_outstanding = true;
    ch.ping_sent_ns = std.time.nanoTimestamp();

    ch.recordActivity();
    try std.testing.expect(!ch.ping_outstanding);
    try std.testing.expect(ch.last_activity_ns > 0);
}
