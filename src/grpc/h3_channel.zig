// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const message = @import("message.zig");
const grpc_status = @import("status.zig");
const channel_mod = @import("channel.zig");

const h3_pool_mod = @import("../quic/h3_pool.zig");
const h3_client_mod = @import("../quic/h3_client.zig");
const qpack = @import("../quic/qpack.zig");

const H3Pool = h3_pool_mod.H3Pool;
const H3PoolConfig = h3_pool_mod.H3PoolConfig;
const H3PoolError = h3_pool_mod.H3PoolError;
const H3Client = h3_client_mod.H3Client;
const H3Response = h3_client_mod.H3Response;
const H3Error = h3_client_mod.H3Error;

// ─── Interceptor types for H3 Channel ───

/// Context passed to H3 unary interceptors.
pub const H3UnaryCallInfo = struct {
    method: []const u8,
    authority: []const u8,
};

/// Type-erased invoker for the next step in the H3 unary interceptor chain.
pub const H3Invoker = struct {
    context: *const anyopaque,
    invokeFn: *const fn (
        ctx: *const anyopaque,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult,

    pub fn invoke(
        self: H3Invoker,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult {
        return self.invokeFn(self.context, request_data, opts, response_buf);
    }
};

/// H3 unary interceptor. Same pattern as interceptor.zig but with H3 types.
/// IMPORTANT: The `next` H3Invoker must be called synchronously within the
/// intercept function. Storing it for deferred invocation causes use-after-free
/// (the Invoker references stack-local chain state invalidated on return).
pub const H3UnaryInterceptor = struct {
    context: *const anyopaque,
    interceptFn: *const fn (
        ctx: *const anyopaque,
        info: H3UnaryCallInfo,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        next: H3Invoker,
    ) H3ChannelError!UnaryResult,

    pub fn intercept(
        self: H3UnaryInterceptor,
        info: H3UnaryCallInfo,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        next: H3Invoker,
    ) H3ChannelError!UnaryResult {
        return self.interceptFn(self.context, info, request_data, opts, response_buf, next);
    }
};

/// H3 unary interceptor chain.
pub const H3InterceptorChain = struct {
    interceptors: []const H3UnaryInterceptor,
    info: H3UnaryCallInfo,
    final_invoker: H3Invoker,

    pub fn init(
        interceptors: []const H3UnaryInterceptor,
        info: H3UnaryCallInfo,
        final_invoker: H3Invoker,
    ) H3InterceptorChain {
        return .{
            .interceptors = interceptors,
            .info = info,
            .final_invoker = final_invoker,
        };
    }

    pub fn proceed(
        self: *const H3InterceptorChain,
        index: usize,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult {
        if (index >= self.interceptors.len) {
            return self.final_invoker.invoke(request_data, opts, response_buf);
        }

        const interceptor = self.interceptors[index];
        const link = H3ChainLink{ .chain = self, .index = index + 1 };
        return interceptor.intercept(self.info, request_data, opts, response_buf, link.invoker());
    }
};

const H3ChainLink = struct {
    chain: *const H3InterceptorChain,
    index: usize,

    fn invoker(self: *const H3ChainLink) H3Invoker {
        return .{
            .context = @ptrCast(self),
            .invokeFn = chainInvokeFn,
        };
    }

    fn chainInvokeFn(
        ctx: *const anyopaque,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult {
        const self: *const H3ChainLink = @alignCast(@ptrCast(ctx));
        return self.chain.proceed(self.index, request_data, opts, response_buf);
    }
};

/// Stream interceptor types for H3.
pub const H3StreamType = enum {
    server_streaming,
    client_streaming,
    bidi_streaming,
};

pub const H3StreamCallInfo = struct {
    method: []const u8,
    authority: []const u8,
    stream_type: H3StreamType,
};

pub const H3StreamInvoker = struct {
    context: *const anyopaque,
    invokeFn: *const fn (
        ctx: *const anyopaque,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream,

    pub fn invoke(
        self: H3StreamInvoker,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        return self.invokeFn(self.context, request_data, opts);
    }
};

/// IMPORTANT: The `next` H3StreamInvoker must be called synchronously within
/// the intercept function. Storing it for deferred invocation causes use-after-free.
pub const H3StreamInterceptor = struct {
    context: *const anyopaque,
    interceptFn: *const fn (
        ctx: *const anyopaque,
        info: H3StreamCallInfo,
        request_data: ?[]const u8,
        opts: CallOptions,
        next: H3StreamInvoker,
    ) H3ChannelError!H3GrpcStream,

    pub fn intercept(
        self: H3StreamInterceptor,
        info: H3StreamCallInfo,
        request_data: ?[]const u8,
        opts: CallOptions,
        next: H3StreamInvoker,
    ) H3ChannelError!H3GrpcStream {
        return self.interceptFn(self.context, info, request_data, opts, next);
    }
};

pub const H3StreamInterceptorChain = struct {
    interceptors: []const H3StreamInterceptor,
    info: H3StreamCallInfo,
    final_invoker: H3StreamInvoker,

    pub fn init(
        interceptors: []const H3StreamInterceptor,
        info: H3StreamCallInfo,
        final_invoker: H3StreamInvoker,
    ) H3StreamInterceptorChain {
        return .{
            .interceptors = interceptors,
            .info = info,
            .final_invoker = final_invoker,
        };
    }

    pub fn proceed(
        self: *const H3StreamInterceptorChain,
        index: usize,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (index >= self.interceptors.len) {
            return self.final_invoker.invoke(request_data, opts);
        }

        const inter = self.interceptors[index];
        const link = H3StreamChainLink{ .chain = self, .index = index + 1 };
        return inter.intercept(self.info, request_data, opts, link.invoker());
    }
};

const H3StreamChainLink = struct {
    chain: *const H3StreamInterceptorChain,
    index: usize,

    fn invoker(self: *const H3StreamChainLink) H3StreamInvoker {
        return .{
            .context = @ptrCast(self),
            .invokeFn = chainInvokeFn,
        };
    }

    fn chainInvokeFn(
        ctx: *const anyopaque,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        const self: *const H3StreamChainLink = @alignCast(@ptrCast(ctx));
        return self.chain.proceed(self.index, request_data, opts);
    }
};

/// Create a stateless H3 unary interceptor from a bare function.
pub fn h3Stateless(
    comptime func: fn (
        H3UnaryCallInfo,
        []const u8,
        CallOptions,
        []u8,
        H3Invoker,
    ) H3ChannelError!UnaryResult,
) H3UnaryInterceptor {
    const S = struct {
        fn intercept(
            _: *const anyopaque,
            info: H3UnaryCallInfo,
            request_data: []const u8,
            opts: CallOptions,
            response_buf: []u8,
            next: H3Invoker,
        ) H3ChannelError!UnaryResult {
            return func(info, request_data, opts, response_buf, next);
        }
    };
    return .{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .interceptFn = S.intercept,
    };
}

/// Create a stateless H3 stream interceptor from a bare function.
pub fn h3StreamStateless(
    comptime func: fn (
        H3StreamCallInfo,
        ?[]const u8,
        CallOptions,
        H3StreamInvoker,
    ) H3ChannelError!H3GrpcStream,
) H3StreamInterceptor {
    const S = struct {
        fn intercept(
            _: *const anyopaque,
            info: H3StreamCallInfo,
            request_data: ?[]const u8,
            opts: CallOptions,
            next: H3StreamInvoker,
        ) H3ChannelError!H3GrpcStream {
            return func(info, request_data, opts, next);
        }
    };
    return .{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .interceptFn = S.intercept,
    };
}

pub const encodeGrpcTimeout = channel_mod.encodeGrpcTimeout;

pub const Metadata = struct {
    key: []const u8,
    value: []const u8,
};

pub const CallOptions = struct {
    timeout_ms: u64 = 0,
    retry_policy: ?RetryPolicy = null,
    metadata: []const Metadata = &.{},
    max_recv_message_size: u32 = 4 * 1024 * 1024,
    max_send_message_size: u32 = 4 * 1024 * 1024,
};

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    initial_backoff_ms: u64 = 100,
    max_backoff_ms: u64 = 10_000,
    backoff_multiplier: u32 = 2,
    retryable_status_codes: []const grpc_status.Code = &default_retryable_codes,

    const default_retryable_codes = [_]grpc_status.Code{ .unavailable, .resource_exhausted, .aborted };

    pub fn isRetryable(self: *const RetryPolicy, code: grpc_status.Code) bool {
        for (self.retryable_status_codes) |c| {
            if (c == code) return true;
        }
        return false;
    }

    pub fn computeBackoffMs(self: *const RetryPolicy, attempt: u32) u64 {
        var backoff = self.initial_backoff_ms;
        var i: u32 = 0;
        while (i < attempt) : (i += 1) {
            backoff = @min(backoff * self.backoff_multiplier, self.max_backoff_ms);
        }
        return backoff;
    }
};

pub const H3ChannelError = error{
    ConnectionFailed,
    EncodingError,
    ProtocolError,
    MessageTooLarge,
    BufferTooSmall,
    RpcFailed,
    ConnectionClosed,
    DeadlineExceeded,
    OutOfMemory,
    PoolExhausted,
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

/// gRPC Channel over HTTP/3 (QUIC transport).
/// Uses H3Pool for connection management instead of H2 ConnPool.
pub const H3Channel = struct {
    pool: H3Pool,
    authority: []const u8,
    allocator: std.mem.Allocator,
    channel_state: ChannelState,
    retry_policy: ?RetryPolicy,
    unary_interceptors: []const H3UnaryInterceptor,
    stream_interceptors: []const H3StreamInterceptor,

    pub fn init(
        allocator: std.mem.Allocator,
        remote: std.net.Address,
        authority: []const u8,
        pool_config: H3PoolConfig,
    ) H3Channel {
        return .{
            .pool = H3Pool.init(allocator, remote, authority, pool_config),
            .authority = authority,
            .allocator = allocator,
            .channel_state = .idle,
            .retry_policy = null,
            .unary_interceptors = &.{},
            .stream_interceptors = &.{},
        };
    }

    pub fn withRetryPolicy(self: *H3Channel, policy: RetryPolicy) void {
        self.retry_policy = policy;
    }

    pub fn withUnaryInterceptors(self: *H3Channel, interceptors: []const H3UnaryInterceptor) void {
        self.unary_interceptors = interceptors;
    }

    pub fn withStreamInterceptors(self: *H3Channel, interceptors: []const H3StreamInterceptor) void {
        self.stream_interceptors = interceptors;
    }

    /// Establish the first connection (QUIC handshake + H3 setup).
    pub fn connect(self: *H3Channel) H3ChannelError!void {
        if (self.channel_state == .shutdown) return H3ChannelError.ConnectionClosed;
        const conn = self.pool.acquire() catch return H3ChannelError.ConnectionFailed;
        self.pool.release(conn);
        self.channel_state = .connected;
    }

    pub fn getState(self: *const H3Channel) ChannelState {
        return self.channel_state;
    }

    /// Unary RPC: send one message, receive one message.
    /// Interceptors are invoked around the full unary call (including retries).
    pub fn unary(
        self: *H3Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult {
        if (self.unary_interceptors.len > 0) {
            const info = H3UnaryCallInfo{ .method = method, .authority = self.authority };
            const ctx = UnaryFinalCtx{ .channel = self, .method = method };
            const chain = H3InterceptorChain.init(self.unary_interceptors, info, ctx.invoker());
            return chain.proceed(0, request_data, opts, response_buf);
        }
        return self.unaryCore(method, request_data, opts, response_buf);
    }

    /// Core unary implementation (retry loop). Called by interceptor chain or directly.
    fn unaryCore(
        self: *H3Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) H3ChannelError!UnaryResult {
        const policy = opts.retry_policy orelse self.retry_policy;
        const max_attempts: u32 = if (policy) |rp| rp.max_attempts else 1;
        const deadline = computeDeadlineNs(opts.timeout_ms);

        var attempt: u32 = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            if (attempt > 0) {
                const rp = policy.?;
                const backoff = rp.computeBackoffMs(attempt - 1);
                if (!hasTimeForRetry(deadline, backoff)) return H3ChannelError.DeadlineExceeded;
                retryBackoff(backoff);
            }

            const result = self.unaryAttempt(method, request_data, opts, response_buf, deadline);
            const unary_result = result catch |e| return e;

            if (!unary_result.status.isOk()) {
                if (policy) |rp| {
                    if (rp.isRetryable(unary_result.status.code) and attempt + 1 < max_attempts) continue;
                }
            }

            return unary_result;
        }
        unreachable;
    }

    const UnaryFinalCtx = struct {
        channel: *H3Channel,
        method: []const u8,

        fn invoker(self: *const UnaryFinalCtx) H3Invoker {
            return .{
                .context = @ptrCast(self),
                .invokeFn = invokeFn,
            };
        }

        fn invokeFn(
            ctx: *const anyopaque,
            request_data: []const u8,
            opts: CallOptions,
            response_buf: []u8,
        ) H3ChannelError!UnaryResult {
            const self: *const UnaryFinalCtx = @alignCast(@ptrCast(ctx));
            return self.channel.unaryCore(self.method, request_data, opts, response_buf);
        }
    };

    fn unaryAttempt(
        self: *H3Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        deadline: ?i128,
    ) H3ChannelError!UnaryResult {
        if (self.channel_state == .shutdown) return H3ChannelError.ConnectionClosed;

        if (isDeadlineExceeded(deadline)) return H3ChannelError.DeadlineExceeded;

        const framed = self.frameMessage(request_data, opts.max_send_message_size) catch |e| return e;
        defer self.allocator.free(framed);

        var headers = buildGrpcHeaders(opts.metadata, opts.timeout_ms) orelse
            return H3ChannelError.EncodingError;

        if (isDeadlineExceeded(deadline)) return H3ChannelError.DeadlineExceeded;

        const resp = self.pool.request("POST", method, headers.slice(), framed) catch |e| {
            return self.mapPoolError(e);
        };

        self.channel_state = .connected;

        return self.parseGrpcResponse(&resp, response_buf, opts.max_recv_message_size);
    }

    fn parseGrpcResponse(self: *H3Channel, resp: *const H3Response, response_buf: []u8, max_recv_size: u32) H3ChannelError!UnaryResult {
        _ = self;
        const status_code = parseGrpcStatusFromHeaders(resp);

        if (!status_code.isOk()) {
            return UnaryResult{ .status = status_code, .data = &.{} };
        }

        const body = resp.bodySlice();
        if (body.len == 0) {
            return UnaryResult{ .status = status_code, .data = &.{} };
        }

        const decoded = message.decodeMessage(body, max_recv_size) catch |e| return switch (e) {
            error.MessageTooLarge => H3ChannelError.MessageTooLarge,
            error.IncompleteMessage => H3ChannelError.ProtocolError,
            error.BufferTooSmall => H3ChannelError.BufferTooSmall,
        };

        if (decoded.payload.len > response_buf.len) return H3ChannelError.BufferTooSmall;
        @memcpy(response_buf[0..decoded.payload.len], decoded.payload);

        return UnaryResult{ .status = status_code, .data = response_buf[0..decoded.payload.len] };
    }

    fn frameMessage(self: *H3Channel, payload: []const u8, max_size: u32) H3ChannelError![]u8 {
        if (payload.len > max_size) return H3ChannelError.MessageTooLarge;
        const total = message.FrameHeader.encoded_size + payload.len;
        const buf = self.allocator.alloc(u8, total) catch return H3ChannelError.OutOfMemory;
        _ = message.encodeMessage(buf, payload, false) catch {
            self.allocator.free(buf);
            return H3ChannelError.MessageTooLarge;
        };
        return buf;
    }

    fn mapPoolError(self: *H3Channel, e: H3PoolError) H3ChannelError {
        return switch (e) {
            H3PoolError.ConnectionFailed => blk: {
                self.channel_state = .disconnected;
                break :blk H3ChannelError.ConnectionFailed;
            },
            H3PoolError.PoolExhausted, H3PoolError.AllConnectionsBusy => H3ChannelError.PoolExhausted,
            H3PoolError.RequestFailed => H3ChannelError.RpcFailed,
        };
    }

    /// Server-streaming RPC: send one message, receive a stream of messages.
    pub fn serverStream(
        self: *H3Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (self.stream_interceptors.len > 0) {
            const info = H3StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .server_streaming,
            };
            const ctx = ServerStreamFinalCtx{ .channel = self, .method = method };
            const chain = H3StreamInterceptorChain.init(self.stream_interceptors, info, ctx.invoker());
            return chain.proceed(0, request_data, opts);
        }
        return self.serverStreamCore(method, request_data, opts);
    }

    fn serverStreamCore(
        self: *H3Channel,
        method: []const u8,
        request_data: []const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (self.channel_state == .shutdown) return H3ChannelError.ConnectionClosed;

        const framed = self.frameMessage(request_data, opts.max_send_message_size) catch |e| return e;
        defer self.allocator.free(framed);

        var headers = buildGrpcHeaders(opts.metadata, opts.timeout_ms) orelse
            return H3ChannelError.EncodingError;

        const conn = self.pool.acquire() catch |e| return self.mapPoolError(e);

        var handle = conn.client.requestStream("POST", method, headers.slice(), framed) catch |e| {
            self.pool.release(conn);
            return switch (e) {
                h3_client_mod.H3Error.NotConnected => H3ChannelError.ConnectionFailed,
                h3_client_mod.H3Error.SessionFull => H3ChannelError.PoolExhausted,
                h3_client_mod.H3Error.Timeout => H3ChannelError.RpcFailed,
                h3_client_mod.H3Error.ConnectionClosed => H3ChannelError.ConnectionClosed,
                else => H3ChannelError.RpcFailed,
            };
        };

        const status = handle.recvHeaders() catch |e| {
            handle.close();
            self.pool.release(conn);
            return switch (e) {
                h3_client_mod.H3Error.Timeout => H3ChannelError.RpcFailed,
                h3_client_mod.H3Error.InvalidResponse => H3ChannelError.ProtocolError,
                else => H3ChannelError.RpcFailed,
            };
        };

        self.channel_state = .connected;

        return H3GrpcStream{
            .handle = handle,
            .pooled_conn = conn,
            .pool = &self.pool,
            .allocator = self.allocator,
            .http_status = status,
            .final_status = null,
            .max_message_size = opts.max_recv_message_size,
        };
    }

    const ServerStreamFinalCtx = struct {
        channel: *H3Channel,
        method: []const u8,

        fn invoker(self: *const ServerStreamFinalCtx) H3StreamInvoker {
            return .{
                .context = @ptrCast(self),
                .invokeFn = invokeFn,
            };
        }

        fn invokeFn(
            ctx: *const anyopaque,
            request_data: ?[]const u8,
            opts: CallOptions,
        ) H3ChannelError!H3GrpcStream {
            const self: *const ServerStreamFinalCtx = @alignCast(@ptrCast(ctx));
            return self.channel.serverStreamCore(self.method, request_data orelse "", opts);
        }
    };

    /// Client-streaming RPC: send a stream of messages, receive one response.
    pub fn clientStream(
        self: *H3Channel,
        method: []const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (self.stream_interceptors.len > 0) {
            const info = H3StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .client_streaming,
            };
            const ctx = BidiFinalCtx{ .channel = self, .method = method };
            const chain = H3StreamInterceptorChain.init(self.stream_interceptors, info, ctx.invoker());
            return chain.proceed(0, null, opts);
        }
        return self.openBidiCore(method, opts);
    }

    /// Bidirectional-streaming RPC: send and receive streams of messages.
    pub fn bidiStream(
        self: *H3Channel,
        method: []const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (self.stream_interceptors.len > 0) {
            const info = H3StreamCallInfo{
                .method = method,
                .authority = self.authority,
                .stream_type = .bidi_streaming,
            };
            const ctx = BidiFinalCtx{ .channel = self, .method = method };
            const chain = H3StreamInterceptorChain.init(self.stream_interceptors, info, ctx.invoker());
            return chain.proceed(0, null, opts);
        }
        return self.openBidiCore(method, opts);
    }

    fn openBidiCore(
        self: *H3Channel,
        method: []const u8,
        opts: CallOptions,
    ) H3ChannelError!H3GrpcStream {
        if (self.channel_state == .shutdown) return H3ChannelError.ConnectionClosed;

        var headers = buildGrpcHeaders(opts.metadata, opts.timeout_ms) orelse
            return H3ChannelError.EncodingError;

        const conn = self.pool.acquire() catch |e| return self.mapPoolError(e);

        var handle = conn.client.requestStreamOpen("POST", method, headers.slice()) catch |e| {
            self.pool.release(conn);
            return switch (e) {
                h3_client_mod.H3Error.NotConnected => H3ChannelError.ConnectionFailed,
                h3_client_mod.H3Error.SessionFull => H3ChannelError.PoolExhausted,
                h3_client_mod.H3Error.Timeout => H3ChannelError.RpcFailed,
                h3_client_mod.H3Error.ConnectionClosed => H3ChannelError.ConnectionClosed,
                else => H3ChannelError.RpcFailed,
            };
        };

        _ = &handle;
        self.channel_state = .connected;

        return H3GrpcStream{
            .handle = handle,
            .pooled_conn = conn,
            .pool = &self.pool,
            .allocator = self.allocator,
            .http_status = 0,
            .final_status = null,
            .max_message_size = opts.max_recv_message_size,
        };
    }

    const BidiFinalCtx = struct {
        channel: *H3Channel,
        method: []const u8,

        fn invoker(self: *const BidiFinalCtx) H3StreamInvoker {
            return .{
                .context = @ptrCast(self),
                .invokeFn = invokeFn,
            };
        }

        fn invokeFn(
            ctx: *const anyopaque,
            _: ?[]const u8,
            opts: CallOptions,
        ) H3ChannelError!H3GrpcStream {
            const self: *const BidiFinalCtx = @alignCast(@ptrCast(ctx));
            return self.channel.openBidiCore(self.method, opts);
        }
    };

    pub fn close(self: *H3Channel) void {
        self.pool.deinit();
        self.channel_state = .shutdown;
    }
};

/// gRPC streaming handle over HTTP/3.
/// Supports server-streaming, client-streaming, and bidirectional RPCs.
pub const H3GrpcStream = struct {
    handle: h3_client_mod.H3StreamHandle,
    pooled_conn: *h3_pool_mod.H3PooledConn,
    pool: *H3Pool,
    allocator: std.mem.Allocator,
    http_status: u16,
    final_status: ?grpc_status.Status,
    max_message_size: u32,

    /// Send a gRPC message on the stream (client-streaming / bidi).
    /// Encodes payload with gRPC length-prefix framing.
    pub fn send(self: *H3GrpcStream, payload: []const u8) H3ChannelError!void {
        if (payload.len > self.max_message_size) return H3ChannelError.MessageTooLarge;
        const total = message.FrameHeader.encoded_size + payload.len;
        const framed = self.allocator.alloc(u8, total) catch return H3ChannelError.OutOfMemory;
        defer self.allocator.free(framed);
        _ = message.encodeMessage(framed, payload, false) catch
            return H3ChannelError.MessageTooLarge;
        self.handle.send(framed) catch |e| {
            return switch (e) {
                h3_client_mod.H3Error.ConnectionClosed => H3ChannelError.ConnectionClosed,
                h3_client_mod.H3Error.WriteFailed => H3ChannelError.RpcFailed,
                else => H3ChannelError.RpcFailed,
            };
        };
    }

    /// Close the send side of the stream. No more send() calls after this.
    pub fn closeSend(self: *H3GrpcStream) H3ChannelError!void {
        self.handle.closeSend() catch |e| {
            return switch (e) {
                h3_client_mod.H3Error.ConnectionClosed => H3ChannelError.ConnectionClosed,
                h3_client_mod.H3Error.WriteFailed => H3ChannelError.RpcFailed,
                else => H3ChannelError.RpcFailed,
            };
        };
    }

    /// Close the send side and receive a single response (client-streaming pattern).
    /// Returns the unary result after the server responds.
    pub fn closeAndRecv(self: *H3GrpcStream, buf: []u8) H3ChannelError!UnaryResult {
        try self.closeSend();

        // Wait for response headers
        self.http_status = self.handle.recvHeaders() catch |e| {
            return switch (e) {
                h3_client_mod.H3Error.Timeout => H3ChannelError.RpcFailed,
                h3_client_mod.H3Error.InvalidResponse => H3ChannelError.ProtocolError,
                else => H3ChannelError.RpcFailed,
            };
        };

        // Receive the single response message
        const data = try self.recv(buf);
        if (data == null) {
            self.extractTrailerStatus();
            const status = self.final_status orelse grpc_status.Status{ .code = .ok, .message = "" };
            return UnaryResult{ .status = status, .data = &.{} };
        }

        // Drain remaining (expect stream to end)
        var drain_buf: [64]u8 = undefined;
        _ = self.recv(&drain_buf) catch {};
        self.extractTrailerStatus();

        const status = self.final_status orelse grpc_status.Status{ .code = .ok, .message = "" };
        return UnaryResult{ .status = status, .data = data.? };
    }

    // H3StreamHandle.recv() yields one H3 DATA frame at a time, bounded by
    // the underlying StreamBuf (64KB). gRPC messages larger than this arrive
    // across multiple DATA frames and require reassembly at the framing layer.
    const MAX_H3_DATA_FRAME: usize = 65536;

    /// Receive the next gRPC message from the stream.
    /// Returns the decoded payload copied into buf, or null when the stream ends.
    /// Note: individual H3 DATA frames are limited to ~64KB by the transport layer.
    /// Messages larger than this must be split by the sender into multiple frames.
    pub fn recv(self: *H3GrpcStream, buf: []u8) H3ChannelError!?[]const u8 {
        const recv_size: usize = @min(@as(usize, self.max_message_size) + message.FrameHeader.encoded_size, MAX_H3_DATA_FRAME);
        const raw_buf = self.allocator.alloc(u8, recv_size) catch return H3ChannelError.OutOfMemory;
        defer self.allocator.free(raw_buf);

        const raw = self.handle.recv(raw_buf) catch |e| {
            return switch (e) {
                h3_client_mod.H3Error.Timeout => H3ChannelError.RpcFailed,
                h3_client_mod.H3Error.InvalidResponse => H3ChannelError.ProtocolError,
                else => H3ChannelError.RpcFailed,
            };
        };

        if (raw == null) {
            self.extractTrailerStatus();
            return null;
        }
        const data = raw.?;

        const decoded = message.decodeMessage(data, self.max_message_size) catch |e| return switch (e) {
            error.MessageTooLarge => H3ChannelError.MessageTooLarge,
            error.IncompleteMessage => H3ChannelError.ProtocolError,
            error.BufferTooSmall => H3ChannelError.BufferTooSmall,
        };

        if (decoded.payload.len > buf.len) return H3ChannelError.BufferTooSmall;
        @memcpy(buf[0..decoded.payload.len], decoded.payload);
        return buf[0..decoded.payload.len];
    }

    /// Get the final gRPC status after stream ends.
    /// Returns null if stream hasn't ended yet.
    pub fn getStatus(self: *const H3GrpcStream) ?grpc_status.Status {
        return self.final_status;
    }

    /// Close the stream and release pool resources.
    pub fn deinit(self: *H3GrpcStream) void {
        self.handle.close();
        self.pool.release(self.pooled_conn);
    }

    fn extractTrailerStatus(self: *H3GrpcStream) void {
        var code: grpc_status.Code = .ok;
        var msg: []const u8 = "";

        if (self.handle.trailerValue("grpc-status")) |val| {
            const parsed = std.fmt.parseInt(u8, val, 10) catch 2;
            code = @enumFromInt(parsed);
        }
        if (self.handle.trailerValue("grpc-message")) |val| {
            msg = val;
        }

        self.final_status = .{ .code = code, .message = msg };
    }
};

// ─── Helpers ───

const MAX_GRPC_HEADERS = 32;

const GrpcHeaders = struct {
    buf: [MAX_GRPC_HEADERS]qpack.HeaderField,
    count: usize,
    timeout_buf: [32]u8,

    fn slice(self: *GrpcHeaders) []const qpack.HeaderField {
        return self.buf[0..self.count];
    }
};

fn buildGrpcHeaders(metadata: []const Metadata, timeout_ms: u64) ?GrpcHeaders {
    var result = GrpcHeaders{ .buf = undefined, .count = 0, .timeout_buf = undefined };

    const required = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "application/grpc" },
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
        if (result.count >= MAX_GRPC_HEADERS) return null;
        result.buf[result.count] = .{ .name = m.key, .value = m.value };
        result.count += 1;
    }

    return result;
}

fn parseGrpcStatusFromHeaders(resp: *const H3Response) grpc_status.Status {
    var code: grpc_status.Code = .ok;
    var msg: []const u8 = "";

    for (resp.headers[0..resp.header_count]) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status")) {
            const parsed = std.fmt.parseInt(u8, h.value, 10) catch 2;
            code = @enumFromInt(parsed);
        } else if (std.mem.eql(u8, h.name, "grpc-message")) {
            msg = h.value;
        }
    }

    return .{ .code = code, .message = msg };
}

fn computeDeadlineNs(timeout_ms: u64) ?i128 {
    if (timeout_ms == 0) return null;
    const now = std.time.nanoTimestamp();
    return now + @as(i128, timeout_ms) * 1_000_000;
}

fn isDeadlineExceeded(deadline_ns: ?i128) bool {
    const dl = deadline_ns orelse return false;
    return std.time.nanoTimestamp() >= dl;
}

fn retryBackoff(backoff_ms: u64) void {
    const ns: u64 = backoff_ms * 1_000_000;
    std.Thread.sleep(ns);
}

fn hasTimeForRetry(deadline_ns: ?i128, backoff_ms: u64) bool {
    const dl = deadline_ns orelse return true;
    const now = std.time.nanoTimestamp();
    const needed: i128 = @as(i128, backoff_ms) * 1_000_000;
    return (dl - now) > needed;
}

// ─── Tests ───

test "H3Channel: init and state" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    defer ch.close();

    try std.testing.expectEqual(ChannelState.idle, ch.getState());
}

test "H3Channel: close sets shutdown state" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    ch.close();
    try std.testing.expectEqual(ChannelState.shutdown, ch.getState());
}

test "H3Channel: unary fails when shutdown" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    ch.channel_state = .shutdown;
    defer ch.close();

    var buf: [256]u8 = undefined;
    const result = ch.unary("/test.Service/Method", "data", .{}, &buf);
    try std.testing.expectError(H3ChannelError.ConnectionClosed, result);
}

test "H3Channel: frameMessage encoding" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    defer ch.close();

    const payload = "hello";
    const framed = try ch.frameMessage(payload, 1024);
    defer allocator.free(framed);

    try std.testing.expectEqual(@as(usize, 5 + payload.len), framed.len);
    try std.testing.expectEqual(@as(u8, 0), framed[0]); // not compressed
    const len = std.mem.readInt(u32, framed[1..5], .big);
    try std.testing.expectEqual(@as(u32, 5), len);
    try std.testing.expectEqualStrings("hello", framed[5..]);
}

test "H3Channel: frameMessage rejects oversized" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    defer ch.close();

    const result = ch.frameMessage("hello", 2);
    try std.testing.expectError(H3ChannelError.MessageTooLarge, result);
}

test "buildGrpcHeaders: basic headers" {
    const hdrs = buildGrpcHeaders(&.{}, 0) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), hdrs.count);
    try std.testing.expectEqualStrings("content-type", hdrs.buf[0].name);
    try std.testing.expectEqualStrings("application/grpc", hdrs.buf[0].value);
}

test "buildGrpcHeaders: with timeout" {
    const hdrs = buildGrpcHeaders(&.{}, 5000) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 3), hdrs.count);
    const timeout_hdr = hdrs.buf[2];
    try std.testing.expectEqualStrings("grpc-timeout", timeout_hdr.name);
    try std.testing.expectEqualStrings("5S", timeout_hdr.value);
}

test "buildGrpcHeaders: with metadata" {
    const md = [_]Metadata{
        .{ .key = "x-custom", .value = "val1" },
    };
    const hdrs = buildGrpcHeaders(&md, 0) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 3), hdrs.count);
    try std.testing.expectEqualStrings("x-custom", hdrs.buf[2].name);
}

test "parseGrpcStatusFromHeaders: OK status" {
    var resp = std.mem.zeroes(H3Response);
    resp.headers[0] = .{ .name = ":status", .value = "200" };
    resp.headers[1] = .{ .name = "grpc-status", .value = "0" };
    resp.header_count = 2;

    const status_result = parseGrpcStatusFromHeaders(&resp);
    try std.testing.expectEqual(grpc_status.Code.ok, status_result.code);
}

test "parseGrpcStatusFromHeaders: error status" {
    var resp = std.mem.zeroes(H3Response);
    resp.headers[0] = .{ .name = ":status", .value = "200" };
    resp.headers[1] = .{ .name = "grpc-status", .value = "14" };
    resp.headers[2] = .{ .name = "grpc-message", .value = "unavailable" };
    resp.header_count = 3;

    const status_result = parseGrpcStatusFromHeaders(&resp);
    try std.testing.expectEqual(grpc_status.Code.unavailable, status_result.code);
    try std.testing.expectEqualStrings("unavailable", status_result.message);
}

// ─── Interceptor tests ───

fn testPassthroughInterceptor(
    _: H3UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: H3Invoker,
) H3ChannelError!UnaryResult {
    return next.invoke(request_data, opts, response_buf);
}

fn testShortCircuitInterceptor(
    _: H3UnaryCallInfo,
    _: []const u8,
    _: CallOptions,
    _: []u8,
    _: H3Invoker,
) H3ChannelError!UnaryResult {
    return UnaryResult{
        .status = .{ .code = .permission_denied, .message = "blocked" },
        .data = &.{},
    };
}

fn testTimeoutInterceptor(
    _: H3UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: H3Invoker,
) H3ChannelError!UnaryResult {
    var modified = opts;
    if (modified.timeout_ms == 0) modified.timeout_ms = 10_000;
    return next.invoke(request_data, modified, response_buf);
}

fn testMethodGuardInterceptor(
    info: H3UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: H3Invoker,
) H3ChannelError!UnaryResult {
    if (!std.mem.startsWith(u8, info.method, "/")) {
        return H3ChannelError.ProtocolError;
    }
    return next.invoke(request_data, opts, response_buf);
}

test "H3InterceptorChain: no interceptors calls final" {
    const info = H3UnaryCallInfo{ .method = "/test/Method", .authority = "example.com" };

    const FinalCtx = struct {
        fn invokeFn(
            _: *const anyopaque,
            request_data: []const u8,
            _: CallOptions,
            response_buf: []u8,
        ) H3ChannelError!UnaryResult {
            @memcpy(response_buf[0..request_data.len], request_data);
            return UnaryResult{
                .status = .{ .code = .ok, .message = "" },
                .data = response_buf[0..request_data.len],
            };
        }
    };

    const final_invoker = H3Invoker{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = FinalCtx.invokeFn,
    };

    const chain = H3InterceptorChain.init(&.{}, info, final_invoker);
    var buf: [256]u8 = undefined;
    const result = try chain.proceed(0, "hello", .{}, &buf);
    try std.testing.expectEqualStrings("hello", result.data);
    try std.testing.expect(result.status.isOk());
}

test "H3InterceptorChain: passthrough interceptor" {
    const info = H3UnaryCallInfo{ .method = "/test/Method", .authority = "example.com" };
    const interceptors = [_]H3UnaryInterceptor{h3Stateless(testPassthroughInterceptor)};

    const FinalCtx = struct {
        fn invokeFn(
            _: *const anyopaque,
            request_data: []const u8,
            _: CallOptions,
            response_buf: []u8,
        ) H3ChannelError!UnaryResult {
            @memcpy(response_buf[0..request_data.len], request_data);
            return UnaryResult{
                .status = .{ .code = .ok, .message = "" },
                .data = response_buf[0..request_data.len],
            };
        }
    };

    const final_invoker = H3Invoker{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = FinalCtx.invokeFn,
    };

    const chain = H3InterceptorChain.init(&interceptors, info, final_invoker);
    var buf: [256]u8 = undefined;
    const result = try chain.proceed(0, "data", .{}, &buf);
    try std.testing.expectEqualStrings("data", result.data);
}

test "H3InterceptorChain: short-circuit interceptor" {
    const info = H3UnaryCallInfo{ .method = "/test/Method", .authority = "example.com" };
    const interceptors = [_]H3UnaryInterceptor{h3Stateless(testShortCircuitInterceptor)};

    const FinalCtx = struct {
        fn invokeFn(
            _: *const anyopaque,
            _: []const u8,
            _: CallOptions,
            _: []u8,
        ) H3ChannelError!UnaryResult {
            return UnaryResult{
                .status = .{ .code = .ok, .message = "" },
                .data = &.{},
            };
        }
    };

    const final_invoker = H3Invoker{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = FinalCtx.invokeFn,
    };

    const chain = H3InterceptorChain.init(&interceptors, info, final_invoker);
    var buf: [256]u8 = undefined;
    const result = try chain.proceed(0, "x", .{}, &buf);
    try std.testing.expectEqual(grpc_status.Code.permission_denied, result.status.code);
    try std.testing.expectEqualStrings("blocked", result.status.message);
}

test "H3InterceptorChain: multiple interceptors in order" {
    const info = H3UnaryCallInfo{ .method = "/test/Method", .authority = "example.com" };
    const interceptors = [_]H3UnaryInterceptor{
        h3Stateless(testPassthroughInterceptor),
        h3Stateless(testTimeoutInterceptor),
        h3Stateless(testPassthroughInterceptor),
    };

    const FinalCtx = struct {
        fn invokeFn(
            _: *const anyopaque,
            request_data: []const u8,
            _: CallOptions,
            response_buf: []u8,
        ) H3ChannelError!UnaryResult {
            @memcpy(response_buf[0..request_data.len], request_data);
            return UnaryResult{
                .status = .{ .code = .ok, .message = "" },
                .data = response_buf[0..request_data.len],
            };
        }
    };

    const final_invoker = H3Invoker{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = FinalCtx.invokeFn,
    };

    const chain = H3InterceptorChain.init(&interceptors, info, final_invoker);
    var buf: [256]u8 = undefined;
    const result = try chain.proceed(0, "chained", .{}, &buf);
    try std.testing.expectEqualStrings("chained", result.data);
}

test "H3InterceptorChain: method guard rejects bad method" {
    const info = H3UnaryCallInfo{ .method = "no-slash", .authority = "example.com" };
    const interceptors = [_]H3UnaryInterceptor{h3Stateless(testMethodGuardInterceptor)};

    const FinalCtx = struct {
        fn invokeFn(
            _: *const anyopaque,
            _: []const u8,
            _: CallOptions,
            _: []u8,
        ) H3ChannelError!UnaryResult {
            return UnaryResult{
                .status = .{ .code = .ok, .message = "" },
                .data = &.{},
            };
        }
    };

    const final_invoker = H3Invoker{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = FinalCtx.invokeFn,
    };

    const chain = H3InterceptorChain.init(&interceptors, info, final_invoker);
    var buf: [256]u8 = undefined;
    try std.testing.expectError(H3ChannelError.ProtocolError, chain.proceed(0, "x", .{}, &buf));
}

test "H3Channel: unary with interceptor short-circuits" {
    const allocator = std.testing.allocator;
    var ch = H3Channel.init(
        allocator,
        std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
        "example.com",
        .{},
    );
    defer ch.close();

    const interceptors = [_]H3UnaryInterceptor{h3Stateless(testShortCircuitInterceptor)};
    ch.withUnaryInterceptors(&interceptors);

    ch.channel_state = .connected;
    var buf: [256]u8 = undefined;
    const result = try ch.unary("/test.Service/Method", "data", .{}, &buf);
    try std.testing.expectEqual(grpc_status.Code.permission_denied, result.status.code);
}
