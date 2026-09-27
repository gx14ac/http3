// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const channel_mod = @import("channel.zig");
const grpc_status = @import("status.zig");

pub const ChannelError = channel_mod.ChannelError;
pub const CallOptions = channel_mod.CallOptions;
pub const StreamHandle = channel_mod.StreamHandle;

/// Context passed to stream interceptors.
pub const StreamCallInfo = struct {
    method: []const u8,
    authority: []const u8,
    stream_type: StreamType,
};

pub const StreamType = enum {
    server_streaming,
    client_streaming,
    bidi_streaming,
};

/// Type-erased invoker for the next step in the stream interceptor chain.
/// Creates a StreamHandle or returns an error.
pub const StreamInvoker = struct {
    context: *const anyopaque,
    invokeFn: *const fn (
        ctx: *const anyopaque,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle,

    pub fn invoke(
        self: StreamInvoker,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        return self.invokeFn(self.context, request_data, opts);
    }
};

/// A stream interceptor. Intercepts stream creation and can modify options,
/// short-circuit with an error, or pass through to the next interceptor.
///
/// IMPORTANT: The `next` StreamInvoker must be called synchronously within
/// the intercept function. Storing it for deferred invocation causes
/// use-after-free (same constraint as UnaryInterceptor).
///
/// NOTE: For server-streaming RPCs, `request_data` is the initial payload and
/// must not be set to null by the interceptor — doing so will cause a ProtocolError.
pub const StreamInterceptor = struct {
    context: *const anyopaque,
    interceptFn: *const fn (
        ctx: *const anyopaque,
        info: StreamCallInfo,
        request_data: ?[]const u8,
        opts: CallOptions,
        next: StreamInvoker,
    ) ChannelError!StreamHandle,

    pub fn intercept(
        self: StreamInterceptor,
        info: StreamCallInfo,
        request_data: ?[]const u8,
        opts: CallOptions,
        next: StreamInvoker,
    ) ChannelError!StreamHandle {
        return self.interceptFn(self.context, info, request_data, opts, next);
    }
};

/// Interceptor chain for streaming RPCs. Walks through interceptors in order,
/// then invokes the final handler (the actual stream creation).
pub const StreamInterceptorChain = struct {
    interceptors: []const StreamInterceptor,
    info: StreamCallInfo,
    final_invoker: StreamInvoker,

    pub fn init(
        interceptors: []const StreamInterceptor,
        info: StreamCallInfo,
        final_invoker: StreamInvoker,
    ) StreamInterceptorChain {
        return .{
            .interceptors = interceptors,
            .info = info,
            .final_invoker = final_invoker,
        };
    }

    pub fn proceed(
        self: *const StreamInterceptorChain,
        index: usize,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        if (index >= self.interceptors.len) {
            return self.final_invoker.invoke(request_data, opts);
        }

        const inter = self.interceptors[index];
        const link = ChainLink{
            .chain = self,
            .index = index + 1,
        };

        return inter.intercept(self.info, request_data, opts, link.invoker());
    }
};

const ChainLink = struct {
    chain: *const StreamInterceptorChain,
    index: usize,

    fn invoker(self: *const ChainLink) StreamInvoker {
        return .{
            .context = @ptrCast(self),
            .invokeFn = chainInvokeFn,
        };
    }

    fn chainInvokeFn(
        ctx: *const anyopaque,
        request_data: ?[]const u8,
        opts: CallOptions,
    ) ChannelError!StreamHandle {
        const self: *const ChainLink = @alignCast(@ptrCast(ctx));
        return self.chain.proceed(self.index, request_data, opts);
    }
};

/// Create a stateless stream interceptor from a bare function.
pub fn stateless(
    comptime func: fn (
        StreamCallInfo,
        ?[]const u8,
        CallOptions,
        StreamInvoker,
    ) ChannelError!StreamHandle,
) StreamInterceptor {
    const S = struct {
        fn intercept(
            _: *const anyopaque,
            info: StreamCallInfo,
            request_data: ?[]const u8,
            opts: CallOptions,
            next: StreamInvoker,
        ) ChannelError!StreamHandle {
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

// ─── Tests ───

fn makeFakeStreamHandle() StreamHandle {
    return .{
        .client = undefined,
        .handle = .{ .stream_id = 1 },
        .max_recv_message_size = 4 * 1024 * 1024,
        .max_send_message_size = 4 * 1024 * 1024,
        .allocator = std.testing.allocator,
        .recv_buf = .{},
        .recv_buf_pos = 0,
        .final_status = null,
        .send_closed = false,
        .recv_closed = false,
        .deadline_ns = null,
    };
}

fn makeFinalStreamInvoker() StreamInvoker {
    return .{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = echoStreamInvokeFn,
    };
}

fn echoStreamInvokeFn(
    _: *const anyopaque,
    _: ?[]const u8,
    _: CallOptions,
) ChannelError!StreamHandle {
    return makeFakeStreamHandle();
}

fn passthroughStreamInterceptor(
    _: StreamCallInfo,
    request_data: ?[]const u8,
    opts: CallOptions,
    next: StreamInvoker,
) ChannelError!StreamHandle {
    return next.invoke(request_data, opts);
}

fn timeoutStreamInterceptor(
    _: StreamCallInfo,
    request_data: ?[]const u8,
    opts: CallOptions,
    next: StreamInvoker,
) ChannelError!StreamHandle {
    var modified = opts;
    if (modified.timeout_ms == 0) modified.timeout_ms = 30_000;
    return next.invoke(request_data, modified);
}

fn shortCircuitStreamInterceptor(
    _: StreamCallInfo,
    _: ?[]const u8,
    _: CallOptions,
    _: StreamInvoker,
) ChannelError!StreamHandle {
    return ChannelError.ConnectionClosed;
}

fn methodGuardStreamInterceptor(
    info: StreamCallInfo,
    request_data: ?[]const u8,
    opts: CallOptions,
    next: StreamInvoker,
) ChannelError!StreamHandle {
    if (!std.mem.startsWith(u8, info.method, "/")) {
        return ChannelError.ProtocolError;
    }
    return next.invoke(request_data, opts);
}

test "stream chain: no interceptors calls final directly" {
    const info = StreamCallInfo{ .method = "/test/Stream", .authority = "localhost", .stream_type = .server_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&.{}, info, final);
    var handle = try chain.proceed(0, "data", .{});
    defer handle.deinit();
    try std.testing.expectEqual(@as(u31, 1), handle.handle.stream_id);
}

test "stream chain: single passthrough interceptor" {
    const interceptors = [_]StreamInterceptor{stateless(passthroughStreamInterceptor)};
    const info = StreamCallInfo{ .method = "/test/Stream", .authority = "localhost", .stream_type = .server_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&interceptors, info, final);
    var handle = try chain.proceed(0, "data", .{});
    defer handle.deinit();
    try std.testing.expectEqual(@as(u31, 1), handle.handle.stream_id);
}

test "stream chain: interceptor can short-circuit" {
    const interceptors = [_]StreamInterceptor{stateless(shortCircuitStreamInterceptor)};
    const info = StreamCallInfo{ .method = "/test/Stream", .authority = "localhost", .stream_type = .bidi_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&interceptors, info, final);
    try std.testing.expectError(ChannelError.ConnectionClosed, chain.proceed(0, null, .{}));
}

test "stream chain: multiple interceptors execute in order" {
    const interceptors = [_]StreamInterceptor{
        stateless(passthroughStreamInterceptor),
        stateless(timeoutStreamInterceptor),
        stateless(passthroughStreamInterceptor),
    };
    const info = StreamCallInfo{ .method = "/test/Stream", .authority = "localhost", .stream_type = .client_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&interceptors, info, final);
    var handle = try chain.proceed(0, null, .{});
    defer handle.deinit();
    try std.testing.expectEqual(@as(u31, 1), handle.handle.stream_id);
}

test "stream chain: method guard rejects bad method" {
    const interceptors = [_]StreamInterceptor{stateless(methodGuardStreamInterceptor)};
    const info = StreamCallInfo{ .method = "no-slash", .authority = "localhost", .stream_type = .server_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&interceptors, info, final);
    try std.testing.expectError(ChannelError.ProtocolError, chain.proceed(0, "x", .{}));
}

test "stream chain: method guard passes valid method" {
    const interceptors = [_]StreamInterceptor{stateless(methodGuardStreamInterceptor)};
    const info = StreamCallInfo{ .method = "/svc/Stream", .authority = "localhost", .stream_type = .server_streaming };
    const final = makeFinalStreamInvoker();
    const chain = StreamInterceptorChain.init(&interceptors, info, final);
    var handle = try chain.proceed(0, "x", .{});
    defer handle.deinit();
    try std.testing.expectEqual(@as(u31, 1), handle.handle.stream_id);
}
