// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const channel_mod = @import("channel.zig");
const grpc_status = @import("status.zig");

pub const ChannelError = channel_mod.ChannelError;
pub const UnaryResult = channel_mod.UnaryResult;
pub const CallOptions = channel_mod.CallOptions;
pub const Metadata = channel_mod.Metadata;

/// Context passed to unary interceptors.
pub const UnaryCallInfo = struct {
    method: []const u8,
    authority: []const u8,
};

/// Type-erased invoker for the next step in the interceptor chain.
/// Interceptors call `invoke()` to proceed to the next interceptor or final RPC.
pub const Invoker = struct {
    context: *const anyopaque,
    invokeFn: *const fn (
        ctx: *const anyopaque,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult,

    pub fn invoke(
        self: Invoker,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult {
        return self.invokeFn(self.context, request_data, opts, response_buf);
    }
};

/// A unary interceptor. Receives call info, request data, options, and an invoker
/// to proceed to the next interceptor or the actual RPC.
///
/// IMPORTANT: The `next` Invoker must be called synchronously within the intercept
/// function. Storing it for deferred invocation causes use-after-free (the Invoker
/// references stack-local chain state that is invalidated when intercept returns).
pub const UnaryInterceptor = struct {
    context: *const anyopaque,
    interceptFn: *const fn (
        ctx: *const anyopaque,
        info: UnaryCallInfo,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        next: Invoker,
    ) ChannelError!UnaryResult,

    pub fn intercept(
        self: UnaryInterceptor,
        info: UnaryCallInfo,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
        next: Invoker,
    ) ChannelError!UnaryResult {
        return self.interceptFn(self.context, info, request_data, opts, response_buf, next);
    }
};

/// Interceptor chain for unary RPCs. Walks through interceptors in order,
/// then invokes the final handler (the actual channel.unaryAttempt).
pub const InterceptorChain = struct {
    interceptors: []const UnaryInterceptor,
    info: UnaryCallInfo,
    final_invoker: Invoker,

    pub fn init(
        interceptors: []const UnaryInterceptor,
        info: UnaryCallInfo,
        final_invoker: Invoker,
    ) InterceptorChain {
        return .{
            .interceptors = interceptors,
            .info = info,
            .final_invoker = final_invoker,
        };
    }

    /// Execute the chain starting at the given index.
    pub fn proceed(
        self: *const InterceptorChain,
        index: usize,
        request_data: []const u8,
        opts: CallOptions,
        response_buf: []u8,
    ) ChannelError!UnaryResult {
        if (index >= self.interceptors.len) {
            return self.final_invoker.invoke(request_data, opts, response_buf);
        }

        const interceptor = self.interceptors[index];
        const next_chain = ChainLink{
            .chain = self,
            .index = index + 1,
        };

        return interceptor.intercept(
            self.info,
            request_data,
            opts,
            response_buf,
            next_chain.invoker(),
        );
    }
};

/// Internal link wrapping chain + index into an Invoker.
const ChainLink = struct {
    chain: *const InterceptorChain,
    index: usize,

    fn invoker(self: *const ChainLink) Invoker {
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
    ) ChannelError!UnaryResult {
        const self: *const ChainLink = @alignCast(@ptrCast(ctx));
        return self.chain.proceed(self.index, request_data, opts, response_buf);
    }
};

// ─── Helper: create UnaryInterceptor from a function pointer ───

/// Create a stateless interceptor from a bare function.
pub fn stateless(
    comptime func: fn (
        UnaryCallInfo,
        []const u8,
        CallOptions,
        []u8,
        Invoker,
    ) ChannelError!UnaryResult,
) UnaryInterceptor {
    const S = struct {
        fn intercept(
            _: *const anyopaque,
            info: UnaryCallInfo,
            request_data: []const u8,
            opts: CallOptions,
            response_buf: []u8,
            next: Invoker,
        ) ChannelError!UnaryResult {
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

// ─── Tests ───

test "interceptor chain: no interceptors calls final directly" {
    var buf: [256]u8 = undefined;
    const info = UnaryCallInfo{ .method = "/test/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&.{}, info, final);
    const result = try chain.proceed(0, "test_data", .{}, &buf);
    try std.testing.expectEqualStrings("test_data", result.data);
    try std.testing.expect(result.status.isOk());
}

test "interceptor chain: single interceptor passes through" {
    var buf: [256]u8 = undefined;
    const interceptors = [_]UnaryInterceptor{stateless(passthroughInterceptor)};
    const info = UnaryCallInfo{ .method = "/test/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&interceptors, info, final);
    const result = try chain.proceed(0, "hello", .{}, &buf);
    try std.testing.expectEqualStrings("hello", result.data);
}

test "interceptor chain: interceptor can modify options" {
    var buf: [256]u8 = undefined;
    const interceptors = [_]UnaryInterceptor{stateless(timeoutInterceptor)};
    const info = UnaryCallInfo{ .method = "/test/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&interceptors, info, final);
    const result = try chain.proceed(0, "data", .{ .timeout_ms = 0 }, &buf);
    try std.testing.expectEqualStrings("data", result.data);
}

test "interceptor chain: interceptor can short-circuit" {
    var buf: [256]u8 = undefined;
    const interceptors = [_]UnaryInterceptor{stateless(shortCircuitInterceptor)};
    const info = UnaryCallInfo{ .method = "/test/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&interceptors, info, final);
    const result = try chain.proceed(0, "anything", .{}, &buf);
    try std.testing.expectEqualStrings("", result.data);
    try std.testing.expectEqual(grpc_status.Code.permission_denied, result.status.code);
}

test "interceptor chain: multiple interceptors execute in order" {
    var buf: [256]u8 = undefined;
    const interceptors = [_]UnaryInterceptor{
        stateless(passthroughInterceptor),
        stateless(passthroughInterceptor),
        stateless(passthroughInterceptor),
    };
    const info = UnaryCallInfo{ .method = "/test/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&interceptors, info, final);
    const result = try chain.proceed(0, "chained", .{}, &buf);
    try std.testing.expectEqualStrings("chained", result.data);
}

test "interceptor chain: interceptor can observe method name" {
    var buf: [256]u8 = undefined;
    const interceptors = [_]UnaryInterceptor{stateless(methodCheckInterceptor)};
    const info = UnaryCallInfo{ .method = "/svc/Method", .authority = "localhost" };
    const final = makeFinalInvoker();
    const chain = InterceptorChain.init(&interceptors, info, final);
    const result = try chain.proceed(0, "x", .{}, &buf);
    try std.testing.expectEqualStrings("x", result.data);
}

// ─── Test helpers ───

fn makeFinalInvoker() Invoker {
    return .{
        .context = @ptrCast(&struct {
            const x: u8 = 0;
        }.x),
        .invokeFn = echoInvokeFn,
    };
}

fn echoInvokeFn(
    _: *const anyopaque,
    request_data: []const u8,
    _: CallOptions,
    response_buf: []u8,
) ChannelError!UnaryResult {
    @memcpy(response_buf[0..request_data.len], request_data);
    return UnaryResult{
        .status = .{ .code = .ok, .message = "" },
        .data = response_buf[0..request_data.len],
    };
}

fn passthroughInterceptor(
    info: UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: Invoker,
) ChannelError!UnaryResult {
    _ = info;
    return next.invoke(request_data, opts, response_buf);
}

fn timeoutInterceptor(
    info: UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: Invoker,
) ChannelError!UnaryResult {
    _ = info;
    var modified = opts;
    if (modified.timeout_ms == 0) modified.timeout_ms = 5000;
    return next.invoke(request_data, modified, response_buf);
}

fn shortCircuitInterceptor(
    _: UnaryCallInfo,
    _: []const u8,
    _: CallOptions,
    _: []u8,
    _: Invoker,
) ChannelError!UnaryResult {
    return UnaryResult{
        .status = .{ .code = .permission_denied, .message = "denied" },
        .data = &.{},
    };
}

fn methodCheckInterceptor(
    info: UnaryCallInfo,
    request_data: []const u8,
    opts: CallOptions,
    response_buf: []u8,
    next: Invoker,
) ChannelError!UnaryResult {
    if (!std.mem.startsWith(u8, info.method, "/")) {
        return UnaryResult{
            .status = .{ .code = .invalid_argument, .message = "bad method" },
            .data = &.{},
        };
    }
    return next.invoke(request_data, opts, response_buf);
}
