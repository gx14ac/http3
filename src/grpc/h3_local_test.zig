const std = @import("std");
const h3_channel_mod = @import("h3_channel.zig");
const grpc_server_mod = @import("server.zig");
const grpc_status = @import("status.zig");

const H3Channel = h3_channel_mod.H3Channel;
const GrpcServer = grpc_server_mod.GrpcServer;
const GrpcRequest = grpc_server_mod.GrpcRequest;
const GrpcResponse = grpc_server_mod.GrpcResponse;
const ServiceHandler = grpc_server_mod.ServiceHandler;

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

fn serverLoop(server: *GrpcServer) void {
    server.setTimeout(500);
    var iterations: usize = 0;
    while (iterations < 100) : (iterations += 1) {
        const event = server.poll();
        switch (event) {
            .request => |req| {
                server.handleAndRespond(&req) catch {};
            },
            .none, .timeout, .connected, .data => {},
        }
    }
}

test "gRPC local: H3Channel unary echo via GrpcServer" {
    const allocator = std.testing.allocator;

    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = GrpcServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    _ = server.addRoute("/test.Echo/", EchoHandler.serviceHandler());
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var ch = H3Channel.init(allocator, server_addr, "localhost", .{});
    defer ch.close();

    ch.connect() catch {
        server_thread.join();
        return;
    };

    var response_buf: [4096]u8 = undefined;
    const result = ch.unary(
        "/test.Echo/Echo",
        "hello from H3Channel",
        .{ .timeout_ms = 5000 },
        &response_buf,
    ) catch {
        server_thread.join();
        return;
    };

    try std.testing.expectEqual(grpc_status.Code.ok, result.status.code);
    try std.testing.expectEqualStrings("hello from H3Channel", result.data);

    server_thread.join();
}

test "gRPC local: H3Channel unimplemented method" {
    const allocator = std.testing.allocator;

    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = GrpcServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    // No routes registered — all methods should be UNIMPLEMENTED
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var ch = H3Channel.init(allocator, server_addr, "localhost", .{});
    defer ch.close();

    ch.connect() catch {
        server_thread.join();
        return;
    };

    var response_buf: [4096]u8 = undefined;
    const result = ch.unary(
        "/unknown.Service/Method",
        "",
        .{ .timeout_ms = 5000 },
        &response_buf,
    ) catch {
        server_thread.join();
        return;
    };

    try std.testing.expectEqual(grpc_status.Code.unimplemented, result.status.code);

    server_thread.join();
}

test "gRPC local: H3Channel multiple sequential RPCs" {
    const allocator = std.testing.allocator;

    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server = GrpcServer.init(bind_addr, .{}) catch return;
    defer server.deinit();
    _ = server.addRoute("/test.Echo/", EchoHandler.serviceHandler());
    const port = server.getPort();

    const server_thread = std.Thread.spawn(.{}, serverLoop, .{&server}) catch return;

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var ch = H3Channel.init(allocator, server_addr, "localhost", .{});
    defer ch.close();

    ch.connect() catch {
        server_thread.join();
        return;
    };

    const messages = [_][]const u8{ "first", "second", "third" };
    for (messages) |msg| {
        var response_buf: [4096]u8 = undefined;
        const result = ch.unary("/test.Echo/Echo", msg, .{ .timeout_ms = 5000 }, &response_buf) catch {
            server_thread.join();
            return;
        };
        try std.testing.expectEqual(grpc_status.Code.ok, result.status.code);
        try std.testing.expectEqualStrings(msg, result.data);
    }

    server_thread.join();
}
