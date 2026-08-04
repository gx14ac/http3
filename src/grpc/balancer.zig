const std = @import("std");
const resolver_mod = @import("resolver.zig");
const Endpoint = resolver_mod.Endpoint;

pub const PickError = error{
    NoEndpoints,
};

/// Type-erased load balancer interface.
pub const Balancer = struct {
    context: *anyopaque,
    pickFn: *const fn (ctx: *anyopaque, endpoints: []const Endpoint) PickError!Endpoint,
    /// Notify the balancer of a successful RPC to the given endpoint.
    reportSuccessFn: *const fn (ctx: *anyopaque, endpoint: Endpoint) void,
    /// Notify the balancer of a failed RPC to the given endpoint.
    reportFailureFn: *const fn (ctx: *anyopaque, endpoint: Endpoint) void,

    pub fn pick(self: Balancer, endpoints: []const Endpoint) PickError!Endpoint {
        return self.pickFn(self.context, endpoints);
    }

    pub fn reportSuccess(self: Balancer, endpoint: Endpoint) void {
        self.reportSuccessFn(self.context, endpoint);
    }

    pub fn reportFailure(self: Balancer, endpoint: Endpoint) void {
        self.reportFailureFn(self.context, endpoint);
    }
};

/// Pick-first policy: always selects the first endpoint in the list.
pub const PickFirst = struct {
    pub fn init() PickFirst {
        return .{};
    }

    pub fn balancer(self: *PickFirst) Balancer {
        return .{
            .context = @ptrCast(self),
            .pickFn = pickFn,
            .reportSuccessFn = noopReport,
            .reportFailureFn = noopReport,
        };
    }

    fn pickFn(_: *anyopaque, endpoints: []const Endpoint) PickError!Endpoint {
        if (endpoints.len == 0) return PickError.NoEndpoints;
        return endpoints[0];
    }

    fn noopReport(_: *anyopaque, _: Endpoint) void {}
};

/// Round-robin policy: cycles through endpoints sequentially.
pub const RoundRobin = struct {
    index: u32,

    pub fn init() RoundRobin {
        return .{ .index = 0 };
    }

    pub fn balancer(self: *RoundRobin) Balancer {
        return .{
            .context = @ptrCast(self),
            .pickFn = pickFn,
            .reportSuccessFn = noopReport,
            .reportFailureFn = noopReport,
        };
    }

    fn pickFn(ctx: *anyopaque, endpoints: []const Endpoint) PickError!Endpoint {
        if (endpoints.len == 0) return PickError.NoEndpoints;
        const self: *RoundRobin = @alignCast(@ptrCast(ctx));
        const idx = self.index % @as(u32, @intCast(endpoints.len));
        self.index +%= 1;
        return endpoints[idx];
    }

    fn noopReport(_: *anyopaque, _: Endpoint) void {}
};

// ─── Tests ───

test "PickFirst: selects first endpoint" {
    var pf = PickFirst.init();
    const b = pf.balancer();

    const endpoints = [_]Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8080) },
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 8080) },
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 3 }, 8080) },
    };

    const picked = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 8080), picked.address.getPort());
    // Always picks first
    const picked2 = try b.pick(&endpoints);
    try std.testing.expectEqual(picked.address.in.sa.addr, picked2.address.in.sa.addr);
}

test "PickFirst: empty list → NoEndpoints" {
    var pf = PickFirst.init();
    const b = pf.balancer();
    try std.testing.expectError(PickError.NoEndpoints, b.pick(&.{}));
}

test "RoundRobin: cycles through endpoints" {
    var rr = RoundRobin.init();
    const b = rr.balancer();

    const endpoints = [_]Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 8001) },
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 8002) },
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 3 }, 8003) },
    };

    const p1 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 8001), p1.address.getPort());

    const p2 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 8002), p2.address.getPort());

    const p3 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 8003), p3.address.getPort());

    // Wraps around
    const p4 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 8001), p4.address.getPort());
}

test "RoundRobin: empty list → NoEndpoints" {
    var rr = RoundRobin.init();
    const b = rr.balancer();
    try std.testing.expectError(PickError.NoEndpoints, b.pick(&.{}));
}

test "RoundRobin: single endpoint always returns same" {
    var rr = RoundRobin.init();
    const b = rr.balancer();

    const endpoints = [_]Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 9090) },
    };

    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const p = try b.pick(&endpoints);
        try std.testing.expectEqual(@as(u16, 9090), p.address.getPort());
    }
}

test "RoundRobin: wraps on u32 overflow" {
    var rr = RoundRobin.init();
    rr.index = 0xFFFFFFFF;
    const b = rr.balancer();

    const endpoints = [_]Endpoint{
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 80) },
        .{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 81) },
    };

    // index=0xFFFFFFFF % 2 = 1 → second endpoint
    const p1 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 81), p1.address.getPort());

    // index wraps to 0, 0 % 2 = 0 → first endpoint
    const p2 = try b.pick(&endpoints);
    try std.testing.expectEqual(@as(u16, 80), p2.address.getPort());
}

test "Balancer: report functions don't crash" {
    var rr = RoundRobin.init();
    const b = rr.balancer();
    const ep = Endpoint{ .address = std.net.Address.initIp4(.{ 10, 0, 0, 1 }, 80) };
    b.reportSuccess(ep);
    b.reportFailure(ep);
}
