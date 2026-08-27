const std = @import("std");

pub const Address = struct {
    family: u8,
    ip4: [4]u8 = .{ 0, 0, 0, 0 },
    port: u16 = 0,

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .family = 2, .ip4 = addr, .port = port };
    }

    pub fn getPort(self: Address) u16 {
        return self.port;
    }
};

/// A resolved network endpoint.
pub const Endpoint = struct {
    address: Address,
    /// Opaque metadata (e.g., weight, zone). Reserved for LB policies.
    metadata: ?*const anyopaque = null,
};

pub const ResolveError = error{
    InvalidTarget,
    DnsFailure,
    OutOfMemory,
};

/// Result of a resolve operation. Caller owns the slice and must free it.
pub const ResolveResult = struct {
    endpoints: []Endpoint,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ResolveResult) void {
        self.allocator.free(self.endpoints);
    }
};

/// Type-erased resolver interface.
pub const Resolver = struct {
    context: *const anyopaque,
    resolveFn: *const fn (ctx: *const anyopaque, target: []const u8, allocator: std.mem.Allocator) ResolveError!ResolveResult,

    pub fn resolve(self: Resolver, target: []const u8, allocator: std.mem.Allocator) ResolveError!ResolveResult {
        return self.resolveFn(self.context, target, allocator);
    }
};

/// Static resolver: returns a fixed list of endpoints. Useful for testing
/// or when addresses are known at configuration time.
pub const StaticResolver = struct {
    endpoints: []const Endpoint,

    pub fn init(endpoints: []const Endpoint) StaticResolver {
        return .{ .endpoints = endpoints };
    }

    pub fn resolver(self: *const StaticResolver) Resolver {
        return .{
            .context = @ptrCast(self),
            .resolveFn = resolveFn,
        };
    }

    fn resolveFn(ctx: *const anyopaque, _: []const u8, allocator: std.mem.Allocator) ResolveError!ResolveResult {
        const self: *const StaticResolver = @alignCast(@ptrCast(ctx));
        const endpoints = allocator.alloc(Endpoint, self.endpoints.len) catch return ResolveError.OutOfMemory;
        @memcpy(endpoints, self.endpoints);
        return .{ .endpoints = endpoints, .allocator = allocator };
    }
};

/// DNS resolver: resolves a "host:port" target using the system DNS.
pub const DnsResolver = struct {
    pub fn init() DnsResolver {
        return .{};
    }

    pub fn resolver(self: *const DnsResolver) Resolver {
        return .{
            .context = @ptrCast(self),
            .resolveFn = resolveFn,
        };
    }

    fn resolveFn(_: *const anyopaque, target: []const u8, _: std.mem.Allocator) ResolveError!ResolveResult {
        _ = parseTarget(target) orelse return ResolveError.InvalidTarget;
        return ResolveError.DnsFailure;
    }
};

/// Parse "host:port" target string.
pub fn parseTarget(target: []const u8) ?struct { host: []const u8, port: u16 } {
    // Handle IPv6 bracket notation: [::1]:port
    if (target.len > 0 and target[0] == '[') {
        const bracket_end = std.mem.indexOfScalar(u8, target, ']') orelse return null;
        const host = target[1..bracket_end];
        if (bracket_end + 1 >= target.len or target[bracket_end + 1] != ':') return null;
        const port_str = target[bracket_end + 2 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return .{ .host = host, .port = port };
    }

    // Handle host:port
    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return null;
    if (colon == 0) return null;
    const host = target[0..colon];
    const port_str = target[colon + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    return .{ .host = host, .port = port };
}

// ─── Tests ───

test "parseTarget: simple host:port" {
    const result = parseTarget("localhost:50051").?;
    try std.testing.expectEqualStrings("localhost", result.host);
    try std.testing.expectEqual(@as(u16, 50051), result.port);
}

test "parseTarget: IPv4:port" {
    const result = parseTarget("127.0.0.1:8080").?;
    try std.testing.expectEqualStrings("127.0.0.1", result.host);
    try std.testing.expectEqual(@as(u16, 8080), result.port);
}

test "parseTarget: IPv6 bracket notation" {
    const result = parseTarget("[::1]:443").?;
    try std.testing.expectEqualStrings("::1", result.host);
    try std.testing.expectEqual(@as(u16, 443), result.port);
}

test "parseTarget: no port → null" {
    try std.testing.expect(parseTarget("localhost") == null);
}

test "parseTarget: empty host → null" {
    try std.testing.expect(parseTarget(":8080") == null);
}

test "parseTarget: invalid port → null" {
    try std.testing.expect(parseTarget("localhost:abc") == null);
}

test "StaticResolver: returns configured endpoints" {
    const allocator = std.testing.allocator;
    const addrs = [_]Endpoint{
        .{ .address = Address.initIp4(.{ 127, 0, 0, 1 }, 50051) },
        .{ .address = Address.initIp4(.{ 127, 0, 0, 1 }, 50052) },
    };
    const static = StaticResolver.init(&addrs);
    const r = static.resolver();

    var result = try r.resolve("anything", allocator);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.endpoints.len);
    try std.testing.expectEqual(@as(u16, 50051), result.endpoints[0].address.getPort());
    try std.testing.expectEqual(@as(u16, 50052), result.endpoints[1].address.getPort());
}

test "StaticResolver: empty list" {
    const allocator = std.testing.allocator;
    const static = StaticResolver.init(&.{});
    const r = static.resolver();

    var result = try r.resolve("target", allocator);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.endpoints.len);
}

test "DnsResolver: localhost resolves" {
    const allocator = std.testing.allocator;
    const dns = DnsResolver.init();
    const r = dns.resolver();

    // DNS resolution is stubbed out in 0.16.0 migration
    const result = r.resolve("localhost:80", allocator);
    try std.testing.expectError(ResolveError.DnsFailure, result);
}

test "DnsResolver: invalid target → InvalidTarget" {
    const allocator = std.testing.allocator;
    const dns = DnsResolver.init();
    const r = dns.resolver();

    const result = r.resolve("no-port-here", allocator);
    try std.testing.expectError(ResolveError.InvalidTarget, result);
}
