pub const message = @import("message.zig");
pub const status = @import("status.zig");
pub const channel = @import("channel.zig");
pub const interceptor = @import("interceptor.zig");
pub const stream_interceptor = @import("stream_interceptor.zig");
pub const resolver = @import("resolver.zig");
pub const balancer = @import("balancer.zig");
pub const dialer = @import("dialer.zig");
pub const tls_dialer = @import("tls_dialer.zig");

pub const Channel = channel.Channel;
pub const ChannelError = channel.ChannelError;
pub const CallOptions = channel.CallOptions;
pub const Metadata = channel.Metadata;
pub const UnaryResult = channel.UnaryResult;
pub const StreamHandle = channel.StreamHandle;
pub const KeepaliveConfig = channel.KeepaliveConfig;
pub const Status = status.Status;
pub const Code = status.Code;

pub const UnaryInterceptor = interceptor.UnaryInterceptor;
pub const InterceptorChain = interceptor.InterceptorChain;
pub const Invoker = interceptor.Invoker;
pub const UnaryCallInfo = interceptor.UnaryCallInfo;

pub const Resolver = resolver.Resolver;
pub const StaticResolver = resolver.StaticResolver;
pub const DnsResolver = resolver.DnsResolver;
pub const Endpoint = resolver.Endpoint;

pub const Balancer = balancer.Balancer;
pub const PickFirst = balancer.PickFirst;
pub const RoundRobin = balancer.RoundRobin;

pub const Dialer = dialer.Dialer;
pub const TcpDialer = dialer.TcpDialer;
pub const DialResult = dialer.DialResult;

pub const TlsDialer = tls_dialer.TlsDialer;

pub const health = @import("health.zig");
pub const HealthClient = health.HealthClient;
pub const ServingStatus = health.ServingStatus;

pub const StreamInterceptor = stream_interceptor.StreamInterceptor;
pub const StreamInterceptorChain = stream_interceptor.StreamInterceptorChain;
pub const StreamInvoker = stream_interceptor.StreamInvoker;
pub const StreamCallInfo = stream_interceptor.StreamCallInfo;
pub const StreamType = stream_interceptor.StreamType;

test {
    _ = message;
    _ = status;
    _ = channel;
    _ = interceptor;
    _ = stream_interceptor;
    _ = resolver;
    _ = balancer;
    _ = dialer;
    _ = tls_dialer;
    _ = health;
    _ = @import("integration_test.zig");
}
