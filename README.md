# http3

HTTP/2, gRPC and HTTP/3 (QUIC) in pure Zig, with no C dependencies. It is
meant to be small enough to read and, eventually, to offer pieces of it to
the Zig standard library.

## What is in it

| Module | What |
|---|---|
| `h2` | HTTP/2 (RFC 9113): frames, HPACK (RFC 7541) with Huffman coding, stream states, flow control, a client connection |
| `grpc` | gRPC over HTTP/2: unary and streaming calls, metadata, status, interceptors, health checks, a channel with a resolver and balancer, a server |
| `quic` | QUIC (RFC 9000/9001/9002) and HTTP/3 (RFC 9114) with QPACK: handshake, loss recovery and congestion control (CUBIC), streams, 0-RTT and resumption, migration, a client and a server |
| `io` | TCP and TLS transports, and the clock (`io/clock.zig`) |

## Status

- **HTTP/2 and gRPC clients:** in daily use with Zig 0.16. runetale-zig, the
  runetale daemon, talks to its control server through them over long-lived
  bidirectional streams. The same code also runs freestanding on a
  microcontroller (RV32, ESP32-C3), where the firmware supplies the clock.
- **QUIC and HTTP/3:** written against the Zig 0.15 standard library and not
  yet ported to 0.16.
- **The test suite** (`zig build test`) does not compile today: it still
  includes the QUIC code that has not been ported. Bringing it back is the
  next step.

`PLAN.md` is the working plan (in Japanese).

## Using it

```zig
// build.zig.zon
.dependencies = .{
    .http3 = .{ .url = "git+https://github.com/gx14ac/http3#<commit>", .hash = "..." },
},
```

```zig
// build.zig
const http3_dep = b.dependency("http3", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("http3", http3_dep.artifact("http3").root_module);
```

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
