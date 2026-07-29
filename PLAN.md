# zig-http3: Pure Zig HTTP/2 + HTTP/3 — targeting std.http integration

## Goal

`std.http.Client` に HTTP/2 多重化を追加するための実装。
最終形は stdlib PR だが、まず外部パッケージとして完成させ、runetale-zig で実運用実績を積む。

## 競合分析

| 実装 | HTTP/2 品質 | std.Io | std.http互換 | 多重化 | h2spec | 活発さ |
|------|------------|--------|-------------|--------|--------|--------|
| httpz.zig | 良い骨格 (frame, HPACK, stream SM, flow control) | 使用 | なし (独自API) | サーバのみ | なし | ★5, 低活動 |
| ziglana/gRPC-zig | 壊れている (endian bug, mux なし) | 不使用 | なし | なし | なし | ★145, 停滞 |
| **本プロジェクト** | codec 正確 (テスト済み) | 目標 | **これが目標** | これから | これから | now |

### httpz.zig から参考にすべき点

- std.Io.Reader / std.Io.Writer 直接使用パターン
- HPACK: static table + dynamic table (ring buffer) + Huffman decode
- Stream state machine (RFC 9113 §5.1 完全対応)
- CONTINUATION frame assembly/splitting
- Settings synchronization lifecycle (pending ACK tracking)

### 避けるべき弱点

- スレッド安全性なし (module-level mutable global)
- Client が多重化しない (stream ID 1 固定と同等)
- std.http 互換ゼロ — stdlib統合の野心がない
- h2spec なし — conformance 未検証

## std.http.Client 統合設計 (bradfitz モデル)

### 現状の std.http.Client フロー

```
request() → connectTcp() → TLS handshake → Connection{reader, writer}
                                                   ↓
                                            HTTP/1.1 text framing
                                                   ↓
                                            Response (chunked/content-length)
```

### 統合後

```
request() → connectTcp() → TLS handshake + ALPN
                                  ↓
                            negotiated == "h2" ?
                            ├─ yes → H2Connection (multiplexed streams)
                            │        → open stream → binary framing → Response
                            └─ no  → Connection (existing HTTP/1.1 path)
```

### 必要な stdlib 変更 (最小限)

1. **std.crypto.tls.Client**: ALPN extension を ClientHello に追加 + negotiated protocol を公開
2. **ConnectionPool**: h2 接続の共有 (1 connection = N requests)
3. **Protocol enum**: `.tls` → `.tls_h1` / `.tls_h2` に拡張
4. **Client.request()**: h2 接続があればそこに stream を開く分岐

## stdlib 採用基準 (Andrew Kelley)

| # | 基準 | 本プロジェクトの戦略 |
|---|------|---------------------|
| 1 | **RFC準拠テストスイート通過** | h2spec client suite CI 必須。quic-interop-runner (Phase 4) |
| 2 | **ゼロアロケーション or allocator-parameterized** | ホットパス (frame codec, HPACK static) ゼロアロケーション。全 public API は Allocator パラメータ |
| 3 | **comptime で不要機能を除去** | `Features` comptime struct: HTTP/2-only / HTTP/3-only / full。不要コードは完全除去 |
| 4 | **io_uring / kqueue / epoll 抽象** | I/O を comptime duck typing で抽象化。std.Io (0.16+) 統合前提 |
| 5 | **十分な実運用実績** | runetale-zig Conductor gRPC (24/7 BiDi streaming) で検証 |

## Strategic Phases

```
┌───────┬─────────────────────────────────────────────┬───────────────────────────────────────┐
│ Phase │                  何をする                   │                成果物                 │
├───────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ 0     │ Codeberg issue + コア開発者との合意         │ 公式 tracking issue                   │
├───────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ 1     │ 外部パッケージとして HTTP/2 実装 (zon 配布) │ std.http.Client と同じ API の drop-in │
├───────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ 2     │ std.crypto.tls に ALPN PR                   │ stdlib への最初の貢献 (小さく始める)  │
├───────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ 3     │ h2spec 完全通過 + runetale-zig 実稼働       │ 信頼性の証明                          │
├───────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ 4     │ std.http.Client 統合 PR                     │ ゴール                                │
└───────┴─────────────────────────────────────────────┴───────────────────────────────────────┘
```

## Phase 1: HTTP/2 Client (外部パッケージ)

### 1a: Frame Layer + HPACK — 2 weeks

**Frame codec** (完了):
- FrameHeader encode/decode (9 bytes, zero allocation)
- Settings diff encode (RFC 9113 §6.5.1)
- Frame builders: SETTINGS, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY

**HPACK** (次):
- Static table (RFC 7541 Appendix A, 61 entries)
- Integer encoding/decoding (prefix-coded)
- Literal header field (without indexing) — Phase 1a minimum
- Dynamic table (ring buffer, configurable size) — Phase 1a full
- Huffman encoding/decoding (RFC 7541 Appendix B)

### 1b: Stream State Machine + Flow Control — 2 weeks

- Stream states: idle → open → half-closed → closed (RFC 9113 §5.1)
- Connection-level flow control window
- Per-stream flow control window
- WINDOW_UPDATE auto-send threshold
- Max concurrent streams enforcement
- RST_STREAM / GOAWAY handling

### 1c: HTTP/2 Connection + TLS — 2 weeks

- Client preface → SETTINGS exchange
- ALPN "h2" negotiation via std.crypto.tls
- HEADERS frame + HPACK encoding (request)
- DATA frame send/recv with flow control
- PING keepalive (configurable interval)
- Graceful GOAWAY drain
- Exponential backoff reconnect

### 1d: Multiplexed Client API — 1 week

- Concurrent request dispatch (multiple streams on one connection)
- Stream ID allocation (odd, client-initiated)
- Request/response correlation
- Connection pool (single host → reuse h2 connection)
- API compatible with std.http.Client patterns:

```zig
const http2 = @import("http2");

var client = try http2.Client.init(allocator, .{});
defer client.deinit();

// Unary request
var req = try client.open(.GET, uri, .{});
defer req.deinit();
try req.send();
try req.finish();
try req.wait();
const body = try req.reader().readAllAlloc(allocator, max_size);

// Concurrent requests (multiplexed on same TCP)
var req1 = try client.open(.GET, uri1, .{});
var req2 = try client.open(.GET, uri2, .{});
try req1.send();
try req2.send();
// Both fly on same underlying h2 connection
```

### 1e: h2spec Conformance — 1 week

- h2spec runner integration in `zig build test`
- Fix all failures
- CI gate: h2spec must pass on every commit

## Phase 2: gRPC Framing Layer — 1 week

HTTP/2 上の gRPC プロトコル:

- 5-byte length-prefixed message framing
- gRPC status codes (trailers: grpc-status, grpc-message)
- gRPC metadata → HTTP/2 headers mapping
- Unary / Server-streaming / Client-streaming / Bidirectional streaming
- gzip compression (optional, comptime gated)

```zig
const grpc = @import("http3").grpc;

var channel = try grpc.Channel.connect(allocator, "conductor.runetale.com", 443, .{});
defer channel.close();

// Unary RPC
const resp = try channel.unary("/runetale.v1.NodeService/LoginNode", request_bytes, .{});

// BiDi streaming
var stream = try channel.bidiStream("/runetale.v1.NodeService/ConnectNetworkMap", .{});
try stream.send(initial_request);
while (try stream.recv()) |msg| {
    // process server push
}
```

## Phase 3: Production Hardening — 2 weeks

- Fuzz testing: frame parser, HPACK decoder (zig build fuzz)
- Thread safety audit (connection shared across request coroutines)
- Memory leak detection (allocator-parameterized = testing.allocator catches all)
- Graceful degradation: malformed frame → RST_STREAM, not connection close
- Metrics hooks: bytes sent/recv, stream count, RTT

## Phase 4: HTTP/3 (QUIC) — 8 weeks (future)

- QUIC transport (RFC 9000)
- QPACK (RFC 9204)
- HTTP/3 framing (RFC 9114)
- 0-RTT resumption
- Connection migration
- quic-interop-runner CI

## Phase 5: stdlib Integration PR — 2 weeks (future)

- ALPN PR to std.crypto.tls (Phase 2 of strategic plan)
- std.http.Client HTTP/2 backend PR (Phase 4 of strategic plan)
- Code review cycles with Zig core team

## Production Validation: runetale-zig

| 利用箇所 | RPC パターン | 検証される特性 |
|----------|-------------|---------------|
| Conductor: LoginNode | Unary | TLS+ALPN, MachineKey auth headers |
| Conductor: ConnectNetworkMapTable | BiDi streaming | 24/7接続, keepalive, reconnect |
| Conductor: InteractiveLogin | Server streaming | ALB RST_STREAM (90s) からの復帰 |
| Signal: ICE negotiation | BiDi streaming | 低レイテンシ、concurrent streams |
| Telemetry: log upload | Client streaming | Backpressure, flow control |

## Design Principles

### 1. Comptime Feature Gating

```zig
pub const Features = struct {
    http2: bool = true,
    http3: bool = false,
    hpack_dynamic_table: bool = true,
    huffman: bool = true,
    grpc: bool = false,
};

pub fn Client(comptime features: Features) type {
    return struct {
        // features.http3 == false → QUIC code eliminated at comptime
        // features.grpc == false → gRPC framing excluded
    };
}
```

### 2. Zero-Allocation Hot Path

```zig
// Frame encode/decode: caller-provided buffer, no heap
pub fn encode(self: FrameHeader, buf: *[9]u8) void { ... }
pub fn decode(buf: *const [9]u8) FrameHeader { ... }

// HPACK static lookup: comptime-generated table
const static_table = comptime buildStaticTable();
```

### 3. I/O Backend Abstraction

```zig
// Comptime duck typing (no VTable overhead)
pub fn Connection(comptime Io: type) type {
    // Requires: Io.read(buf) !usize, Io.write(buf) !usize, Io.close() void
    return struct { ... };
}
```

### 4. std.http.Client API Compatibility

外部パッケージ段階でも、API surface は std.http.Client に揃える。
統合 PR 時に最小限のdiffで済むようにする。

## Repository Structure

```
gx14ac/http3/
├── PLAN.md
├── build.zig
├── build.zig.zon
├── src/
│   ├── root.zig              (public entry point)
│   ├── h2/
│   │   ├── frame.zig         (frame codec) ✅ done
│   │   ├── hpack.zig         (HPACK encoder/decoder)
│   │   ├── huffman.zig       (Huffman table)
│   │   ├── stream.zig        (stream state machine)
│   │   ├── connection.zig    (HTTP/2 connection)
│   │   ├── flow_control.zig  (window management)
│   │   └── settings.zig      (SETTINGS lifecycle)
│   ├── h3/                   (Phase 4, future)
│   ├── grpc/                 (Phase 2)
│   │   ├── framing.zig
│   │   ├── status.zig
│   │   └── channel.zig
│   ├── client.zig            (unified Client API)
│   └── io/
│       ├── tls.zig           (std.crypto.tls + ALPN)
│       └── test_stub.zig
└── test/
    ├── h2spec/               (conformance runner)
    └── fuzz/
```

## RFC References

| RFC | Title | Phase |
|-----|-------|-------|
| 9113 | HTTP/2 | 1 |
| 7541 | HPACK | 1 |
| 9218 | Extensible Priorities | 3 |
| 9000 | QUIC Transport | 4 |
| 9001 | QUIC-TLS | 4 |
| 9002 | QUIC Loss Detection | 4 |
| 9114 | HTTP/3 | 4 |
| 9204 | QPACK | 4 |

## Timeline

| Phase | 期間 | ゲート条件 |
|-------|------|-----------|
| 1a (Frame + HPACK) | 2 weeks | HPACK encode/decode roundtrip, Huffman |
| 1b (Stream SM + Flow) | 2 weeks | State machine covers all RFC transitions |
| 1c (Connection + TLS) | 2 weeks | TLS h2 negotiation, SETTINGS exchange |
| 1d (Multiplexed API) | 1 week | Concurrent requests on one connection |
| 1e (h2spec) | 1 week | h2spec client suite 100% pass |
| 2 (gRPC) | 1 week | runetale-zig Conductor全RPC動作 |
| 3 (Hardening) | 2 weeks | Fuzz 0 crash, CI green |
| — | — | **runetale-zig production deploy** |
| 4 (HTTP/3) | 8 weeks | quic-interop-runner pass |
| 5 (stdlib PR) | 2 weeks | PR submitted, review cycle |

**HTTP/2 production-ready: ~9 weeks**
**stdlib PR submission: ~21 weeks**
