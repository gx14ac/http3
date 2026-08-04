# zig-http3: Pure Zig HTTP/2 + HTTP/3 — targeting std.http integration

## Goal

`std.http.Client` に HTTP/2 多重化を transparent に統合するための RFC 9113 準拠実装。
最終形は stdlib PR だが、bradfitz/http2 → golang.org/x/net/http2 → net/http と同じ段階的信頼モデルで進める。

**bradfitz モデル:**
1. 外部リポジトリで高速イテレーション (GitHub, zon 配布)
2. 実運用で信頼性を証明 (runetale-zig 24/7 稼働)
3. stdlib へ小さい PR から入り始める (ALPN)
4. 最終的に std.http.Client に transparent 統合

## 競合分析

### Zig エコシステムの現状

| 実装 | HTTP/2 品質 | std.Io | std.http互換 | 多重化 | h2spec | 活発さ |
|------|------------|--------|-------------|--------|--------|--------|
| allain/httpz.zig | 良い骨格 (frame, HPACK, stream SM, flow control) | 使用 | なし (独自API) | サーバのみ (client は単一stream) | なし | ★5, 低活動 |
| ziglana/gRPC-zig | 壊れている (endian bug, mux なし) | 不使用 | なし | なし | なし | ★145, 停滞 |
| **本プロジェクト** | codec 正確 (テスト済み) + HPACK完了 | 目標 | **これが目標** | これから | これから | now |

### httpz.zig の詳細分析

**参考にすべき点:**
- `std.Io.Reader` / `std.Io.Writer` を直接受け取るパターン
- HPACK: static table + dynamic table (ring buffer) + Huffman decode
- Stream state machine (RFC 9113 §5.1 完全対応)
- CONTINUATION frame assembly/splitting (ConnectionIO.zig)
- Settings synchronization lifecycle (pending ACK tracking, timeout detection)
- DoS protection: rapid RST_STREAM 検出 (`ENHANCE_YOUR_CALM`)

**避けるべき弱点:**
- スレッド安全性なし (`var huffman_decode_scratch: [16384]u8` = module-level mutable global)
- Client が多重化しない (single stream, blocking)
- std.http 互換ゼロ — stdlib 統合の野心がない
- h2spec なし — conformance 未検証
- Server が HTTP/2 → HTTP/1.1 テキスト変換して再パース (無駄なコピー)

### ziglana/gRPC-zig の詳細分析

- Frame encode が **リトルエンディアン** (RFC 違反 — big-endian が正しい)
- Transport が `src/http2/` モジュールをバイパスし手動バイト操作
- Stream ID 1 に固定 (多重化不能)
- Flow control フィールドはあるがロジックなし
- Copilot 生成コミットが多く、2026年2月以降停滞

## 参照実装: Go http2 (golang.org/x/net/http2)

Brad Fitzpatrick が書いた Go の HTTP/2 実装は本プロジェクトの主要なアーキテクチャ参照。
以下、コンポーネントごとに Go の設計判断と Zig への翻訳方針を記録する。

### Timeline (bradfitz の成功パターン)

| 日付 | マイルストーン |
|------|-------------|
| 2014-07 | github.com/bradfitz/http2 作成、外部リポで高速イテレーション |
| 2015-04 | golang.org/x/net/http2 に移行 (準公式 sub-repo) |
| 2015-10 | net/http にvendor統合 + TLSNextProto hook で transparent 有効化 |
| 2016-02 | Go 1.6 リリース: 既存コードが変更なしで HTTP/2 対応 |

**成功要因:**
1. Brad は `net/http` のメンテナ — 摩擦ゼロ
2. API 変更ゼロ — 既存ユーザは何もせず HTTP/2 を得た
3. RFC の XML をパースして仕様の文ごとにテスト対応付け
4. 最初から「入れる」と宣言 — 競合乱立を防止
5. 段階的信頼: GitHub → x/net → stdlib

### frame.go から学ぶ設計パターン

**Framer (読み書き統合):**
```go
type Framer struct {
    r         io.Reader
    w         io.Writer
    wbuf      []byte        // 再利用される書き込みバッファ
    readBuf   []byte        // 再利用される読み込みバッファ
    // frame は次の ReadFrame() まで有効
}
```

**Zig での翻訳:**
```zig
pub const Framer = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    read_buf: [16384 + 9]u8 = undefined,  // max_frame_size + header
    write_buf: [16384 + 9]u8 = undefined,

    pub fn readFrame(self: *Framer) !Frame {
        // 9 bytes header → validate → read payload into read_buf
        // Frame.payload は read_buf のスライス (次の readFrame まで有効)
    }

    pub fn startWrite(self: *Framer, frame_type: FrameType, flags: Flags, stream_id: u31) void {
        // write_buf[0..9] を予約、payload を append
    }

    pub fn endWrite(self: *Framer) !void {
        // length を back-fill して flush
    }
};
```

**Parser dispatch table:**
```go
var frameParsers [256]frameParser  // frame type byte → parser function
```

Zig: `const frame_parsers: [256]?*const fn(FrameHeader, []const u8) FrameParseError!Frame`

**Frame validity model:**
- Frame は次の `readFrame()` まで有効 (zero-copy, バッファ再利用)
- これは Zig の明示的ライフタイムモデルと完全に一致
- API ドキュメントで明示 + テストで検証

### flow.go から学ぶ Flow Control

```go
type inflow struct {
    avail  int32   // 受信可能バイト数
    unsent int32   // WINDOW_UPDATE を送るべき蓄積量
}

type outflow struct {
    n    int32     // 送信可能バイト数
    conn *outflow  // stream → connection へのリンク
}
```

**Zig での翻訳:**
```zig
pub const Inflow = struct {
    avail: i32 = 65535,
    unsent: i32 = 0,

    const min_refresh: i32 = 4096;  // inflowMinRefresh

    pub fn take(self: *Inflow, n: u32) void {
        self.avail -= @intCast(n);
    }

    pub fn add(self: *Inflow, n: i32) ?u32 {
        // WINDOW_UPDATE を送るべき量を返す (null = まだ閾値未満)
        self.unsent += n;
        if (self.unsent < min_refresh) return null;
        const ret = self.unsent;
        self.unsent = 0;
        self.avail += ret;
        return @intCast(ret);
    }
};

pub const Outflow = struct {
    n: i32 = 65535,
    conn: *Outflow,  // connection-level flow control へのリンク

    pub fn available(self: *const Outflow) i32 {
        return @min(self.n, self.conn.n);
    }

    pub fn take(self: *Outflow, n: i32) void {
        self.n -= n;
        self.conn.n -= n;
    }
};
```

**重要な設計判断:**
- batched WINDOW_UPDATE (4KB 閾値) — 細かい UPDATE を送らない
- stream の outflow が connection の outflow をポインタで参照 — `available()` が自動的に両方を考慮
- i32 を使う (u32 ではない) — RFC 9113 §6.9.2 で負の window が許容されるため

### transport.go から学ぶ Client 多重化

**ClientConn のコア構造:**
```go
type ClientConn struct {
    mu           sync.Mutex
    wmu          sync.Mutex       // 書き込み直列化
    streams      map[uint32]*clientStream
    nextStreamID uint32
    maxConcurrent uint32
    cond         *sync.Cond      // flow control / stream 空き待ち
    fr           *Framer
    // ...
}
```

**Zig での翻訳:**
```zig
pub const ClientConn = struct {
    mutex: std.Thread.Mutex = .{},
    write_mutex: std.Thread.Mutex = .{},
    streams: std.AutoHashMap(u31, *ClientStream),
    next_stream_id: u31 = 1,  // client = odd
    max_concurrent: u32 = 100,
    cond: std.Thread.Condition = .{},
    framer: Framer,
    conn_flow: Outflow,
    allocator: std.mem.Allocator,
    // ...
};
```

**Concurrency model (Go → Zig 翻訳):**

| Go | 役割 | Zig |
|----|------|-----|
| readLoop goroutine | frame 読み取り → stream dispatch | 専用 reader (std.Io async or thread) |
| `cc.mu` (Mutex) | stream map / state 保護 | `std.Thread.Mutex` |
| `cc.wmu` (Mutex) | 書き込み直列化 | `std.Thread.Mutex` |
| `cc.cond` (Cond) | flow window 空き / stream slot 待ち | `std.Thread.Condition` |
| per-stream channels | response header 受信, peer close 通知 | `std.Thread.ResetEvent` or atomic flag |
| `reqHeaderMu` (1-elem chan) | stream ID 割り当ての排他 | mutex で十分 |

**Stream ライフサイクル signal (Go の channel close パターン):**

| Signal | Go | Zig |
|--------|----|----|
| Response headers received | `respHeaderRecv chan struct{}` | `resp_ready: std.Thread.ResetEvent` |
| Peer sent END_STREAM | `peerClosed chan struct{}` | `peer_closed: std.atomic.Value(bool)` |
| Stream done (cleanup) | `donec chan struct{}` | `done: std.Thread.ResetEvent` |
| Error/cancel | `abort chan struct{}` | `abort_err: ?anyerror` + atomic flag |

**ALPN 統合 (Go の TLSNextProto パターン):**
```go
func configureTransports(t1 *http.Transport) {
    t1.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
    t1.TLSNextProto = map[string]func(...){
        "h2": func(...) { /* upgrade to h2 */ },
    }
}
```

Zig equivalent (将来の std.http.Client 統合時):
```zig
// std.crypto.tls.Client.Options に ALPN を追加
pub const Options = struct {
    alpn_protocols: []const []const u8 = &.{ "h2", "http/1.1" },
    // ...
};

// Connection 作成後に negotiated protocol で分岐
const negotiated = tls_client.negotiated_protocol;
if (std.mem.eql(u8, negotiated, "h2")) {
    return H2Connection.init(allocator, tls_client.reader(), tls_client.writer());
}
```

### server.go から学ぶ構造 (Phase 3+ 参考)

**イベントループ (select ベース):**
- `readFrameCh` — reader goroutine からの frame
- `wantWriteFrameCh` — handler からの書き込み要求
- `wroteFrameCh` — 書き込み完了通知
- `bodyReadCh` — body 消費後の flow control 更新

**Write scheduler:**
- interface: `WriteScheduler { OpenStream, CloseStream, AdjustStream, Pop, Push }`
- 実装: RFC 9218 priority (default), round-robin, custom
- フレーム優先度: GOAWAY > SettingsAck > scheduler.Pop() > flush

**DoS guard:**
- `queuedControlFrames > 10000` → 接続切断
- rapid RST_STREAM detection → `ENHANCE_YOUR_CALM`

## std.http.Client 内部構造 (Zig master)

### 現状のアーキテクチャ

```
Client struct:
    allocator: Allocator
    io: Io                      ← std.Io vtable instance
    ca_bundle: Certificate.Bundle
    connection_pool: ConnectionPool
    http_proxy / https_proxy

ConnectionPool:
    mutex: Thread.Mutex
    used: DoublyLinkedList       ← active requests
    free: DoublyLinkedList       ← idle, reusable
    free_size: usize = 32        ← max idle connections

Connection:
    protocol: enum { plain, tls }
    stream_writer: Io.net.Stream.Writer
    stream_reader: Io.net.Stream.Reader
    → reader() / writer() returns *Io.Reader / *Io.Writer (vtable)
```

### 致命的なギャップ: ALPN が未実装

`std.crypto.tls.Client` の ClientHello に **ALPN extension が送信されていない**。
`encrypted_extensions` ハンドラも ALPN レスポンスを無視している。

**必要な変更 (S2: ALPN PR):**
1. `Options` に `alpn_protocols: []const []const u8` フィールド追加
2. ClientHello の extensions_payload に ALPN extension を emit
3. `encrypted_extensions` で ALPN response をパース
4. `negotiated_protocol: ?[]const u8` を公開

### HTTP/2 統合に必要な std.http.Client の変更 (S4)

```
現状:  request() → connect → TLS → Connection{reader, writer} → HTTP/1.1 framing

統合後: request() → connect → TLS + ALPN
                                   ↓
                             negotiated == "h2" ?
                             ├─ yes → H2Connection (multiplexed)
                             │        → open stream → binary framing → Response
                             └─ no  → Connection (existing HTTP/1.1)
```

**必要な変更:**
1. `Protocol` enum: `.tls` → `.tls_h1` / `.tls_h2` に拡張
2. `ConnectionPool`: h2 接続は `used` に入れたまま共有 (1 conn = N requests)
3. `Client.request()`: 既存 h2 接続があればそこに stream を開く分岐
4. `Request`/`Response` は API 互換のまま — 内部の framing だけ差し替え

## stdlib 品質方針 (本プロジェクト独自)

| # | 基準 | 本プロジェクトの戦略 |
|---|------|---------------------|
| 1 | **RFC準拠テストスイート通過** | h2spec client suite CI 必須。quic-interop-runner (Phase 4) |
| 2 | **ゼロアロケーション or allocator-parameterized** | ホットパス (frame codec, HPACK static) ゼロアロケーション。全 public API は Allocator パラメータ |
| 3 | **comptime で不要機能を除去** | `Features` comptime struct: HTTP/2-only / HTTP/3-only / full。不要コードは完全除去 |
| 4 | **std.Io 互換** | std.Io (0.16) の vtable dispatch を直接使用。テスト時は std.Io テストバックエンド |
| 5 | **十分な実運用実績** | runetale-zig Conductor gRPC (24/7 BiDi streaming) で検証 |

## Strategic Milestones (S0–S4)

```
┌────┬─────────────────────────────────────────────┬───────────────────────────────────────┐
│ SM │                  何をする                   │                成果物                 │
├────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ S0 │ Codeberg issue + コア開発者との合意         │ 公式 tracking issue                   │
├────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ S1 │ 外部パッケージとして HTTP/2 実装 (zon 配布) │ std.http.Client と同じ API の drop-in │
├────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ S2 │ std.crypto.tls に ALPN PR                   │ stdlib への最初の貢献 (小さく始める)  │
├────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ S3 │ h2spec 完全通過 + runetale-zig 実稼働       │ 信頼性の証明                          │
├────┼─────────────────────────────────────────────┼───────────────────────────────────────┤
│ S4 │ std.http.Client 統合 PR                     │ ゴール                                │
└────┴─────────────────────────────────────────────┴───────────────────────────────────────┘
```

以下の Implementation Phases (1a–5) は S1 の内訳 + S2–S4 への道筋を示す。

## Phase 1: HTTP/2 Client (外部パッケージ)

### 1a: Frame Layer + HPACK — 2 weeks

**Frame codec** (完了):
- FrameHeader encode/decode (9 bytes, zero allocation)
- Settings diff encode (RFC 9113 §6.5.1)
- Frame builders: SETTINGS, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY
- RFC validation: increment=0 → ProtocolError, buffer bounds check

**HPACK** (完了):
- Static table (RFC 7541 Appendix A, 61 entries)
- Integer encoding/decoding (prefix-coded, RFC 7541 §5.1)
- String literal encode/decode (raw + Huffman)
- Dynamic table (ring buffer, eviction, configurable size)
- Huffman encode/decode (comptime-generated state machine)
- Encoder (indexed / literal with/without/never indexing)
- Decoder (full header block parsing)

**次のステップ (Phase 1a 残り):**
- Framer struct 実装 (Go の frame.go パターン: read_buf/write_buf 再利用)
- Frame parser dispatch (FrameType → parser function)
- CONTINUATION frame assembly (header block が max_frame_size を超える場合)

### 1b: Stream State Machine + Flow Control — 2 weeks

**参照: Go http2 flow.go + transport.go の stream 管理**

**Stream state machine (RFC 9113 §5.1):**
```
           send PP  /  recv PP
          +--------+   +--------+
          |        v   |        v
    +-----+---+    +---+-----+
    |         |    |         |
    |  idle   |    | reserved|
    |         |    |  (local |
    +----+----+    |   or    |
         |         | remote) |
         | send H  +----+----+
         | recv H       |
         v              | send H / recv H
    +----+----+         |
    |         |<--------+
    |  open   |
    |         |
    +----+----+
         |
    +----+----+          +----------+
    | half    |          | half     |
    | closed  +--------->| closed   |
    | (remote)|  send ES | (local)  |
    +----+----+          +-----+----+
         |                     |
         | recv ES             | send ES
         v                     v
    +----+----+          +-----+----+
    |         |          |          |
    | closed  |          |  closed  |
    |         |          |          |
    +---------+          +----------+
```

**実装:**
```zig
pub const StreamState = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

pub const Stream = struct {
    id: u31,
    state: StreamState,
    inflow: Inflow,
    outflow: Outflow,
    // ...

    pub fn recv(self: *Stream, frame_type: FrameType, flags: Flags) !void {
        // State transition validation
    }

    pub fn send(self: *Stream, frame_type: FrameType, flags: Flags) !void {
        // State transition validation
    }
};
```

**Flow control (Go flow.go パターン):**
- `Inflow`: 受信 window + batched WINDOW_UPDATE (4KB threshold)
- `Outflow`: 送信 window + connection-level リンク
- `available()` = min(stream, connection) — Go と同一
- i32 使用 (RFC 9113 §6.9.2 の負の window 許容)

**Stream registry:**
- `std.AutoHashMap(u31, *Stream)` — Go の `streams map[uint32]*clientStream`
- Stream ID allocation: client = odd, monotonically increasing
- Max concurrent streams enforcement (SETTINGS 由来)
- Closed stream の GC (GOAWAY の last_stream_id 以降を即 close)

### 1c: HTTP/2 Connection + TLS — 2 weeks

**参照: Go transport.go の ClientConn + readLoop**

**Connection lifecycle:**
1. TCP connect
2. TLS handshake + ALPN "h2" negotiation
3. Send client preface (24 bytes magic)
4. Send SETTINGS frame
5. Receive server SETTINGS → send SETTINGS ACK
6. Ready for requests

**Framer (Go frame.go パターン):**
```zig
pub const Framer = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    read_buf: [max_frame_size + FrameHeader.encoded_size]u8 = undefined,
    write_buf: std.ArrayList(u8),

    // startWrite → append payload → endWrite (length back-fill)
    pub fn startWrite(self: *Framer, ftype: FrameType, flags: Flags, stream_id: u31) void { ... }
    pub fn writeBytes(self: *Framer, data: []const u8) void { ... }
    pub fn endWrite(self: *Framer) !void { ... }

    // readFrame: frame は次の readFrame まで有効
    pub fn readFrame(self: *Framer) !Frame { ... }
};
```

**Reader loop (Go readLoop パターン):**
```zig
fn readerLoop(conn: *H2Connection) void {
    while (true) {
        const frame = conn.framer.readFrame() catch |err| {
            conn.handleReadError(err);
            return;
        };
        conn.dispatch(frame);
    }
}

fn dispatch(conn: *H2Connection, frame: Frame) void {
    switch (frame.header.frame_type) {
        .settings => conn.handleSettings(frame),
        .ping => conn.handlePing(frame),
        .goaway => conn.handleGoaway(frame),
        .window_update => conn.handleWindowUpdate(frame),
        .headers, .data, .rst_stream => {
            const stream = conn.streams.get(frame.header.stream_id) orelse return;
            stream.handleFrame(frame);
        },
        else => {},
    }
}
```

**PING keepalive:**
- Configurable interval (default 30s)
- Timeout detection → connection close + reconnect

**GOAWAY handling:**
- Graceful drain: no new streams, existing streams complete normally
- Last stream ID 以降の pending requests を別接続にリトライ

### 1d: Multiplexed Client API — 1 week

**参照: Go transport.go の ClientConn concurrency model**

**Concurrency model:**
```zig
pub const H2Connection = struct {
    mutex: std.Thread.Mutex = .{},        // stream map / state
    write_mutex: std.Thread.Mutex = .{},  // 書き込み直列化
    cond: std.Thread.Condition = .{},     // flow/stream slot 待ち
    streams: std.AutoHashMap(u31, *ClientStream),
    next_stream_id: u31 = 1,
    max_concurrent: u32 = 100,
    conn_inflow: Inflow,
    conn_outflow: Outflow,
    framer: Framer,
    allocator: std.mem.Allocator,
};
```

**Request dispatch:**
1. `mutex.lock()` → stream slot が空くまで `cond.wait()`
2. Stream ID 割り当て (next_stream_id += 2)
3. Stream を map に登録
4. `mutex.unlock()`
5. `write_mutex.lock()` → HEADERS frame 送信 → `write_mutex.unlock()`
6. Body 送信 (DATA frames, flow control respect)
7. Response 待ち (stream の event で通知)

**Connection pool (h2 専用):**
- 同一 host:port に対して h2 接続は1本で十分 (多重化のため)
- h2 接続は "in use" 状態のまま共有される (HTTP/1.1 と異なる)
- 接続選択: 既存 h2 接続があればそれを返す

**Public API (std.http.Client 互換):**
```zig
const http2 = @import("http2");

var client = try http2.Client.init(allocator, io, .{});
defer client.deinit();

// Unary request (std.http.Client と同じパターン)
var req = try client.open(.GET, uri, .{});
defer req.deinit();
try req.send();
try req.finish();
try req.wait();
const body = try req.reader().readAllAlloc(allocator, max_size);

// Concurrent requests (multiplexed on same TCP connection)
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
- Spec coverage tracking (bradfitz 方式: RFC 文ごとにテスト対応付け)

## Phase 2: gRPC Framing Layer — 1 week

HTTP/2 上の gRPC プロトコル:

- 5-byte length-prefixed message framing (compress flag + 4-byte length)
- gRPC status codes (trailers: grpc-status, grpc-message)
- gRPC metadata → HTTP/2 headers mapping
- Unary / Server-streaming / Client-streaming / Bidirectional streaming
- gzip compression (optional, comptime gated)

```zig
const grpc = @import("http3").grpc;

var channel = try grpc.Channel.connect(allocator, io, "conductor.runetale.com", 443, .{});
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

**参照: Go server.go の DoS guard + transport.go のエラーハンドリング**

- Fuzz testing: frame parser, HPACK decoder (zig build fuzz)
- Thread safety audit (connection shared across request coroutines)
- Memory leak detection (allocator-parameterized = testing.allocator catches all)
- Graceful degradation: malformed frame → RST_STREAM, not connection close
- DoS guards:
  - queued control frames > 10000 → connection close (Go パターン)
  - rapid RST_STREAM → ENHANCE_YOUR_CALM
  - max header list size enforcement
- DynamicTable の allocator 化 (固定サイズ制限の解消)
- Encoder lookup の高速化 (static table hash map, comptime 生成)
- Metrics hooks: bytes sent/recv, stream count, RTT

## Phase 4: HTTP/3 (QUIC) — 8 weeks (future)

- QUIC transport (RFC 9000)
- QPACK (RFC 9204)
- HTTP/3 framing (RFC 9114)
- 0-RTT resumption
- Connection migration
- quic-interop-runner CI

## Phase 5: stdlib Integration PR — 2 weeks (future)

- ALPN PR to std.crypto.tls (S2)
- std.http.Client HTTP/2 backend PR (S4)
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
const static_table = [61]StaticEntry{ ... };

// Frame read: payload は read_buf のスライス (次の readFrame まで有効)
// → Go の "frame valid until next ReadFrame" パターンと同一
```

### 3. I/O Backend: std.Io (vtable dispatch)

```zig
// std.Io は vtable ベース (comptime duck typing ではない)。
// 統合時に書き直しを避けるため、最初から直接受け取る。
pub const Connection = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
};
```

### 4. Memory Management: Arena per Connection

```zig
// Go の sync.Pool → Zig では Arena allocator per connection
// 接続 close 時に一括解放 → per-frame tracking 不要
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();

var conn = try H2Connection.init(arena.allocator(), io);
```

### 5. std.http.Client API Compatibility

外部パッケージ段階でも、API surface は std.http.Client に揃える。
統合 PR 時に最小限の diff で済むようにする。

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
│   │   ├── hpack.zig         (HPACK encoder/decoder) ✅ done
│   │   ├── huffman.zig       (Huffman table) ✅ done
│   │   ├── framer.zig        (read/write with buffer reuse — Go frame.go pattern)
│   │   ├── stream.zig        (stream state machine)
│   │   ├── flow_control.zig  (Inflow/Outflow — Go flow.go pattern)
│   │   ├── connection.zig    (H2Connection — Go transport.go pattern)
│   │   └── settings.zig      (SETTINGS lifecycle + ACK sync)
│   ├── h3/                   (Phase 4, future)
│   ├── grpc/                 (Phase 2)
│   │   ├── framing.zig
│   │   ├── status.zig
│   │   └── channel.zig
│   ├── client.zig            (unified Client API, std.http.Client 互換)
│   └── tls.zig               (std.crypto.tls + ALPN wrapper)
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

## Go http2 → Zig 翻訳マッピング

| Go パターン | Zig 実装 | 対応ファイル |
|------------|---------|-------------|
| `sync.Pool` (buffer reuse) | Arena allocator per connection | connection.zig |
| goroutine (readLoop) | 専用 reader thread via std.Io | connection.zig |
| `sync.Mutex` | `std.Thread.Mutex` | connection.zig |
| `sync.Cond` (backpressure) | `std.Thread.Condition` | connection.zig |
| channel close (signal once) | `std.Thread.ResetEvent` | stream.zig |
| `map[uint32]*clientStream` | `std.AutoHashMap(u31, *Stream)` | connection.zig |
| `interface{}` Frame dispatch | `switch` on `FrameType` enum | framer.zig |
| `bufio.Writer` (buffered write) | `std.Io.Writer` with internal buf | framer.zig |
| `bytes.Buffer` (growing) | `std.ArrayList(u8)` | framer.zig |
| GC-managed lifetime | Explicit allocator + arena | all |
| `startWrite/endWrite` (length back-fill) | Same pattern, mutable `[]u8` | framer.zig |

## Timeline

| Phase | 期間 | ゲート条件 |
|-------|------|-----------|
| 1a (Frame + HPACK) | 2 weeks | ✅ HPACK encode/decode roundtrip, Huffman |
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
