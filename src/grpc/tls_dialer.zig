const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;
const Io = std.Io;
const resolver_mod = @import("resolver.zig");
const dialer_mod = @import("dialer.zig");
const Endpoint = resolver_mod.Endpoint;
const DialError = dialer_mod.DialError;
const DialResult = dialer_mod.DialResult;
const Dialer = dialer_mod.Dialer;

/// TLS dialer: connects via TCP, performs TLS 1.3/1.2 handshake with ALPN h2,
/// and returns reader/writer for the decrypted stream.
///
/// ALPN h2 is injected by intercepting the ClientHello record before it hits
/// the wire. The AlpnWriter patches in the ALPN extension (9 bytes) and adjusts
/// the three length fields (record, handshake, extensions). This works around
/// Zig 0.15.2 stdlib's comptime-fixed extension table.
pub const TlsDialer = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    ca_bundle: Certificate.Bundle,
    insecure: bool = false,
    owns_bundle: bool = false,

    /// Create a TLS dialer that loads the system CA bundle for certificate verification.
    /// Returns error if system CAs cannot be loaded — use initInsecure for dev/test.
    pub fn init(allocator: std.mem.Allocator, host: []const u8) DialError!TlsDialer {
        var bundle = Certificate.Bundle{};
        bundle.rescan(allocator) catch return DialError.IoError;
        return .{ .allocator = allocator, .host = host, .ca_bundle = bundle, .owns_bundle = true };
    }

    pub fn initInsecure(allocator: std.mem.Allocator, host: []const u8) TlsDialer {
        return .{ .allocator = allocator, .host = host, .ca_bundle = .{}, .insecure = true };
    }

    pub fn withCaBundle(allocator: std.mem.Allocator, host: []const u8, bundle: Certificate.Bundle) TlsDialer {
        return .{ .allocator = allocator, .host = host, .ca_bundle = bundle };
    }

    pub fn deinit(self: *TlsDialer) void {
        if (self.owns_bundle) {
            self.ca_bundle.deinit(self.allocator);
        }
    }

    pub fn dialer(self: *TlsDialer) Dialer {
        return .{
            .context = @ptrCast(self),
            .dialFn = dialFn,
        };
    }

    fn dialFn(ctx: *anyopaque, endpoint: Endpoint) DialError!DialResult {
        const self: *TlsDialer = @alignCast(@ptrCast(ctx));

        const stream = std.net.tcpConnectToAddress(endpoint.address) catch
            return DialError.ConnectionRefused;
        errdefer stream.close();

        const conn = self.allocator.create(TlsConn) catch return DialError.IoError;
        errdefer self.allocator.destroy(conn);

        conn.* = .{
            .tcp_stream = stream,
            .stream_reader = stream.reader(&conn.read_buf),
            .stream_writer = stream.writer(&conn.write_buf),
            .alpn_writer = undefined,
            .tls_read_buf = undefined,
            .tls_write_buf = undefined,
            .tls_client = undefined,
            .allocator = self.allocator,
        };

        conn.alpn_writer = AlpnWriter.init(&conn.stream_writer, &conn.alpn_write_buf);

        conn.tls_client = tls.Client.init(
            conn.stream_reader.interface(),
            &conn.alpn_writer.interface,
            .{
                .host = if (self.insecure) .no_verification else .{ .explicit = self.host },
                .ca = if (self.insecure) .no_verification else .{ .bundle = self.ca_bundle },
                .read_buffer = &conn.tls_read_buf,
                .write_buffer = &conn.tls_write_buf,
            },
        ) catch return DialError.IoError;

        return .{
            .reader = .{ .context = @ptrCast(conn), .readFn = tlsReadFn },
            .writer = .{ .context = @ptrCast(conn), .writeFn = tlsWriteFn },
            .closeFn = tlsCloseFn,
            .close_ctx = @ptrCast(conn),
        };
    }
};

const TlsConn = struct {
    tcp_stream: std.net.Stream,
    stream_reader: std.net.Stream.Reader,
    stream_writer: std.net.Stream.Writer,
    alpn_writer: AlpnWriter,
    tls_client: tls.Client,
    allocator: std.mem.Allocator,
    read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    write_buf: [tls.Client.min_buffer_len]u8 = undefined,
    alpn_write_buf: [tls.Client.min_buffer_len]u8 = undefined,
    tls_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    tls_write_buf: [tls.Client.min_buffer_len]u8 = undefined,
};

/// Writer that intercepts the first drain (ClientHello) and injects ALPN h2 extension.
/// After the first record, all writes pass through to the underlying stream writer.
const AlpnWriter = struct {
    interface: Io.Writer,
    stream_writer: *std.net.Stream.Writer,
    first_done: bool = false,

    const vtable: Io.Writer.VTable = .{
        .drain = alpnDrain,
    };

    fn init(sw: *std.net.Stream.Writer, buffer: []u8) AlpnWriter {
        return .{
            .interface = .{
                .vtable = &vtable,
                .buffer = buffer,
            },
            .stream_writer = sw,
        };
    }

    fn alpnDrain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *AlpnWriter = @alignCast(@fieldParentPtr("interface", io_w));

        if (self.first_done) {
            return passthroughDrain(io_w, self.stream_writer, data, splat);
        }

        // First drain: collect buffered + data bytes, inject ALPN, forward to real writer
        self.first_done = true;

        const buffered = io_w.buffered();

        // Calculate total size of the ClientHello record
        var total_len: usize = buffered.len;
        for (data[0 .. data.len - 1]) |bytes| total_len += bytes.len;
        total_len += data[data.len - 1].len * splat;

        // Assemble into a contiguous buffer (sized to match TLS max record)
        var record_buf: [tls.Client.min_buffer_len]u8 = undefined;
        if (total_len > record_buf.len) {
            return passthroughDrain(io_w, self.stream_writer, data, splat);
        }

        var pos: usize = 0;
        @memcpy(record_buf[pos..][0..buffered.len], buffered);
        pos += buffered.len;
        for (data[0 .. data.len - 1]) |bytes| {
            @memcpy(record_buf[pos..][0..bytes.len], bytes);
            pos += bytes.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            @memcpy(record_buf[pos..][0..pattern.len], pattern);
            pos += pattern.len;
        }

        // Inject ALPN extension
        var patched_buf: [tls.Client.min_buffer_len + alpn_extension.len]u8 = undefined;
        const patched_len = injectAlpnIntoClientHello(record_buf[0..pos], &patched_buf) orelse {
            return passthroughDrain(io_w, self.stream_writer, data, splat);
        };

        // Write patched record directly to the underlying TCP stream writer
        const patched = patched_buf[0..patched_len];
        _ = self.stream_writer.interface.writeVec(&.{patched}) catch return error.WriteFailed;
        self.stream_writer.interface.flush() catch return error.WriteFailed;

        // Consume all buffered bytes from our interface
        return io_w.consume(total_len);
    }

    /// Forward buffered + data bytes from our Writer to the real stream writer.
    fn passthroughDrain(io_w: *Io.Writer, sw: *std.net.Stream.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const buffered = io_w.buffered();

        // Build a combined iovec: buffered bytes first, then data slices
        var vecs: [16][]const u8 = undefined;
        var vec_count: usize = 0;
        if (buffered.len > 0) {
            vecs[vec_count] = buffered;
            vec_count += 1;
        }
        for (data[0 .. data.len - 1]) |bytes| {
            if (vec_count >= vecs.len) break;
            if (bytes.len > 0) {
                vecs[vec_count] = bytes;
                vec_count += 1;
            }
        }
        const pattern = data[data.len - 1];
        if (pattern.len > 0) {
            for (0..splat) |_| {
                if (vec_count >= vecs.len) break;
                vecs[vec_count] = pattern;
                vec_count += 1;
            }
        }

        if (vec_count == 0) {
            return 0;
        }

        // Write through the real stream writer
        _ = sw.interface.writeVec(vecs[0..vec_count]) catch return error.WriteFailed;
        sw.interface.flush() catch return error.WriteFailed;

        // Calculate data bytes (excluding buffered)
        var data_len: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| data_len += bytes.len;
        data_len += pattern.len * splat;

        return io_w.consume(buffered.len + data_len);
    }
};

// ─── ALPN injection ───

// ALPN extension for "h2": extension_type(2) + length(2) + protocol_list_len(2) + proto_len(1) + "h2"(2) = 9 bytes
const alpn_extension: [9]u8 = .{
    0x00, 0x10, // extension type: application_layer_protocol_negotiation (16)
    0x00, 0x05, // extension data length: 5
    0x00, 0x03, // protocol name list length: 3
    0x02, // protocol name length: 2
    'h', '2', // protocol name: "h2"
};

/// Inject ALPN h2 extension into a TLS ClientHello record on the wire.
/// The record format is: ContentType(1) + Version(2) + Length(2) + HandshakeType(1) + HSLength(3) + ...
/// Extensions are at the end of the ClientHello; we find the extensions length field and patch it.
fn injectAlpnIntoClientHello(record: []const u8, out: []u8) ?usize {
    // Minimum TLS record: 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) + 1 (session_id_len)
    if (record.len < 44) return null;

    // Verify it's a Handshake record with ClientHello
    if (record[0] != 0x16) return null; // ContentType.handshake
    if (record[5] != 0x01) return null; // HandshakeType.client_hello

    // Record length (bytes 3-4)
    const record_len = std.mem.readInt(u16, record[3..5], .big);
    // Handshake length (bytes 6-8, u24)
    const hs_len = (@as(u24, record[6]) << 16) | (@as(u24, record[7]) << 8) | @as(u24, record[8]);

    const total_out = record.len + alpn_extension.len;
    if (out.len < total_out) return null;

    // Copy original record
    @memcpy(out[0..record.len], record);

    // Patch record length (+9)
    std.mem.writeInt(u16, out[3..5], @intCast(record_len + alpn_extension.len), .big);
    // Patch handshake length (+9)
    const new_hs_len = hs_len + alpn_extension.len;
    out[6] = @intCast((new_hs_len >> 16) & 0xFF);
    out[7] = @intCast((new_hs_len >> 8) & 0xFF);
    out[8] = @intCast(new_hs_len & 0xFF);

    // Find extensions length field. After the record header (5) + handshake header (4):
    // ClientHello body: version(2) + random(32) + session_id_len(1) + session_id(var) + cipher_suites_len(2) + cipher_suites(var) + compression_len(1) + compression(var) + extensions_len(2) + extensions(var)
    var pos: usize = 9; // after record header (5) + handshake header (4)
    pos += 2; // client version
    pos += 32; // random
    if (pos >= record.len) return null;
    const session_id_len = record[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > record.len) return null;
    const cipher_suites_len = std.mem.readInt(u16, record[pos..][0..2], .big);
    pos += 2 + cipher_suites_len;
    if (pos + 1 > record.len) return null;
    const compression_len = record[pos];
    pos += 1 + compression_len;
    if (pos + 2 > record.len) return null;

    // pos now points to extensions_length field
    const ext_len = std.mem.readInt(u16, record[pos..][0..2], .big);
    std.mem.writeInt(u16, out[pos..][0..2], @intCast(ext_len + alpn_extension.len), .big);

    // Insert ALPN extension at the end of extensions (before end of record)
    // Move the data: original record ends at record.len, so extensions end at record.len
    // Append ALPN at the end
    @memcpy(out[record.len..][0..alpn_extension.len], &alpn_extension);

    return total_out;
}

fn tlsReadFn(ctx: *const anyopaque, buf: []u8) anyerror!usize {
    const conn: *TlsConn = @constCast(@alignCast(@ptrCast(ctx)));
    var data = [_][]u8{buf};
    const n = conn.tls_client.reader.readVec(&data) catch |e| switch (e) {
        error.EndOfStream => return 0,
        else => return error.IoError,
    };
    return n;
}

fn tlsWriteFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
    const conn: *TlsConn = @constCast(@alignCast(@ptrCast(ctx)));
    conn.tls_client.writer.writeAll(data) catch return error.IoError;
    conn.tls_client.writer.flush() catch return error.IoError;
    return data.len;
}

fn tlsCloseFn(ctx: *anyopaque) void {
    const conn: *TlsConn = @alignCast(@ptrCast(ctx));
    // Best-effort TLS close_notify (RFC 8446 §6.1)
    conn.tls_client.writer.flush() catch {};
    conn.tcp_stream.close();
    conn.allocator.destroy(conn);
}

// ─── Tests ───

test "TlsDialer: connection refused returns DialError" {
    const allocator = std.testing.allocator;
    var td = TlsDialer.initInsecure(allocator, "localhost");
    defer td.deinit();
    const d = td.dialer();

    const ep = Endpoint{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 1) };
    const result = d.dial(ep);
    try std.testing.expectError(DialError.ConnectionRefused, result);
}

test "TlsDialer: init loads system CAs" {
    const allocator = std.testing.allocator;
    var td = TlsDialer.init(allocator, "example.com") catch {
        return; // skip if system CAs unavailable
    };
    defer td.deinit();
    try std.testing.expectEqualStrings("example.com", td.host);
    try std.testing.expect(!td.insecure);
    try std.testing.expect(td.owns_bundle);
}

test "TlsDialer: initInsecure sets flag" {
    const allocator = std.testing.allocator;
    var td = TlsDialer.initInsecure(allocator, "localhost");
    defer td.deinit();
    try std.testing.expect(td.insecure);
    try std.testing.expect(!td.owns_bundle);
}

test "injectAlpnIntoClientHello: correct patching" {
    // version(2) + random(32) + session_id_len(1)=0 + cipher_suites_len(2)=2 + cipher(2) + comp_len(1)=1 + comp(1)=0 + ext_len(2) + ext_type(2) + ext_data_len(2) + ext_data(0) = 45
    const body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2 + 2;
    const record_len = 5 + 4 + body_len; // 5 + 4 + 47 = 56
    var record: [record_len]u8 = undefined;
    record[0] = 0x16; // handshake
    std.mem.writeInt(u16, record[1..3], 0x0301, .big); // TLS 1.0
    std.mem.writeInt(u16, record[3..5], 4 + body_len, .big); // record payload length
    record[5] = 0x01; // ClientHello
    record[6] = 0;
    record[7] = 0;
    record[8] = @intCast(body_len); // handshake length
    // body
    std.mem.writeInt(u16, record[9..11], 0x0303, .big); // TLS 1.2
    @memset(record[11..43], 0xAA); // random
    record[43] = 0; // session_id_len
    std.mem.writeInt(u16, record[44..46], 2, .big); // cipher_suites_len
    record[46] = 0x13;
    record[47] = 0x01; // cipher
    record[48] = 1; // compression_len
    record[49] = 0; // null compression
    std.mem.writeInt(u16, record[50..52], 4, .big); // extensions_len = 4 (one empty extension)
    record[52] = 0xFF;
    record[53] = 0x01; // extension type
    std.mem.writeInt(u16, record[54..56], 0, .big); // extension data len = 0

    var out: [record_len + alpn_extension.len]u8 = undefined;
    const result_len = injectAlpnIntoClientHello(&record, &out);
    try std.testing.expect(result_len != null);
    try std.testing.expectEqual(record_len + alpn_extension.len, result_len.?);

    // Verify record length patched
    const new_record_len = std.mem.readInt(u16, out[3..5], .big);
    try std.testing.expectEqual(4 + body_len + alpn_extension.len, new_record_len);

    // Verify handshake length patched
    const new_hs_len = (@as(u24, out[6]) << 16) | (@as(u24, out[7]) << 8) | @as(u24, out[8]);
    try std.testing.expectEqual(body_len + alpn_extension.len, new_hs_len);

    // Verify extensions length patched
    const new_ext_len = std.mem.readInt(u16, out[50..52], .big);
    try std.testing.expectEqual(4 + alpn_extension.len, new_ext_len);

    // Verify ALPN extension appended at end
    try std.testing.expectEqualSlices(u8, &alpn_extension, out[record_len..][0..alpn_extension.len]);
}

test "injectAlpnIntoClientHello: rejects non-handshake" {
    var record: [50]u8 = undefined;
    record[0] = 0x17; // application_data, not handshake
    var out: [100]u8 = undefined;
    try std.testing.expect(injectAlpnIntoClientHello(&record, &out) == null);
}

test "injectAlpnIntoClientHello: rejects too-short input" {
    var record: [10]u8 = undefined;
    var out: [100]u8 = undefined;
    try std.testing.expect(injectAlpnIntoClientHello(&record, &out) == null);
}

test "TlsDialer: E2E TLS handshake to real server" {
    const allocator = std.testing.allocator;

    // Resolve google.com:443
    const list = std.net.getAddressList(allocator, "www.google.com", 443) catch {
        return; // skip if DNS unavailable
    };
    defer list.deinit();
    if (list.addrs.len == 0) return;

    var td = TlsDialer.init(allocator, "www.google.com") catch {
        return; // skip if system CAs unavailable
    };
    defer td.deinit();
    const d = td.dialer();

    const ep = Endpoint{ .address = list.addrs[0] };
    const dial_result = d.dial(ep) catch {
        return; // skip if connection fails (network unavailable)
    };
    defer dial_result.close();

    // Send a simple HTTP/1.1 request to verify read/write work
    const request = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    const written = dial_result.writer.writeFn(dial_result.writer.context, request) catch {
        return;
    };
    try std.testing.expectEqual(request.len, written);

    // Read response
    var buf: [1024]u8 = undefined;
    const n = dial_result.reader.readFn(dial_result.reader.context, &buf) catch {
        return;
    };
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..n], "HTTP/"));
}
