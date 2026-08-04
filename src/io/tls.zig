const std = @import("std");
const crypto = std.crypto;
const Certificate = crypto.Certificate;

pub const TlsTransport = struct {
    tls_client: crypto.tls.Client,
    tcp_read_adapter: std.io.AnyReader.Adapter,
    tcp_write_adapter: std.io.AnyWriter.Adapter,

    pub const min_buffer_len = crypto.tls.max_ciphertext_record_len;

    pub const Options = struct {
        host: []const u8,
        ca: union(enum) {
            no_verification,
            bundle: Certificate.Bundle,
        } = .no_verification,
    };

    /// Initialize a TLS connection over an existing TCP transport.
    /// Uses prior knowledge mode (no ALPN) — server must accept h2 without negotiation.
    ///
    /// IMPORTANT: `self` must be at its final address before calling this function.
    /// The TLS client stores pointers into `self`'s adapter fields — moving `self`
    /// after init would create dangling pointers.
    ///
    /// Buffers (caller-owned, must outlive TlsTransport):
    /// - `tcp_read_buf`: adapter buffer for reading encrypted data from TCP (>= min_buffer_len)
    /// - `tcp_write_buf`: adapter buffer for writing encrypted data to TCP
    /// - `tls_read_buf`: internal buffer for TLS Client's decrypted reader (>= min_buffer_len)
    /// - `tls_write_buf`: internal buffer for TLS Client's plaintext writer
    pub fn init(
        self: *TlsTransport,
        tcp_reader: std.io.AnyReader,
        tcp_writer: std.io.AnyWriter,
        tcp_read_buf: []u8,
        tcp_write_buf: []u8,
        tls_read_buf: []u8,
        tls_write_buf: []u8,
        options: Options,
    ) !void {
        self.tcp_read_adapter = tcp_reader.adaptToNewApi(tcp_read_buf);
        self.tcp_write_adapter = tcp_writer.adaptToNewApi(tcp_write_buf);

        const tls_options: crypto.tls.Client.Options = .{
            .host = switch (options.host.len) {
                0 => .no_verification,
                else => .{ .explicit = options.host },
            },
            .ca = switch (options.ca) {
                .no_verification => .no_verification,
                .bundle => |b| .{ .bundle = b },
            },
            .read_buffer = tls_read_buf,
            .write_buffer = tls_write_buf,
        };

        self.tls_client = try crypto.tls.Client.init(
            &self.tcp_read_adapter.new_interface,
            &self.tcp_write_adapter.new_interface,
            tls_options,
        );
    }

    /// Send TLS close_notify and clean up.
    pub fn close(self: *TlsTransport) void {
        self.tls_client.writer.flush() catch {};
        // close_notify is best-effort; TCP close will follow
    }

    /// Get an AnyReader that reads decrypted TLS data.
    pub fn reader(self: *TlsTransport) std.io.AnyReader {
        return self.tls_client.reader.adaptToOldInterface();
    }

    /// Get an AnyWriter that writes plaintext data through TLS encryption.
    pub fn writer(self: *TlsTransport) std.io.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = tlsWriteFn };
    }

    fn tlsWriteFn(ctx: *const anyopaque, data: []const u8) anyerror!usize {
        const self: *TlsTransport = @constCast(@alignCast(@ptrCast(ctx)));
        self.tls_client.writer.writeAll(data) catch return error.WriteFailed;
        self.tls_client.writer.flush() catch return error.WriteFailed;
        return data.len;
    }
};
