// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const resolver_mod = @import("resolver.zig");
const dialer_mod = @import("dialer.zig");
const Endpoint = resolver_mod.Endpoint;
const DialError = dialer_mod.DialError;
const DialResult = dialer_mod.DialResult;
const Dialer = dialer_mod.Dialer;

pub const TlsDialer = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    ca_bundle: Certificate.Bundle,
    insecure: bool = false,
    owns_bundle: bool = false,

    pub fn init(allocator: std.mem.Allocator, host: []const u8) DialError!TlsDialer {
        const Io = std.Io;
        const io: Io = Io.Threaded.global_single_threaded.io();
        var bundle: Certificate.Bundle = .empty;
        const now = Io.Timestamp.now(io, .real);
        bundle.rescan(allocator, io, now) catch return DialError.IoError;
        return .{ .allocator = allocator, .host = host, .ca_bundle = bundle, .owns_bundle = true };
    }

    pub fn initInsecure(allocator: std.mem.Allocator, host: []const u8) TlsDialer {
        return .{ .allocator = allocator, .host = host, .ca_bundle = .empty, .insecure = true };
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

    fn dialFn(_: *anyopaque, _: Endpoint) DialError!DialResult {
        return DialError.ConnectionRefused;
    }
};
