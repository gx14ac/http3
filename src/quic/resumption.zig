const std = @import("std");
const quic_crypto = @import("crypto.zig");
const tls_messages = @import("tls_messages.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

// ─── Session Ticket (RFC 8446 §4.6.1) ───

pub const SessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: [255]u8,
    ticket_nonce_len: u8,
    ticket: [1024]u8,
    ticket_len: u16,
    max_early_data_size: u32,
    psk: [32]u8,
    server_name: [256]u8,
    server_name_len: u8,
    received_at_ms: i64,
};

/// Parse a NewSessionTicket message from TLS 1.3 post-handshake data.
/// Returns the parsed ticket fields (without PSK — caller must compute).
pub fn parseNewSessionTicket(payload: []const u8) ?ParsedTicket {
    if (payload.len < 12) return null;

    const lifetime = std.mem.readInt(u32, payload[0..4], .big);
    const age_add = std.mem.readInt(u32, payload[4..8], .big);

    const nonce_len = payload[8];
    if (payload.len < 9 + @as(usize, nonce_len) + 2) return null;
    const nonce_start: usize = 9;
    const nonce_end = nonce_start + nonce_len;

    const ticket_len_raw = std.mem.readInt(u16, payload[nonce_end..][0..2], .big);
    const ticket_start = nonce_end + 2;
    const ticket_end = ticket_start + @as(usize, ticket_len_raw);
    if (payload.len < ticket_end) return null;

    // Extensions follow the ticket (RFC 8446 §4.6.1)
    var max_early_data: u32 = 0;
    if (payload.len >= ticket_end + 2) {
        const ext_len = std.mem.readInt(u16, payload[ticket_end..][0..2], .big);
        const ext_start = ticket_end + 2;
        const ext_end = ext_start + @as(usize, ext_len);
        if (payload.len >= ext_end) {
            max_early_data = parseEarlyDataExtension(payload[ext_start..ext_end]);
        }
    }

    var result: ParsedTicket = undefined;
    result.lifetime = lifetime;
    result.age_add = age_add;
    result.nonce_len = nonce_len;
    @memcpy(result.nonce[0..nonce_len], payload[nonce_start..nonce_end]);
    result.ticket_len = ticket_len_raw;
    if (ticket_len_raw > 1024) return null;
    @memcpy(result.ticket[0..ticket_len_raw], payload[ticket_start..ticket_end]);
    result.max_early_data_size = max_early_data;

    return result;
}

pub const ParsedTicket = struct {
    lifetime: u32,
    age_add: u32,
    nonce: [255]u8,
    nonce_len: u8,
    ticket: [1024]u8,
    ticket_len: u16,
    max_early_data_size: u32,
};

fn parseEarlyDataExtension(data: []const u8) u32 {
    var pos: usize = 0;
    while (pos + 4 <= data.len) {
        const ext_type = std.mem.readInt(u16, data[pos..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        pos += 4;
        if (ext_type == 0x002a and ext_data_len == 4 and pos + 4 <= data.len) {
            return std.mem.readInt(u32, data[pos..][0..4], .big);
        }
        pos += ext_data_len;
    }
    return 0;
}

// ─── Key Derivation for Resumption (RFC 8446 §7.1) ───

/// Derive resumption_master_secret from master_secret and full transcript hash.
/// resumption_master_secret = Derive-Secret(master_secret, "res master", transcript_hash_full)
pub fn deriveResumptionMasterSecret(master_secret: [32]u8, transcript_hash_full: [32]u8) [32]u8 {
    var rms: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&rms, &master_secret, "res master", &transcript_hash_full);
    return rms;
}

/// Compute PSK from resumption_master_secret and ticket_nonce.
/// PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)
pub fn computePsk(resumption_master_secret: [32]u8, ticket_nonce: []const u8) [32]u8 {
    var psk: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&psk, &resumption_master_secret, "resumption", ticket_nonce);
    return psk;
}

/// Derive early_secret and 0-RTT keys from PSK.
/// early_secret = HKDF-Extract(0, PSK)
/// client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", CH_hash)
pub fn deriveEarlySecret(psk: [32]u8) [32]u8 {
    var early_secret: [32]u8 = undefined;
    const zero_salt = [_]u8{0} ** 32;
    quic_crypto.hkdfExtract(&early_secret, &zero_salt, &psk);
    return early_secret;
}

/// Derive 0-RTT QUIC keys from early_secret and ClientHello hash.
pub const EarlyKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub fn deriveEarlyKeys(early_secret: [32]u8, client_hello_hash: [32]u8) EarlyKeys {
    var client_early_secret: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&client_early_secret, &early_secret, "c e traffic", &client_hello_hash);

    var keys: EarlyKeys = undefined;
    quic_crypto.hkdfExpandLabel(&keys.key, &client_early_secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&keys.iv, &client_early_secret, "quic iv", "");
    quic_crypto.hkdfExpandLabel(&keys.hp, &client_early_secret, "quic hp", "");
    return keys;
}

// ─── Session Ticket Store ───

pub const MAX_TICKETS = 4;

pub const TicketStore = struct {
    tickets: [MAX_TICKETS]?SessionTicket,
    count: usize,

    pub fn init() TicketStore {
        return .{
            .tickets = [_]?SessionTicket{null} ** MAX_TICKETS,
            .count = 0,
        };
    }

    /// Store a session ticket for a given server.
    pub fn store(self: *TicketStore, ticket: SessionTicket) void {
        // Find existing slot for same server or use empty/oldest
        var target: usize = 0;
        var oldest_time: i64 = std.math.maxInt(i64);

        for (&self.tickets, 0..) |*t, i| {
            if (t.*) |existing| {
                if (std.mem.eql(u8, existing.server_name[0..existing.server_name_len], ticket.server_name[0..ticket.server_name_len])) {
                    target = i;
                    break;
                }
                if (existing.received_at_ms < oldest_time) {
                    oldest_time = existing.received_at_ms;
                    target = i;
                }
            } else {
                target = i;
                break;
            }
        }

        const was_empty = self.tickets[target] == null;
        self.tickets[target] = ticket;
        if (was_empty and self.count < MAX_TICKETS) self.count += 1;
    }

    /// Look up a valid ticket for the given server name.
    /// Returns null if no valid (non-expired) ticket exists.
    pub fn lookup(self: *const TicketStore, server_name: []const u8, now_ms: i64) ?*const SessionTicket {
        for (&self.tickets) |*slot| {
            if (slot.*) |*t| {
                if (!std.mem.eql(u8, t.server_name[0..t.server_name_len], server_name)) continue;
                const age_ms = now_ms - t.received_at_ms;
                if (age_ms < 0) continue;
                if (age_ms > @as(i64, t.ticket_lifetime) * 1000) continue;
                return t;
            }
        }
        return null;
    }

    /// Remove tickets for a given server.
    pub fn remove(self: *TicketStore, server_name: []const u8) void {
        for (&self.tickets) |*slot| {
            if (slot.*) |t| {
                if (std.mem.eql(u8, t.server_name[0..t.server_name_len], server_name)) {
                    slot.* = null;
                    if (self.count > 0) self.count -= 1;
                }
            }
        }
    }
};

// ─── PSK ClientHello Extension Builder (RFC 8446 §4.2.11) ───

/// Build the pre_shared_key extension for ClientHello.
/// Returns bytes written, or null if buffer too small.
/// The binder is computed as HMAC(binder_key, transcript_hash_truncated).
pub fn buildPskExtension(
    buf: []u8,
    ticket: []const u8,
    obfuscated_ticket_age: u32,
    binder: [32]u8,
) ?usize {
    // pre_shared_key extension structure:
    //   extension_type (2) = 0x0029
    //   extension_data_length (2)
    //     identities_length (2)
    //       identity_length (2) + identity + obfuscated_ticket_age (4)
    //     binders_length (2)
    //       binder_length (1) + binder (32)
    const identity_entry_len = 2 + ticket.len + 4;
    const identities_len = identity_entry_len;
    const binders_len: usize = 1 + 32;
    const ext_data_len = 2 + identities_len + 2 + binders_len;
    const total = 4 + ext_data_len;

    if (buf.len < total) return null;
    var pos: usize = 0;

    // Extension type
    std.mem.writeInt(u16, buf[pos..][0..2], 0x0029, .big);
    pos += 2;
    // Extension data length
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ext_data_len), .big);
    pos += 2;
    // Identities length
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(identities_len), .big);
    pos += 2;
    // Identity length + identity
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(ticket.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..ticket.len], ticket);
    pos += ticket.len;
    // Obfuscated ticket age
    std.mem.writeInt(u32, buf[pos..][0..4], obfuscated_ticket_age, .big);
    pos += 4;
    // Binders length
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(binders_len), .big);
    pos += 2;
    // Binder entry
    buf[pos] = 32;
    pos += 1;
    @memcpy(buf[pos..][0..32], &binder);
    pos += 32;

    return pos;
}

/// Build early_data extension (empty, just type + zero length).
pub fn buildEarlyDataExtension(buf: []u8) ?usize {
    if (buf.len < 4) return null;
    std.mem.writeInt(u16, buf[0..2], 0x002a, .big);
    std.mem.writeInt(u16, buf[2..4], 0, .big);
    return 4;
}

/// Compute the PSK binder value.
/// binder_key = Derive-Secret(early_secret, "res binder", "")
/// binder = HMAC(binder_key, transcript_hash_truncated)
/// where transcript_hash_truncated = Hash(partial_ClientHello up to but not including binders)
pub fn computeBinder(early_secret: [32]u8, transcript_hash_truncated: [32]u8) [32]u8 {
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});

    var binder_key: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&binder_key, &early_secret, "res binder", &empty_hash);

    // Finished-style computation: HMAC(finished_key, transcript)
    var finished_key: [32]u8 = undefined;
    quic_crypto.hkdfExpandLabel(&finished_key, &binder_key, "finished", "");

    var binder: [32]u8 = undefined;
    HmacSha256.create(&binder, &transcript_hash_truncated, &finished_key);
    return binder;
}

/// Compute obfuscated_ticket_age per RFC 8446 §4.2.11.2:
/// obfuscated_ticket_age = (now_ms - received_at_ms) + ticket_age_add
pub fn obfuscatedTicketAge(received_at_ms: i64, now_ms: i64, age_add: u32) u32 {
    const diff = @max(now_ms - received_at_ms, 0);
    const age_ms: u32 = @truncate(@as(u64, @intCast(diff)));
    return age_ms +% age_add;
}

// ─── 0-RTT Packet Encoding ───

/// Encode a 0-RTT Long Header packet.
/// Type = 1 (0-RTT), encrypted with early keys.
pub fn encode0RttPacket(
    buf: []u8,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
) ?usize {
    const packet_mod = @import("packet.zig");

    var pos: usize = 0;
    const pn_len: u8 = if (packet_number < 256) 0 else if (packet_number < 65536) 1 else 3;
    const pn_bytes: u8 = pn_len + 1;

    // First byte: Long header, type=1 (0-RTT)
    buf[pos] = 0xC0 | (1 << 4) | pn_len;
    pos += 1;

    // Version
    std.mem.writeInt(u32, buf[pos..][0..4], packet_mod.QUIC_VERSION_1, .big);
    pos += 4;

    // DCID
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos..][0..dcid.len], dcid);
    pos += dcid.len;

    // SCID
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos..][0..scid.len], scid);
    pos += scid.len;

    // Length: pn_bytes + payload + 16 (AEAD tag)
    const length_val: usize = @as(usize, pn_bytes) + payload.len + 16;
    pos += packet_mod.encodeVarint(buf[pos..], length_val) orelse return null;

    // Packet number
    const pn_offset = pos;
    var pn_i: u8 = 0;
    while (pn_i < pn_bytes) : (pn_i += 1) {
        buf[pos] = @intCast((packet_number >> @intCast((pn_bytes - 1 - pn_i) * 8)) & 0xFF);
        pos += 1;
    }

    // Encrypt payload
    const aad = buf[0..pos];
    var ciphertext: [4096]u8 = undefined;
    var tag: [16]u8 = undefined;
    if (payload.len > ciphertext.len) return null;
    quic_crypto.encryptPayload(ciphertext[0..payload.len], &tag, payload, key, iv, packet_number, aad);

    @memcpy(buf[pos..][0..payload.len], ciphertext[0..payload.len]);
    pos += payload.len;
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    // Header protection
    quic_crypto.applyHeaderProtection(buf[0..pos], pn_offset, hp);

    return pos;
}

// ─── Tests ───

test "parseNewSessionTicket: valid ticket" {
    // Build a minimal NewSessionTicket message
    var msg: [64]u8 = undefined;
    var pos: usize = 0;

    // lifetime = 7200
    std.mem.writeInt(u32, msg[pos..][0..4], 7200, .big);
    pos += 4;
    // age_add = 0xDEADBEEF
    std.mem.writeInt(u32, msg[pos..][0..4], 0xDEADBEEF, .big);
    pos += 4;
    // nonce_len = 2, nonce = {0x01, 0x02}
    msg[pos] = 2;
    pos += 1;
    msg[pos] = 0x01;
    msg[pos + 1] = 0x02;
    pos += 2;
    // ticket_len = 4, ticket = "ABCD"
    std.mem.writeInt(u16, msg[pos..][0..2], 4, .big);
    pos += 2;
    @memcpy(msg[pos..][0..4], "ABCD");
    pos += 4;
    // extensions_len = 0
    std.mem.writeInt(u16, msg[pos..][0..2], 0, .big);
    pos += 2;

    const parsed = parseNewSessionTicket(msg[0..pos]) orelse unreachable;
    try std.testing.expectEqual(@as(u32, 7200), parsed.lifetime);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), parsed.age_add);
    try std.testing.expectEqual(@as(u8, 2), parsed.nonce_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, parsed.nonce[0..2]);
    try std.testing.expectEqual(@as(u16, 4), parsed.ticket_len);
    try std.testing.expectEqualSlices(u8, "ABCD", parsed.ticket[0..4]);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_early_data_size);
}

test "parseNewSessionTicket: with early_data extension" {
    var msg: [80]u8 = undefined;
    var pos: usize = 0;

    std.mem.writeInt(u32, msg[pos..][0..4], 3600, .big);
    pos += 4;
    std.mem.writeInt(u32, msg[pos..][0..4], 0x12345678, .big);
    pos += 4;
    msg[pos] = 0;
    pos += 1; // nonce_len=0
    std.mem.writeInt(u16, msg[pos..][0..2], 3, .big);
    pos += 2;
    @memcpy(msg[pos..][0..3], "XYZ");
    pos += 3;

    // Extensions: early_data (0x002a) with max_early_data_size=16384
    std.mem.writeInt(u16, msg[pos..][0..2], 8, .big);
    pos += 2; // extensions length
    std.mem.writeInt(u16, msg[pos..][0..2], 0x002a, .big);
    pos += 2; // ext type
    std.mem.writeInt(u16, msg[pos..][0..2], 4, .big);
    pos += 2; // ext data len
    std.mem.writeInt(u32, msg[pos..][0..4], 16384, .big);
    pos += 4;

    const parsed = parseNewSessionTicket(msg[0..pos]) orelse unreachable;
    try std.testing.expectEqual(@as(u32, 16384), parsed.max_early_data_size);
}

test "deriveResumptionMasterSecret: deterministic" {
    const master = [_]u8{0xAA} ** 32;
    const transcript = [_]u8{0xBB} ** 32;
    const rms1 = deriveResumptionMasterSecret(master, transcript);
    const rms2 = deriveResumptionMasterSecret(master, transcript);
    try std.testing.expectEqualSlices(u8, &rms1, &rms2);
}

test "computePsk: deterministic" {
    const rms = [_]u8{0xCC} ** 32;
    const nonce = [_]u8{ 0x01, 0x02, 0x03 };
    const psk1 = computePsk(rms, &nonce);
    const psk2 = computePsk(rms, &nonce);
    try std.testing.expectEqualSlices(u8, &psk1, &psk2);
}

test "computePsk: different nonces produce different PSKs" {
    const rms = [_]u8{0xDD} ** 32;
    const n1 = [_]u8{0x01};
    const n2 = [_]u8{0x02};
    const psk1 = computePsk(rms, &n1);
    const psk2 = computePsk(rms, &n2);
    try std.testing.expect(!std.mem.eql(u8, &psk1, &psk2));
}

test "deriveEarlyKeys: produces non-zero keys" {
    const psk = [_]u8{0xEE} ** 32;
    const early_secret = deriveEarlySecret(psk);
    const ch_hash = [_]u8{0xFF} ** 32;
    const keys = deriveEarlyKeys(early_secret, ch_hash);
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &([_]u8{0} ** 16)));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &([_]u8{0} ** 12)));
    try std.testing.expect(!std.mem.eql(u8, &keys.hp, &([_]u8{0} ** 16)));
}

test "TicketStore: store and lookup" {
    var store = TicketStore.init();
    var ticket: SessionTicket = undefined;
    ticket.ticket_lifetime = 7200;
    ticket.ticket_age_add = 1000;
    ticket.ticket_nonce_len = 1;
    ticket.ticket_nonce[0] = 0x42;
    ticket.ticket_len = 4;
    @memcpy(ticket.ticket[0..4], "TEST");
    ticket.max_early_data_size = 16384;
    ticket.psk = [_]u8{0xAA} ** 32;
    ticket.server_name_len = 11;
    @memcpy(ticket.server_name[0..11], "example.com");
    ticket.received_at_ms = 1000;

    store.store(ticket);
    try std.testing.expectEqual(@as(usize, 1), store.count);

    const found = store.lookup("example.com", 2000) orelse unreachable;
    try std.testing.expectEqual(@as(u32, 7200), found.ticket_lifetime);

    // Not found for different server
    try std.testing.expect(store.lookup("other.com", 2000) == null);
}

test "TicketStore: expired ticket not returned" {
    var store = TicketStore.init();
    var ticket: SessionTicket = undefined;
    ticket.ticket_lifetime = 1; // 1 second
    ticket.ticket_age_add = 0;
    ticket.ticket_nonce_len = 0;
    ticket.ticket_len = 2;
    @memcpy(ticket.ticket[0..2], "TK");
    ticket.max_early_data_size = 0;
    ticket.psk = [_]u8{0} ** 32;
    ticket.server_name_len = 4;
    @memcpy(ticket.server_name[0..4], "test");
    ticket.received_at_ms = 0;

    store.store(ticket);

    // 2 seconds later — expired (lifetime=1s → 1000ms)
    try std.testing.expect(store.lookup("test", 2000) == null);
    // Within lifetime
    try std.testing.expect(store.lookup("test", 500) != null);
}

test "buildPskExtension: produces correct structure" {
    const ticket_data = "SESSION_TICKET";
    const binder = [_]u8{0xBB} ** 32;
    var buf: [256]u8 = undefined;

    const len = buildPskExtension(&buf, ticket_data, 42, binder) orelse unreachable;
    try std.testing.expect(len > 0);

    // Extension type = 0x0029
    try std.testing.expectEqual(@as(u16, 0x0029), std.mem.readInt(u16, buf[0..2], .big));
}

test "buildEarlyDataExtension: 4 bytes" {
    var buf: [8]u8 = undefined;
    const len = buildEarlyDataExtension(&buf) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 4), len);
    try std.testing.expectEqual(@as(u16, 0x002a), std.mem.readInt(u16, buf[0..2], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, buf[2..4], .big));
}

test "computeBinder: deterministic" {
    const early_secret = [_]u8{0x11} ** 32;
    const hash = [_]u8{0x22} ** 32;
    const b1 = computeBinder(early_secret, hash);
    const b2 = computeBinder(early_secret, hash);
    try std.testing.expectEqualSlices(u8, &b1, &b2);
}

test "obfuscatedTicketAge: wrapping addition" {
    const age = obfuscatedTicketAge(0, 1000, 0xFFFFFF00);
    // 1000 + 0xFFFFFF00 wraps around u32
    const expected: u32 = @as(u32, 0xFFFFFF00) +% 1000;
    try std.testing.expectEqual(expected, age);
}

test "encode0RttPacket: produces valid packet" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06 };
    const key = [_]u8{0xAA} ** 16;
    const iv = [_]u8{0xBB} ** 12;
    const hp = [_]u8{0xCC} ** 16;
    const payload = "early data payload";

    var buf: [256]u8 = undefined;
    const len = encode0RttPacket(&buf, &dcid, &scid, 0, payload, key, iv, hp) orelse unreachable;
    try std.testing.expect(len > 0);
    // Form bit set (long header)
    try std.testing.expect(buf[0] & 0x80 != 0);
}
