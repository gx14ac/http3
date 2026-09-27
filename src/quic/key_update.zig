// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const quic_crypto = @import("crypto.zig");

/// Application traffic secret (32 bytes for SHA-256 based TLS 1.3).
pub const TrafficSecret = [32]u8;

/// A key generation: key + IV derived from a traffic secret.
/// HP key does NOT rotate on Key Update (RFC 9001 §6.6).
pub const KeyGeneration = struct {
    key: [16]u8,
    iv: [12]u8,
};

/// Derive the next-generation traffic secret (RFC 9001 §6.1):
///   next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", 32)
pub fn updateTrafficSecret(current: *const TrafficSecret) TrafficSecret {
    var next: TrafficSecret = undefined;
    quic_crypto.hkdfExpandLabel(&next, current, "quic ku", "");
    return next;
}

/// Derive key + IV from a traffic secret (same as initial derivation).
pub fn deriveKeyIv(secret: *const TrafficSecret) KeyGeneration {
    var gen: KeyGeneration = undefined;
    quic_crypto.hkdfExpandLabel(&gen.key, secret, "quic key", "");
    quic_crypto.hkdfExpandLabel(&gen.iv, secret, "quic iv", "");
    return gen;
}

/// Manages key phase transitions for a QUIC 1-RTT connection.
///
/// RFC 9001 §6 Key Update:
/// - Either endpoint can initiate by flipping the Key Phase bit
/// - Receiver detects phase change → derives new keys → decrypts
/// - Old keys retained for 1 PTO (handles reordered packets)
/// - At most one key update in flight at a time
pub const KeyUpdateManager = struct {
    // Current generation secrets
    client_secret: TrafficSecret,
    server_secret: TrafficSecret,

    // Current key phase (bit value in Short Header)
    key_phase: u1,

    // Current generation keys (for sending / receiving current phase)
    current_client: KeyGeneration,
    current_server: KeyGeneration,

    // Previous generation keys (for receiving old-phase packets)
    prev_server: ?KeyGeneration,

    // Cached next-gen server keys (avoids re-deriving per reordered packet)
    next_server_cache: ?KeyGeneration,
    next_server_secret_cache: ?TrafficSecret,

    // HP keys (never change)
    client_hp: [16]u8,
    server_hp: [16]u8,

    // Timer: when prev keys should be discarded (in microseconds)
    prev_expire_us: ?u64,

    // Guard: cannot initiate another update while one is pending
    update_pending: bool,

    // First PN sent in the new key phase (for ACK confirmation, RFC 9001 §6)
    first_pn_in_new_phase: ?u64,

    // Largest PN successfully decrypted per phase (RFC 9001 §6.2 replay protection)
    largest_pn_current_phase: ?u64,
    largest_pn_prev_phase: ?u64,

    // Generation counter (for debugging/logging)
    generation: u32,

    pub fn init(
        client_secret: TrafficSecret,
        server_secret: TrafficSecret,
        client_hp: [16]u8,
        server_hp: [16]u8,
    ) KeyUpdateManager {
        const client_gen = deriveKeyIv(&client_secret);
        const server_gen = deriveKeyIv(&server_secret);

        return .{
            .client_secret = client_secret,
            .server_secret = server_secret,
            .key_phase = 0,
            .current_client = client_gen,
            .current_server = server_gen,
            .prev_server = null,
            .next_server_cache = null,
            .next_server_secret_cache = null,
            .client_hp = client_hp,
            .server_hp = server_hp,
            .prev_expire_us = null,
            .update_pending = false,
            .first_pn_in_new_phase = null,
            .largest_pn_current_phase = null,
            .largest_pn_prev_phase = null,
            .generation = 0,
        };
    }

    /// Get the current send keys (key, iv, hp, key_phase).
    pub fn sendKeys(self: *const KeyUpdateManager) SendKeys {
        return .{
            .key = self.current_client.key,
            .iv = self.current_client.iv,
            .hp = self.client_hp,
            .key_phase = self.key_phase,
        };
    }

    /// Initiate a Key Update (RFC 9001 §6.1).
    /// `first_pn` is the PN that will be used for the first packet in the new phase.
    /// Returns false if an update is already in flight.
    pub fn initiateUpdate(self: *KeyUpdateManager, first_pn: u64, now_us: u64, pto_us: u64) bool {
        if (self.update_pending) return false;

        // Rotate server keys to prev (for decrypting reordered old-phase packets)
        self.prev_server = self.current_server;
        self.prev_expire_us = now_us + pto_us;
        self.largest_pn_prev_phase = self.largest_pn_current_phase;
        self.largest_pn_current_phase = null;

        // Derive next secrets
        self.client_secret = updateTrafficSecret(&self.client_secret);
        self.server_secret = updateTrafficSecret(&self.server_secret);

        // Derive next keys
        self.current_client = deriveKeyIv(&self.client_secret);
        self.current_server = deriveKeyIv(&self.server_secret);

        // Invalidate next-gen cache (it was for the old generation's next)
        self.next_server_cache = null;
        self.next_server_secret_cache = null;

        // Flip phase
        self.key_phase ^= 1;
        self.generation += 1;
        self.update_pending = true;
        self.first_pn_in_new_phase = first_pn;

        return true;
    }

    /// Try to confirm the pending key update based on received ACK.
    /// RFC 9001 §6: update is confirmed when peer ACKs a packet sent in the new phase.
    /// Returns true if confirmation happened.
    pub fn tryConfirmUpdate(self: *KeyUpdateManager, largest_acked: u64) bool {
        if (!self.update_pending) return false;
        const first_pn = self.first_pn_in_new_phase orelse return false;
        if (largest_acked >= first_pn) {
            self.update_pending = false;
            self.first_pn_in_new_phase = null;
            return true;
        }
        return false;
    }

    /// Try to decrypt a received packet. Handles key phase detection.
    /// Returns the decrypted plaintext length, or null on failure.
    ///
    /// Logic (RFC 9001 §6.2):
    /// - If received key_phase matches current → use current_server
    /// - If received key_phase differs:
    ///   1. Try prev generation first (likely reordered old-phase packet)
    ///   2. Then try next generation (peer-initiated key update)
    pub fn tryDecrypt(
        self: *KeyUpdateManager,
        out: []u8,
        ciphertext: []const u8,
        tag: [16]u8,
        pn: u64,
        aad: []const u8,
        received_key_phase: u1,
        now_us: u64,
        pto_us: u64,
    ) ?usize {
        if (received_key_phase == self.key_phase) {
            // Same phase — use current server keys
            if (quic_crypto.decryptPayload(out[0..ciphertext.len], ciphertext, tag, self.current_server.key, self.current_server.iv, pn, aad)) {
                self.updateLargestPn(&self.largest_pn_current_phase, pn);
                return ciphertext.len;
            }
        } else {
            // Different phase — try prev first (reordered old packet is more common)
            if (self.prev_server) |prev| {
                if (quic_crypto.decryptPayload(out[0..ciphertext.len], ciphertext, tag, prev.key, prev.iv, pn, aad)) {
                    self.updateLargestPn(&self.largest_pn_prev_phase, pn);
                    return ciphertext.len;
                }
            }

            // Try next generation (peer-initiated key update)
            // Use cached next-gen keys to avoid re-deriving per packet
            const next_secret = self.next_server_secret_cache orelse blk: {
                const s = updateTrafficSecret(&self.server_secret);
                self.next_server_secret_cache = s;
                break :blk s;
            };
            const next_gen = self.next_server_cache orelse blk: {
                const g = deriveKeyIv(&next_secret);
                self.next_server_cache = g;
                break :blk g;
            };

            if (quic_crypto.decryptPayload(out[0..ciphertext.len], ciphertext, tag, next_gen.key, next_gen.iv, pn, aad)) {
                // Success — accept peer's key update
                self.prev_server = self.current_server;
                self.prev_expire_us = now_us + pto_us;
                self.largest_pn_prev_phase = self.largest_pn_current_phase;
                self.largest_pn_current_phase = pn;

                self.server_secret = next_secret;
                self.current_server = next_gen;

                // Also advance our client secret and keys
                self.client_secret = updateTrafficSecret(&self.client_secret);
                self.current_client = deriveKeyIv(&self.client_secret);

                // Invalidate next-gen cache
                self.next_server_cache = null;
                self.next_server_secret_cache = null;

                self.key_phase ^= 1;
                self.generation += 1;
                self.update_pending = false;
                self.first_pn_in_new_phase = null;

                return ciphertext.len;
            }
        }

        return null;
    }

    /// Expire old keys if the timer has passed.
    /// Should be called periodically (e.g., on every packet receive).
    pub fn expireOldKeys(self: *KeyUpdateManager, now_us: u64) void {
        if (self.prev_expire_us) |expire| {
            if (now_us >= expire) {
                self.prev_server = null;
                self.prev_expire_us = null;
                self.largest_pn_prev_phase = null;
            }
        }
    }

    fn updateLargestPn(_: *KeyUpdateManager, field: *?u64, pn: u64) void {
        if (field.*) |current| {
            if (pn > current) field.* = pn;
        } else {
            field.* = pn;
        }
    }
};

/// Keys needed for sending a 1-RTT packet.
pub const SendKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
    key_phase: u1,
};

// ─── Tests ───

test "updateTrafficSecret: deterministic" {
    const secret = [_]u8{0xAA} ** 32;
    const next1 = updateTrafficSecret(&secret);
    const next2 = updateTrafficSecret(&secret);
    try std.testing.expectEqualSlices(u8, &next1, &next2);
}

test "updateTrafficSecret: produces different output" {
    const secret = [_]u8{0xBB} ** 32;
    const next = updateTrafficSecret(&secret);
    try std.testing.expect(!std.mem.eql(u8, &secret, &next));
}

test "deriveKeyIv: deterministic" {
    const secret = [_]u8{0xCC} ** 32;
    const gen1 = deriveKeyIv(&secret);
    const gen2 = deriveKeyIv(&secret);
    try std.testing.expectEqualSlices(u8, &gen1.key, &gen2.key);
    try std.testing.expectEqualSlices(u8, &gen1.iv, &gen2.iv);
}

test "KeyUpdateManager: init produces valid send keys" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;

    const mgr = KeyUpdateManager.init(cs, ss, chp, shp);
    const sk = mgr.sendKeys();
    try std.testing.expectEqual(@as(u1, 0), sk.key_phase);
    try std.testing.expectEqualSlices(u8, &chp, &sk.hp);
    // key/iv should be derived from client_secret
    const expected = deriveKeyIv(&cs);
    try std.testing.expectEqualSlices(u8, &expected.key, &sk.key);
    try std.testing.expectEqualSlices(u8, &expected.iv, &sk.iv);
}

test "KeyUpdateManager: initiateUpdate flips phase" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    var mgr = KeyUpdateManager.init(cs, ss, [_]u8{0} ** 16, [_]u8{0} ** 16);

    try std.testing.expectEqual(@as(u1, 0), mgr.key_phase);
    try std.testing.expectEqual(@as(u32, 0), mgr.generation);

    const ok = mgr.initiateUpdate(10, 1_000_000, 100_000);
    try std.testing.expect(ok);
    try std.testing.expectEqual(@as(u1, 1), mgr.key_phase);
    try std.testing.expectEqual(@as(u32, 1), mgr.generation);
    try std.testing.expect(mgr.update_pending);
    try std.testing.expect(mgr.prev_server != null);
    try std.testing.expectEqual(@as(?u64, 10), mgr.first_pn_in_new_phase);
}

test "KeyUpdateManager: cannot double-initiate, tryConfirmUpdate gates" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    var mgr = KeyUpdateManager.init(cs, ss, [_]u8{0} ** 16, [_]u8{0} ** 16);

    try std.testing.expect(mgr.initiateUpdate(5, 1_000_000, 100_000));
    try std.testing.expect(!mgr.initiateUpdate(6, 1_050_000, 100_000)); // blocked

    // ACK for PN 4 (before new phase) — should NOT confirm
    try std.testing.expect(!mgr.tryConfirmUpdate(4));
    try std.testing.expect(mgr.update_pending);

    // ACK for PN 5 (first in new phase) — confirms
    try std.testing.expect(mgr.tryConfirmUpdate(5));
    try std.testing.expect(!mgr.update_pending);

    // Now can initiate again
    try std.testing.expect(mgr.initiateUpdate(20, 1_200_000, 100_000));
}

test "KeyUpdateManager: expireOldKeys clears prev" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    var mgr = KeyUpdateManager.init(cs, ss, [_]u8{0} ** 16, [_]u8{0} ** 16);

    _ = mgr.initiateUpdate(0, 1_000_000, 100_000);
    try std.testing.expect(mgr.prev_server != null);

    mgr.expireOldKeys(1_050_000); // not yet
    try std.testing.expect(mgr.prev_server != null);

    mgr.expireOldKeys(1_100_000); // exactly at expiry
    try std.testing.expect(mgr.prev_server == null);
}

test "KeyUpdateManager: encrypt/decrypt roundtrip with current keys" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    const chp = [_]u8{0x33} ** 16;
    const shp = [_]u8{0x44} ** 16;

    // Simulate two endpoints: client and server
    var client = KeyUpdateManager.init(cs, ss, chp, shp);
    var server = KeyUpdateManager.init(ss, cs, shp, chp); // swapped roles

    const plaintext = "hello key update";
    const pn: u64 = 42;
    const aad = [_]u8{ 0x40, 0x01, 0x02, 0x03 };

    // Client encrypts
    const sk = client.sendKeys();
    var ciphertext: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ciphertext, &tag, plaintext, sk.key, sk.iv, pn, &aad);

    // Server decrypts (server's "current_server" = client's send keys role)
    // For this test, server sees client_secret as its server_secret
    var out: [16]u8 = undefined;
    const result = server.tryDecrypt(&out, &ciphertext, tag, pn, &aad, sk.key_phase, 1_000_000, 100_000);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(plaintext, out[0..result.?]);
}

test "KeyUpdateManager: peer-initiated update accepted" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    const hp = [_]u8{0} ** 16;

    var mgr = KeyUpdateManager.init(cs, ss, hp, hp);
    try std.testing.expectEqual(@as(u1, 0), mgr.key_phase);

    // Simulate peer sending with flipped phase: peer advances its send secret
    // Peer's send secret (= our server_secret) after update:
    const next_server_secret = updateTrafficSecret(&ss);
    const next_gen = deriveKeyIv(&next_server_secret);

    // Encrypt a packet with the new keys
    const plaintext = "updated!";
    const pn: u64 = 100;
    const aad = [_]u8{0x44};
    var ciphertext: [8]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ciphertext, &tag, plaintext, next_gen.key, next_gen.iv, pn, &aad);

    // Receive with flipped key_phase (1 instead of 0)
    var out: [8]u8 = undefined;
    const result = mgr.tryDecrypt(&out, &ciphertext, tag, pn, &aad, 1, 2_000_000, 100_000);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(plaintext, out[0..result.?]);

    // Phase should now be flipped
    try std.testing.expectEqual(@as(u1, 1), mgr.key_phase);
    try std.testing.expectEqual(@as(u32, 1), mgr.generation);
    try std.testing.expect(mgr.prev_server != null);
}

test "KeyUpdateManager: reordered old-phase packet decrypts with prev keys" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    const hp = [_]u8{0} ** 16;

    var mgr = KeyUpdateManager.init(cs, ss, hp, hp);

    // Save old server keys
    const old_gen = mgr.current_server;

    // Initiate update
    _ = mgr.initiateUpdate(10, 1_000_000, 200_000);
    // Now prev_server = old_gen, key_phase = 1

    // A reordered packet arrives with old phase (0 = different from current 1)
    // tryDecrypt tries prev first (before next-gen), so it should succeed
    const plaintext = "old pkt";
    const pn: u64 = 5;
    const aad = [_]u8{0x40};
    var ciphertext: [7]u8 = undefined;
    var tag: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ciphertext, &tag, plaintext, old_gen.key, old_gen.iv, pn, &aad);

    // Receive with phase 0 (different from current 1)
    // tryDecrypt tries prev_server first, succeeds
    var out: [7]u8 = undefined;
    const result = mgr.tryDecrypt(&out, &ciphertext, tag, pn, &aad, 0, 1_050_000, 200_000);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(plaintext, out[0..result.?]);
}

test "KeyUpdateManager: largest PN tracked per phase" {
    const cs = [_]u8{0x11} ** 32;
    const ss = [_]u8{0x22} ** 32;
    const hp = [_]u8{0} ** 16;

    var mgr = KeyUpdateManager.init(cs, ss, hp, hp);

    // Encrypt packets with current server keys at PNs 1, 5, 3
    const gen = mgr.current_server;
    const aad = [_]u8{0x40};

    var ct1: [4]u8 = undefined;
    var tag1: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ct1, &tag1, "aaaa", gen.key, gen.iv, 1, &aad);

    var ct5: [4]u8 = undefined;
    var tag5: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ct5, &tag5, "bbbb", gen.key, gen.iv, 5, &aad);

    var ct3: [4]u8 = undefined;
    var tag3: [16]u8 = undefined;
    quic_crypto.encryptPayload(&ct3, &tag3, "cccc", gen.key, gen.iv, 3, &aad);

    var out: [4]u8 = undefined;
    _ = mgr.tryDecrypt(&out, &ct1, tag1, 1, &aad, 0, 1_000_000, 100_000) orelse unreachable;
    try std.testing.expectEqual(@as(?u64, 1), mgr.largest_pn_current_phase);

    _ = mgr.tryDecrypt(&out, &ct5, tag5, 5, &aad, 0, 1_000_000, 100_000) orelse unreachable;
    try std.testing.expectEqual(@as(?u64, 5), mgr.largest_pn_current_phase);

    _ = mgr.tryDecrypt(&out, &ct3, tag3, 3, &aad, 0, 1_000_000, 100_000) orelse unreachable;
    try std.testing.expectEqual(@as(?u64, 5), mgr.largest_pn_current_phase); // still 5
}
