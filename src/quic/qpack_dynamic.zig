// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const static_qpack = @import("qpack.zig");

pub const HeaderField = static_qpack.HeaderField;
pub const static_table = static_qpack.static_table;

// Re-export low-level helpers for use in this module
const encodePrefixedInt = static_qpack.encodePrefixedInt;
const decodePrefixedInt = static_qpack.decodePrefixedInt;
const encodeLiteralString = static_qpack.encodeLiteralString;
const decodeLiteralString = static_qpack.decodeLiteralString;
const findStaticMatch = static_qpack.findStaticMatch;

// ─── Dynamic Table (RFC 9204 §3.2) ───

const MAX_DYNAMIC_ENTRIES = 128;
const ENTRY_OVERHEAD = 32; // RFC 9204 §3.2.1: each entry has 32 bytes overhead

pub const DynamicTable = struct {
    entries: [MAX_DYNAMIC_ENTRIES]TableEntry,
    head: usize,
    count: usize,
    insert_count: usize,
    capacity: usize,
    max_capacity: usize,
    used_size: usize,

    const TableEntry = struct {
        name_buf: [128]u8,
        name_len: u8,
        value_buf: [256]u8,
        value_len: u16,

        fn name(self: *const TableEntry) []const u8 {
            return self.name_buf[0..self.name_len];
        }

        fn value(self: *const TableEntry) []const u8 {
            return self.value_buf[0..self.value_len];
        }

        fn size(self: *const TableEntry) usize {
            return @as(usize, self.name_len) + @as(usize, self.value_len) + ENTRY_OVERHEAD;
        }
    };

    pub fn init(max_capacity: usize) DynamicTable {
        return .{
            .entries = undefined,
            .head = 0,
            .count = 0,
            .insert_count = 0,
            .capacity = max_capacity,
            .max_capacity = max_capacity,
            .used_size = 0,
        };
    }

    pub fn setCapacity(self: *DynamicTable, cap: usize) void {
        self.capacity = @min(cap, self.max_capacity);
        self.evict();
    }

    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) bool {
        if (name.len > 128 or value.len > 256) return false;

        const entry_size = name.len + value.len + ENTRY_OVERHEAD;
        if (entry_size > self.capacity) return false;

        while (self.used_size + entry_size > self.capacity and self.count > 0) {
            self.evictOldest();
        }

        if (self.count >= MAX_DYNAMIC_ENTRIES) return false;

        // O(1) insert: move head backwards in the ring buffer
        self.head = if (self.head == 0) MAX_DYNAMIC_ENTRIES - 1 else self.head - 1;
        var entry = &self.entries[self.head];
        entry.name_len = @intCast(name.len);
        @memcpy(entry.name_buf[0..name.len], name);
        entry.value_len = @intCast(value.len);
        @memcpy(entry.value_buf[0..value.len], value);

        self.count += 1;
        self.insert_count += 1;
        self.used_size += entry_size;
        return true;
    }

    /// Get entry by relative index (0 = most recent insertion).
    pub fn get(self: *const DynamicTable, index: usize) ?HeaderField {
        if (index >= self.count) return null;
        const actual = (self.head + index) % MAX_DYNAMIC_ENTRIES;
        const entry = &self.entries[actual];
        return .{ .name = entry.name(), .value = entry.value() };
    }

    /// Get entry by absolute index (RFC 9204 §3.2.4).
    /// Absolute index = insert_count - relative_index - 1.
    pub fn getAbsolute(self: *const DynamicTable, abs_index: usize) ?HeaderField {
        if (abs_index >= self.insert_count) return null;
        const rel = self.insert_count - abs_index - 1;
        return self.get(rel);
    }

    /// Find a match in the dynamic table. Returns relative index.
    pub fn findMatch(self: *const DynamicTable, name: []const u8, value: []const u8) DynamicMatch {
        var result = DynamicMatch{ .exact_index = null, .name_index = null };
        for (0..self.count) |i| {
            const actual = (self.head + i) % MAX_DYNAMIC_ENTRIES;
            const entry = &self.entries[actual];
            if (std.mem.eql(u8, entry.name(), name)) {
                if (result.name_index == null) result.name_index = i;
                if (std.mem.eql(u8, entry.value(), value)) {
                    result.exact_index = i;
                    return result;
                }
            }
        }
        return result;
    }

    pub fn getInsertCount(self: *const DynamicTable) usize {
        return self.insert_count;
    }

    fn evictOldest(self: *DynamicTable) void {
        if (self.count == 0) return;
        const tail = (self.head + self.count - 1) % MAX_DYNAMIC_ENTRIES;
        const oldest = &self.entries[tail];
        self.used_size -= oldest.size();
        self.count -= 1;
    }

    fn evict(self: *DynamicTable) void {
        while (self.used_size > self.capacity and self.count > 0) {
            self.evictOldest();
        }
    }
};

pub const DynamicMatch = struct {
    exact_index: ?usize,
    name_index: ?usize,
};

// ─── Encoder Stream Instructions (RFC 9204 §4.3.1) ───

pub const EncoderStreamWriter = struct {
    /// Encode "Insert with Name Reference" (static table): 1 1 T=1 name_index + value
    pub fn insertWithStaticNameRef(buf: []u8, name_index: usize, value: []const u8) ?usize {
        var pos: usize = 0;
        // 11NNNNNN — T=1 (static), 6-bit prefix
        pos += encodePrefixedInt(buf[pos..], name_index, 6, 0xC0) orelse return null;
        pos += encodeLiteralString(buf[pos..], value) orelse return null;
        return pos;
    }

    /// Encode "Insert with Name Reference" (dynamic table): 1 0 T=0 name_index + value
    pub fn insertWithDynamicNameRef(buf: []u8, name_index: usize, value: []const u8) ?usize {
        var pos: usize = 0;
        // 10NNNNNN — T=0 (dynamic), 6-bit prefix
        pos += encodePrefixedInt(buf[pos..], name_index, 6, 0x80) orelse return null;
        pos += encodeLiteralString(buf[pos..], value) orelse return null;
        return pos;
    }

    /// Encode "Insert with Literal Name" (RFC 9204 §4.3.3):
    /// 01 H=0 NNNNN (5-bit prefixed int for name length) + name bytes + value
    pub fn insertWithLiteralName(buf: []u8, name: []const u8, value: []const u8) ?usize {
        var pos: usize = 0;
        pos += encodePrefixedInt(buf[pos..], name.len, 5, 0x40) orelse return null;
        if (buf.len < pos + name.len) return null;
        @memcpy(buf[pos..][0..name.len], name);
        pos += name.len;
        pos += encodeLiteralString(buf[pos..], value) orelse return null;
        return pos;
    }

    /// Encode "Set Dynamic Table Capacity": 001 NNNNN (5-bit prefix)
    pub fn setDynamicTableCapacity(buf: []u8, capacity: usize) ?usize {
        return encodePrefixedInt(buf, capacity, 5, 0x20);
    }
};

// ─── Decoder Stream Instructions (RFC 9204 §4.4) ───

pub const DecoderStreamWriter = struct {
    /// Encode "Section Acknowledgement": 1 NNNNNNN (7-bit stream_id prefix)
    pub fn sectionAck(buf: []u8, stream_id: usize) ?usize {
        return encodePrefixedInt(buf, stream_id, 7, 0x80);
    }

    /// Encode "Stream Cancellation": 01 NNNNNN (6-bit stream_id prefix)
    pub fn streamCancellation(buf: []u8, stream_id: usize) ?usize {
        return encodePrefixedInt(buf, stream_id, 6, 0x40);
    }

    /// Encode "Insert Count Increment": 00 NNNNNN (6-bit increment prefix)
    pub fn insertCountIncrement(buf: []u8, increment: usize) ?usize {
        return encodePrefixedInt(buf, increment, 6, 0x00);
    }
};

// ─── Encoder Stream Decoder (processes instructions from peer's encoder stream) ───

pub const EncoderStreamDecoder = struct {
    table: *DynamicTable,

    pub fn init(table: *DynamicTable) EncoderStreamDecoder {
        return .{ .table = table };
    }

    /// Process encoder stream data. Returns bytes consumed.
    pub fn process(self: *EncoderStreamDecoder, data: []const u8) ?usize {
        var pos: usize = 0;
        while (pos < data.len) {
            const byte = data[pos];
            if (byte & 0x80 != 0) {
                // Insert with Name Reference
                const is_static = (byte & 0x40) != 0;
                const prefix_bits: u4 = 6;
                const idx_result = decodePrefixedInt(data[pos..], prefix_bits) orelse return pos;
                pos += idx_result.consumed;
                const val = decodeLiteralString(data[pos..]) orelse return pos;
                pos += val.consumed;

                if (is_static) {
                    if (idx_result.value >= static_table.len) return null;
                    const entry = static_table[idx_result.value];
                    if (!self.table.insert(entry.name, val.value)) return null;
                } else {
                    const dyn_entry = self.table.get(idx_result.value) orelse return null;
                    // Copy name before insert (insert may shift entries)
                    var name_copy: [128]u8 = undefined;
                    @memcpy(name_copy[0..dyn_entry.name.len], dyn_entry.name);
                    if (!self.table.insert(name_copy[0..dyn_entry.name.len], val.value)) return null;
                }
            } else if (byte & 0x40 != 0) {
                // Insert with Literal Name: 01HNNNNN
                const h_bit = (byte & 0x20) != 0;
                if (h_bit) return null; // Huffman-encoded names not supported
                const name_len_result = decodePrefixedInt(data[pos..], 5) orelse return pos;
                pos += name_len_result.consumed;
                if (pos + name_len_result.value > data.len) return pos;
                const name = data[pos..][0..name_len_result.value];
                pos += name_len_result.value;
                const val = decodeLiteralString(data[pos..]) orelse return pos;
                pos += val.consumed;
                if (!self.table.insert(name, val.value)) return null;
            } else if (byte & 0x20 != 0) {
                // Set Dynamic Table Capacity: 001NNNNN
                const cap_result = decodePrefixedInt(data[pos..], 5) orelse return pos;
                pos += cap_result.consumed;
                self.table.setCapacity(cap_result.value);
            } else {
                // Duplicate (00NNNNNN, 5-bit relative index) — RFC 9204 §4.3.4
                const idx_result = decodePrefixedInt(data[pos..], 5) orelse return pos;
                pos += idx_result.consumed;
                const entry = self.table.get(idx_result.value) orelse return null;
                var name_copy: [128]u8 = undefined;
                var value_copy: [256]u8 = undefined;
                @memcpy(name_copy[0..entry.name.len], entry.name);
                @memcpy(value_copy[0..entry.value.len], entry.value);
                if (!self.table.insert(name_copy[0..entry.name.len], value_copy[0..entry.value.len])) return null;
            }
        }
        return pos;
    }
};

// ─── Dynamic-aware Encoder (RFC 9204 §4.5) ───

pub const DynamicEncoder = struct {
    table: DynamicTable,
    known_received_count: usize,

    pub fn init(max_capacity: usize) DynamicEncoder {
        return .{
            .table = DynamicTable.init(max_capacity),
            .known_received_count = 0,
        };
    }

    /// Acknowledge that the decoder has processed entries up to this insert count.
    pub fn onSectionAck(self: *DynamicEncoder, insert_count: usize) void {
        if (insert_count > self.known_received_count) {
            self.known_received_count = insert_count;
        }
    }

    pub fn onInsertCountIncrement(self: *DynamicEncoder, increment: usize) void {
        self.known_received_count += increment;
    }

    /// Encode headers into a field section, writing encoder stream instructions for new entries.
    /// Returns: encoded field section length. Also writes encoder_stream instructions.
    pub fn encode(
        self: *DynamicEncoder,
        buf: []u8,
        headers: []const HeaderField,
        encoder_stream_buf: []u8,
        encoder_stream_len: *usize,
    ) ?usize {
        var es_pos: usize = 0;
        var required_insert_count: usize = 0;

        // First pass: insert new entries into dynamic table and generate encoder stream instructions
        for (headers) |hdr| {
            const static_match = findStaticMatch(hdr.name, hdr.value);
            if (static_match.exact_index != null) continue;

            const dyn_match = self.table.findMatch(hdr.name, hdr.value);
            if (dyn_match.exact_index != null) {
                // Already in dynamic table — track required insert count
                const abs_idx = self.table.insert_count - dyn_match.exact_index.? - 1;
                if (abs_idx + 1 > required_insert_count) required_insert_count = abs_idx + 1;
                continue;
            }

            // Insert new entry
            if (static_match.name_index) |si| {
                const written = EncoderStreamWriter.insertWithStaticNameRef(
                    encoder_stream_buf[es_pos..],
                    si,
                    hdr.value,
                ) orelse continue;
                es_pos += written;
            } else {
                const written = EncoderStreamWriter.insertWithLiteralName(
                    encoder_stream_buf[es_pos..],
                    hdr.name,
                    hdr.value,
                ) orelse continue;
                es_pos += written;
            }
            _ = self.table.insert(hdr.name, hdr.value);
            required_insert_count = self.table.insert_count;
        }
        encoder_stream_len.* = es_pos;

        // Second pass: encode field section
        var pos: usize = 0;

        // Required Insert Count (RFC 9204 §4.5.1)
        const ric_encoded = encodeRequiredInsertCount(required_insert_count, self.table.max_capacity);
        pos += encodePrefixedInt(buf[pos..], ric_encoded, 8, 0x00) orelse return null;

        // Delta Base (sign=0, delta=0 — base equals required_insert_count)
        if (buf.len <= pos) return null;
        buf[pos] = 0x00; // S=0, Delta Base = 0
        pos += 1;

        // Encode each header
        for (headers) |hdr| {
            const static_match = findStaticMatch(hdr.name, hdr.value);

            if (static_match.exact_index) |idx| {
                // Indexed Field Line (static): 1 T=1 NNNNNN
                pos += encodePrefixedInt(buf[pos..], idx, 6, 0xC0) orelse return null;
            } else {
                const dyn_match = self.table.findMatch(hdr.name, hdr.value);
                if (dyn_match.exact_index) |di| {
                    // Indexed Field Line (dynamic): 1 T=0 NNNNNN
                    pos += encodePrefixedInt(buf[pos..], di, 6, 0x80) orelse return null;
                } else if (static_match.name_index) |si| {
                    // Literal with Name Reference (static): 0101NNNN
                    pos += encodePrefixedInt(buf[pos..], si, 4, 0x50) orelse return null;
                    pos += encodeLiteralString(buf[pos..], hdr.value) orelse return null;
                } else if (dyn_match.name_index) |di| {
                    // Literal with Name Reference (dynamic): 0100NNNN
                    pos += encodePrefixedInt(buf[pos..], di, 4, 0x40) orelse return null;
                    pos += encodeLiteralString(buf[pos..], hdr.value) orelse return null;
                } else {
                    // Literal with Literal Name (RFC 9204 §4.5.6):
                    // 001 N=0 H=0 NNN (3-bit prefix for name length)
                    pos += encodePrefixedInt(buf[pos..], hdr.name.len, 3, 0x20) orelse return null;
                    if (buf.len < pos + hdr.name.len) return null;
                    @memcpy(buf[pos..][0..hdr.name.len], hdr.name);
                    pos += hdr.name.len;
                    pos += encodeLiteralString(buf[pos..], hdr.value) orelse return null;
                }
            }
        }

        return pos;
    }
};

// ─── Dynamic-aware Decoder (RFC 9204 §4.5) ───

pub const DynamicDecoder = struct {
    table: DynamicTable,
    known_received_count: usize,

    pub fn init(max_capacity: usize) DynamicDecoder {
        return .{
            .table = DynamicTable.init(max_capacity),
            .known_received_count = 0,
        };
    }

    /// Get encoder stream decoder to process instructions.
    pub fn encoderStreamDecoder(self: *DynamicDecoder) EncoderStreamDecoder {
        return EncoderStreamDecoder.init(&self.table);
    }

    /// Decode a field section that may reference the dynamic table.
    pub fn decode(self: *const DynamicDecoder, data: []const u8, headers: []HeaderField) ?DecodeResult {
        if (data.len < 2) return null;

        var pos: usize = 0;

        // Required Insert Count
        const ric_result = decodePrefixedInt(data[pos..], 8) orelse return null;
        pos += ric_result.consumed;
        const max_entries = self.table.max_capacity / ENTRY_OVERHEAD;
        const required_insert_count = decodeRequiredInsertCount(ric_result.value, max_entries, self.table.insert_count);

        // Delta Base
        const db_byte = data[pos];
        const sign = (db_byte & 0x80) != 0;
        const db_result = decodePrefixedInt(data[pos..], 7) orelse return null;
        pos += db_result.consumed;

        const base = if (sign)
            required_insert_count -| db_result.value -| 1
        else
            required_insert_count + db_result.value;

        _ = base;

        var count: usize = 0;
        while (pos < data.len and count < headers.len) {
            const byte = data[pos];

            if (byte & 0xC0 == 0xC0) {
                // Indexed Field Line (static): 11NNNNNN
                const idx_result = decodePrefixedInt(data[pos..], 6) orelse return null;
                pos += idx_result.consumed;
                if (idx_result.value >= static_table.len) return null;
                const entry = static_table[idx_result.value];
                headers[count] = .{ .name = entry.name, .value = entry.value };
                count += 1;
            } else if (byte & 0xC0 == 0x80) {
                // Indexed Field Line (dynamic): 10NNNNNN
                const idx_result = decodePrefixedInt(data[pos..], 6) orelse return null;
                pos += idx_result.consumed;
                const entry = self.table.get(idx_result.value) orelse return null;
                headers[count] = .{ .name = entry.name, .value = entry.value };
                count += 1;
            } else if (byte & 0xF0 == 0x50) {
                // Literal with Name Reference (static): 0101NNNN
                const idx_result = decodePrefixedInt(data[pos..], 4) orelse return null;
                pos += idx_result.consumed;
                if (idx_result.value >= static_table.len) return null;
                const entry = static_table[idx_result.value];
                const val = decodeLiteralString(data[pos..]) orelse return null;
                pos += val.consumed;
                headers[count] = .{ .name = entry.name, .value = val.value };
                count += 1;
            } else if (byte & 0xF0 == 0x40) {
                // Literal with Name Reference (dynamic): 0100NNNN
                const idx_result = decodePrefixedInt(data[pos..], 4) orelse return null;
                pos += idx_result.consumed;
                const entry = self.table.get(idx_result.value) orelse return null;
                const val = decodeLiteralString(data[pos..]) orelse return null;
                pos += val.consumed;
                headers[count] = .{ .name = entry.name, .value = val.value };
                count += 1;
            } else if (byte & 0xE0 == 0x20) {
                // Literal with Literal Name (RFC 9204 §4.5.6):
                // 001 N H NNN — 3-bit prefix for name length
                const name_len_result = decodePrefixedInt(data[pos..], 3) orelse return null;
                pos += name_len_result.consumed;
                if (pos + name_len_result.value > data.len) return null;
                const name = data[pos..][0..name_len_result.value];
                pos += name_len_result.value;
                const val = decodeLiteralString(data[pos..]) orelse return null;
                pos += val.consumed;
                headers[count] = .{ .name = name, .value = val.value };
                count += 1;
            } else {
                return null;
            }
        }

        return .{ .count = count, .required_insert_count = required_insert_count };
    }
};

pub const DecodeResult = struct {
    count: usize,
    required_insert_count: usize,
};

// ─── Required Insert Count encoding (RFC 9204 §4.5.1.1) ───

fn encodeRequiredInsertCount(ric: usize, max_capacity: usize) usize {
    if (ric == 0) return 0;
    const max_entries = max_capacity / ENTRY_OVERHEAD;
    if (max_entries == 0) return ric;
    return (ric % (2 * max_entries)) + 1;
}

fn decodeRequiredInsertCount(encoded: usize, max_entries: usize, total_inserted: usize) usize {
    if (encoded == 0) return 0;
    if (max_entries == 0) return encoded;

    const full_range = 2 * max_entries;
    const val = encoded - 1;
    const current_wrapped = total_inserted % full_range;

    if (current_wrapped >= val) {
        return total_inserted - current_wrapped + val;
    } else {
        // Use addition to avoid usize underflow:
        // base = total_inserted + val - (current_wrapped + full_range)
        const sum = current_wrapped + full_range;
        if (total_inserted + val >= sum) {
            return total_inserted + val - sum;
        }
        return 0;
    }
}

// ─── Tests ───

test "DynamicTable: init and insert" {
    var table = DynamicTable.init(4096);
    try std.testing.expectEqual(@as(usize, 0), table.count);
    try std.testing.expectEqual(@as(usize, 0), table.insert_count);

    try std.testing.expect(table.insert(":authority", "example.com"));
    try std.testing.expectEqual(@as(usize, 1), table.count);
    try std.testing.expectEqual(@as(usize, 1), table.insert_count);

    const entry = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings(":authority", entry.name);
    try std.testing.expectEqualStrings("example.com", entry.value);
}

test "DynamicTable: FIFO ordering" {
    var table = DynamicTable.init(4096);
    _ = table.insert("first", "1");
    _ = table.insert("second", "2");
    _ = table.insert("third", "3");

    const e0 = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings("third", e0.name);

    const e1 = table.get(1) orelse unreachable;
    try std.testing.expectEqualStrings("second", e1.name);

    const e2 = table.get(2) orelse unreachable;
    try std.testing.expectEqualStrings("first", e2.name);
}

test "DynamicTable: eviction on capacity" {
    // Small capacity: 32 (overhead) + 5 + 1 = 38 per entry
    var table = DynamicTable.init(80);
    _ = table.insert("aaaaa", "x"); // 38 bytes
    _ = table.insert("bbbbb", "y"); // 38 bytes → evicts first
    try std.testing.expectEqual(@as(usize, 2), table.count);

    _ = table.insert("ccccc", "z"); // 38 bytes → should evict "aaaaa"
    try std.testing.expectEqual(@as(usize, 2), table.count);

    // "aaaaa" should be evicted (oldest)
    const e0 = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings("ccccc", e0.name);
    const e1 = table.get(1) orelse unreachable;
    try std.testing.expectEqualStrings("bbbbb", e1.name);
}

test "DynamicTable: findMatch" {
    var table = DynamicTable.init(4096);
    _ = table.insert("content-type", "application/grpc");
    _ = table.insert(":path", "/api/v1/health");

    const m1 = table.findMatch("content-type", "application/grpc");
    try std.testing.expectEqual(@as(?usize, 1), m1.exact_index);

    const m2 = table.findMatch("content-type", "text/html");
    try std.testing.expect(m2.exact_index == null);
    try std.testing.expectEqual(@as(?usize, 1), m2.name_index);

    const m3 = table.findMatch("x-nonexistent", "foo");
    try std.testing.expect(m3.exact_index == null);
    try std.testing.expect(m3.name_index == null);
}

test "DynamicTable: getAbsolute" {
    var table = DynamicTable.init(4096);
    _ = table.insert("first", "1"); // abs=0
    _ = table.insert("second", "2"); // abs=1
    _ = table.insert("third", "3"); // abs=2

    const e0 = table.getAbsolute(0) orelse unreachable;
    try std.testing.expectEqualStrings("first", e0.name);

    const e2 = table.getAbsolute(2) orelse unreachable;
    try std.testing.expectEqualStrings("third", e2.name);
}

test "DynamicTable: setCapacity evicts" {
    var table = DynamicTable.init(4096);
    _ = table.insert("content-type", "application/grpc"); // 32+12+16=60
    _ = table.insert(":path", "/api"); // 32+5+4=41
    try std.testing.expectEqual(@as(usize, 2), table.count);

    table.setCapacity(60); // Only room for one
    try std.testing.expectEqual(@as(usize, 1), table.count);
    const e = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings(":path", e.name);
}

test "EncoderStreamWriter: insertWithStaticNameRef" {
    var buf: [64]u8 = undefined;
    const len = EncoderStreamWriter.insertWithStaticNameRef(&buf, 0, "example.com") orelse unreachable;
    try std.testing.expect(len > 0);
    // First byte: 0xC0 | 0 = 0xC0
    try std.testing.expectEqual(@as(u8, 0xC0), buf[0]);
}

test "EncoderStreamWriter: insertWithLiteralName" {
    var buf: [128]u8 = undefined;
    const len = EncoderStreamWriter.insertWithLiteralName(&buf, "x-custom", "val") orelse unreachable;
    try std.testing.expect(len > 0);
    // First byte should have 0x40 pattern
    try std.testing.expect(buf[0] & 0xC0 == 0x40);
}

test "EncoderStreamWriter: setDynamicTableCapacity" {
    var buf: [16]u8 = undefined;
    const len = EncoderStreamWriter.setDynamicTableCapacity(&buf, 4096) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expect(buf[0] & 0xE0 == 0x20);
}

test "DecoderStreamWriter: sectionAck" {
    var buf: [8]u8 = undefined;
    const len = DecoderStreamWriter.sectionAck(&buf, 4) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x84), buf[0]); // 0x80 | 4
}

test "DecoderStreamWriter: insertCountIncrement" {
    var buf: [8]u8 = undefined;
    const len = DecoderStreamWriter.insertCountIncrement(&buf, 3) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, 0x03), buf[0]);
}

test "EncoderStreamDecoder: insert with static name ref" {
    var table = DynamicTable.init(4096);
    var dec = EncoderStreamDecoder.init(&table);

    var buf: [64]u8 = undefined;
    const len = EncoderStreamWriter.insertWithStaticNameRef(&buf, 0, "test.example.com") orelse unreachable;

    const consumed = dec.process(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(len, consumed);
    try std.testing.expectEqual(@as(usize, 1), table.count);

    const entry = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings(":authority", entry.name);
    try std.testing.expectEqualStrings("test.example.com", entry.value);
}

test "EncoderStreamDecoder: insert with literal name" {
    var table = DynamicTable.init(4096);
    var dec = EncoderStreamDecoder.init(&table);

    var buf: [128]u8 = undefined;
    const len = EncoderStreamWriter.insertWithLiteralName(&buf, "grpc-encoding", "identity") orelse unreachable;

    const consumed = dec.process(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(len, consumed);

    const entry = table.get(0) orelse unreachable;
    try std.testing.expectEqualStrings("grpc-encoding", entry.name);
    try std.testing.expectEqualStrings("identity", entry.value);
}

test "EncoderStreamDecoder: set capacity" {
    var table = DynamicTable.init(4096);
    var dec = EncoderStreamDecoder.init(&table);

    var buf: [16]u8 = undefined;
    const len = EncoderStreamWriter.setDynamicTableCapacity(&buf, 2048) orelse unreachable;

    _ = dec.process(buf[0..len]) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2048), table.capacity);
}

test "DynamicEncoder: encode with dynamic table insertion" {
    var enc = DynamicEncoder.init(4096);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" }, // static exact match
        .{ .name = ":scheme", .value = "https" }, // static exact match
        .{ .name = ":authority", .value = "grpc.example.com" }, // → dynamic insert
        .{ .name = "content-type", .value = "application/grpc" }, // → dynamic insert
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    const len = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expect(len > 0);
    try std.testing.expect(es_len > 0);
    try std.testing.expectEqual(@as(usize, 2), enc.table.count);
}

test "DynamicEncoder: second encode uses dynamic table references" {
    var enc = DynamicEncoder.init(4096);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":authority", .value = "grpc.example.com" },
        .{ .name = "content-type", .value = "application/grpc" },
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    // First encode — inserts into dynamic table
    _ = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    const first_es_len = es_len;
    try std.testing.expect(first_es_len > 0);

    // Second encode — should reference dynamic table (no new encoder stream instructions)
    const len2 = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expect(len2 > 0);
    try std.testing.expectEqual(@as(usize, 0), es_len); // no new insertions
}

test "DynamicEncoder + DynamicDecoder: roundtrip" {
    var enc = DynamicEncoder.init(4096);
    var dec = DynamicDecoder.init(4096);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "grpc.example.com" },
        .{ .name = ":path", .value = "/pkg.Service/Method" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    // Encode
    const field_section_len = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;

    // Simulate: deliver encoder stream instructions to decoder
    var es_dec = dec.encoderStreamDecoder();
    if (es_len > 0) {
        _ = es_dec.process(es_buf[0..es_len]) orelse unreachable;
    }

    // Decode
    var decoded: [8]HeaderField = undefined;
    const result = dec.decode(buf[0..field_section_len], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 6), result.count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("POST", decoded[0].value);
    try std.testing.expectEqualStrings(":authority", decoded[2].name);
    try std.testing.expectEqualStrings("grpc.example.com", decoded[2].value);
    try std.testing.expectEqualStrings("content-type", decoded[4].name);
    try std.testing.expectEqualStrings("application/grpc", decoded[4].value);
    try std.testing.expectEqualStrings("te", decoded[5].name);
    try std.testing.expectEqualStrings("trailers", decoded[5].value);
}

test "DynamicEncoder + DynamicDecoder: repeated requests amortize encoder stream cost" {
    var enc = DynamicEncoder.init(4096);
    var dec = DynamicDecoder.init(4096);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":authority", .value = "very-long-service-name.internal.example.com" },
        .{ .name = ":path", .value = "/com.example.longpackagename.ServiceName/VeryLongMethodName" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "x-request-id", .value = "550e8400-e29b-41d4-a716-446655440000" },
    };

    var buf: [512]u8 = undefined;
    var es_buf: [512]u8 = undefined;
    var es_len: usize = 0;

    // First request — inserts into dynamic table, encodes with literals
    const len1 = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    const first_es_len = es_len;
    var es_dec = dec.encoderStreamDecoder();
    if (es_len > 0) _ = es_dec.process(es_buf[0..es_len]);

    // Second request — no encoder stream instructions needed
    const len2 = enc.encode(&buf, &headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 0), es_len);
    // Both field sections are the same size (dynamic table refs used in both passes),
    // but the total wire cost is lower on repeat since encoder stream is amortized.
    const first_total_cost = first_es_len + len1;
    try std.testing.expect(len2 < first_total_cost);

    // Verify decode still works
    var decoded: [8]HeaderField = undefined;
    const result = dec.decode(buf[0..len2], &decoded) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 5), result.count);
    try std.testing.expectEqualStrings(":authority", decoded[1].name);
    try std.testing.expectEqualStrings("very-long-service-name.internal.example.com", decoded[1].value);
}

test "encodeRequiredInsertCount / decodeRequiredInsertCount: roundtrip" {
    const max_cap: usize = 4096;
    const max_entries = max_cap / ENTRY_OVERHEAD;

    // RIC = 0
    try std.testing.expectEqual(@as(usize, 0), encodeRequiredInsertCount(0, max_cap));
    try std.testing.expectEqual(@as(usize, 0), decodeRequiredInsertCount(0, max_entries, 0));

    // RIC = 5, total_inserted = 5
    const encoded = encodeRequiredInsertCount(5, max_cap);
    const decoded = decodeRequiredInsertCount(encoded, max_entries, 5);
    try std.testing.expectEqual(@as(usize, 5), decoded);

    // RIC = 1, total_inserted = 1
    const e1 = encodeRequiredInsertCount(1, max_cap);
    const d1 = decodeRequiredInsertCount(e1, max_entries, 1);
    try std.testing.expectEqual(@as(usize, 1), d1);
}

test "DynamicEncoder: gRPC pattern — authority and path vary, rest static" {
    var enc = DynamicEncoder.init(4096);

    const req1_headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = ":path", .value = "/pkg.Svc/MethodA" },
        .{ .name = "content-type", .value = "application/grpc" },
    };

    const req2_headers = [_]HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" }, // same
        .{ .name = ":path", .value = "/pkg.Svc/MethodB" }, // different
        .{ .name = "content-type", .value = "application/grpc" }, // same
    };

    var buf: [512]u8 = undefined;
    var es_buf: [256]u8 = undefined;
    var es_len: usize = 0;

    _ = enc.encode(&buf, &req1_headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 3), enc.table.count); // authority, path, content-type

    const len2 = enc.encode(&buf, &req2_headers, &es_buf, &es_len) orelse unreachable;
    try std.testing.expect(len2 > 0);
    // Only :path changed → 1 new encoder stream instruction
    try std.testing.expect(es_len > 0);
    try std.testing.expectEqual(@as(usize, 4), enc.table.count); // +1 new path
}
