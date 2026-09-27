// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,

    pub fn size(self: HeaderField) usize {
        // RFC 7541 §4.1: entry size = name octets + value octets + 32
        return self.name.len + self.value.len + 32;
    }
};

// ─── Static Table (RFC 7541 Appendix A) ───

const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

// ─── Integer Encoding/Decoding (RFC 7541 §5.1) ───

pub const IntegerError = error{
    IntegerOverflow,
    UnexpectedEnd,
};

/// Decode a prefix-coded integer. Returns (value, bytes_consumed).
pub fn decodeInteger(data: []const u8, prefix_bits: u3) IntegerError!struct { value: u32, consumed: usize } {
    if (data.len == 0) return IntegerError.UnexpectedEnd;

    const mask: u8 = (@as(u8, 1) << prefix_bits) - 1;
    var value: u32 = data[0] & mask;

    if (value < mask) {
        return .{ .value = value, .consumed = 1 };
    }

    var m: u5 = 0;
    var i: usize = 1;
    while (i < data.len) : (i += 1) {
        const b = data[i];
        const add = @as(u32, b & 0x7F) << m;
        if (add > std.math.maxInt(u32) - value) return IntegerError.IntegerOverflow;
        value += add;
        if (b & 0x80 == 0) {
            return .{ .value = value, .consumed = i + 1 };
        }
        if (m >= 28) return IntegerError.IntegerOverflow;
        m += 7;
    }
    return IntegerError.UnexpectedEnd;
}

/// Encode a prefix-coded integer into buf. Returns bytes written.
pub fn encodeInteger(buf: []u8, value: u32, prefix_bits: u3, pattern: u8) usize {
    const mask: u8 = (@as(u8, 1) << prefix_bits) - 1;

    if (value < mask) {
        buf[0] = pattern | @as(u8, @intCast(value));
        return 1;
    }

    buf[0] = pattern | mask;
    var remaining = value - mask;
    var i: usize = 1;
    while (remaining >= 128) : (i += 1) {
        buf[i] = @intCast((remaining & 0x7F) | 0x80);
        remaining >>= 7;
    }
    buf[i] = @intCast(remaining);
    return i + 1;
}

// ─── String Literal (RFC 7541 §5.2) ───

pub const StringError = error{
    UnexpectedEnd,
    IntegerOverflow,
    HuffmanDecodingError,
};

/// Decode a string literal. Returns (string_slice, bytes_consumed).
/// The returned slice points into the input data (no allocation for raw strings).
/// Huffman-encoded strings are decoded into decode_buf.
pub fn decodeString(data: []const u8, decode_buf: []u8) StringError!struct { value: []const u8, consumed: usize } {
    if (data.len == 0) return StringError.UnexpectedEnd;

    const huffman = (data[0] & 0x80) != 0;
    const int_result = decodeInteger(data, 7) catch |e| switch (e) {
        IntegerError.IntegerOverflow => return StringError.IntegerOverflow,
        IntegerError.UnexpectedEnd => return StringError.UnexpectedEnd,
    };
    const str_len = int_result.value;
    const header_len = int_result.consumed;

    if (data.len < header_len + str_len) return StringError.UnexpectedEnd;

    const raw = data[header_len..][0..str_len];

    if (huffman) {
        const decoded_len = huffmanDecode(raw, decode_buf) catch return StringError.HuffmanDecodingError;
        return .{ .value = decode_buf[0..decoded_len], .consumed = header_len + str_len };
    }

    return .{ .value = raw, .consumed = header_len + str_len };
}

/// Encode a string literal (without Huffman). Returns bytes written.
pub fn encodeString(buf: []u8, value: []const u8, use_huffman: bool) usize {
    if (use_huffman) {
        const huff_len = huffmanEncodedLength(value);
        var offset = encodeInteger(buf, @intCast(huff_len), 7, 0x80);
        offset += huffmanEncode(value, buf[offset..]);
        return offset;
    }
    const offset = encodeInteger(buf, @intCast(value.len), 7, 0x00);
    @memcpy(buf[offset..][0..value.len], value);
    return offset + value.len;
}

// ─── Dynamic Table (RFC 7541 §2.3.2) ───

pub const DynamicTable = struct {
    const max_entries = 128;

    const Entry = struct {
        name_start: u16,
        name_len: u16,
        value_start: u16,
        value_len: u16,
    };

    entries: [max_entries]Entry = undefined,
    head: usize = 0,
    len: usize = 0,
    current_size: usize = 0,
    max_size: usize = 4096,
    storage: [8192]u8 = undefined,
    storage_used: usize = 0,

    pub fn init(max_size: usize) DynamicTable {
        return .{ .max_size = max_size };
    }

    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) void {
        const entry_size = name.len + value.len + 32;

        // Evict until there's room
        while (self.current_size + entry_size > self.max_size and self.len > 0) {
            self.evict();
        }

        // Entry too large for table — clear everything (RFC 7541 §4.4)
        if (entry_size > self.max_size) {
            self.len = 0;
            self.head = 0;
            self.current_size = 0;
            self.storage_used = 0;
            return;
        }

        // Compact storage if needed
        if (self.storage_used + name.len + value.len > self.storage.len) {
            self.compactStorage();
        }

        const name_start = self.storage_used;
        @memcpy(self.storage[name_start..][0..name.len], name);
        self.storage_used += name.len;

        const value_start = self.storage_used;
        @memcpy(self.storage[value_start..][0..value.len], value);
        self.storage_used += value.len;

        // Insert at head (newest entry = index 0 in dynamic table)
        if (self.head == 0) {
            self.head = max_entries - 1;
        } else {
            self.head -= 1;
        }
        if (self.len < max_entries) self.len += 1;

        self.entries[self.head] = .{
            .name_start = @intCast(name_start),
            .name_len = @intCast(name.len),
            .value_start = @intCast(value_start),
            .value_len = @intCast(value.len),
        };

        self.current_size += entry_size;
    }

    /// Get entry by dynamic table index (0 = newest).
    pub fn get(self: *const DynamicTable, index: usize) ?HeaderField {
        if (index >= self.len) return null;
        const actual = (self.head + index) % max_entries;
        const entry = self.entries[actual];
        return .{
            .name = self.storage[entry.name_start..][0..entry.name_len],
            .value = self.storage[entry.value_start..][0..entry.value_len],
        };
    }

    pub fn setMaxSize(self: *DynamicTable, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size and self.len > 0) {
            self.evict();
        }
    }

    fn evict(self: *DynamicTable) void {
        // Remove oldest entry (tail of ring buffer)
        const tail = (self.head + self.len - 1) % max_entries;
        const entry = self.entries[tail];
        const entry_size = @as(usize, entry.name_len) + @as(usize, entry.value_len) + 32;
        self.current_size -= entry_size;
        self.len -= 1;
    }

    fn compactStorage(self: *DynamicTable) void {
        var new_storage: [8192]u8 = undefined;
        var offset: usize = 0;

        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const actual = (self.head + i) % max_entries;
            const entry = &self.entries[actual];

            const name = self.storage[entry.name_start..][0..entry.name_len];
            @memcpy(new_storage[offset..][0..name.len], name);
            entry.name_start = @intCast(offset);
            offset += name.len;

            const value = self.storage[entry.value_start..][0..entry.value_len];
            @memcpy(new_storage[offset..][0..value.len], value);
            entry.value_start = @intCast(offset);
            offset += value.len;
        }

        @memcpy(self.storage[0..offset], new_storage[0..offset]);
        self.storage_used = offset;
    }
};

// ─── Decoder (RFC 7541 §6) ───

pub const DecodeError = error{
    UnexpectedEnd,
    IntegerOverflow,
    InvalidIndex,
    HuffmanDecodingError,
};

pub const Decoder = struct {
    dynamic_table: DynamicTable,

    pub fn init(max_table_size: usize) Decoder {
        return .{ .dynamic_table = DynamicTable.init(max_table_size) };
    }

    /// Lookup by HPACK index (1-based). 1–61 = static, 62+ = dynamic.
    pub fn lookup(self: *const Decoder, index: u32) ?HeaderField {
        if (index == 0) return null;
        if (index <= 61) {
            const e = static_table[index - 1];
            return .{ .name = e.name, .value = e.value };
        }
        return self.dynamic_table.get(index - 62);
    }

    /// Decode a header block into the provided output slice. Returns headers decoded count.
    /// Caller must ensure decode_buf outlives any use of returned HeaderField slices,
    /// as Huffman-decoded name/value strings point into decode_buf.
    pub fn decode(self: *Decoder, block: []const u8, headers_out: []HeaderField, decode_buf: []u8) DecodeError!usize {
        var pos: usize = 0;
        var count: usize = 0;
        var buf_offset: usize = 0;

        while (pos < block.len) {
            if (count >= headers_out.len) break;

            const b = block[pos];

            if (b & 0x80 != 0) {
                // §6.1 Indexed header field
                const result = decodeInteger(block[pos..], 7) catch |e| return decodeIntErr(e);
                pos += result.consumed;
                const field = self.lookup(result.value) orelse return DecodeError.InvalidIndex;
                headers_out[count] = field;
                count += 1;
            } else if (b & 0x40 != 0) {
                // §6.2.1 Literal with incremental indexing
                const field = try self.decodeLiteral(block[pos..], 6, decode_buf[buf_offset..], &pos);
                // decodeLiteral consumes decode_buf for: value always, name only if literal.
                // Detect indexed name: field.name won't point into our decode_buf sub-slice.
                const name_in_buf = @intFromPtr(field.name.ptr) >= @intFromPtr(decode_buf[buf_offset..].ptr) and
                    @intFromPtr(field.name.ptr) < @intFromPtr(decode_buf[buf_offset..].ptr) + decode_buf[buf_offset..].len;
                const decoded_len = if (name_in_buf) field.name.len + field.value.len else field.value.len;
                buf_offset += decoded_len;
                // Copy name/value to fresh decode_buf space before insert, because name may
                // point into dynamic_table.storage which compactStorage() moves.
                const safe_name = decode_buf[buf_offset..][0..field.name.len];
                @memcpy(safe_name, field.name);
                buf_offset += field.name.len;
                const safe_value = decode_buf[buf_offset..][0..field.value.len];
                @memcpy(safe_value, field.value);
                buf_offset += field.value.len;
                self.dynamic_table.insert(safe_name, safe_value);
                headers_out[count] = .{ .name = safe_name, .value = safe_value };
                count += 1;
            } else if (b & 0x20 != 0) {
                // §6.3 Dynamic table size update
                const result = decodeInteger(block[pos..], 5) catch |e| return decodeIntErr(e);
                pos += result.consumed;
                self.dynamic_table.setMaxSize(result.value);
            } else {
                // §6.2.2 / §6.2.3 Literal without indexing / never indexed
                const prefix: u3 = 4;
                const field = try self.decodeLiteral(block[pos..], prefix, decode_buf[buf_offset..], &pos);
                const name_in_buf2 = @intFromPtr(field.name.ptr) >= @intFromPtr(decode_buf[buf_offset..].ptr) and
                    @intFromPtr(field.name.ptr) < @intFromPtr(decode_buf[buf_offset..].ptr) + decode_buf[buf_offset..].len;
                buf_offset += if (name_in_buf2) field.name.len + field.value.len else field.value.len;
                headers_out[count] = field;
                count += 1;
            }
        }

        return count;
    }

    fn decodeLiteral(self: *const Decoder, data: []const u8, prefix: u3, buf: []u8, pos: *usize) DecodeError!HeaderField {
        const idx_result = decodeInteger(data, prefix) catch |e| return decodeIntErr(e);
        var offset = idx_result.consumed;

        var name: []const u8 = undefined;
        var name_len: usize = 0;
        if (idx_result.value != 0) {
            // Name from index
            const field = self.lookup(idx_result.value) orelse return DecodeError.InvalidIndex;
            name = field.name;
        } else {
            // Name as literal
            const str_result = decodeString(data[offset..], buf) catch |e| switch (e) {
                StringError.UnexpectedEnd => return DecodeError.UnexpectedEnd,
                StringError.IntegerOverflow => return DecodeError.IntegerOverflow,
                StringError.HuffmanDecodingError => return DecodeError.HuffmanDecodingError,
            };
            name = str_result.value;
            name_len = str_result.value.len;
            offset += str_result.consumed;
        }

        // Value as literal
        const val_result = decodeString(data[offset..], buf[name_len..]) catch |e| switch (e) {
            StringError.UnexpectedEnd => return DecodeError.UnexpectedEnd,
            StringError.IntegerOverflow => return DecodeError.IntegerOverflow,
            StringError.HuffmanDecodingError => return DecodeError.HuffmanDecodingError,
        };
        offset += val_result.consumed;

        pos.* += offset;
        return .{ .name = name, .value = val_result.value };
    }

    fn decodeIntErr(e: IntegerError) DecodeError {
        return switch (e) {
            IntegerError.IntegerOverflow => DecodeError.IntegerOverflow,
            IntegerError.UnexpectedEnd => DecodeError.UnexpectedEnd,
        };
    }
};

// ─── Encoder (RFC 7541 §6) ───

pub const Encoder = struct {
    dynamic_table: DynamicTable,
    use_huffman: bool = false,

    pub fn init(max_table_size: usize) Encoder {
        return .{
            .dynamic_table = DynamicTable.init(max_table_size),
        };
    }

    /// Encode a header field. Returns bytes written to buf.
    pub fn encodeHeader(self: *Encoder, buf: []u8, name: []const u8, value: []const u8, indexing: Indexing) usize {
        // Try indexed representation first
        if (self.findIndex(name, value)) |full_match| {
            return encodeInteger(buf, full_match, 7, 0x80);
        }

        // Try name-only match
        const name_idx = self.findNameIndex(name);

        var offset: usize = 0;
        switch (indexing) {
            .with_indexing => {
                if (name_idx) |idx| {
                    offset = encodeInteger(buf, idx, 6, 0x40);
                } else {
                    buf[0] = 0x40;
                    offset = 1;
                    offset += encodeString(buf[offset..], name, self.use_huffman);
                }
                offset += encodeString(buf[offset..], value, self.use_huffman);
                self.dynamic_table.insert(name, value);
            },
            .without_indexing => {
                if (name_idx) |idx| {
                    offset = encodeInteger(buf, idx, 4, 0x00);
                } else {
                    buf[0] = 0x00;
                    offset = 1;
                    offset += encodeString(buf[offset..], name, self.use_huffman);
                }
                offset += encodeString(buf[offset..], value, self.use_huffman);
            },
            .never_indexed => {
                if (name_idx) |idx| {
                    offset = encodeInteger(buf, idx, 4, 0x10);
                } else {
                    buf[0] = 0x10;
                    offset = 1;
                    offset += encodeString(buf[offset..], name, self.use_huffman);
                }
                offset += encodeString(buf[offset..], value, self.use_huffman);
            },
        }
        return offset;
    }

    pub const Indexing = enum {
        with_indexing,
        without_indexing,
        never_indexed,
    };

    fn findIndex(self: *const Encoder, name: []const u8, value: []const u8) ?u32 {
        // Check static table
        for (static_table, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return @intCast(i + 1);
            }
        }
        // Check dynamic table
        var i: usize = 0;
        while (i < self.dynamic_table.len) : (i += 1) {
            if (self.dynamic_table.get(i)) |field| {
                if (std.mem.eql(u8, field.name, name) and std.mem.eql(u8, field.value, value)) {
                    return @intCast(i + 62);
                }
            }
        }
        return null;
    }

    fn findNameIndex(self: *const Encoder, name: []const u8) ?u32 {
        // Check static table
        for (static_table, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return @intCast(i + 1);
            }
        }
        // Check dynamic table
        var i: usize = 0;
        while (i < self.dynamic_table.len) : (i += 1) {
            if (self.dynamic_table.get(i)) |field| {
                if (std.mem.eql(u8, field.name, name)) {
                    return @intCast(i + 62);
                }
            }
        }
        return null;
    }
};

// ─── Huffman Coding (RFC 7541 Appendix B) ───

const huffman_table = @import("huffman.zig").huffman_table;
const huffman_decode_table = @import("huffman.zig").huffman_decode_table;

pub fn huffmanEncodedLength(input: []const u8) usize {
    var bits: usize = 0;
    for (input) |c| {
        bits += huffman_table[c].bit_len;
    }
    return (bits + 7) / 8;
}

pub fn huffmanEncode(input: []const u8, output: []u8) usize {
    const total_bytes = huffmanEncodedLength(input);
    @memset(output[0..@min(total_bytes, output.len)], 0);

    var bit_pos: usize = 0;
    for (input) |c| {
        const entry = huffman_table[c];
        var remaining = entry.bit_len;
        var code = entry.code;

        while (remaining > 0) {
            const byte_idx = bit_pos / 8;
            const bit_offset: u3 = @intCast(bit_pos % 8);
            const available: u4 = 8 - @as(u4, bit_offset);

            if (remaining >= available) {
                const shift: u5 = @intCast(remaining - available);
                output[byte_idx] |= @intCast((code >> shift) & ((@as(u32, 1) << available) - 1));
                remaining -= available;
                bit_pos += available;
                code &= (@as(u32, 1) << shift) - 1;
            } else {
                const shift: u3 = @intCast(available - @as(u4, @intCast(remaining)));
                output[byte_idx] |= @as(u8, @intCast(code)) << shift;
                bit_pos += remaining;
                remaining = 0;
            }
        }
    }

    // Pad with EOS (all 1s)
    const out_bytes = (bit_pos + 7) / 8;
    const final_bit_offset = bit_pos % 8;
    if (final_bit_offset > 0) {
        const padding_bits: u3 = @intCast(8 - final_bit_offset);
        output[out_bytes - 1] |= (@as(u8, 1) << padding_bits) - 1;
    }

    return total_bytes;
}

pub fn huffmanDecode(input: []const u8, output: []u8) !usize {
    var state: u16 = 0;
    var out_pos: usize = 0;

    for (input) |byte| {
        var bits_remaining: u4 = 8;
        var b = byte;
        while (bits_remaining > 0) : (bits_remaining -= 1) {
            const bit: u1 = @intCast((b >> 7) & 1);
            b <<= 1;

            const entry = huffman_decode_table[state][bit];
            if (entry.flags & 0x01 != 0) {
                // Emit symbol
                if (out_pos >= output.len) return error.HuffmanDecodingError;
                output[out_pos] = entry.symbol;
                out_pos += 1;
                state = 0;
            } else if (entry.flags & 0x02 != 0) {
                return error.HuffmanDecodingError;
            } else {
                state = entry.next_state;
            }
        }
    }

    // Verify we ended in an accepting state (partial EOS padding is OK)
    if (state != 0) {
        const entry = huffman_decode_table[state][1];
        if (entry.flags & 0x04 == 0) {
            return error.HuffmanDecodingError;
        }
    }

    return out_pos;
}

// ─── Pseudo-header validation (RFC 9113 §8.1) ───

pub const PseudoHeaderError = error{
    PseudoHeaderAfterRegular,
    UnknownPseudoHeader,
    DuplicatePseudoHeader,
    MissingMethodPseudo,
    MissingSchemePseudo,
    MissingPathPseudo,
    MissingStatusPseudo,
    InvalidStatusValue,
    ConnectionHeaderForbidden,
    TEHeaderInvalid,
    UppercaseHeaderName,
};

pub fn validateRequestHeaders(headers: []const HeaderField) PseudoHeaderError!void {
    var saw_regular = false;
    var has_method = false;
    var has_scheme = false;
    var has_path = false;
    var has_authority = false;

    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            if (saw_regular) return PseudoHeaderError.PseudoHeaderAfterRegular;
            if (std.mem.eql(u8, h.name, ":method")) {
                if (has_method) return PseudoHeaderError.DuplicatePseudoHeader;
                has_method = true;
            } else if (std.mem.eql(u8, h.name, ":scheme")) {
                if (has_scheme) return PseudoHeaderError.DuplicatePseudoHeader;
                has_scheme = true;
            } else if (std.mem.eql(u8, h.name, ":path")) {
                if (has_path) return PseudoHeaderError.DuplicatePseudoHeader;
                has_path = true;
            } else if (std.mem.eql(u8, h.name, ":authority")) {
                if (has_authority) return PseudoHeaderError.DuplicatePseudoHeader;
                has_authority = true;
            } else {
                return PseudoHeaderError.UnknownPseudoHeader;
            }
        } else {
            saw_regular = true;
            if (hasUppercase(h.name)) return PseudoHeaderError.UppercaseHeaderName;
            if (std.mem.eql(u8, h.name, "connection")) return PseudoHeaderError.ConnectionHeaderForbidden;
            if (std.mem.eql(u8, h.name, "te")) {
                if (!std.mem.eql(u8, h.value, "trailers")) return PseudoHeaderError.TEHeaderInvalid;
            }
        }
    }

    if (!has_method) return PseudoHeaderError.MissingMethodPseudo;
    if (!has_scheme) return PseudoHeaderError.MissingSchemePseudo;
    if (!has_path) return PseudoHeaderError.MissingPathPseudo;
}

pub fn validateResponseHeaders(headers: []const HeaderField) PseudoHeaderError!void {
    var saw_regular = false;
    var has_status = false;

    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            if (saw_regular) return PseudoHeaderError.PseudoHeaderAfterRegular;
            if (std.mem.eql(u8, h.name, ":status")) {
                if (has_status) return PseudoHeaderError.DuplicatePseudoHeader;
                if (!isValidStatusCode(h.value)) return PseudoHeaderError.InvalidStatusValue;
                has_status = true;
            } else {
                return PseudoHeaderError.UnknownPseudoHeader;
            }
        } else {
            saw_regular = true;
            if (hasUppercase(h.name)) return PseudoHeaderError.UppercaseHeaderName;
            if (std.mem.eql(u8, h.name, "connection")) return PseudoHeaderError.ConnectionHeaderForbidden;
            if (std.mem.eql(u8, h.name, "te")) {
                if (!std.mem.eql(u8, h.value, "trailers")) return PseudoHeaderError.TEHeaderInvalid;
            }
        }
    }

    if (!has_status) return PseudoHeaderError.MissingStatusPseudo;
}

fn isValidStatusCode(value: []const u8) bool {
    if (value.len != 3) return false;
    for (value) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn hasUppercase(name: []const u8) bool {
    for (name) |c| {
        if (c >= 'A' and c <= 'Z') return true;
    }
    return false;
}

// ─── Tests ───

test "integer encode/decode roundtrip" {
    var buf: [8]u8 = undefined;

    // Small value (fits in prefix)
    const len1 = encodeInteger(&buf, 10, 5, 0x00);
    const result1 = try decodeInteger(buf[0..len1], 5);
    try std.testing.expectEqual(@as(u32, 10), result1.value);
    try std.testing.expectEqual(@as(usize, 1), result1.consumed);

    // Value equal to prefix max
    const len2 = encodeInteger(&buf, 31, 5, 0x00);
    const result2 = try decodeInteger(buf[0..len2], 5);
    try std.testing.expectEqual(@as(u32, 31), result2.value);

    // Large value
    const len3 = encodeInteger(&buf, 1337, 5, 0x00);
    const result3 = try decodeInteger(buf[0..len3], 5);
    try std.testing.expectEqual(@as(u32, 1337), result3.value);
}

test "integer encode preserves pattern bits" {
    var buf: [1]u8 = undefined;
    _ = encodeInteger(&buf, 5, 5, 0xE0);
    try std.testing.expectEqual(@as(u8, 0xE5), buf[0]);
}

test "string encode/decode roundtrip (no huffman)" {
    var encode_buf: [64]u8 = undefined;
    const len = encodeString(&encode_buf, "hello", false);

    var decode_buf: [64]u8 = undefined;
    const result = try decodeString(encode_buf[0..len], &decode_buf);
    try std.testing.expectEqualStrings("hello", result.value);
    try std.testing.expectEqual(len, result.consumed);
}

test "dynamic table insert and get" {
    var dt = DynamicTable.init(4096);
    dt.insert("custom-header", "custom-value");

    const field = dt.get(0).?;
    try std.testing.expectEqualStrings("custom-header", field.name);
    try std.testing.expectEqualStrings("custom-value", field.value);
}

test "dynamic table eviction" {
    var dt = DynamicTable.init(100);
    // Each entry = name.len + value.len + 32
    // "a" + "b" + 32 = 34 bytes
    dt.insert("a", "b"); // 34, total: 34
    dt.insert("c", "d"); // 34, total: 68
    dt.insert("e", "f"); // 34, total would be 102 > 100, evict oldest

    try std.testing.expectEqual(@as(usize, 2), dt.len);
    const newest = dt.get(0).?;
    try std.testing.expectEqualStrings("e", newest.name);
    // Oldest "a" should be evicted
    const second = dt.get(1).?;
    try std.testing.expectEqualStrings("c", second.name);
}

test "encoder/decoder roundtrip" {
    var encoder = Encoder.init(4096);
    var decoder = Decoder.init(4096);

    var encode_buf: [256]u8 = @splat(0);
    var offset: usize = 0;

    // Encode :method GET (indexed)
    offset += encoder.encodeHeader(encode_buf[offset..], ":method", "GET", .without_indexing);
    // Encode :path / (indexed)
    offset += encoder.encodeHeader(encode_buf[offset..], ":path", "/", .without_indexing);
    // Encode custom header (literal with indexing)
    offset += encoder.encodeHeader(encode_buf[offset..], "x-custom", "test-val", .with_indexing);

    // Decode
    var headers: [8]HeaderField = undefined;
    var decode_buf: [512]u8 = undefined;
    const count = try decoder.decode(encode_buf[0..offset], &headers, &decode_buf);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("GET", headers[0].value);
    try std.testing.expectEqualStrings(":path", headers[1].name);
    try std.testing.expectEqualStrings("/", headers[1].value);
    try std.testing.expectEqualStrings("x-custom", headers[2].name);
    try std.testing.expectEqualStrings("test-val", headers[2].value);
}

test "static table indexed lookup" {
    var decoder = Decoder.init(4096);
    const field = decoder.lookup(2).?;
    try std.testing.expectEqualStrings(":method", field.name);
    try std.testing.expectEqualStrings("GET", field.value);
}

test "decoder handles dynamic table size update" {
    var decoder = Decoder.init(4096);
    // Encode a size update to 1024
    var buf: [4]u8 = undefined;
    const len = encodeInteger(&buf, 1024, 5, 0x20);

    var headers: [1]HeaderField = undefined;
    var decode_buf: [64]u8 = undefined;
    const count = try decoder.decode(buf[0..len], &headers, &decode_buf);
    try std.testing.expectEqual(@as(usize, 0), count);
    try std.testing.expectEqual(@as(usize, 1024), decoder.dynamic_table.max_size);
}

test "huffman encode/decode roundtrip" {
    var encode_out: [64]u8 = @splat(0);
    const encoded_len = huffmanEncode("www.example.com", &encode_out);

    var decode_out: [64]u8 = undefined;
    const decoded_len = try huffmanDecode(encode_out[0..encoded_len], &decode_out);
    try std.testing.expectEqualStrings("www.example.com", decode_out[0..decoded_len]);
}

test "huffman rejects invalid EOS padding (non-1 pad bits)" {
    // Encode "a" (code=0x3, 5 bits) then corrupt padding to 0 instead of all-1s
    var buf: [1]u8 = .{0};
    _ = huffmanEncode("a", &buf);
    // "a" is 0x3 (5 bits) = 00011, padded with 111 → 00011_111 = 0x1F
    try std.testing.expectEqual(@as(u8, 0x1F), buf[0]);

    // Corrupt: replace EOS padding with zeros → 00011_000 = 0x18
    buf[0] = 0x18;
    var out: [1]u8 = undefined;
    try std.testing.expectError(error.HuffmanDecodingError, huffmanDecode(&buf, &out));
}

test "huffman empty input" {
    var out: [1]u8 = undefined;
    const len = try huffmanDecode(&[_]u8{}, &out);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "string encode/decode roundtrip (with huffman)" {
    var encode_buf: [64]u8 = @splat(0);
    const len = encodeString(&encode_buf, "www.example.com", true);

    var decode_buf: [64]u8 = undefined;
    const result = try decodeString(encode_buf[0..len], &decode_buf);
    try std.testing.expectEqualStrings("www.example.com", result.value);
}
