/// HPACK Huffman coding tables (RFC 7541 Appendix B)
/// Generated from the canonical Huffman code table.

pub const HuffmanEntry = struct {
    code: u32,
    bit_len: u8,
};

/// Encode table: symbol (0-255) → (code, bit_length)
pub const huffman_table = [256]HuffmanEntry{
    .{ .code = 0x1ff8, .bit_len = 13 }, // 0
    .{ .code = 0x7fffd8, .bit_len = 23 }, // 1
    .{ .code = 0xfffffe2, .bit_len = 28 }, // 2
    .{ .code = 0xfffffe3, .bit_len = 28 }, // 3
    .{ .code = 0xfffffe4, .bit_len = 28 }, // 4
    .{ .code = 0xfffffe5, .bit_len = 28 }, // 5
    .{ .code = 0xfffffe6, .bit_len = 28 }, // 6
    .{ .code = 0xfffffe7, .bit_len = 28 }, // 7
    .{ .code = 0xfffffe8, .bit_len = 28 }, // 8
    .{ .code = 0xffffea, .bit_len = 24 }, // 9
    .{ .code = 0x3ffffffc, .bit_len = 30 }, // 10
    .{ .code = 0xfffffe9, .bit_len = 28 }, // 11
    .{ .code = 0xfffffea, .bit_len = 28 }, // 12
    .{ .code = 0x3ffffffd, .bit_len = 30 }, // 13
    .{ .code = 0xfffffeb, .bit_len = 28 }, // 14
    .{ .code = 0xfffffec, .bit_len = 28 }, // 15
    .{ .code = 0xfffffed, .bit_len = 28 }, // 16
    .{ .code = 0xfffffee, .bit_len = 28 }, // 17
    .{ .code = 0xfffffef, .bit_len = 28 }, // 18
    .{ .code = 0xffffff0, .bit_len = 28 }, // 19
    .{ .code = 0xffffff1, .bit_len = 28 }, // 20
    .{ .code = 0xffffff2, .bit_len = 28 }, // 21
    .{ .code = 0x3ffffffe, .bit_len = 30 }, // 22
    .{ .code = 0xffffff3, .bit_len = 28 }, // 23
    .{ .code = 0xffffff4, .bit_len = 28 }, // 24
    .{ .code = 0xffffff5, .bit_len = 28 }, // 25
    .{ .code = 0xffffff6, .bit_len = 28 }, // 26
    .{ .code = 0xffffff7, .bit_len = 28 }, // 27
    .{ .code = 0xffffff8, .bit_len = 28 }, // 28
    .{ .code = 0xffffff9, .bit_len = 28 }, // 29
    .{ .code = 0xffffffa, .bit_len = 28 }, // 30
    .{ .code = 0xffffffb, .bit_len = 28 }, // 31
    .{ .code = 0x14, .bit_len = 6 }, // 32 ' '
    .{ .code = 0x3f8, .bit_len = 10 }, // 33 '!'
    .{ .code = 0x3f9, .bit_len = 10 }, // 34 '"'
    .{ .code = 0xffa, .bit_len = 12 }, // 35 '#'
    .{ .code = 0x1ff9, .bit_len = 13 }, // 36 '$'
    .{ .code = 0x15, .bit_len = 6 }, // 37 '%'
    .{ .code = 0xf8, .bit_len = 8 }, // 38 '&'
    .{ .code = 0x7fa, .bit_len = 11 }, // 39 '\''
    .{ .code = 0x3fa, .bit_len = 10 }, // 40 '('
    .{ .code = 0x3fb, .bit_len = 10 }, // 41 ')'
    .{ .code = 0xf9, .bit_len = 8 }, // 42 '*'
    .{ .code = 0x7fb, .bit_len = 11 }, // 43 '+'
    .{ .code = 0xfa, .bit_len = 8 }, // 44 ','
    .{ .code = 0x16, .bit_len = 6 }, // 45 '-'
    .{ .code = 0x17, .bit_len = 6 }, // 46 '.'
    .{ .code = 0x18, .bit_len = 6 }, // 47 '/'
    .{ .code = 0x0, .bit_len = 5 }, // 48 '0'
    .{ .code = 0x1, .bit_len = 5 }, // 49 '1'
    .{ .code = 0x2, .bit_len = 5 }, // 50 '2'
    .{ .code = 0x19, .bit_len = 6 }, // 51 '3'
    .{ .code = 0x1a, .bit_len = 6 }, // 52 '4'
    .{ .code = 0x1b, .bit_len = 6 }, // 53 '5'
    .{ .code = 0x1c, .bit_len = 6 }, // 54 '6'
    .{ .code = 0x1d, .bit_len = 6 }, // 55 '7'
    .{ .code = 0x1e, .bit_len = 6 }, // 56 '8'
    .{ .code = 0x1f, .bit_len = 6 }, // 57 '9'
    .{ .code = 0x5c, .bit_len = 7 }, // 58 ':'
    .{ .code = 0xfb, .bit_len = 8 }, // 59 ';'
    .{ .code = 0x7ffc, .bit_len = 15 }, // 60 '<'
    .{ .code = 0x20, .bit_len = 6 }, // 61 '='
    .{ .code = 0xffb, .bit_len = 12 }, // 62 '>'
    .{ .code = 0x3fc, .bit_len = 10 }, // 63 '?'
    .{ .code = 0x1ffa, .bit_len = 13 }, // 64 '@'
    .{ .code = 0x21, .bit_len = 6 }, // 65 'A'
    .{ .code = 0x5d, .bit_len = 7 }, // 66 'B'
    .{ .code = 0x5e, .bit_len = 7 }, // 67 'C'
    .{ .code = 0x5f, .bit_len = 7 }, // 68 'D'
    .{ .code = 0x60, .bit_len = 7 }, // 69 'E'
    .{ .code = 0x61, .bit_len = 7 }, // 70 'F'
    .{ .code = 0x62, .bit_len = 7 }, // 71 'G'
    .{ .code = 0x63, .bit_len = 7 }, // 72 'H'
    .{ .code = 0x64, .bit_len = 7 }, // 73 'I'
    .{ .code = 0x65, .bit_len = 7 }, // 74 'J'
    .{ .code = 0x66, .bit_len = 7 }, // 75 'K'
    .{ .code = 0x67, .bit_len = 7 }, // 76 'L'
    .{ .code = 0x68, .bit_len = 7 }, // 77 'M'
    .{ .code = 0x69, .bit_len = 7 }, // 78 'N'
    .{ .code = 0x6a, .bit_len = 7 }, // 79 'O'
    .{ .code = 0x6b, .bit_len = 7 }, // 80 'P'
    .{ .code = 0x6c, .bit_len = 7 }, // 81 'Q'
    .{ .code = 0x6d, .bit_len = 7 }, // 82 'R'
    .{ .code = 0x6e, .bit_len = 7 }, // 83 'S'
    .{ .code = 0x6f, .bit_len = 7 }, // 84 'T'
    .{ .code = 0x70, .bit_len = 7 }, // 85 'U'
    .{ .code = 0x71, .bit_len = 7 }, // 86 'V'
    .{ .code = 0x72, .bit_len = 7 }, // 87 'W'
    .{ .code = 0xfc, .bit_len = 8 }, // 88 'X'
    .{ .code = 0x73, .bit_len = 7 }, // 89 'Y'
    .{ .code = 0xfd, .bit_len = 8 }, // 90 'Z'
    .{ .code = 0x1ffb, .bit_len = 13 }, // 91 '['
    .{ .code = 0x7ffc, .bit_len = 15 }, // 92 '\\'
    .{ .code = 0x1ffc, .bit_len = 13 }, // 93 ']'
    .{ .code = 0x3ffc, .bit_len = 14 }, // 94 '^'
    .{ .code = 0x22, .bit_len = 6 }, // 95 '_'
    .{ .code = 0x7ffd, .bit_len = 15 }, // 96 '`'
    .{ .code = 0x3, .bit_len = 5 }, // 97 'a'
    .{ .code = 0x23, .bit_len = 6 }, // 98 'b'
    .{ .code = 0x4, .bit_len = 5 }, // 99 'c'
    .{ .code = 0x24, .bit_len = 6 }, // 100 'd'
    .{ .code = 0x5, .bit_len = 5 }, // 101 'e'
    .{ .code = 0x25, .bit_len = 6 }, // 102 'f'
    .{ .code = 0x26, .bit_len = 6 }, // 103 'g'
    .{ .code = 0x27, .bit_len = 6 }, // 104 'h'
    .{ .code = 0x6, .bit_len = 5 }, // 105 'i'
    .{ .code = 0x74, .bit_len = 7 }, // 106 'j'
    .{ .code = 0x75, .bit_len = 7 }, // 107 'k'
    .{ .code = 0x28, .bit_len = 6 }, // 108 'l'
    .{ .code = 0x29, .bit_len = 6 }, // 109 'm'
    .{ .code = 0x2a, .bit_len = 6 }, // 110 'n'
    .{ .code = 0x7, .bit_len = 5 }, // 111 'o'
    .{ .code = 0x2b, .bit_len = 6 }, // 112 'p'
    .{ .code = 0x76, .bit_len = 7 }, // 113 'q'
    .{ .code = 0x2c, .bit_len = 6 }, // 114 'r'
    .{ .code = 0x8, .bit_len = 5 }, // 115 's'
    .{ .code = 0x9, .bit_len = 5 }, // 116 't'
    .{ .code = 0x2d, .bit_len = 6 }, // 117 'u'
    .{ .code = 0x77, .bit_len = 7 }, // 118 'v'
    .{ .code = 0x78, .bit_len = 7 }, // 119 'w'
    .{ .code = 0x79, .bit_len = 7 }, // 120 'x'
    .{ .code = 0x7a, .bit_len = 7 }, // 121 'y'
    .{ .code = 0x7b, .bit_len = 7 }, // 122 'z'
    .{ .code = 0x7ffe, .bit_len = 15 }, // 123 '{'
    .{ .code = 0x7fc, .bit_len = 11 }, // 124 '|'
    .{ .code = 0x3ffd, .bit_len = 14 }, // 125 '}'
    .{ .code = 0x1ffd, .bit_len = 13 }, // 126 '~'
    .{ .code = 0xffffffc, .bit_len = 28 }, // 127
    .{ .code = 0xfffe6, .bit_len = 20 }, // 128
    .{ .code = 0x3fffd2, .bit_len = 22 }, // 129
    .{ .code = 0xfffe7, .bit_len = 20 }, // 130
    .{ .code = 0xfffe8, .bit_len = 20 }, // 131
    .{ .code = 0x3fffd3, .bit_len = 22 }, // 132
    .{ .code = 0x3fffd4, .bit_len = 22 }, // 133
    .{ .code = 0x3fffd5, .bit_len = 22 }, // 134
    .{ .code = 0x7fffd9, .bit_len = 23 }, // 135
    .{ .code = 0x3fffd6, .bit_len = 22 }, // 136
    .{ .code = 0x7fffda, .bit_len = 23 }, // 137
    .{ .code = 0x7fffdb, .bit_len = 23 }, // 138
    .{ .code = 0x7fffdc, .bit_len = 23 }, // 139
    .{ .code = 0x7fffdd, .bit_len = 23 }, // 140
    .{ .code = 0x7fffde, .bit_len = 23 }, // 141
    .{ .code = 0xffffeb, .bit_len = 24 }, // 142
    .{ .code = 0x7fffdf, .bit_len = 23 }, // 143
    .{ .code = 0xffffec, .bit_len = 24 }, // 144
    .{ .code = 0xffffed, .bit_len = 24 }, // 145
    .{ .code = 0x3fffd7, .bit_len = 22 }, // 146
    .{ .code = 0x7fffe0, .bit_len = 23 }, // 147
    .{ .code = 0xffffee, .bit_len = 24 }, // 148
    .{ .code = 0x7fffe1, .bit_len = 23 }, // 149
    .{ .code = 0x7fffe2, .bit_len = 23 }, // 150
    .{ .code = 0x7fffe3, .bit_len = 23 }, // 151
    .{ .code = 0x7fffe4, .bit_len = 23 }, // 152
    .{ .code = 0x1fffdc, .bit_len = 21 }, // 153
    .{ .code = 0x3fffd8, .bit_len = 22 }, // 154
    .{ .code = 0x7fffe5, .bit_len = 23 }, // 155
    .{ .code = 0x3fffd9, .bit_len = 22 }, // 156
    .{ .code = 0x7fffe6, .bit_len = 23 }, // 157
    .{ .code = 0x7fffe7, .bit_len = 23 }, // 158
    .{ .code = 0xffffef, .bit_len = 24 }, // 159
    .{ .code = 0x3fffda, .bit_len = 22 }, // 160
    .{ .code = 0x1fffdd, .bit_len = 21 }, // 161
    .{ .code = 0xfffe9, .bit_len = 20 }, // 162
    .{ .code = 0x3fffdb, .bit_len = 22 }, // 163
    .{ .code = 0x3fffdc, .bit_len = 22 }, // 164
    .{ .code = 0x7fffe8, .bit_len = 23 }, // 165
    .{ .code = 0x7fffe9, .bit_len = 23 }, // 166
    .{ .code = 0x1fffde, .bit_len = 21 }, // 167
    .{ .code = 0x7fffea, .bit_len = 23 }, // 168
    .{ .code = 0x3fffdd, .bit_len = 22 }, // 169
    .{ .code = 0x3fffde, .bit_len = 22 }, // 170
    .{ .code = 0xfffff0, .bit_len = 24 }, // 171
    .{ .code = 0x1fffdf, .bit_len = 21 }, // 172
    .{ .code = 0x3fffdf, .bit_len = 22 }, // 173
    .{ .code = 0x7fffeb, .bit_len = 23 }, // 174
    .{ .code = 0x7fffec, .bit_len = 23 }, // 175
    .{ .code = 0x1fffe0, .bit_len = 21 }, // 176
    .{ .code = 0x1fffe1, .bit_len = 21 }, // 177
    .{ .code = 0x3fffe0, .bit_len = 22 }, // 178
    .{ .code = 0x1fffe2, .bit_len = 21 }, // 179
    .{ .code = 0x7fffed, .bit_len = 23 }, // 180
    .{ .code = 0x3fffe1, .bit_len = 22 }, // 181
    .{ .code = 0x7fffee, .bit_len = 23 }, // 182
    .{ .code = 0x7fffef, .bit_len = 23 }, // 183
    .{ .code = 0xfffea, .bit_len = 20 }, // 184
    .{ .code = 0x3fffe2, .bit_len = 22 }, // 185
    .{ .code = 0x3fffe3, .bit_len = 22 }, // 186
    .{ .code = 0x3fffe4, .bit_len = 22 }, // 187
    .{ .code = 0x7ffff0, .bit_len = 23 }, // 188
    .{ .code = 0x3fffe5, .bit_len = 22 }, // 189
    .{ .code = 0x3fffe6, .bit_len = 22 }, // 190
    .{ .code = 0x7ffff1, .bit_len = 23 }, // 191
    .{ .code = 0x3ffffe0, .bit_len = 26 }, // 192
    .{ .code = 0x3ffffe1, .bit_len = 26 }, // 193
    .{ .code = 0xfffeb, .bit_len = 20 }, // 194
    .{ .code = 0x7fff1, .bit_len = 19 }, // 195
    .{ .code = 0x3fffe7, .bit_len = 22 }, // 196
    .{ .code = 0x7ffff2, .bit_len = 23 }, // 197
    .{ .code = 0x3fffe8, .bit_len = 22 }, // 198
    .{ .code = 0x1ffffec, .bit_len = 25 }, // 199
    .{ .code = 0x3ffffe2, .bit_len = 26 }, // 200
    .{ .code = 0x3ffffe3, .bit_len = 26 }, // 201
    .{ .code = 0x3ffffe4, .bit_len = 26 }, // 202
    .{ .code = 0x7ffffde, .bit_len = 27 }, // 203
    .{ .code = 0x7ffffdf, .bit_len = 27 }, // 204
    .{ .code = 0x3ffffe5, .bit_len = 26 }, // 205
    .{ .code = 0xfffff1, .bit_len = 24 }, // 206
    .{ .code = 0x1ffffed, .bit_len = 25 }, // 207
    .{ .code = 0x7fff2, .bit_len = 19 }, // 208
    .{ .code = 0x1fffe3, .bit_len = 21 }, // 209
    .{ .code = 0x3ffffe6, .bit_len = 26 }, // 210
    .{ .code = 0x7ffffe0, .bit_len = 27 }, // 211
    .{ .code = 0x7ffffe1, .bit_len = 27 }, // 212
    .{ .code = 0x3ffffe7, .bit_len = 26 }, // 213
    .{ .code = 0x7ffffe2, .bit_len = 27 }, // 214
    .{ .code = 0xfffff2, .bit_len = 24 }, // 215
    .{ .code = 0x1fffe4, .bit_len = 21 }, // 216
    .{ .code = 0x1fffe5, .bit_len = 21 }, // 217
    .{ .code = 0x3ffffe8, .bit_len = 26 }, // 218
    .{ .code = 0x3ffffe9, .bit_len = 26 }, // 219
    .{ .code = 0xffffffd, .bit_len = 28 }, // 220
    .{ .code = 0x7ffffe3, .bit_len = 27 }, // 221
    .{ .code = 0x7ffffe4, .bit_len = 27 }, // 222
    .{ .code = 0x7ffffe5, .bit_len = 27 }, // 223
    .{ .code = 0xfffec, .bit_len = 20 }, // 224
    .{ .code = 0xfffff3, .bit_len = 24 }, // 225
    .{ .code = 0xfffed, .bit_len = 20 }, // 226
    .{ .code = 0x1fffe6, .bit_len = 21 }, // 227
    .{ .code = 0x3fffe9, .bit_len = 22 }, // 228
    .{ .code = 0x1fffe7, .bit_len = 21 }, // 229
    .{ .code = 0x1fffe8, .bit_len = 21 }, // 230
    .{ .code = 0x7ffff3, .bit_len = 23 }, // 231
    .{ .code = 0x3fffea, .bit_len = 22 }, // 232
    .{ .code = 0x3fffeb, .bit_len = 22 }, // 233
    .{ .code = 0x1ffffee, .bit_len = 25 }, // 234
    .{ .code = 0x1ffffef, .bit_len = 25 }, // 235
    .{ .code = 0xfffff4, .bit_len = 24 }, // 236
    .{ .code = 0xfffff5, .bit_len = 24 }, // 237
    .{ .code = 0x3ffffea, .bit_len = 26 }, // 238
    .{ .code = 0x7ffff4, .bit_len = 23 }, // 239
    .{ .code = 0x3ffffeb, .bit_len = 26 }, // 240
    .{ .code = 0x7ffffe6, .bit_len = 27 }, // 241
    .{ .code = 0x3ffffec, .bit_len = 26 }, // 242
    .{ .code = 0x3ffffed, .bit_len = 26 }, // 243
    .{ .code = 0x7ffffe7, .bit_len = 27 }, // 244
    .{ .code = 0x7ffffe8, .bit_len = 27 }, // 245
    .{ .code = 0x7ffffe9, .bit_len = 27 }, // 246
    .{ .code = 0x7ffffea, .bit_len = 27 }, // 247
    .{ .code = 0x7ffffeb, .bit_len = 27 }, // 248
    .{ .code = 0xffffffe, .bit_len = 28 }, // 249
    .{ .code = 0x7ffffec, .bit_len = 27 }, // 250
    .{ .code = 0x7ffffed, .bit_len = 27 }, // 251
    .{ .code = 0x7ffffee, .bit_len = 27 }, // 252
    .{ .code = 0x7ffffef, .bit_len = 27 }, // 253
    .{ .code = 0x7fffff0, .bit_len = 27 }, // 254
    .{ .code = 0x3ffffee, .bit_len = 26 }, // 255
};

/// Huffman decode state machine entry.
/// flags: 0x01 = emit symbol, 0x02 = error/EOS, 0x04 = accepting (valid EOS padding state)
pub const DecodeEntry = struct {
    next_state: u16,
    symbol: u8,
    flags: u8,
};

/// Placeholder decode table — a simplified bit-by-bit decoder.
/// For production, this should be a pre-computed multi-bit lookup table.
/// Using a flat approach: state = current partial code bit position.
/// This is a stub that will be replaced with a proper state machine.
///
/// For now, we use a simple approach: decode one bit at a time by traversing
/// the code tree implied by the huffman_table.
/// The decode table has 512 states x 2 entries (one per input bit).
pub const huffman_decode_table = buildDecodeTable();

const max_decode_states = 1024;

fn buildDecodeTable() [max_decode_states][2]DecodeEntry {
    @setEvalBranchQuota(100_000_000);

    var table: [max_decode_states][2]DecodeEntry = undefined;
    for (&table) |*row| {
        row[0] = .{ .next_state = 0, .symbol = 0, .flags = 0x02 };
        row[1] = .{ .next_state = 0, .symbol = 0, .flags = 0x02 };
    }

    var next_free_state: u16 = 1;

    for (huffman_table, 0..) |entry, sym| {
        var state: u16 = 0;
        var bit_idx: u32 = 0;
        while (bit_idx < entry.bit_len) : (bit_idx += 1) {
            const shift = entry.bit_len - 1 - bit_idx;
            const bit: u1 = @intCast((entry.code >> @intCast(shift)) & 1);
            const is_last = (bit_idx == entry.bit_len - 1);

            if (is_last) {
                table[state][bit] = .{
                    .next_state = 0,
                    .symbol = @intCast(sym),
                    .flags = 0x01,
                };
            } else {
                const existing = table[state][bit];
                if (existing.flags == 0x02) {
                    table[state][bit] = .{
                        .next_state = next_free_state,
                        .symbol = 0,
                        .flags = 0x00,
                    };
                    state = next_free_state;
                    next_free_state += 1;
                } else {
                    state = existing.next_state;
                }
            }
        }
    }

    markAcceptingStates(&table);

    return table;
}

fn markAcceptingStates(table: *[max_decode_states][2]DecodeEntry) void {
    // A state accepts EOS padding if following all-1-bits from it
    // only reaches other intermediate states or the EOS error state.
    // We iterate: mark states where bit=1 leads to error as accepting,
    // then propagate backwards.
    var changed = true;
    while (changed) {
        changed = false;
        for (table) |*row| {
            const entry_1 = &row[1];
            if (entry_1.flags & 0x04 != 0) continue; // already marked
            if (entry_1.flags & 0x01 != 0) continue; // emit — not an accepting boundary
            if (entry_1.flags & 0x02 != 0) {
                // Error/EOS on bit=1: this is accepting
                entry_1.flags |= 0x04;
                changed = true;
            } else {
                // Intermediate: accepting if target state is also accepting
                const target = entry_1.next_state;
                const target_entry_1 = table[target][1];
                if (target_entry_1.flags & 0x04 != 0) {
                    entry_1.flags |= 0x04;
                    changed = true;
                }
            }
        }
    }
}
