// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

/// gRPC status codes (https://grpc.github.io/grpc/core/md_doc_statuscodes.html)
pub const Code = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,

    pub fn fromInt(v: u32) Code {
        if (v > 16) return .unknown;
        return @enumFromInt(v);
    }

    pub fn isOk(self: Code) bool {
        return self == .ok;
    }
};

pub const Status = struct {
    code: Code,
    message: []const u8,

    pub const ok = Status{ .code = .ok, .message = "" };

    pub fn isOk(self: Status) bool {
        return self.code.isOk();
    }
};
