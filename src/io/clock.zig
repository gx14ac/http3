// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

//! Reading the monotonic clock, and waiting, on POSIX and on Windows.
//!
//! `clock_gettime` and `nanosleep` are POSIX and live in libc. Windows has
//! neither, and `std.c` says so by giving `clockid_t` and `timespec` the
//! type `void` for a Windows target — so a call that compiles everywhere
//! else fails there with a message about a zero-bit parameter in a
//! `x86_64_win` function, which does not look like the missing-function
//! problem it is.
//!
//! Two callers had a copy of the same four lines each. They share this
//! instead, and the difference between the platforms is written down once.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// Declared here because `std.os.windows.kernel32` does not declare them.
const kernel32 = if (!is_windows) struct {} else struct {
    extern "kernel32" fn QueryPerformanceCounter(count: *i64) callconv(.winapi) i32;
    extern "kernel32" fn QueryPerformanceFrequency(freq: *i64) callconv(.winapi) i32;
    extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
};

var cached_freq: std.atomic.Value(i64) = .init(0);

/// Fixed for the life of the process, says the documentation, so it is
/// asked for once: this clock is read on every request.
fn performanceFrequency() i64 {
    if (comptime !is_windows) return 0;
    const cached = cached_freq.load(.monotonic);
    if (cached != 0) return cached;
    var freq: i64 = 0;
    _ = kernel32.QueryPerformanceFrequency(&freq);
    // A racing thread writes the same number, so there is nothing to lose.
    cached_freq.store(freq, .monotonic);
    return freq;
}

/// Nanoseconds from an arbitrary point that only moves forward. The point
/// differs between runs and between the two implementations; only
/// differences mean anything, which is all the callers take.
///
/// Windows reads QueryPerformanceCounter rather than GetTickCount64, whose
/// step is about 15ms — coarse enough to read a request on a local network
/// as having taken no time at all.
pub fn monotonicNs() i128 {
    if (comptime is_windows) {
        var count: i64 = 0;
        _ = kernel32.QueryPerformanceCounter(&count);
        return nsFromTicks(count, performanceFrequency());
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// Performance counter ticks as nanoseconds.
///
/// Its own function, and not behind `is_windows`, so that it is compiled
/// and tested everywhere. The arithmetic is the part of the Windows clock
/// that can be wrong by a factor of a thousand, and a test that only ever
/// runs on POSIX would never look at it.
///
/// The multiply comes first and cannot overflow: both sides widen to i128,
/// and the largest counter an i64 can hold times a billion is about
/// 9.2e27, against an i128 ceiling near 1.7e38.
///
/// A frequency of zero means QueryPerformanceFrequency failed, which is
/// documented not to happen since Windows XP. If it did, the counter is
/// still a number that only grows, so it is returned as it is: the wrong
/// units beat a zero that would make every elapsed time after the first
/// one enormous.
fn nsFromTicks(count: i64, freq: i64) i128 {
    if (freq <= 0) return count;
    return @divTrunc(@as(i128, count) * std.time.ns_per_s, @as(i128, freq));
}

/// Nanoseconds as the milliseconds Sleep counts.
///
/// Its own function for the same reason as nsFromTicks: it is only ever
/// called on Windows, and a rounding rule that is only compiled there is
/// a rounding rule nothing checks.
///
/// Rounded up, not truncated. A wait shorter than a millisecond would
/// otherwise become Sleep(0), which yields the rest of the time slice and
/// turns a backoff into a spin.
///
/// Capped below 0xFFFFFFFF, which Sleep reads as INFINITE: a caller
/// asking for 49 days does not mean "never return", and the cast would
/// trap on the way there.
fn msFromNs(ns: u64) u32 {
    const whole = ns / std.time.ns_per_ms;
    const rounded = whole + @intFromBool(ns % std.time.ns_per_ms != 0);
    return @intCast(@min(rounded, 0xFFFF_FFFE));
}

/// Wait about this long.
///
/// A POSIX sleep that a signal cuts short is resumed with what is left, so
/// the caller gets the wait it asked for; any other error ends the wait,
/// because retrying it would spin. Windows' Sleep is not interruptible and
/// counts whole milliseconds, so a wait there is rounded up to one.
pub fn sleepNs(ns: u64) void {
    if (comptime is_windows) {
        kernel32.Sleep(msFromNs(ns));
        return;
    }
    var req = std.c.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (true) {
        var rem: std.c.timespec = undefined;
        if (std.c.nanosleep(&req, &rem) == 0) return;
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return;
        req = rem;
    }
}

const testing = std.testing;

test "clock: monotonicNs does not go backwards" {
    var last = monotonicNs();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const now = monotonicNs();
        try testing.expect(now >= last);
        last = now;
    }
}

test "clock: monotonicNs counts nanoseconds, not something else" {
    // A 30ms sleep has to read as about 30 million of whatever the unit
    // is. On POSIX this is what catches a units mistake; on Windows the
    // arithmetic it would catch is in nsFromTicks, which the next test
    // reaches directly, because this one only runs on the host.
    const start = monotonicNs();
    sleepNs(30 * std.time.ns_per_ms);
    const elapsed = monotonicNs() - start;
    try testing.expect(elapsed >= 25 * std.time.ns_per_ms);
    // Loose on the upper end: a loaded machine is late, and a test that
    // fails for being late fails in CI.
    try testing.expect(elapsed < 3 * std.time.ns_per_s);
}

test "clock: performance counter ticks convert to nanoseconds" {
    // The Windows arithmetic, tested on whatever host runs this: the
    // Windows clock itself cannot be, and this is the half that can be
    // wrong by a factor of a thousand.
    const qpc_freq: i64 = 10_000_000; // what Windows 10 reports: 10MHz

    // A second of ticks is a second of nanoseconds, whatever the rate.
    try testing.expectEqual(@as(i128, std.time.ns_per_s), nsFromTicks(qpc_freq, qpc_freq));
    try testing.expectEqual(@as(i128, std.time.ns_per_s), nsFromTicks(1000, 1000));

    // 30ms, the interval the sleep test above measures.
    try testing.expectEqual(
        @as(i128, 30 * std.time.ns_per_ms),
        nsFromTicks(@divExact(qpc_freq * 3, 100), qpc_freq),
    );

    // One tick is 100ns at 10MHz — the resolution that GetTickCount64,
    // with its ~15ms step, would have thrown away.
    try testing.expectEqual(@as(i128, 100), nsFromTicks(1, qpc_freq));

    // A month of uptime, exactly: the multiply happens in i128, so there
    // is nothing here to overflow.
    const month_s: i64 = 30 * 24 * 60 * 60;
    try testing.expectEqual(
        @as(i128, month_s) * std.time.ns_per_s,
        nsFromTicks(qpc_freq * month_s, qpc_freq),
    );

    // Zero and a nonsense frequency: the ticks come back as they are,
    // which is a clock in the wrong units rather than a clock stuck at
    // the same answer.
    try testing.expectEqual(@as(i128, 1234), nsFromTicks(1234, 0));
    try testing.expectEqual(@as(i128, 1234), nsFromTicks(1234, -1));
    try testing.expectEqual(@as(i128, 0), nsFromTicks(0, qpc_freq));
}

test "clock: a wait is rounded up to the milliseconds Sleep counts" {
    // Also the Windows half, also tested on whatever host runs this.
    // Anything under a millisecond has to round up to one: Sleep(0)
    // yields the rest of the time slice, so a backoff of 100us would
    // spin instead of waiting.
    try testing.expectEqual(@as(u32, 1), msFromNs(1));
    try testing.expectEqual(@as(u32, 1), msFromNs(100 * std.time.ns_per_us));
    try testing.expectEqual(@as(u32, 1), msFromNs(std.time.ns_per_ms));
    try testing.expectEqual(@as(u32, 2), msFromNs(std.time.ns_per_ms + 1));
    try testing.expectEqual(@as(u32, 30), msFromNs(30 * std.time.ns_per_ms));

    // Nothing asked for is nothing waited.
    try testing.expectEqual(@as(u32, 0), msFromNs(0));

    // INFINITE is 0xFFFFFFFF, and a wait must never become one: 49 days
    // and anything past it stop one millisecond short.
    try testing.expectEqual(@as(u32, 0xFFFF_FFFE), msFromNs(0xFFFF_FFFF * std.time.ns_per_ms));
    try testing.expectEqual(@as(u32, 0xFFFF_FFFE), msFromNs(std.math.maxInt(u64)));
}

test "clock: a sleep of zero returns" {
    sleepNs(0);
}
