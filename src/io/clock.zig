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
        const freq = performanceFrequency();
        // Documented never to fail since Windows XP. If it did, the
        // counter is still a number that only grows: the wrong units beat
        // a zero that would make every elapsed time after the first one
        // enormous.
        if (freq == 0) return count;
        // Whole seconds first, so a machine up for weeks does not
        // overflow the multiply.
        const f: i128 = freq;
        const c: i128 = count;
        return @divTrunc(c, f) * 1_000_000_000 + @divTrunc(@rem(c, f) * 1_000_000_000, f);
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

/// Wait about this long.
///
/// A POSIX sleep that a signal cuts short is resumed with what is left, so
/// the caller gets the wait it asked for; any other error ends the wait,
/// because retrying it would spin. Windows' Sleep takes milliseconds and
/// is not interruptible, so a sub-millisecond wait there rounds down to
/// yielding the rest of the time slice, which is what these callers —
/// retry backoffs — want from a wait that short.
pub fn sleepNs(ns: u64) void {
    if (comptime is_windows) {
        kernel32.Sleep(@intCast(ns / 1_000_000));
        return;
    }
    var req = std.c.timespec{
        .sec = @intCast(ns / 1_000_000_000),
        .nsec = @intCast(ns % 1_000_000_000),
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
    // is. This is what catches a frequency conversion that is off by a
    // factor of a thousand, which a monotonicity test cannot see.
    const start = monotonicNs();
    sleepNs(30 * std.time.ns_per_ms);
    const elapsed = monotonicNs() - start;
    try testing.expect(elapsed >= 25 * std.time.ns_per_ms);
    // Loose on the upper end: a loaded machine is late, and a test that
    // fails for being late fails in CI.
    try testing.expect(elapsed < 3 * std.time.ns_per_s);
}

test "clock: a sleep of zero returns" {
    sleepNs(0);
}
