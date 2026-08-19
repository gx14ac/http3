const std = @import("std");
const loss_mod = @import("loss.zig");

const SentPacket = loss_mod.SentPacket;
const RttEstimator = loss_mod.RttEstimator;

/// RFC 9438: CUBIC Congestion Control.
///
/// All arithmetic is integer-only. Time is in microseconds, window in bytes.
/// Constants use rational representation to avoid floating point.
///
/// Key parameters (RFC 9438 §5.1):
///   C = 0.4 (scaling factor)
///   β_cubic = 0.7 (multiplicative decrease)
pub const CubicCc = struct {
    max_datagram_size: u64,
    congestion_window: u64,
    bytes_in_flight: u64,
    ssthresh: u64,

    // Cubic state
    w_max: u64, // cwnd at last congestion event (bytes)
    prior_w_max: u64, // W_max before the previous one (for fast convergence)
    epoch_start_us: ?u64, // time of last congestion event
    k_us: u64, // time to reach W_max from origin (microseconds)
    w_est: u64, // TCP-friendly estimate (bytes)
    cwnd_at_epoch: u64, // cwnd when epoch started

    // Recovery
    recovery_start_time_us: ?u64,

    // Batch state
    congestion_pending_acks: u64,
    send_one_packet_in_recovery: bool,
    in_recovery: bool,
    underutilized: bool,
    ack_last_loss_us: ?u64,

    // Persistent congestion per space
    persistent_congestion: [NUMBER_SPACE_COUNT]PersistentCongestionState,

    const NUMBER_SPACE_COUNT: usize = 3;
    const MIN_WINDOW_PACKETS: u64 = 2;

    // β_cubic = 7/10
    const BETA_NUM: u64 = 7;
    const BETA_DEN: u64 = 10;
    // C = 4/10 (in segments); in bytes: C_bytes = 4 / (10 * MDS)
    const C_NUM: u64 = 4;
    const C_DEN: u64 = 10;
    // For TCP-friendly: 3*(1-β)/(1+β) = 3*3/10 / (17/10) = 9/17
    const RENO_GROWTH_NUM: u64 = 9;
    const RENO_GROWTH_DEN: u64 = 17;

    pub fn init() CubicCc {
        return initWithMds(1200);
    }

    pub fn initWithMds(mds: u64) CubicCc {
        const min_window = 2 * mds;
        const initial_window = @min(10 * mds, @max(@as(u64, 14720), min_window));
        return .{
            .max_datagram_size = mds,
            .congestion_window = initial_window,
            .bytes_in_flight = 0,
            .ssthresh = std.math.maxInt(u64),
            .w_max = 0,
            .prior_w_max = 0,
            .epoch_start_us = null,
            .k_us = 0,
            .w_est = 0,
            .cwnd_at_epoch = 0,
            .recovery_start_time_us = null,
            .congestion_pending_acks = 0,
            .send_one_packet_in_recovery = false,
            .in_recovery = false,
            .underutilized = false,
            .ack_last_loss_us = null,
            .persistent_congestion = [_]PersistentCongestionState{PersistentCongestionState.init()} ** NUMBER_SPACE_COUNT,
        };
    }

    pub fn canSend(self: *const CubicCc) bool {
        if (self.send_one_packet_in_recovery) return true;
        return self.bytes_in_flight + self.max_datagram_size <= self.congestion_window;
    }

    pub fn sendBudget(self: *const CubicCc) u64 {
        if (self.send_one_packet_in_recovery) return self.max_datagram_size;
        if (self.congestion_window <= self.bytes_in_flight) return 0;
        return self.congestion_window - self.bytes_in_flight;
    }

    pub fn setUnderutilized(self: *CubicCc, v: bool) void {
        self.underutilized = v;
    }

    pub fn packetSent(self: *CubicCc, sent: *const SentPacket) void {
        if (!sent.in_flight) return;
        self.bytes_in_flight += sent.size;
        if (self.send_one_packet_in_recovery) {
            self.send_one_packet_in_recovery = false;
        }
    }

    pub fn packetAcked(self: *CubicCc, sent: *const SentPacket) void {
        if (!sent.in_flight) return;
        self.bytes_in_flight -= sent.size;

        if (self.underutilized) return;

        if (self.recovery_start_time_us) |recovery_start| {
            if (sent.time_sent_us < recovery_start) return;
        }
        self.congestion_pending_acks += sent.size;
    }

    pub fn packetLost(self: *CubicCc, space: usize, sent: *const SentPacket, rtt: *const RttEstimator) void {
        self.trackPersistentCongestion(space, sent, rtt);

        if (!sent.in_flight) return;
        self.bytes_in_flight -= sent.size;

        if (self.ack_last_loss_us == null or sent.time_sent_us > self.ack_last_loss_us.?) {
            self.ack_last_loss_us = sent.time_sent_us;
        }
    }

    pub fn packetBatchEnd(self: *CubicCc, now_us: u64, space: usize, rtt: *RttEstimator, max_ack_delay_us: u64) void {
        if (self.ack_last_loss_us) |loss_time| {
            const recovery_start = self.recovery_start_time_us orelse 0;
            if (loss_time >= recovery_start) {
                self.enterRecovery(now_us);
            }
        } else if (self.congestion_pending_acks > 0) {
            self.in_recovery = false;
            if (self.congestion_window < self.ssthresh) {
                // Slow start
                const d = @min(self.ssthresh - self.congestion_window, self.congestion_pending_acks);
                self.congestion_window += d;
                self.congestion_pending_acks -= d;
                if (self.congestion_pending_acks == 0) {
                    // All acked bytes consumed by slow start
                } else {
                    // Transition mid-batch: remaining goes to Cubic
                    self.cubicGrowth(now_us, rtt);
                }
            } else {
                self.cubicGrowth(now_us, rtt);
            }
        }

        // Check persistent congestion (RFC 9002 §7.6)
        if (self.ack_last_loss_us != null) {
            self.checkPersistentCongestion(space, rtt, max_ack_delay_us);
        }

        self.congestion_pending_acks = 0;
        self.ack_last_loss_us = null;
    }

    /// Handle ECN CE signal — enters recovery if not already in this round.
    pub fn onCongestionEvent(self: *CubicCc, now_us: u64) void {
        const recovery_start = self.recovery_start_time_us orelse 0;
        if (now_us <= recovery_start) return;
        self.enterRecovery(now_us);
    }

    pub fn packetDiscarded(self: *CubicCc, sent: *const SentPacket) void {
        if (sent.in_flight) {
            if (self.bytes_in_flight >= sent.size) {
                self.bytes_in_flight -= sent.size;
            }
        }
    }

    pub fn minimumCongestionWindow(self: *const CubicCc) u64 {
        return MIN_WINDOW_PACKETS * self.max_datagram_size;
    }

    pub fn inSlowStart(self: *const CubicCc) bool {
        return self.congestion_window < self.ssthresh;
    }

    pub fn inRecovery(self: *const CubicCc) bool {
        return self.in_recovery;
    }

    // ─── Cubic internals ───

    fn enterRecovery(self: *CubicCc, now_us: u64) void {
        self.recovery_start_time_us = now_us;

        // Fast convergence (RFC 9438 §5.8)
        if (self.congestion_window < self.prior_w_max) {
            // W_max = cwnd * (1+β)/2 = cwnd * 17/20
            self.prior_w_max = self.congestion_window;
            self.w_max = (self.congestion_window * 17) / 20;
        } else {
            self.prior_w_max = self.congestion_window;
            self.w_max = self.congestion_window;
        }

        // β_cubic multiplicative decrease: ssthresh = cwnd * β
        self.ssthresh = (self.congestion_window * BETA_NUM) / BETA_DEN;
        self.congestion_window = @max(self.ssthresh, self.minimumCongestionWindow());
        self.send_one_packet_in_recovery = true;
        self.in_recovery = true;

        // Reset epoch
        self.epoch_start_us = null;
        self.k_us = 0;
    }

    fn cubicGrowth(self: *CubicCc, now_us: u64, rtt: *const RttEstimator) void {
        if (self.epoch_start_us == null) {
            self.epoch_start_us = now_us;
            self.cwnd_at_epoch = self.congestion_window;
            // K = cbrt(W_max - cwnd_epoch) * something... let me compute properly
            // K = cbrt((W_max - cwnd) / C) in segments, time in seconds
            // In our units: K_us = cbrt((W_max - cwnd) * MDS * DEN_C / NUM_C) * 1_000_000^(1/3)
            // Simplified: see computeK()
            self.k_us = self.computeK();
            // Initialize TCP-friendly estimate
            self.w_est = self.congestion_window;
        }

        const t_us = now_us - self.epoch_start_us.?;

        // W_cubic(t) = C * (t - K)^3 + W_max
        const w_cubic = self.cubicWindow(t_us);

        // TCP-friendly region (RFC 9438 §5.5)
        // W_est grows by 3*(1-β)/(1+β) * MDS per RTT worth of acked bytes
        if (rtt.smoothed_rtt_us > 0) {
            // Growth per acked bytes: (RENO_GROWTH_NUM * MDS / RENO_GROWTH_DEN) per cwnd worth
            const reno_increment = (self.congestion_pending_acks * RENO_GROWTH_NUM * self.max_datagram_size) /
                (RENO_GROWTH_DEN * self.congestion_window);
            self.w_est += reno_increment;
        }

        // Use max(W_cubic, W_est) — Cubic is TCP-friendly (RFC 9438 §5.5)
        const target = @max(w_cubic, self.w_est);

        if (target > self.congestion_window) {
            // Grow by min(target - cwnd, pending_acks) to avoid jumping
            const growth = @min(target - self.congestion_window, self.congestion_pending_acks);
            self.congestion_window += growth;
        }
    }

    /// Compute K in microseconds: K = cbrt(W_max * (1 - β) / C) converted to time.
    /// W_max and cwnd are in bytes. We need K in microseconds.
    ///
    /// RFC 9438 §5.1: W_cubic(t) = C * (t - K)^3 + W_max (W in segments, t in seconds)
    /// K = cbrt((W_max - cwnd_epoch) / C)  (in segments, seconds)
    ///
    /// Converting to our units (bytes, microseconds):
    /// K_us = cbrt((W_max - cwnd_epoch) * MDS / (C_NUM/C_DEN)) * 1e6
    ///      = cbrt((W_max - cwnd_epoch) * MDS * C_DEN / C_NUM) * 1e6
    ///
    /// To avoid overflow with 1e6^3 = 1e18, we compute:
    /// K_us = intCbrt(delta_segs * C_DEN / C_NUM) * 1_000_000
    /// where delta_segs = (W_max - cwnd_epoch) / MDS
    fn computeK(self: *const CubicCc) u64 {
        if (self.w_max <= self.cwnd_at_epoch) return 0;
        const delta_bytes = self.w_max - self.cwnd_at_epoch;
        const delta_segs = delta_bytes / self.max_datagram_size;
        // K^3 = delta_segs * C_DEN / C_NUM = delta_segs * 10 / 4 = delta_segs * 5 / 2
        const k_cubed = (delta_segs * C_DEN) / C_NUM;
        const k_segs = intCbrt(k_cubed);
        // K is in "RTT units" conceptually, but RFC defines it in seconds.
        // Since our W is in segments and C=0.4/s^3, K is in seconds.
        // Convert to microseconds:
        return k_segs * 1_000_000;
    }

    /// W_cubic(t) = C * (t - K)^3 + W_max
    /// With t, K in microseconds; result in bytes.
    ///
    /// C * (t-K)^3 in bytes:
    ///   = (C_NUM / C_DEN) * ((t_us - K_us) / 1e6)^3 * MDS + W_max
    ///   = C_NUM * MDS * (t_us - K_us)^3 / (C_DEN * 1e18) + W_max
    ///
    /// To avoid overflow: compute in steps, cap intermediate values.
    fn cubicWindow(self: *const CubicCc, t_us: u64) u64 {
        const k = self.k_us;

        if (t_us >= k) {
            const diff_us = t_us - k;
            return self.cubicWindowPositive(diff_us);
        } else {
            const diff_us = k - t_us;
            return self.cubicWindowNegative(diff_us);
        }
    }

    /// W_cubic when t >= K: W_max + C * MDS * diff^3 / 1e18
    fn cubicWindowPositive(self: *const CubicCc, diff_us: u64) u64 {
        const cubic_bytes = self.cubicTerm(diff_us);
        const result = self.w_max +| cubic_bytes;
        return @max(result, self.minimumCongestionWindow());
    }

    /// W_cubic when t < K: W_max - C * MDS * diff^3 / 1e18
    fn cubicWindowNegative(self: *const CubicCc, diff_us: u64) u64 {
        const cubic_bytes = self.cubicTerm(diff_us);
        if (self.w_max > cubic_bytes) {
            return @max(self.w_max - cubic_bytes, self.minimumCongestionWindow());
        }
        return self.minimumCongestionWindow();
    }

    /// Compute |C * MDS * diff^3| / 1e18 without overflow.
    /// Uses stepwise division to keep values in u64 range.
    fn cubicTerm(self: *const CubicCc, diff_us: u64) u64 {
        // C * MDS * diff^3 / 1e18
        // = (C_NUM * MDS / C_DEN) * diff^3 / 1e18
        //
        // Split 1e18 = 1e6 * 1e6 * 1e6, divide after each multiply:
        // step1 = diff / 1e6 is too lossy for small diff.
        // Better: (diff/1000)^3 / 1e9, then * C_NUM * MDS / C_DEN
        //
        // For diff_us up to ~100s (1e8 us), diff/1000 = 1e5, cubed = 1e15 — fits u64.
        const diff_ms = diff_us / 1000;
        if (diff_ms == 0) return 0;

        // diff_ms^3 (max ~1e15 for 100s, fits u64)
        const cube = diff_ms *| (diff_ms *| diff_ms);
        // * C_NUM * MDS / (C_DEN * 1e9)
        // = cube * 4 * MDS / (10 * 1e9)
        // = cube * MDS * 4 / 10_000_000_000
        const numerator = (cube / 1000) *| (C_NUM * self.max_datagram_size);
        return numerator / (C_DEN * 1_000_000);
    }

    fn trackPersistentCongestion(self: *CubicCc, space: usize, sent: *const SentPacket, rtt: *const RttEstimator) void {
        const is_valid_sample = sent.ack_eliciting and
            rtt.first_sample_time_us != null and
            sent.time_sent_us >= rtt.first_sample_time_us.?;

        if (is_valid_sample) {
            if (self.persistent_congestion[space].next_pn == null or
                sent.pn != self.persistent_congestion[space].next_pn.?)
            {
                self.persistent_congestion[space].start_us = sent.time_sent_us;
            }
            self.persistent_congestion[space].end_us = sent.time_sent_us;
            self.persistent_congestion[space].next_pn = sent.pn + 1;
        } else {
            if (self.persistent_congestion[space].next_pn) |next| {
                if (sent.pn == next) {
                    self.persistent_congestion[space].next_pn = sent.pn + 1;
                }
            }
        }
    }

    fn checkPersistentCongestion(self: *CubicCc, space: usize, rtt: *RttEstimator, max_ack_delay_us: u64) void {
        const K_GRANULARITY_US: u64 = 1000;
        const pto_duration = rtt.smoothed_rtt_us + @max(4 * rtt.rttvar_us, K_GRANULARITY_US) + max_ack_delay_us;
        const persistent_threshold = pto_duration * 3;

        if (self.persistent_congestion[space].start_us) |start| {
            if (self.persistent_congestion[space].end_us) |end| {
                if (end >= start and (end - start) >= persistent_threshold) {
                    self.congestion_window = self.minimumCongestionWindow();
                    self.recovery_start_time_us = null;
                    self.w_max = self.congestion_window;
                    self.epoch_start_us = null;
                    rtt.establishPersistentCongestion();
                }
            }
        }
    }

    pub const PersistentCongestionState = struct {
        start_us: ?u64,
        end_us: ?u64,
        next_pn: ?u64,

        pub fn init() PersistentCongestionState {
            return .{ .start_us = null, .end_us = null, .next_pn = null };
        }
    };
};

/// Integer cube root via binary search.
fn intCbrt(n: u64) u64 {
    if (n == 0) return 0;
    if (n < 8) return 1;

    var lo: u64 = 1;
    var hi: u64 = @min(n, 2_642_245); // cbrt(u64 max) < 2^21.3
    if (n > 1_000_000) {
        hi = @min(hi, 1_000_000);
    }

    while (lo < hi) {
        const mid = lo + (hi - lo + 1) / 2;
        const cube = mid *| (mid *| mid);
        if (cube <= n) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    return lo;
}

// ─── Tests ───

test "intCbrt: basic values" {
    try std.testing.expectEqual(@as(u64, 0), intCbrt(0));
    try std.testing.expectEqual(@as(u64, 1), intCbrt(1));
    try std.testing.expectEqual(@as(u64, 2), intCbrt(8));
    try std.testing.expectEqual(@as(u64, 2), intCbrt(9));
    try std.testing.expectEqual(@as(u64, 2), intCbrt(26));
    try std.testing.expectEqual(@as(u64, 3), intCbrt(27));
    try std.testing.expectEqual(@as(u64, 10), intCbrt(1000));
    try std.testing.expectEqual(@as(u64, 100), intCbrt(1_000_000));
    try std.testing.expectEqual(@as(u64, 1000), intCbrt(1_000_000_000));
}

test "CubicCc: init state" {
    const cc = CubicCc.init();
    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
    try std.testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    try std.testing.expect(cc.inSlowStart());
    try std.testing.expect(!cc.inRecovery());
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "CubicCc: canSend" {
    var cc = CubicCc.init();
    try std.testing.expect(cc.canSend());

    cc.bytes_in_flight = 10800;
    try std.testing.expect(cc.canSend());

    cc.bytes_in_flight = 10801;
    try std.testing.expect(!cc.canSend());
}

test "CubicCc: slow start growth" {
    var cc = CubicCc.init();
    const initial_cwnd = cc.congestion_window;
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    cc.packetAcked(&pkt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);

    try std.testing.expectEqual(initial_cwnd + 1200, cc.congestion_window);
}

test "CubicCc: multiplicative decrease uses β=0.7" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 900_000;

    // Fill cwnd to exit slow start
    cc.ssthresh = 12000;
    cc.congestion_window = 20000;

    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    cc.packetLost(2, &pkt, &rtt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);

    // ssthresh = 20000 * 7/10 = 14000
    try std.testing.expectEqual(@as(u64, 14000), cc.ssthresh);
    try std.testing.expectEqual(@as(u64, 14000), cc.congestion_window);
    try std.testing.expect(cc.in_recovery);
    // W_max should be set to previous cwnd
    try std.testing.expectEqual(@as(u64, 20000), cc.w_max);
}

test "CubicCc: fast convergence reduces W_max" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 900_000;

    cc.ssthresh = 12000;
    cc.congestion_window = 20000;

    // First loss — sets W_max = 20000
    const pkt1 = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt1);
    cc.packetLost(2, &pkt1, &rtt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);
    try std.testing.expectEqual(@as(u64, 20000), cc.w_max);

    // Grow cwnd back partially (simulate recovery)
    cc.congestion_window = 15000;
    cc.in_recovery = false;
    cc.recovery_start_time_us = null;
    // Reset persistent congestion state to avoid spurious detection
    cc.persistent_congestion[2] = CubicCc.PersistentCongestionState.init();

    // Second loss at cwnd=15000 < prior_w_max=20000 → fast convergence
    // Use a time close to pkt1 so persistent congestion doesn't trigger
    const pkt2 = SentPacket{ .pn = 10, .time_sent_us = 1_200_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt2);
    cc.packetLost(2, &pkt2, &rtt);
    cc.packetBatchEnd(1_300_000, 2, &rtt, 25_000);

    // Fast convergence: W_max = cwnd * 17/20 = 15000 * 17/20 = 12750
    try std.testing.expectEqual(@as(u64, 12750), cc.w_max);
}

test "CubicCc: batch prevents multiple cwnd halvings" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 900_000;

    cc.ssthresh = 12000;
    cc.congestion_window = 24000;

    const pkts = [_]SentPacket{
        .{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
        .{ .pn = 1, .time_sent_us = 1_001_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
        .{ .pn = 2, .time_sent_us = 1_002_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
    };
    for (&pkts) |*p| cc.packetSent(p);

    cc.packetLost(2, &pkts[0], &rtt);
    cc.packetLost(2, &pkts[1], &rtt);
    cc.packetLost(2, &pkts[2], &rtt);

    cc.packetBatchEnd(1_200_000, 2, &rtt, 25_000);

    // cwnd halved ONCE: 24000 * 0.7 = 16800
    try std.testing.expectEqual(@as(u64, 16800), cc.ssthresh);
    try std.testing.expectEqual(@as(u64, 16800), cc.congestion_window);
}

test "CubicCc: cubic growth after recovery" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(50_000, 0, 25_000); // 50ms RTT

    // Simulate: was at 100 segments, lost, now at 70 segments
    cc.max_datagram_size = 1200;
    cc.w_max = 120000; // 100 segments
    cc.ssthresh = 84000; // 70 segments
    cc.congestion_window = 84000;
    cc.epoch_start_us = null;

    // Simulate several RTTs of ACKs — cwnd should grow toward W_max
    var now_us: u64 = 10_000_000;
    const cwnd_start = cc.congestion_window;

    var round: u32 = 0;
    while (round < 20) : (round += 1) {
        // Simulate one RTT of acks (cwnd worth of bytes)
        const pkt = SentPacket{ .pn = round, .time_sent_us = now_us, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
        cc.packetSent(&pkt);
        cc.packetAcked(&pkt);
        cc.packetBatchEnd(now_us + 50_000, 2, &rtt, 25_000);
        now_us += 50_000;
    }

    // After 20 RTTs (~1s), cwnd should have grown beyond starting point
    try std.testing.expect(cc.congestion_window > cwnd_start);
}

test "CubicCc: tcp-friendly region prevents starvation" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000); // 100ms RTT

    // Small W_max — Cubic would grow very slowly, TCP-friendly region kicks in
    cc.max_datagram_size = 1200;
    cc.w_max = 6000; // 5 segments
    cc.ssthresh = 4200; // 3.5 segments
    cc.congestion_window = 4200;
    cc.epoch_start_us = null;

    var now_us: u64 = 10_000_000;
    const cwnd_start = cc.congestion_window;

    // Simulate 10 RTTs of acks
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const pkt = SentPacket{ .pn = round, .time_sent_us = now_us, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
        cc.packetSent(&pkt);
        cc.packetAcked(&pkt);
        cc.packetBatchEnd(now_us + 100_000, 2, &rtt, 25_000);
        now_us += 100_000;
    }

    // Should grow — TCP-friendly region ensures at least Reno-equivalent growth
    try std.testing.expect(cc.congestion_window > cwnd_start);
}

test "CubicCc: persistent congestion resets to minimum window" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 1_000_000;

    cc.congestion_window = 24000;
    cc.ssthresh = 12000;

    // Two consecutive lost packets spanning > 3*PTO
    // PTO = 100000 + max(4*50000, 1000) + 25000 = 325000
    // 3*PTO = 975000
    const pkt0 = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    const pkt1 = SentPacket{ .pn = 1, .time_sent_us = 2_100_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt0);
    cc.packetSent(&pkt1);

    cc.packetLost(2, &pkt0, &rtt);
    cc.packetLost(2, &pkt1, &rtt);
    cc.packetBatchEnd(3_000_000, 2, &rtt, 25_000);

    // Persistent congestion → minimum window
    try std.testing.expectEqual(cc.minimumCongestionWindow(), cc.congestion_window);
}

test "CubicCc: underutilized suppresses growth" {
    var cc = CubicCc.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    cc.setUnderutilized(true);

    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    cc.packetAcked(&pkt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);

    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
}
