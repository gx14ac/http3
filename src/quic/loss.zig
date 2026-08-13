const std = @import("std");
const packet_mod = @import("packet.zig");
const ack_mod = @import("ack.zig");
const cubic_mod = @import("cubic.zig");

/// A contiguous range of acknowledged packet numbers [start, end] inclusive.
pub const AckRange = struct {
    start: u64,
    end: u64,
};

/// RFC 9002 §6.1.1: kPacketThreshold
const K_PACKET_THRESHOLD: u64 = 3;
/// RFC 9002 §6.1.2: kTimeThreshold numerator/denominator (9/8)
const K_TIME_THRESHOLD_NUM: u64 = 9;
const K_TIME_THRESHOLD_DEN: u64 = 8;
/// RFC 9002 §6.2: kGranularity (timer granularity, 1ms in microseconds)
const K_GRANULARITY_US: u64 = 1000;
/// Initial RTT estimate (333ms) per RFC 9002 §6.2.2
const INITIAL_RTT_US: u64 = 333_000;
/// Number of encryption level spaces
const NUMBER_SPACE_COUNT: usize = 3;

/// Metadata for a single sent packet.
pub const SentPacket = struct {
    pn: u64,
    time_sent_us: u64,
    size: u32,
    ack_eliciting: bool,
    in_flight: bool,
    declared_lost: bool,
};

/// Fixed-size ring buffer of sent packets per encryption level.
pub const SentPacketRegistry = struct {
    packets: [MAX_SENT]?SentPacket,
    count: usize,

    const MAX_SENT = 256;

    pub fn init() SentPacketRegistry {
        return .{
            .packets = [_]?SentPacket{null} ** MAX_SENT,
            .count = 0,
        };
    }

    pub fn insert(self: *SentPacketRegistry, pkt: SentPacket) u32 {
        const slot = @as(usize, @intCast(pkt.pn % MAX_SENT));
        var evicted_size: u32 = 0;
        if (self.packets[slot]) |existing| {
            if (existing.in_flight and !existing.declared_lost) {
                evicted_size = existing.size;
            }
        } else {
            self.count += 1;
        }
        self.packets[slot] = pkt;
        return evicted_size;
    }

    pub fn get(self: *const SentPacketRegistry, pn: u64) ?*const SentPacket {
        const slot = @as(usize, @intCast(pn % MAX_SENT));
        if (self.packets[slot]) |*p| {
            if (p.pn == pn) return p;
        }
        return null;
    }

    pub fn getMut(self: *SentPacketRegistry, pn: u64) ?*SentPacket {
        const slot = @as(usize, @intCast(pn % MAX_SENT));
        if (self.packets[slot]) |*p| {
            if (p.pn == pn) return p;
        }
        return null;
    }

    pub fn remove(self: *SentPacketRegistry, pn: u64) void {
        const slot = @as(usize, @intCast(pn % MAX_SENT));
        if (self.packets[slot]) |p| {
            if (p.pn == pn) {
                self.packets[slot] = null;
                if (self.count > 0) self.count -= 1;
            }
        }
    }

    pub fn hasAckElicitingInFlight(self: *const SentPacketRegistry) bool {
        for (&self.packets) |*entry| {
            if (entry.*) |p| {
                if (p.ack_eliciting and p.in_flight and !p.declared_lost) return true;
            }
        }
        return false;
    }

    pub fn earliestSendTime(self: *const SentPacketRegistry) ?u64 {
        var earliest: ?u64 = null;
        for (&self.packets) |*entry| {
            if (entry.*) |p| {
                if (p.ack_eliciting and p.in_flight and !p.declared_lost) {
                    if (earliest == null or p.time_sent_us < earliest.?) {
                        earliest = p.time_sent_us;
                    }
                }
            }
        }
        return earliest;
    }
};

/// RTT estimator per RFC 9002 §5.
pub const RttEstimator = struct {
    smoothed_rtt_us: u64,
    rttvar_us: u64,
    min_rtt_us: u64,
    latest_rtt_us: u64,
    has_sample: bool,
    first_sample_time_us: ?u64,

    pub fn init() RttEstimator {
        return .{
            .smoothed_rtt_us = INITIAL_RTT_US,
            .rttvar_us = INITIAL_RTT_US / 2,
            .min_rtt_us = std.math.maxInt(u64),
            .latest_rtt_us = 0,
            .has_sample = false,
            .first_sample_time_us = null,
        };
    }

    /// Update RTT on receiving an ACK. RFC 9002 §5.3.
    pub fn updateRtt(self: *RttEstimator, latest_rtt_us: u64, ack_delay_us: u64, max_ack_delay_us: u64) void {
        self.latest_rtt_us = latest_rtt_us;

        if (!self.has_sample) {
            self.min_rtt_us = latest_rtt_us;
            self.smoothed_rtt_us = latest_rtt_us;
            self.rttvar_us = latest_rtt_us / 2;
            self.has_sample = true;
            return;
        }

        if (latest_rtt_us < self.min_rtt_us) {
            self.min_rtt_us = latest_rtt_us;
        }

        var adjusted_rtt = latest_rtt_us;
        if (latest_rtt_us > self.min_rtt_us) {
            const clamped_delay = @min(ack_delay_us, max_ack_delay_us);
            if (adjusted_rtt > clamped_delay) {
                adjusted_rtt -= clamped_delay;
            }
        }

        const diff = if (self.smoothed_rtt_us > adjusted_rtt)
            self.smoothed_rtt_us - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt_us;
        self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
        self.smoothed_rtt_us = (7 * self.smoothed_rtt_us + adjusted_rtt) / 8;
    }

    /// Record the time of the first RTT sample (for persistent congestion).
    pub fn recordFirstSample(self: *RttEstimator, time_us: u64) void {
        if (self.first_sample_time_us == null) {
            self.first_sample_time_us = time_us;
        }
    }

    /// Called when persistent congestion is established. RFC 9002 §7.6.
    pub fn establishPersistentCongestion(self: *RttEstimator) void {
        self.first_sample_time_us = null;
        self.has_sample = false;
        self.smoothed_rtt_us = INITIAL_RTT_US;
        self.rttvar_us = INITIAL_RTT_US / 2;
        self.min_rtt_us = std.math.maxInt(u64);
    }

    /// PTO duration: smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
    pub fn ptoBase(self: *const RttEstimator, max_ack_delay_us: u64) u64 {
        return self.smoothed_rtt_us + @max(4 * self.rttvar_us, K_GRANULARITY_US) + max_ack_delay_us;
    }

    /// Time threshold for loss detection: 9/8 * max(smoothed_rtt, latest_rtt)
    pub fn timeThreshold(self: *const RttEstimator) u64 {
        const base = @max(self.smoothed_rtt_us, self.latest_rtt_us);
        const threshold = (base * K_TIME_THRESHOLD_NUM) / K_TIME_THRESHOLD_DEN;
        return @max(threshold, K_GRANULARITY_US);
    }
};

/// Persistent congestion tracking state per number space (RFC 9002 §7.6).
const PersistentCongestionState = struct {
    start_us: ?u64,
    end_us: ?u64,
    next_pn: ?u64,

    fn init() PersistentCongestionState {
        return .{ .start_us = null, .end_us = null, .next_pn = null };
    }
};

/// RFC 9002 §7: NewReno Congestion Controller with batch-based design.
///
/// Acked and lost packets are processed in batches. A batch consists of
/// zero or more calls to packetAcked/packetLost, followed by a single
/// call to packetBatchEnd which performs the actual cwnd update.
pub const CongestionController = struct {
    max_datagram_size: u64,
    congestion_window: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    recovery_start_time_us: ?u64,

    // Batch state — accumulated during ACK processing, applied in packetBatchEnd
    congestion_pending_acks: u64,
    send_one_packet_in_recovery: bool,
    in_recovery: bool,
    underutilized: bool,
    ack_last_loss_us: ?u64,

    // Persistent congestion per space
    persistent_congestion: [NUMBER_SPACE_COUNT]PersistentCongestionState,

    const MIN_WINDOW_PACKETS: u64 = 2;

    pub fn init() CongestionController {
        return initWithMds(1200);
    }

    /// Initialize with explicit max datagram size.
    /// cwnd = min(10*mds, max(14720, 2*mds)) per RFC 9002 §7.2.
    pub fn initWithMds(mds: u64) CongestionController {
        const min_window = 2 * mds;
        const initial_window = @min(10 * mds, @max(@as(u64, 14720), min_window));
        return .{
            .max_datagram_size = mds,
            .congestion_window = initial_window,
            .bytes_in_flight = 0,
            .ssthresh = std.math.maxInt(u64),
            .recovery_start_time_us = null,
            .congestion_pending_acks = 0,
            .send_one_packet_in_recovery = false,
            .in_recovery = false,
            .underutilized = false,
            .ack_last_loss_us = null,
            .persistent_congestion = [_]PersistentCongestionState{PersistentCongestionState.init()} ** NUMBER_SPACE_COUNT,
        };
    }

    /// Reports whether the congestion controller permits sending.
    /// RFC 9002 §7: bytes_in_flight + max_datagram_size <= congestion_window.
    pub fn canSend(self: *const CongestionController) bool {
        if (self.send_one_packet_in_recovery) return true;
        return self.bytes_in_flight + self.max_datagram_size <= self.congestion_window;
    }

    /// Available send budget before hitting cwnd.
    pub fn sendBudget(self: *const CongestionController) u64 {
        if (self.send_one_packet_in_recovery) return self.max_datagram_size;
        if (self.congestion_window <= self.bytes_in_flight) return 0;
        return self.congestion_window - self.bytes_in_flight;
    }

    pub fn setUnderutilized(self: *CongestionController, v: bool) void {
        self.underutilized = v;
    }

    /// Record a sent packet. Updates bytes_in_flight.
    pub fn packetSent(self: *CongestionController, sent: *const SentPacket) void {
        if (!sent.in_flight) return;
        self.bytes_in_flight += sent.size;
        if (self.send_one_packet_in_recovery) {
            self.send_one_packet_in_recovery = false;
        }
    }

    /// Record an acknowledged packet. Only accumulates — does NOT update cwnd.
    /// The actual cwnd update happens in packetBatchEnd.
    pub fn packetAcked(self: *CongestionController, sent: *const SentPacket) void {
        if (!sent.in_flight) return;
        self.bytes_in_flight -= sent.size;

        if (self.underutilized) return;

        if (self.recovery_start_time_us) |recovery_start| {
            if (sent.time_sent_us < recovery_start) {
                // Packet sent before recovery — don't count toward growth
                return;
            }
        }
        self.congestion_pending_acks += sent.size;
    }

    /// Record a lost packet. Tracks the newest loss time for batch processing.
    /// Lost packets must be reported in increasing PN order.
    pub fn packetLost(self: *CongestionController, space: usize, sent: *const SentPacket, rtt: *const RttEstimator) void {
        // Track persistent congestion (RFC 9002 §7.6)
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

        if (!sent.in_flight) return;
        self.bytes_in_flight -= sent.size;

        if (self.ack_last_loss_us == null or sent.time_sent_us > self.ack_last_loss_us.?) {
            self.ack_last_loss_us = sent.time_sent_us;
        }
    }

    /// End of batch — performs a single cwnd update based on accumulated state.
    /// This is the only place cwnd changes, preventing multiple halvings per ACK frame.
    pub fn packetBatchEnd(self: *CongestionController, now_us: u64, space: usize, rtt: *RttEstimator, max_ack_delay_us: u64) void {
        if (self.ack_last_loss_us) |loss_time| {
            const recovery_start = self.recovery_start_time_us orelse 0;
            if (loss_time >= recovery_start) {
                // Enter recovery — halve cwnd ONCE for the entire batch
                self.recovery_start_time_us = now_us;
                self.ssthresh = self.congestion_window / 2;
                self.congestion_window = @max(self.ssthresh, self.minimumCongestionWindow());
                self.send_one_packet_in_recovery = true;
                self.congestion_pending_acks = 0;
                self.in_recovery = true;
            }
        } else if (self.congestion_pending_acks > 0) {
            self.in_recovery = false;
            if (self.congestion_window < self.ssthresh) {
                // Slow start: grow by acked bytes (capped at ssthresh)
                const d = @min(self.ssthresh - self.congestion_window, self.congestion_pending_acks);
                self.congestion_window += d;
                self.congestion_pending_acks -= d;
            }
            // Congestion avoidance: increment by mds each time acked >= cwnd
            while (self.congestion_pending_acks > self.congestion_window) {
                self.congestion_pending_acks -= self.congestion_window;
                self.congestion_window += self.max_datagram_size;
            }
        }

        // Check persistent congestion (RFC 9002 §7.6)
        if (self.ack_last_loss_us != null) {
            const pto_duration = rtt.smoothed_rtt_us + @max(4 * rtt.rttvar_us, K_GRANULARITY_US) + max_ack_delay_us;
            const persistent_threshold = pto_duration * 3;

            if (self.persistent_congestion[space].start_us) |start| {
                if (self.persistent_congestion[space].end_us) |end| {
                    if (end >= start and (end - start) >= persistent_threshold) {
                        self.congestion_window = self.minimumCongestionWindow();
                        self.recovery_start_time_us = null;
                        rtt.establishPersistentCongestion();
                    }
                }
            }
        }

        self.ack_last_loss_us = null;
    }

    /// Packet discarded (keys dropped). Remove from bytes_in_flight without triggering CC.
    pub fn packetDiscarded(self: *CongestionController, sent: *const SentPacket) void {
        if (sent.in_flight) {
            if (self.bytes_in_flight >= sent.size) {
                self.bytes_in_flight -= sent.size;
            }
        }
    }

    pub fn minimumCongestionWindow(self: *const CongestionController) u64 {
        return MIN_WINDOW_PACKETS * self.max_datagram_size;
    }

    pub fn inSlowStart(self: *const CongestionController) bool {
        return self.congestion_window < self.ssthresh;
    }

    pub fn inRecovery(self: *const CongestionController) bool {
        return self.in_recovery;
    }
};

/// RFC 9002 §7.7: Leaky-bucket pacer.
pub const Pacer = struct {
    bucket: i64,
    max_bucket: i64,
    timer_granularity_us: u64,
    last_update_us: u64,
    next_send_us: u64,

    pub fn init(now_us: u64, max_burst: u64, timer_granularity_us: u64) Pacer {
        return .{
            .bucket = @intCast(max_burst),
            .max_bucket = @intCast(max_burst),
            .timer_granularity_us = timer_granularity_us,
            .last_update_us = now_us,
            .next_send_us = now_us,
        };
    }

    /// Refill the bucket based on elapsed time.
    pub fn advance(self: *Pacer, now_us: u64, congestion_window: u64, smoothed_rtt_us: u64) void {
        if (now_us <= self.last_update_us) {
            self.next_send_us = now_us;
            if (self.bucket < 0) self.bucket = 0;
            self.last_update_us = now_us;
            return;
        }
        const elapsed = now_us - self.last_update_us;
        self.last_update_us = now_us;

        if (smoothed_rtt_us == 0) {
            self.bucket = self.max_bucket;
            return;
        }

        const delta = bytesForInterval(elapsed, congestion_window, smoothed_rtt_us);
        self.bucket = @min(self.bucket + @as(i64, @intCast(delta)), self.max_bucket);
    }

    /// Record transmission of a packet.
    pub fn packetSent(self: *Pacer, now_us: u64, size: u64, congestion_window: u64, smoothed_rtt_us: u64) void {
        self.bucket -= @as(i64, @intCast(size));
        const neg_cwnd: i64 = -@as(i64, @intCast(congestion_window));
        if (self.bucket < neg_cwnd) {
            self.bucket = neg_cwnd;
        }

        if (self.bucket >= 0) {
            self.next_send_us = now_us;
            return;
        }

        if (congestion_window == 0 or smoothed_rtt_us == 0) {
            self.next_send_us = now_us;
            return;
        }
        const deficit: u64 = @intCast(-self.bucket);
        const delay = intervalForBytes(deficit, congestion_window, smoothed_rtt_us);
        self.next_send_us = now_us + delay;
    }

    /// Check if a packet can be sent now.
    pub fn canSend(self: *const Pacer, now_us: u64) struct { ok: bool, next_us: u64 } {
        if (self.next_send_us > now_us + self.timer_granularity_us) {
            return .{ .ok = false, .next_us = self.next_send_us };
        }
        return .{ .ok = true, .next_us = 0 };
    }

    /// rate = 1.25 * congestion_window / smoothed_rtt; bytes = interval * rate
    fn bytesForInterval(interval_us: u64, congestion_window: u64, rtt_us: u64) u64 {
        if (rtt_us == 0) return congestion_window;
        const bytes = (interval_us * congestion_window) / rtt_us;
        return (bytes * 5) / 4;
    }

    /// interval = (rtt / cwnd) * bytes / 1.25
    fn intervalForBytes(bytes: u64, congestion_window: u64, rtt_us: u64) u64 {
        if (congestion_window == 0) return 0;
        const interval = (rtt_us * bytes) / congestion_window;
        return (interval * 4) / 5;
    }
};

/// Per-level loss detection state.
pub const LossDetectionLevel = struct {
    sent: SentPacketRegistry,
    largest_acked_pn: ?u64,
    loss_time_us: ?u64,
    time_of_last_ack_eliciting_us: ?u64,

    pub fn init() LossDetectionLevel {
        return .{
            .sent = SentPacketRegistry.init(),
            .largest_acked_pn = null,
            .loss_time_us = null,
            .time_of_last_ack_eliciting_us = null,
        };
    }
};

/// Loss detection results returned to the caller.
pub const LossEvent = struct {
    lost_packets: [MAX_LOST]u64,
    lost_count: usize,
    bytes_lost: u64,

    const MAX_LOST = 32;

    pub fn init() LossEvent {
        return .{
            .lost_packets = undefined,
            .lost_count = 0,
            .bytes_lost = 0,
        };
    }

    pub fn addLost(self: *LossEvent, pn: u64, size: u32) void {
        if (self.lost_count < MAX_LOST) {
            self.lost_packets[self.lost_count] = pn;
            self.lost_count += 1;
        }
        self.bytes_lost += size;
    }
};

/// Send limit status (matching Go's ccLimit).
pub const SendLimit = enum {
    ok,
    blocked,
    limited,
    paced,
};

/// Congestion control algorithm selection.
pub const CongestionAlgorithm = enum {
    new_reno,
    cubic,
};

/// Unified CC dispatch layer. Delegates to either NewReno or Cubic.
pub const CcState = struct {
    algo: CongestionAlgorithm,
    new_reno: CongestionController,
    cubic: cubic_mod.CubicCc,

    pub fn init(algo: CongestionAlgorithm) CcState {
        return initWithMds(algo, 1200);
    }

    pub fn initWithMds(algo: CongestionAlgorithm, mds: u64) CcState {
        return .{
            .algo = algo,
            .new_reno = CongestionController.initWithMds(mds),
            .cubic = cubic_mod.CubicCc.initWithMds(mds),
        };
    }

    pub fn canSend(self: *const CcState) bool {
        return switch (self.algo) {
            .new_reno => self.new_reno.canSend(),
            .cubic => self.cubic.canSend(),
        };
    }

    pub fn sendBudget(self: *const CcState) u64 {
        return switch (self.algo) {
            .new_reno => self.new_reno.sendBudget(),
            .cubic => self.cubic.sendBudget(),
        };
    }

    pub fn congestionWindow(self: *const CcState) u64 {
        return switch (self.algo) {
            .new_reno => self.new_reno.congestion_window,
            .cubic => self.cubic.congestion_window,
        };
    }

    pub fn bytesInFlight(self: *const CcState) u64 {
        return switch (self.algo) {
            .new_reno => self.new_reno.bytes_in_flight,
            .cubic => self.cubic.bytes_in_flight,
        };
    }

    /// Subtract evicted bytes from bytes_in_flight (ring buffer slot reuse).
    pub fn adjustBytesInFlight(self: *CcState, evicted: u32) void {
        switch (self.algo) {
            .new_reno => {
                if (self.new_reno.bytes_in_flight >= evicted) {
                    self.new_reno.bytes_in_flight -= evicted;
                }
            },
            .cubic => {
                if (self.cubic.bytes_in_flight >= evicted) {
                    self.cubic.bytes_in_flight -= evicted;
                }
            },
        }
    }

    pub fn setUnderutilized(self: *CcState, v: bool) void {
        switch (self.algo) {
            .new_reno => self.new_reno.setUnderutilized(v),
            .cubic => self.cubic.setUnderutilized(v),
        }
    }

    pub fn packetSent(self: *CcState, sent: *const SentPacket) void {
        switch (self.algo) {
            .new_reno => self.new_reno.packetSent(sent),
            .cubic => self.cubic.packetSent(sent),
        }
    }

    pub fn packetAcked(self: *CcState, sent: *const SentPacket) void {
        switch (self.algo) {
            .new_reno => self.new_reno.packetAcked(sent),
            .cubic => self.cubic.packetAcked(sent),
        }
    }

    pub fn packetLost(self: *CcState, space: usize, sent: *const SentPacket, rtt: *const RttEstimator) void {
        switch (self.algo) {
            .new_reno => self.new_reno.packetLost(space, sent, rtt),
            .cubic => self.cubic.packetLost(space, sent, rtt),
        }
    }

    pub fn packetBatchEnd(self: *CcState, now_us: u64, space: usize, rtt: *RttEstimator, max_ack_delay_us: u64) void {
        switch (self.algo) {
            .new_reno => self.new_reno.packetBatchEnd(now_us, space, rtt, max_ack_delay_us),
            .cubic => self.cubic.packetBatchEnd(now_us, space, rtt, max_ack_delay_us),
        }
    }

    pub fn packetDiscarded(self: *CcState, sent: *const SentPacket) void {
        switch (self.algo) {
            .new_reno => self.new_reno.packetDiscarded(sent),
            .cubic => self.cubic.packetDiscarded(sent),
        }
    }

    pub fn inSlowStart(self: *const CcState) bool {
        return switch (self.algo) {
            .new_reno => self.new_reno.inSlowStart(),
            .cubic => self.cubic.inSlowStart(),
        };
    }

    pub fn inRecovery(self: *const CcState) bool {
        return switch (self.algo) {
            .new_reno => self.new_reno.inRecovery(),
            .cubic => self.cubic.inRecovery(),
        };
    }

    pub fn sendOnePacketInRecovery(self: *const CcState) bool {
        return switch (self.algo) {
            .new_reno => self.new_reno.send_one_packet_in_recovery,
            .cubic => self.cubic.send_one_packet_in_recovery,
        };
    }
};

/// Integrated loss detection + congestion controller + pacer (RFC 9002).
///
/// Uses Go-style batch processing: receiveAckStart → receiveAckRange × N → receiveAckEnd.
/// The cwnd is only modified once per ACK frame in receiveAckEnd.
pub const LossDetector = struct {
    rtt: RttEstimator,
    cc: CcState,
    pacer: Pacer,
    levels: [NUMBER_SPACE_COUNT]LossDetectionLevel,
    pto_count: u32,
    loss_detection_timer_us: ?u64,
    max_ack_delay_us: u64,
    pto_expired: bool,

    // Temporary state used during ACK frame processing
    ack_frame_rtt_us: ?u64,
    ack_frame_contains_ack_eliciting: bool,

    pub fn init() LossDetector {
        return initWithTime(0);
    }

    pub fn initWithAlgo(algo: CongestionAlgorithm, now_us: u64) LossDetector {
        const cc = CcState.init(algo);
        return .{
            .rtt = RttEstimator.init(),
            .cc = cc,
            .pacer = Pacer.init(now_us, cc.congestionWindow(), K_GRANULARITY_US),
            .levels = [_]LossDetectionLevel{LossDetectionLevel.init()} ** NUMBER_SPACE_COUNT,
            .pto_count = 0,
            .loss_detection_timer_us = null,
            .max_ack_delay_us = 25_000,
            .pto_expired = false,
            .ack_frame_rtt_us = null,
            .ack_frame_contains_ack_eliciting = false,
        };
    }

    pub fn initWithTime(now_us: u64) LossDetector {
        return initWithAlgo(.new_reno, now_us);
    }

    fn levelIndex(level: ack_mod.EncryptionLevel) usize {
        return switch (level) {
            .initial => 0,
            .handshake => 1,
            .application => 2,
        };
    }

    /// Convenience: bytes currently in flight (owned by CC).
    pub fn bytesInFlight(self: *const LossDetector) u64 {
        return self.cc.bytesInFlight();
    }

    /// Check if sending is allowed and return the limiting factor.
    pub fn sendLimit(self: *const LossDetector, now_us: u64) struct { limit: SendLimit, next_us: u64 } {
        if (self.pto_expired) {
            return .{ .limit = .ok, .next_us = 0 };
        }
        if (!self.cc.canSend()) {
            return .{ .limit = .limited, .next_us = 0 };
        }
        if (self.cc.bytesInFlight() == 0) {
            return .{ .limit = .ok, .next_us = 0 };
        }
        const pacer_result = self.pacer.canSend(now_us);
        if (!pacer_result.ok) {
            return .{ .limit = .paced, .next_us = pacer_result.next_us };
        }
        return .{ .limit = .ok, .next_us = 0 };
    }

    /// Record that a packet was sent.
    pub fn onPacketSent(
        self: *LossDetector,
        level: ack_mod.EncryptionLevel,
        pn: u64,
        size: u32,
        ack_eliciting: bool,
        now_us: u64,
    ) void {
        const idx = levelIndex(level);
        const pkt = SentPacket{
            .pn = pn,
            .time_sent_us = now_us,
            .size = size,
            .ack_eliciting = ack_eliciting,
            .in_flight = true,
            .declared_lost = false,
        };
        const evicted = self.levels[idx].sent.insert(pkt);
        if (evicted > 0) {
            self.cc.adjustBytesInFlight(evicted);
        }

        self.cc.packetSent(&pkt);
        self.pacer.packetSent(now_us, size, self.cc.congestionWindow(), self.rtt.smoothed_rtt_us);

        if (ack_eliciting) {
            self.levels[idx].time_of_last_ack_eliciting_us = now_us;
            self.pto_expired = false;
        }
        self.setLossDetectionTimer(now_us);
    }

    // ─── Batch ACK API (Go-style) ───

    /// Start processing an ACK frame. Resets batch state.
    pub fn receiveAckStart(self: *LossDetector) void {
        self.ack_frame_contains_ack_eliciting = false;
        self.ack_frame_rtt_us = null;
    }

    /// Process a range within an ACK frame. Marks packets as acknowledged
    /// and calls cc.packetAcked (which only accumulates, doesn't update cwnd).
    pub fn receiveAckRange(self: *LossDetector, level: ack_mod.EncryptionLevel, range_index: usize, start: u64, end: u64, now_us: u64) void {
        const idx = levelIndex(level);
        const lev = &self.levels[idx];

        // Update largest acked
        if (lev.largest_acked_pn == null or end > lev.largest_acked_pn.?) {
            lev.largest_acked_pn = end;
        }

        // For the first range (containing largest), compute RTT
        if (range_index == 0) {
            if (lev.sent.get(end)) |pkt| {
                if (now_us >= pkt.time_sent_us) {
                    self.ack_frame_rtt_us = now_us - pkt.time_sent_us;
                }
            }
        }

        // Mark all packets in [start, end] as acknowledged
        var pn = start;
        while (pn <= end) : (pn += 1) {
            if (lev.sent.getMut(pn)) |p| {
                if (p.in_flight and !p.declared_lost) {
                    self.cc.packetAcked(p);
                    if (p.ack_eliciting) {
                        self.ack_frame_contains_ack_eliciting = true;
                    }
                    p.in_flight = false;
                }
            }
        }
    }

    /// Finish processing an ACK frame. Updates RTT, runs loss detection,
    /// and calls cc.packetBatchEnd for a single cwnd update.
    pub fn receiveAckEnd(self: *LossDetector, level: ack_mod.EncryptionLevel, ack_delay_us: u64, now_us: u64) LossEvent {
        const idx = levelIndex(level);

        // Update RTT if the largest packet was newly acked and ack-eliciting
        if (self.ack_frame_rtt_us) |frame_rtt| {
            if (self.ack_frame_contains_ack_eliciting) {
                const effective_max_ack_delay = if (level == .application) self.max_ack_delay_us else 0;
                self.rtt.updateRtt(frame_rtt, ack_delay_us, effective_max_ack_delay);
                self.rtt.recordFirstSample(now_us);
            }
        }

        // Reset PTO
        self.pto_count = 0;

        // Detect lost packets — this calls cc.packetLost for each
        const loss_event = self.detectLostPackets(idx, now_us);

        // Single cwnd update for the entire batch
        self.cc.packetBatchEnd(now_us, idx, &self.rtt, self.max_ack_delay_us);

        self.pacer.advance(now_us, self.cc.congestionWindow(), self.rtt.smoothed_rtt_us);
        self.setLossDetectionTimer(now_us);

        return loss_event;
    }

    // ─── Convenience wrappers (legacy API) ───

    /// Process a received ACK frame (single range). Uses batch API internally.
    pub fn onAckReceived(
        self: *LossDetector,
        level: ack_mod.EncryptionLevel,
        largest_acked: u64,
        first_ack_range: u64,
        ack_delay_us: u64,
        now_us: u64,
    ) LossEvent {
        self.receiveAckStart();
        const range_start = if (largest_acked >= first_ack_range) largest_acked - first_ack_range else 0;
        self.receiveAckRange(level, 0, range_start, largest_acked, now_us);
        return self.receiveAckEnd(level, ack_delay_us, now_us);
    }

    /// Process an ACK frame with multiple ranges. Uses batch API internally.
    pub fn onAckReceivedRanges(
        self: *LossDetector,
        level: ack_mod.EncryptionLevel,
        largest_acked: u64,
        ack_delay_us: u64,
        ranges: []const AckRange,
        now_us: u64,
    ) LossEvent {
        self.receiveAckStart();
        for (ranges, 0..) |r, i| {
            self.receiveAckRange(level, i, r.start, r.end, now_us);
        }
        // Ensure largest_acked is tracked even if not in a range
        const idx = levelIndex(level);
        if (self.levels[idx].largest_acked_pn == null or largest_acked > self.levels[idx].largest_acked_pn.?) {
            self.levels[idx].largest_acked_pn = largest_acked;
        }
        return self.receiveAckEnd(level, ack_delay_us, now_us);
    }

    /// Called when the loss detection timer expires.
    pub fn onLossDetectionTimeout(self: *LossDetector, now_us: u64) ?ack_mod.EncryptionLevel {
        // Check for time-based loss first
        for (0..NUMBER_SPACE_COUNT) |idx| {
            if (self.levels[idx].loss_time_us) |loss_time| {
                if (now_us >= loss_time) {
                    _ = self.detectLostPackets(idx, now_us);
                    self.cc.packetBatchEnd(now_us, idx, &self.rtt, self.max_ack_delay_us);
                    self.setLossDetectionTimer(now_us);
                    return null;
                }
            }
        }

        // PTO expired
        self.pto_count += 1;
        self.pto_expired = true;

        if (self.levels[0].sent.hasAckElicitingInFlight()) {
            self.setLossDetectionTimer(now_us);
            return .initial;
        }
        if (self.levels[1].sent.hasAckElicitingInFlight()) {
            self.setLossDetectionTimer(now_us);
            return .handshake;
        }
        if (self.levels[2].sent.hasAckElicitingInFlight()) {
            self.setLossDetectionTimer(now_us);
            return .application;
        }

        self.setLossDetectionTimer(now_us);
        return .application;
    }

    /// Get the current loss detection timer deadline.
    pub fn getTimer(self: *const LossDetector) ?u64 {
        return self.loss_detection_timer_us;
    }

    /// Available send budget before congestion window is full.
    pub fn sendBudget(self: *const LossDetector) u64 {
        return self.cc.sendBudget();
    }

    /// Discard keys for a level.
    pub fn discardLevel(self: *LossDetector, level: ack_mod.EncryptionLevel) void {
        const idx = levelIndex(level);
        for (&self.levels[idx].sent.packets) |*entry| {
            if (entry.*) |*p| {
                if (p.in_flight and !p.declared_lost) {
                    self.cc.packetDiscarded(p);
                }
                entry.* = null;
            }
        }
        self.levels[idx].sent.count = 0;
        self.levels[idx].largest_acked_pn = null;
        self.levels[idx].loss_time_us = null;
        self.levels[idx].time_of_last_ack_eliciting_us = null;
    }

    /// Mark a range of packets as acknowledged (external helper).
    pub fn markAckedRange(self: *LossDetector, level: ack_mod.EncryptionLevel, from: u64, to: u64) void {
        const idx = levelIndex(level);
        var pn = from;
        while (pn <= to) : (pn += 1) {
            if (self.levels[idx].sent.getMut(pn)) |p| {
                if (p.in_flight and !p.declared_lost) {
                    self.cc.packetAcked(p);
                    p.in_flight = false;
                }
            }
        }
    }

    // ─── Internal ───

    fn detectLostPackets(self: *LossDetector, level_idx: usize, now_us: u64) LossEvent {
        var event = LossEvent.init();
        const lev = &self.levels[level_idx];
        const largest = lev.largest_acked_pn orelse return event;

        const time_threshold = self.rtt.timeThreshold();
        lev.loss_time_us = null;

        for (&lev.sent.packets) |*entry| {
            if (entry.*) |*p| {
                if (p.pn > largest) continue;
                if (p.declared_lost or !p.in_flight) continue;

                const pn_gap = largest - p.pn;
                const time_since_sent = if (now_us >= p.time_sent_us) now_us - p.time_sent_us else 0;

                if (pn_gap >= K_PACKET_THRESHOLD or time_since_sent >= time_threshold) {
                    p.declared_lost = true;
                    self.cc.packetLost(level_idx, p, &self.rtt);
                    p.in_flight = false;
                    event.addLost(p.pn, p.size);
                } else {
                    const expected_loss_time = p.time_sent_us + time_threshold;
                    if (lev.loss_time_us == null or expected_loss_time < lev.loss_time_us.?) {
                        lev.loss_time_us = expected_loss_time;
                    }
                }
            }
        }

        return event;
    }

    fn setLossDetectionTimer(self: *LossDetector, now_us: u64) void {
        var earliest_loss_time: ?u64 = null;
        for (&self.levels) |*lev| {
            if (lev.loss_time_us) |lt| {
                if (earliest_loss_time == null or lt < earliest_loss_time.?) {
                    earliest_loss_time = lt;
                }
            }
        }

        if (earliest_loss_time) |lt| {
            self.loss_detection_timer_us = lt;
            return;
        }

        if (self.pto_expired) {
            self.loss_detection_timer_us = null;
            return;
        }

        var has_in_flight = false;
        for (&self.levels) |*lev| {
            if (lev.sent.hasAckElicitingInFlight()) {
                has_in_flight = true;
                break;
            }
        }

        if (!has_in_flight) {
            self.loss_detection_timer_us = null;
            return;
        }

        var pto_timeout = self.rtt.ptoBase(self.max_ack_delay_us);
        pto_timeout *= @as(u64, 1) << @intCast(@min(self.pto_count, 30));

        var last_send: u64 = 0;
        for (&self.levels) |*lev| {
            if (lev.time_of_last_ack_eliciting_us) |t| {
                last_send = @max(last_send, t);
            }
        }
        if (last_send == 0) last_send = now_us;

        self.loss_detection_timer_us = last_send + pto_timeout;
    }
};

// ─── Tests ───

test "RttEstimator: first sample" {
    var rtt = RttEstimator.init();
    try std.testing.expect(!rtt.has_sample);
    try std.testing.expectEqual(INITIAL_RTT_US, rtt.smoothed_rtt_us);

    rtt.updateRtt(100_000, 0, 25_000);
    try std.testing.expect(rtt.has_sample);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 50_000), rtt.rttvar_us);
    try std.testing.expectEqual(@as(u64, 100_000), rtt.min_rtt_us);
}

test "RttEstimator: subsequent samples converge" {
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.updateRtt(120_000, 0, 25_000);
    rtt.updateRtt(110_000, 0, 25_000);

    try std.testing.expect(rtt.smoothed_rtt_us >= 100_000);
    try std.testing.expect(rtt.smoothed_rtt_us <= 120_000);
    try std.testing.expect(rtt.min_rtt_us == 100_000);
}

test "RttEstimator: ack_delay subtracted" {
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    rtt.updateRtt(120_000, 20_000, 25_000);
    try std.testing.expect(rtt.smoothed_rtt_us <= 105_000);
}

test "RttEstimator: ptoBase" {
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    const pto = rtt.ptoBase(25_000);
    try std.testing.expectEqual(@as(u64, 325_000), pto);
}

test "RttEstimator: timeThreshold" {
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    try std.testing.expectEqual(@as(u64, 112_500), rtt.timeThreshold());
}

test "SentPacketRegistry: insert and get" {
    var reg = SentPacketRegistry.init();
    _ = reg.insert(.{ .pn = 0, .time_sent_us = 1000, .size = 100, .ack_eliciting = true, .in_flight = true, .declared_lost = false });
    _ = reg.insert(.{ .pn = 1, .time_sent_us = 2000, .size = 200, .ack_eliciting = true, .in_flight = true, .declared_lost = false });

    const p0 = reg.get(0) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0), p0.pn);
    try std.testing.expectEqual(@as(u32, 100), p0.size);

    const p1 = reg.get(1) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 1), p1.pn);

    try std.testing.expect(reg.get(99) == null);
}

test "SentPacketRegistry: remove" {
    var reg = SentPacketRegistry.init();
    _ = reg.insert(.{ .pn = 5, .time_sent_us = 1000, .size = 50, .ack_eliciting = true, .in_flight = true, .declared_lost = false });
    try std.testing.expect(reg.get(5) != null);
    reg.remove(5);
    try std.testing.expect(reg.get(5) == null);
}

test "SentPacketRegistry: hasAckElicitingInFlight" {
    var reg = SentPacketRegistry.init();
    try std.testing.expect(!reg.hasAckElicitingInFlight());

    _ = reg.insert(.{ .pn = 0, .time_sent_us = 1000, .size = 100, .ack_eliciting = false, .in_flight = true, .declared_lost = false });
    try std.testing.expect(!reg.hasAckElicitingInFlight());

    _ = reg.insert(.{ .pn = 1, .time_sent_us = 2000, .size = 100, .ack_eliciting = true, .in_flight = true, .declared_lost = false });
    try std.testing.expect(reg.hasAckElicitingInFlight());
}

test "SentPacketRegistry: earliestSendTime" {
    var reg = SentPacketRegistry.init();
    try std.testing.expect(reg.earliestSendTime() == null);

    _ = reg.insert(.{ .pn = 0, .time_sent_us = 5000, .size = 100, .ack_eliciting = true, .in_flight = true, .declared_lost = false });
    _ = reg.insert(.{ .pn = 1, .time_sent_us = 3000, .size = 100, .ack_eliciting = true, .in_flight = true, .declared_lost = false });
    try std.testing.expectEqual(@as(u64, 3000), reg.earliestSendTime().?);
}

test "CongestionController: init state" {
    const cc = CongestionController.init();
    // min(10*1200, max(14720, 2*1200)) = min(12000, 14720) = 12000
    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
    try std.testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    try std.testing.expect(cc.inSlowStart());
    try std.testing.expect(!cc.inRecovery());
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "CongestionController: canSend" {
    var cc = CongestionController.init();
    try std.testing.expect(cc.canSend()); // 0 + 1200 <= 12000

    cc.bytes_in_flight = 10800;
    try std.testing.expect(cc.canSend()); // 10800 + 1200 = 12000 <= 12000

    cc.bytes_in_flight = 10801;
    try std.testing.expect(!cc.canSend()); // 10801 + 1200 = 12001 > 12000
}

test "CongestionController: sendOnePacketInRecovery bypasses canSend" {
    var cc = CongestionController.init();
    cc.bytes_in_flight = 12000;
    try std.testing.expect(!cc.canSend());

    cc.send_one_packet_in_recovery = true;
    try std.testing.expect(cc.canSend());
}

test "CongestionController: batch slow start growth" {
    var cc = CongestionController.init();
    const initial_cwnd = cc.congestion_window;
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    // Simulate: packetSent, then packetAcked (accumulate), then packetBatchEnd (apply)
    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    try std.testing.expectEqual(@as(u64, 1200), cc.bytes_in_flight);

    cc.packetAcked(&pkt);
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    // cwnd unchanged — only accumulated
    try std.testing.expectEqual(initial_cwnd, cc.congestion_window);

    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);
    // Now cwnd grows by acked bytes (slow start)
    try std.testing.expectEqual(initial_cwnd + 1200, cc.congestion_window);
}

test "CongestionController: batch prevents multiple cwnd halvings" {
    var cc = CongestionController.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 900_000;

    // Send 4 packets
    const pkts = [_]SentPacket{
        .{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
        .{ .pn = 1, .time_sent_us = 1_001_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
        .{ .pn = 2, .time_sent_us = 1_002_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
        .{ .pn = 3, .time_sent_us = 1_003_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false },
    };
    for (&pkts) |*p| cc.packetSent(p);

    // Two packets lost in the same batch
    cc.packetLost(2, &pkts[0], &rtt);
    cc.packetLost(2, &pkts[1], &rtt);

    const cwnd_before = cc.congestion_window;
    cc.packetBatchEnd(1_200_000, 2, &rtt, 25_000);

    // cwnd halved only ONCE (not twice)
    const expected_ssthresh = cwnd_before / 2;
    try std.testing.expectEqual(expected_ssthresh, cc.ssthresh);
    try std.testing.expectEqual(@max(expected_ssthresh, cc.minimumCongestionWindow()), cc.congestion_window);
    try std.testing.expect(cc.in_recovery);
    try std.testing.expect(cc.send_one_packet_in_recovery);
}

test "CongestionController: congestion avoidance growth" {
    var cc = CongestionController.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    cc.ssthresh = 12000;
    cc.congestion_window = 12000;

    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    cc.packetAcked(&pkt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);

    // In congestion avoidance: pending(1200) < cwnd(12000), so no increment yet
    // The algorithm accumulates until pending >= cwnd
    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
    try std.testing.expectEqual(@as(u64, 1200), cc.congestion_pending_acks);
}

test "CongestionController: underutilized suppresses growth" {
    var cc = CongestionController.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);

    cc.setUnderutilized(true);

    const pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&pkt);
    cc.packetAcked(&pkt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);

    // No growth because underutilized
    try std.testing.expectEqual(@as(u64, 12000), cc.congestion_window);
    try std.testing.expectEqual(@as(u64, 0), cc.congestion_pending_acks);
}

test "CongestionController: recovery exit on post-recovery ACK" {
    var cc = CongestionController.init();
    var rtt = RttEstimator.init();
    rtt.updateRtt(100_000, 0, 25_000);
    rtt.first_sample_time_us = 900_000;

    // Enter recovery
    const lost_pkt = SentPacket{ .pn = 0, .time_sent_us = 1_000_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&lost_pkt);
    cc.packetLost(2, &lost_pkt, &rtt);
    cc.packetBatchEnd(1_100_000, 2, &rtt, 25_000);
    try std.testing.expect(cc.in_recovery);

    // ACK a packet sent AFTER recovery started
    const new_pkt = SentPacket{ .pn = 1, .time_sent_us = 1_200_000, .size = 1200, .ack_eliciting = true, .in_flight = true, .declared_lost = false };
    cc.packetSent(&new_pkt);
    cc.packetAcked(&new_pkt);
    cc.packetBatchEnd(1_300_000, 2, &rtt, 25_000);

    // Should exit recovery and grow cwnd
    try std.testing.expect(!cc.in_recovery);
}

test "Pacer: init and canSend" {
    const p = Pacer.init(1_000_000, 12000, K_GRANULARITY_US);
    const result = p.canSend(1_000_000);
    try std.testing.expect(result.ok);
}

test "Pacer: packetSent depletes bucket" {
    var p = Pacer.init(1_000_000, 12000, K_GRANULARITY_US);
    // Send more than bucket allows
    p.packetSent(1_000_000, 12000, 12000, 100_000);
    // Bucket exactly at 0, still OK
    const r1 = p.canSend(1_000_000);
    try std.testing.expect(r1.ok);

    p.packetSent(1_000_000, 1200, 12000, 100_000);
    // Bucket negative, next_send in future
    const r2 = p.canSend(1_000_000);
    try std.testing.expect(!r2.ok);
    try std.testing.expect(r2.next_us > 1_000_000);
}

test "Pacer: advance refills bucket" {
    var p = Pacer.init(1_000_000, 12000, K_GRANULARITY_US);
    p.packetSent(1_000_000, 13000, 12000, 100_000);
    try std.testing.expect(!p.canSend(1_000_000).ok);

    // Advance 50ms with cwnd=12000, rtt=100ms → refill = 50000 * 12000 / 100000 * 1.25 = 7500
    p.advance(1_050_000, 12000, 100_000);
    const r = p.canSend(1_050_000);
    try std.testing.expect(r.ok);
}

test "LossDetector: onPacketSent updates bytes_in_flight" {
    var ld = LossDetector.init();
    ld.onPacketSent(.initial, 0, 1200, true, 1000);
    try std.testing.expectEqual(@as(u64, 1200), ld.bytesInFlight());

    ld.onPacketSent(.initial, 1, 100, true, 2000);
    try std.testing.expectEqual(@as(u64, 1300), ld.bytesInFlight());
}

test "LossDetector: onPacketSent arms timer" {
    var ld = LossDetector.init();
    try std.testing.expect(ld.getTimer() == null);
    ld.onPacketSent(.application, 0, 100, true, 1000);
    try std.testing.expect(ld.getTimer() != null);
}

test "LossDetector: onAckReceived updates RTT" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    ld.onPacketSent(.application, 1, 200, true, 1_050_000);

    const event = ld.onAckReceived(.application, 1, 0, 0, 1_100_000);
    try std.testing.expectEqual(@as(usize, 1), event.lost_count);
    try std.testing.expectEqual(@as(u64, 0), event.lost_packets[0]);
    try std.testing.expectEqual(@as(u64, 0), ld.bytesInFlight());
    try std.testing.expect(ld.rtt.has_sample);
    try std.testing.expectEqual(@as(u64, 50_000), ld.rtt.latest_rtt_us);
}

test "LossDetector: packet threshold loss detection" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);

    ld.onPacketSent(.application, 1, 100, true, 2_000_000);
    ld.onPacketSent(.application, 2, 100, true, 2_001_000);
    ld.onPacketSent(.application, 3, 100, true, 2_002_000);
    ld.onPacketSent(.application, 4, 100, true, 2_003_000);

    const event = ld.onAckReceived(.application, 4, 0, 0, 2_050_000);
    try std.testing.expectEqual(@as(usize, 1), event.lost_count);
    try std.testing.expectEqual(@as(u64, 1), event.lost_packets[0]);
    try std.testing.expectEqual(@as(u64, 100), event.bytes_lost);
}

test "LossDetector: time threshold loss detection" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);

    ld.onPacketSent(.application, 1, 100, true, 1_200_000);
    ld.onPacketSent(.application, 2, 100, true, 1_300_000);

    const event = ld.onAckReceived(.application, 2, 0, 0, 1_500_000);
    try std.testing.expectEqual(@as(usize, 1), event.lost_count);
    try std.testing.expectEqual(@as(u64, 1), event.lost_packets[0]);
}

test "LossDetector: PTO exponential backoff" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);

    const timer1 = ld.getTimer().?;
    _ = ld.onLossDetectionTimeout(timer1);
    try std.testing.expectEqual(@as(u32, 1), ld.pto_count);
    try std.testing.expect(ld.pto_expired);

    // After PTO expires, timer is cleared until a probe is sent.
    // Simulate sending a probe — this clears pto_expired and rearms the timer.
    ld.onPacketSent(.application, 1, 100, true, timer1);
    try std.testing.expect(!ld.pto_expired);

    const timer2 = ld.getTimer().?;
    try std.testing.expect(timer2 > timer1);

    _ = ld.onLossDetectionTimeout(timer2);
    try std.testing.expectEqual(@as(u32, 2), ld.pto_count);
}

test "LossDetector: discardLevel removes in-flight bytes" {
    var ld = LossDetector.init();
    ld.onPacketSent(.initial, 0, 1200, true, 1000);
    ld.onPacketSent(.initial, 1, 1200, true, 2000);
    try std.testing.expectEqual(@as(u64, 2400), ld.bytesInFlight());

    ld.discardLevel(.initial);
    try std.testing.expectEqual(@as(u64, 0), ld.bytesInFlight());
    try std.testing.expect(!ld.levels[0].sent.hasAckElicitingInFlight());
}

test "LossDetector: no timer when nothing in flight" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);
    try std.testing.expect(ld.getTimer() == null);
}

test "LossDetector: pto_count resets on ACK" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    ld.pto_count = 3;

    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);
    try std.testing.expectEqual(@as(u32, 0), ld.pto_count);
}

test "LossDetector: onAckReceived with first_ack_range marks full range" {
    var ld = LossDetector.init();
    ld.onPacketSent(.application, 0, 100, true, 1_000_000);
    ld.onPacketSent(.application, 1, 100, true, 1_001_000);
    ld.onPacketSent(.application, 2, 100, true, 1_002_000);
    ld.onPacketSent(.application, 3, 100, true, 1_003_000);
    try std.testing.expectEqual(@as(u64, 400), ld.bytesInFlight());

    const event = ld.onAckReceived(.application, 3, 3, 0, 1_100_000);
    try std.testing.expectEqual(@as(usize, 0), event.lost_count);
    try std.testing.expectEqual(@as(u64, 0), ld.bytesInFlight());
}

test "LossDetector: onAckReceivedRanges marks multiple ranges" {
    var ld = LossDetector.init();
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) {
        ld.onPacketSent(.application, pn, 100, true, 1_000_000 + pn * 1000);
    }
    try std.testing.expectEqual(@as(u64, 1000), ld.bytesInFlight());

    const ranges = [_]AckRange{
        .{ .start = 8, .end = 9 },
        .{ .start = 5, .end = 6 },
        .{ .start = 1, .end = 2 },
    };
    const event = ld.onAckReceivedRanges(.application, 9, 0, &ranges, 1_100_000);

    // Loss: largest=9, gap >= 3 → PNs 0,3,4 declared lost
    // PN 7 (gap=2) stays in-flight
    try std.testing.expectEqual(@as(u64, 100), ld.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 3), event.lost_count);
}

test "LossDetector: batch API prevents multi-halving" {
    var ld = LossDetector.init();

    // Send 10 packets
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) {
        ld.onPacketSent(.application, pn, 1200, true, 1_000_000 + pn * 1000);
    }
    const cwnd_before = ld.cc.congestionWindow();

    // ACK only PN 9 → PNs 0-6 are lost (gap >= 3), PN 7,8 not lost
    const event = ld.onAckReceived(.application, 9, 0, 0, 1_100_000);
    try std.testing.expect(event.lost_count >= 3);

    // cwnd should be halved ONCE, not 7 times
    const expected_ssthresh = cwnd_before / 2;
    try std.testing.expectEqual(expected_ssthresh, ld.cc.new_reno.ssthresh);
    try std.testing.expect(ld.cc.inRecovery());
}

test "LossDetector: sendLimit reflects pacer state" {
    var ld = LossDetector.initWithTime(1_000_000);
    ld.onPacketSent(.application, 0, 12000, true, 1_000_000);

    // After sending full cwnd, CC should block
    const result = ld.sendLimit(1_000_000);
    try std.testing.expectEqual(SendLimit.limited, result.limit);
}

test "LossDetector: Cubic algorithm via initWithAlgo" {
    var ld = LossDetector.initWithAlgo(.cubic, 1_000_000);
    try std.testing.expectEqual(CongestionAlgorithm.cubic, ld.cc.algo);

    // Slow start growth
    ld.onPacketSent(.application, 0, 1200, true, 1_000_000);
    try std.testing.expectEqual(@as(u64, 1200), ld.bytesInFlight());

    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);
    try std.testing.expectEqual(@as(u64, 0), ld.bytesInFlight());
    // cwnd should grow in slow start
    try std.testing.expect(ld.cc.congestionWindow() > 12000);
}

test "LossDetector: Cubic β=0.7 on loss" {
    var ld = LossDetector.initWithAlgo(.cubic, 0);

    // Get an RTT sample first
    ld.onPacketSent(.application, 0, 1200, true, 1_000_000);
    _ = ld.onAckReceived(.application, 0, 0, 0, 1_100_000);

    // Set cwnd manually for predictable test
    ld.cc.cubic.congestion_window = 20000;
    ld.cc.cubic.ssthresh = 12000;

    // Send 4 packets, ACK only the last → pn 1 lost (gap >= 3)
    ld.onPacketSent(.application, 1, 1200, true, 2_000_000);
    ld.onPacketSent(.application, 2, 1200, true, 2_001_000);
    ld.onPacketSent(.application, 3, 1200, true, 2_002_000);
    ld.onPacketSent(.application, 4, 1200, true, 2_003_000);

    const event = ld.onAckReceived(.application, 4, 0, 0, 2_100_000);
    try std.testing.expect(event.lost_count >= 1);

    // Cubic uses β=0.7: ssthresh = 20000 * 7/10 = 14000
    try std.testing.expectEqual(@as(u64, 14000), ld.cc.cubic.ssthresh);
    try std.testing.expect(ld.cc.inRecovery());
}
