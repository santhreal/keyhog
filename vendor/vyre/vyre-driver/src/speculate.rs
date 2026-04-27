//! Speculative rule evaluation with commit/rollback (G6).
//!
//! # What this is
//!
//! Rules split into a cheap **pre-filter** (literal-strings via
//! gpumatch) and an expensive **confirmer** (flows_to, dominates,
//! the full taint solver). The classical path is:
//!
//! ```text
//!   dispatch(prefilter) → readback(hits) → dispatch(confirmer on hits)
//! ```
//!
//! The gather between the two dispatches is a host-visible sync
//! point that drains the GPU: the confirmer starts with 0%
//! occupancy while it fills from a compacted input stream.
//!
//! The speculative path runs the confirmer on *every* tile,
//! assuming the pre-filter would pass, and commits only the tiles
//! whose pre-filter actually passed. Rollback is free — a tile
//! that shouldn't have produced output writes nothing, because the
//! commit is gated on the pre-filter bit.
//!
//! ```text
//!   dispatch(prefilter & confirmer fused) → readback(committed_tiles)
//! ```
//!
//! One dispatch, no host round-trip. On Ada-class hardware this is
//! a 2-4x wall-clock win on the fused kernel vs the serial pair,
//! *if* the pre-filter hit rate is high enough to amortise the
//! speculative confirmer work. `AdaptiveSpeculator` watches the
//! commit-rate EMA and disables speculation when it stops paying.
//!
//! # Wire format
//!
//! Every speculative dispatch's output buffer carries a two-u32
//! trailer: `[committed, rolled_back]`. The host reads it via
//! [`parse_counter_tail`] to build a [`SpeculationReport`].

#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::sync::atomic::{AtomicU32, Ordering};

/// Counts from one speculative dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpeculationReport {
    /// Lanes whose confirmer output survived the commit gate.
    pub committed_tiles: u32,
    /// Lanes the confirmer ran on that the pre-filter rejected
    /// (work thrown away — the "cost" side of the trade).
    pub rolled_back_tiles: u32,
}

impl SpeculationReport {
    /// Construct a report from the raw counter pair a kernel wrote.
    #[must_use]
    pub fn from_counts(committed: u32, rolled: u32) -> Self {
        Self {
            committed_tiles: committed,
            rolled_back_tiles: rolled,
        }
    }

    /// Empty report — no tiles touched yet. Equivalent to
    /// [`Self::default`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Total tiles the confirmer ran on.
    #[must_use]
    pub fn attempted_tiles(&self) -> u32 {
        self.committed_tiles.saturating_add(self.rolled_back_tiles)
    }

    /// Commit rate in parts-per-million. `0` when no tiles ran, to
    /// keep the return total-order (a missing observation doesn't
    /// outrank a 0% observation).
    #[must_use]
    pub fn commit_rate_ppm(&self) -> u32 {
        let total = self.attempted_tiles();
        if total == 0 {
            return 0;
        }
        let num = u64::from(self.committed_tiles) * 1_000_000;
        (num / u64::from(total)) as u32
    }

    /// Commit rate as a whole-percent, floored.
    #[must_use]
    pub fn commit_rate_pct(&self) -> u32 {
        self.commit_rate_ppm() / 10_000
    }

    /// True when speculation is paying for itself vs the serial
    /// path at the caller's threshold. Integer-only comparison.
    #[must_use]
    pub fn worthwhile(&self, threshold_pct: u32) -> bool {
        let threshold_ppm = threshold_pct.saturating_mul(10_000);
        self.commit_rate_ppm() >= threshold_ppm
    }
}

/// Default crossover threshold. Below this commit rate the
/// speculative path underperforms the serial prefilter → confirmer
/// pair on Ada-class hardware. Empirical.
pub const DEFAULT_THRESHOLD_PCT: u32 = 15;

/// α = 1/4 for the commit-rate EMA. Reacts inside ~4 batches while
/// staying quiet on a single anomalous dispatch.
const EMA_SHIFT: u32 = 2;

/// Online speculator — decides dispatch by dispatch whether to run
/// the fused speculative kernel or fall back to the serial pair.
///
/// The EMA is stored in ppm so we never leave integer math.
#[derive(Debug)]
pub struct AdaptiveSpeculator {
    threshold_ppm: u32,
    ema_commit_rate_ppm: AtomicU32,
    speculation_enabled: AtomicU32,
    samples: AtomicU32,
}

impl AdaptiveSpeculator {
    /// Construct with the given threshold in whole percent.
    /// Speculation starts **enabled** with a seed EMA equal to the
    /// threshold, so the first few dispatches take the speculative
    /// path and produce real evidence for the EMA.
    #[must_use]
    pub fn new(threshold_pct: u32) -> Self {
        let threshold_ppm = threshold_pct.saturating_mul(10_000);
        Self {
            threshold_ppm,
            ema_commit_rate_ppm: AtomicU32::new(threshold_ppm),
            speculation_enabled: AtomicU32::new(1),
            samples: AtomicU32::new(0),
        }
    }

    /// Default-threshold speculator.
    #[must_use]
    pub fn default_threshold() -> Self {
        Self::new(DEFAULT_THRESHOLD_PCT)
    }

    /// Current EMA-smoothed commit rate in ppm.
    #[must_use]
    pub fn commit_rate_ppm(&self) -> u32 {
        self.ema_commit_rate_ppm.load(Ordering::Acquire)
    }

    /// Number of dispatches folded into the EMA so far.
    #[must_use]
    pub fn samples(&self) -> u32 {
        self.samples.load(Ordering::Acquire)
    }

    /// Whether the next dispatch should use the speculative kernel.
    #[must_use]
    pub fn should_speculate(&self) -> bool {
        self.speculation_enabled.load(Ordering::Acquire) != 0
    }

    /// Record the outcome of one speculative dispatch and update
    /// the routing decision for the next one.
    ///
    /// EMA: `new = old + (obs - old) / 4`, implemented on u32 with
    /// signed intermediate to avoid wrap. A report with zero
    /// attempted tiles is ignored — it carries no signal.
    pub fn record(&self, report: SpeculationReport) {
        if report.attempted_tiles() == 0 {
            return;
        }
        let observation = report.commit_rate_ppm();
        // EMA update — single fetch_update so concurrent callers
        // cannot lose samples.
        let _ = self
            .ema_commit_rate_ppm
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                let delta = i64::from(observation) - i64::from(old);
                let step = delta >> EMA_SHIFT;
                let new = i64::from(old) + step;
                Some(new.clamp(0, i64::from(u32::MAX)) as u32)
            });
        self.samples.fetch_add(1, Ordering::AcqRel);
        let new_ppm = self.ema_commit_rate_ppm.load(Ordering::Acquire);
        // Hysteresis: enable when we clearly beat threshold,
        // disable when we clearly miss it. Deadband is ±25% of
        // threshold to avoid flapping right at the crossover.
        let margin = self.threshold_ppm / 4;
        let enable_at = self.threshold_ppm.saturating_add(margin);
        let disable_at = self.threshold_ppm.saturating_sub(margin);
        let prev = self.speculation_enabled.load(Ordering::Acquire);
        if prev == 0 && new_ppm >= enable_at {
            self.speculation_enabled.store(1, Ordering::Release);
        } else if prev != 0 && new_ppm < disable_at {
            self.speculation_enabled.store(0, Ordering::Release);
        }
    }

    /// Threshold in ppm.
    #[must_use]
    pub fn threshold_ppm(&self) -> u32 {
        self.threshold_ppm
    }
}

/// Two little-endian u32s written at the tail of a speculative
/// output buffer by the fused kernel: `[committed, rolled_back]`.
pub const COUNTER_TAIL_BYTES: usize = 8;

/// Read the two-u32 trailer a speculative kernel wrote at the end
/// of its output buffer. Returns `None` if the buffer is too short
/// or its length is not a multiple of 4.
#[must_use]
pub fn parse_counter_tail(output_bytes: &[u8]) -> Option<SpeculationReport> {
    if output_bytes.len() < COUNTER_TAIL_BYTES {
        return None;
    }
    if output_bytes.len() % 4 != 0 {
        return None;
    }
    let tail_start = output_bytes.len() - COUNTER_TAIL_BYTES;
    let mut committed_bytes = [0_u8; 4];
    committed_bytes.copy_from_slice(&output_bytes[tail_start..tail_start + 4]);
    let mut rolled_bytes = [0_u8; 4];
    rolled_bytes.copy_from_slice(&output_bytes[tail_start + 4..tail_start + 8]);
    Some(SpeculationReport::from_counts(
        u32::from_le_bytes(committed_bytes),
        u32::from_le_bytes(rolled_bytes),
    ))
}

/// Encode a counter tail — used by CPU-reference kernels and
/// tests. Keeps the host + device endianness consistent.
#[must_use]
pub fn encode_counter_tail(report: SpeculationReport) -> [u8; COUNTER_TAIL_BYTES] {
    let mut out = [0_u8; COUNTER_TAIL_BYTES];
    out[0..4].copy_from_slice(&report.committed_tiles.to_le_bytes());
    out[4..8].copy_from_slice(&report.rolled_back_tiles.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_has_zero_commit_rate() {
        let r = SpeculationReport::empty();
        assert_eq!(r.commit_rate_ppm(), 0);
        assert_eq!(r.commit_rate_pct(), 0);
        assert_eq!(r.attempted_tiles(), 0);
        assert!(!r.worthwhile(1));
    }

    #[test]
    fn commit_rate_exact_at_quarter() {
        let r = SpeculationReport::from_counts(1, 3);
        assert_eq!(r.commit_rate_ppm(), 250_000);
        assert_eq!(r.commit_rate_pct(), 25);
    }

    #[test]
    fn worthwhile_honors_threshold() {
        let r = SpeculationReport::from_counts(20, 80);
        assert!(r.worthwhile(20));
        assert!(!r.worthwhile(25));
    }

    #[test]
    fn all_rolled_back_is_zero_commit_rate() {
        let r = SpeculationReport::from_counts(0, 1024);
        assert_eq!(r.commit_rate_ppm(), 0);
        assert!(!r.worthwhile(1));
    }

    #[test]
    fn all_committed_is_full_commit_rate() {
        let r = SpeculationReport::from_counts(1024, 0);
        assert_eq!(r.commit_rate_ppm(), 1_000_000);
        assert!(r.worthwhile(99));
    }

    #[test]
    fn parse_counter_tail_reads_pair() {
        let mut buf = vec![0_u8; 32];
        buf[24..28].copy_from_slice(&42_u32.to_le_bytes());
        buf[28..32].copy_from_slice(&100_u32.to_le_bytes());
        let r = parse_counter_tail(&buf).expect("valid length");
        assert_eq!(r.committed_tiles, 42);
        assert_eq!(r.rolled_back_tiles, 100);
    }

    #[test]
    fn parse_counter_tail_rejects_short_buffer() {
        assert!(parse_counter_tail(&[0_u8; 7]).is_none());
    }

    #[test]
    fn parse_counter_tail_rejects_misaligned_length() {
        assert!(parse_counter_tail(&[0_u8; 9]).is_none());
    }

    #[test]
    fn encode_then_parse_roundtrips() {
        let r = SpeculationReport::from_counts(7, 13);
        let tail = encode_counter_tail(r);
        let mut buf = vec![0_u8; 32];
        buf[24..32].copy_from_slice(&tail);
        let parsed = parse_counter_tail(&buf).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn adaptive_speculator_starts_enabled_at_threshold_seed() {
        let s = AdaptiveSpeculator::new(15);
        assert!(s.should_speculate());
        assert_eq!(s.commit_rate_ppm(), 150_000);
        assert_eq!(s.samples(), 0);
    }

    #[test]
    fn adaptive_speculator_disables_on_sustained_low_commit_rate() {
        let s = AdaptiveSpeculator::new(20);
        for _ in 0..20 {
            // 1% commit rate, well under 20% - 5% = 15% disable threshold.
            s.record(SpeculationReport::from_counts(1, 99));
        }
        assert!(
            !s.should_speculate(),
            "EMA should have collapsed below disable threshold"
        );
        assert!(s.commit_rate_ppm() < 150_000);
    }

    #[test]
    fn adaptive_speculator_reenables_after_sustained_high_commit_rate() {
        let s = AdaptiveSpeculator::new(20);
        for _ in 0..20 {
            s.record(SpeculationReport::from_counts(1, 99));
        }
        assert!(!s.should_speculate());
        for _ in 0..20 {
            s.record(SpeculationReport::from_counts(80, 20));
        }
        assert!(
            s.should_speculate(),
            "EMA should have climbed past enable threshold"
        );
    }

    #[test]
    fn adaptive_speculator_ignores_empty_report() {
        let s = AdaptiveSpeculator::new(15);
        let before = s.commit_rate_ppm();
        s.record(SpeculationReport::empty());
        assert_eq!(s.commit_rate_ppm(), before);
        assert_eq!(s.samples(), 0);
    }

    #[test]
    fn adaptive_speculator_hysteresis_avoids_flap_near_threshold() {
        let s = AdaptiveSpeculator::new(20);
        // Hover right at 20% — inside the ±5% deadband.
        for _ in 0..50 {
            s.record(SpeculationReport::from_counts(20, 80));
        }
        assert!(s.should_speculate(), "should stay on inside deadband");
    }

    #[test]
    fn adaptive_speculator_samples_count_matches_record_calls() {
        let s = AdaptiveSpeculator::new(15);
        for i in 0..17 {
            s.record(SpeculationReport::from_counts(i + 1, 10));
        }
        assert_eq!(s.samples(), 17);
    }
}
