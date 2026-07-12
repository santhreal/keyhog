//! Internal timing split of the Hyperscan always-active prefilter mark path.
//!
//! `#67` ([`super::mark_stats`]) decomposed the `phase2:prefilter` leaf at the
//! CALL level and showed that on a credential-dense corpus ~99% of per-pattern
//! calls are HS-served. This module decomposes a single HS-served call's TIME
//! into its two halves, so the dominant sub-cost is identifiable:
//!
//!   * **scan** — `HsScanner::scan_each_result`: one SIMD pass over the chunk
//!     against the whole always-active pattern database (~2.7k patterns incl. the
//!     unicode homoglyph classes), plus the marking callback for each hit.
//!   * **dropped-host-loop** — the HS-incompatible patterns (those with `^`/`$`,
//!     see `hs_prefilter_requires_host_regex`) each run their OWN whole-chunk
//!     `regex::is_match` on EVERY HS mark call, unconditionally.
//!
//! If the split shows scan dominates, the lever is the HS database itself (the
//! homoglyph pattern burden), which is recall-critical and deep. If the dropped
//! loop is material, batching those patterns into one `RegexSet` is a localized,
//! recall-identical win. The decomposition exists so that choice is measured, not
//! guessed.
//!
//! Cost discipline: the timing is PROFILE-GATED — `Phase2AlwaysActivePrefilter`'s
//! caller only takes `Instant::now()` when the unified profiler is enabled (the
//! same gate the per-pattern profiler uses). When profiling is off this module
//! contributes nothing to the hot path. The counters are process-wide relaxed
//! atomics that sum across rayon workers, matching `POPULATE_PREFILTER_NS`.

use super::mark_stats::pct;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Nanoseconds spent in the HS SIMD scan + mark callback, summed across workers.
static HS_MARK_SCAN_NS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds spent in the dropped HS-incompatible host-regex loop, summed
/// across workers.
static HS_MARK_DROPPED_NS: AtomicU64 = AtomicU64::new(0);

/// Immutable view of the HS-mark timing split. Cumulative since the last
/// [`hs_mark_timing_reset`]. The derived helpers centralize the percentage
/// arithmetic the profiler would otherwise inline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HsMarkSplit {
    /// Nanoseconds in the HS SIMD scan + mark callback.
    pub scan_ns: u64,
    /// Nanoseconds in the dropped HS-incompatible host-regex loop.
    pub dropped_ns: u64,
}

impl HsMarkSplit {
    /// Total measured HS-mark nanoseconds (`scan_ns + dropped_ns`).
    pub fn total_ns(&self) -> u64 {
        self.scan_ns + self.dropped_ns
    }

    /// Fraction of measured HS-mark time spent in the SIMD scan, in `[0, 100]`.
    /// Returns `0.0` when nothing was measured (no divide-by-zero).
    pub fn scan_pct(&self) -> f64 {
        pct(self.scan_ns, self.total_ns())
    }

    /// Fraction of measured HS-mark time spent in the dropped host loop,
    /// in `[0, 100]`.
    pub fn dropped_pct(&self) -> f64 {
        pct(self.dropped_ns, self.total_ns())
    }

    /// True iff any HS-mark time was recorded (the profiler only prints the split
    /// line when this holds, so an unprofiled run stays silent).
    pub fn any_recorded(&self) -> bool {
        self.total_ns() > 0
    }
}

/// Render the HS-mark timing split line the profiler prints beneath the mark
/// decomposition. Pure (no I/O) so the formatting is unit-testable.
///
/// Example:
/// `hs-mark: scan=8100.0 ms (96.7%)  dropped-host-loop=280.0 ms (3.3%)`
pub(crate) fn format_hs_mark_split(s: &HsMarkSplit) -> String {
    format!(
        "hs-mark: scan={:.1} ms ({:.1}%)  dropped-host-loop={:.1} ms ({:.1}%)",
        s.scan_ns as f64 / 1e6,
        s.scan_pct(),
        s.dropped_ns as f64 / 1e6,
        s.dropped_pct(),
    )
}

/// Add `ns` to the HS SIMD scan accumulator. Called only when profiling is on
/// (the caller gates the `Instant`), so the add is never on the unprofiled path.
#[cfg(feature = "simd")]
#[inline]
pub(crate) fn record_hs_mark_scan_ns(ns: u64) {
    HS_MARK_SCAN_NS.fetch_add(ns, Relaxed);
}

/// Add `ns` to the dropped host-loop accumulator.
#[cfg(feature = "simd")]
#[inline]
pub(crate) fn record_hs_mark_dropped_ns(ns: u64) {
    HS_MARK_DROPPED_NS.fetch_add(ns, Relaxed);
}

/// Snapshot the HS-mark timing split without resetting it.
pub(crate) fn hs_mark_timing_snapshot() -> HsMarkSplit {
    HsMarkSplit {
        scan_ns: HS_MARK_SCAN_NS.load(Relaxed),
        dropped_ns: HS_MARK_DROPPED_NS.load(Relaxed),
    }
}

/// Reset the HS-mark timing accumulators (profiler warm-up and post-dump reset).
pub(crate) fn hs_mark_timing_reset() {
    HS_MARK_SCAN_NS.store(0, Relaxed);
    HS_MARK_DROPPED_NS.store(0, Relaxed);
}
