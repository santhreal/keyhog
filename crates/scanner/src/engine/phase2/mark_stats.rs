//! Phase-2 always-active prefilter call accounting.
//!
//! The unified profiler (`keyhog scan --profile`) times the `phase2:prefilter`
//! leaf, the single most expensive pass in a real scan, but a raw "N calls,
//! M ns/call" line cannot answer the one question that decides every prefilter
//! optimization: *where does that time go?* A `mark_matches` call resolves down
//! exactly one of three paths, cheapest to most expensive:
//!
//!   1. **gate-skip**: the SWE-101 combined no-candidate gate proved no
//!      anchorable always-active pattern can fire on this (pure-ASCII, no-anchor)
//!      chunk, so only the tiny non-anchorable set was checked. Near-free.
//!   2. **HS-served**: a candidate is possible and the chunk is within the HS
//!      size window, so ONE Hyperscan SIMD scan marked the active set.
//!   3. **RegexSet-served**: a candidate is possible but HS was unavailable,
//!      errored, or the chunk exceeded `hs_prefilter_max_len`, so the portable
//!      `regex::RegexSet` batches ran (the ~2.7k-pattern whole-chunk pass).
//!
//! These counters record which path each call took. `gate_skips + HS-served +
//! RegexSet-served == calls` (a gate-skip never reaches per-pattern work; a
//! per-pattern call is served by exactly one of HS / RegexSet). The profiler
//! reads them in [`super::super::profile::dump`] and prints the decomposition
//! under the `phase2:prefilter` leaf, so the dominant scan cost is diagnosable
//! instead of opaque.
//!
//! Cost: each counter is one relaxed atomic add. `record_mark_call` /
//! `record_mark_gate_skip` fire once per chunk; the HS/RegexSet counters fire
//! only on per-pattern calls (the minority on sparse corpora) whose body, an HS
//! scan or a multi-pattern RegexSet pass, is hundreds-to-thousands of ns, so the
//! added atomic is a rounding error and never gates a fast path (Law 7).
//!
//! Storage: the keyhog-profile runtime owns the counters. Each `record_*` is
//! one `keyhog_profile::add_counter` call, which is a no-op when no profile
//! runtime is active (one relaxed atomic load on the disabled path), records
//! into the per-thread legacy store under `--perf-trace`, and into the
//! worker-sharded session store under an active `Runtime`/`Session`. The
//! unified profiler drains them once per dump via
//! `keyhog_profile::take_typed_metrics` and builds a [`MarkSnapshot`] from the
//! drained values with [`mark_snapshot_from_typed`].

/// Immutable snapshot of the prefilter call counters at one instant.
///
/// Fields are cumulative since the last typed-metric drain. The derived
/// helpers ([`per_pattern_work`], [`served_total`], the `*_pct` accessors)
/// centralize the arithmetic the profiler and tests would otherwise duplicate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MarkSnapshot {
    /// Total `mark_matches` calls (one per chunk that reaches the always-active
    /// prefilter). Equals the `phase2:prefilter` leaf's `calls` in the profiler.
    pub calls: u64,
    /// Calls the no-candidate gate resolved without any per-pattern work.
    pub gate_skips: u64,
    /// Calls that fell through the gate into real per-pattern marking. Equals
    /// `hs_served + regexset_served`.
    pub perpattern_work: u64,
    /// Per-pattern calls served by the Hyperscan SIMD fast path.
    pub hs_served: u64,
    /// Per-pattern calls served by the portable `regex::RegexSet` batches (HS
    /// unavailable/errored, chunk over the size gate, or a non-`simd` build).
    pub regexset_served: u64,
}

impl MarkSnapshot {
    /// Per-pattern calls, derived from the path split. Equal to
    /// [`Self::perpattern_work`] in a consistent snapshot; exposed so the
    /// invariant `gate_skips + served_total == calls` is checkable two ways.
    pub fn served_total(&self) -> u64 {
        self.hs_served + self.regexset_served
    }

    /// True iff the path split accounts for every call exactly once:
    /// `gate_skips + served_total() == calls` AND `served_total() == perpattern_work`.
    ///
    /// A gate-skip never reaches per-pattern work and a per-pattern call is
    /// served by exactly one of HS / RegexSet, so a *quiescent* snapshot (read
    /// after scanning stops) must satisfy both equalities. The profiler asserts
    /// this before printing the decomposition: an inconsistent snapshot means a
    /// `record_*` path bumped `calls` without its matching sub-counter (an
    /// accounting bug), which would make every reported percentage wrong, so it
    /// is surfaced loudly rather than printed as if correct (Law 10).
    ///
    /// Only valid post-scan: a live read across rayon workers can momentarily
    /// skew because the five relaxed atomics are loaded at slightly different
    /// instants, so callers must not assert this on a snapshot taken mid-scan.
    pub fn is_consistent(&self) -> bool {
        self.gate_skips + self.served_total() == self.calls
            && self.served_total() == self.perpattern_work
    }

    /// Fraction of all calls that took the cheap gate-skip path, in `[0, 100]`.
    /// Returns `0.0` when no calls were recorded (avoids a divide-by-zero).
    pub fn gate_skip_pct(&self) -> f64 {
        pct(self.gate_skips, self.calls)
    }

    /// Fraction of all calls that reached per-pattern marking, in `[0, 100]`.
    pub fn perpattern_pct(&self) -> f64 {
        pct(self.perpattern_work, self.calls)
    }

    /// Fraction of PER-PATTERN calls served by Hyperscan, in `[0, 100]`.
    /// Denominator is per-pattern work, not total calls, so this reads as "of the
    /// expensive calls, how many took the fast path".
    pub fn hs_served_pct(&self) -> f64 {
        pct(self.hs_served, self.perpattern_work)
    }

    /// Fraction of PER-PATTERN calls served by the RegexSet path, in `[0, 100]`.
    pub fn regexset_served_pct(&self) -> f64 {
        pct(self.regexset_served, self.perpattern_work)
    }
}

/// `100 * part / whole`, or `0.0` when `whole == 0`. Shared by the snapshot
/// accessors so the divide-by-zero guard lives in exactly one place. Also the
/// single owner for the sibling [`super::hs_mark_timing`] percentage accessors,
/// so the divide-by-zero guard is not re-implemented per module.
pub(super) fn pct(part: u64, whole: u64) -> f64 {
    if whole > 0 {
        100.0 * part as f64 / whole as f64
    } else {
        0.0
    }
}

/// Render the one-line prefilter decomposition the profiler prints beneath the
/// `phase2:prefilter` leaf. Pure (no I/O) so the formatting is unit-testable.
///
/// Example (candidate-dense corpus, HS engaged on small chunks):
/// `mark: calls=10123  gate-skip=120 (1.2%)  per-pattern=10003 (98.8%)  [hs=8800 (88.0%)  regexset=1203 (12.0%)]  batches: run=4012 skip=39988 (90.9% skipped)`
///
/// The batch tail answers the question the call-level split cannot: once a
/// chunk falls through to per-pattern work, how much of the batch set the
/// prefix gate actually eliminated. It is the difference between "the prefilter
/// is expensive because every chunk reaches it" and "because every batch runs".
/// It is omitted when no gateable batch was evaluated, which is the case on any
/// build that never reaches the portable RegexSet path.
pub(crate) fn format_mark_decomposition(s: &MarkSnapshot) -> String {
    let mut line = format!(
        "mark: calls={}  gate-skip={} ({:.1}%)  per-pattern={} ({:.1}%)  \
         [hs={} ({:.1}%)  regexset={} ({:.1}%)]",
        s.calls,
        s.gate_skips,
        s.gate_skip_pct(),
        s.perpattern_work,
        s.perpattern_pct(),
        s.hs_served,
        s.hs_served_pct(),
        s.regexset_served,
        s.regexset_served_pct(),
    );
    let batch_runs = super::GATE_BATCH_RUNS.load(std::sync::atomic::Ordering::Relaxed);
    let batch_skips = super::GATE_BATCH_SKIPS.load(std::sync::atomic::Ordering::Relaxed);
    let batch_total = batch_runs.saturating_add(batch_skips);
    if batch_total > 0 {
        line.push_str(&format!(
            "  batches: run={batch_runs} skip={batch_skips} ({:.1}% skipped)",
            pct(batch_skips, batch_total)
        ));
    }
    line
}

#[inline]
pub(crate) fn record_mark_call() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::Phase2PrefilterMarkCalls, 1);
}

#[inline]
pub(crate) fn record_mark_gate_skip() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::Phase2PrefilterGateSkips, 1);
}

#[inline]
pub(crate) fn record_mark_perpattern_work() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::Phase2PrefilterPerPatternWork, 1);
}

/// A per-pattern call was served by the Hyperscan SIMD fast path. Fires exactly
/// once per such call, after the HS scan succeeds.
///
/// Only ever called from the `#[cfg(feature = "simd")]` HS dispatch, so in a
/// non-`simd` build it is absent and `hs_served` stays zero.
#[cfg(feature = "simd")]
#[inline]
pub(crate) fn record_mark_hs_served() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::Phase2PrefilterHsServed, 1);
}

/// A per-pattern call was served by the portable `regex::RegexSet` batches.
/// Fires exactly once per such call, when execution reaches the RegexSet path
/// (HS unavailable/errored, chunk over the size gate, or a non-`simd` build).
#[inline]
pub(crate) fn record_mark_regexset_served() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::Phase2PrefilterRegexsetServed, 1);
}

/// Build a [`MarkSnapshot`] from one drained typed-metric batch
/// (`keyhog_profile::take_typed_metrics`). Missing counters read as zero, so a
/// scan with the profiler off (or a scan that never reached the prefilter)
/// yields the default snapshot.
pub(crate) fn mark_snapshot_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> MarkSnapshot {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    use keyhog_profile::CounterId;
    MarkSnapshot {
        calls: value(CounterId::Phase2PrefilterMarkCalls),
        gate_skips: value(CounterId::Phase2PrefilterGateSkips),
        perpattern_work: value(CounterId::Phase2PrefilterPerPatternWork),
        hs_served: value(CounterId::Phase2PrefilterHsServed),
        regexset_served: value(CounterId::Phase2PrefilterRegexsetServed),
    }
}

/// Drain the prefilter call counters for test isolation. Returns the drained
/// snapshot so a test can reset-then-scan-then-read with exact values; each
/// drain is destructive, matching the profile runtime's bounded-storage model.
#[cfg(test)]
pub(crate) fn take_mark_stats() -> MarkSnapshot {
    mark_snapshot_from_typed(&keyhog_profile::take_typed_metrics())
}

#[cfg(test)]
mod pct_owner_tests {
    use super::pct;

    // `pct` is the single owner for both this module's `*_pct` accessors and the
    // sibling `hs_mark_timing` split accessors (dedup: the divide-by-zero guard
    // and rounding live in exactly one place). Pin its concrete arithmetic so a
    // future edit to either caller cannot silently reintroduce a divergent copy.
    #[test]
    fn pct_is_percentage_of_whole() {
        assert_eq!(pct(1, 4), 25.0);
        assert_eq!(pct(900, 1000), 90.0);
        assert_eq!(pct(3, 3), 100.0);
    }

    #[test]
    fn pct_is_zero_when_whole_is_zero_no_div_by_zero() {
        assert_eq!(pct(5, 0), 0.0);
        assert_eq!(pct(0, 0), 0.0);
    }
}
