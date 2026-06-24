#[cfg(not(test))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// SWE-101 no-candidate fast-path counters. A regression test reads them to
/// prove the always-active prefilter does no per-pattern work on a chunk that
/// cannot activate any always-active pattern.
///
/// In normal builds these are relaxed atomics. Under `cargo test` they are
/// thread-local so full-suite parallel scans cannot pollute a reset -> scan ->
/// read window owned by one counter-sensitive test.
#[cfg(not(test))]
pub(crate) static MARK_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
pub(crate) static MARK_GATE_SKIPS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
pub(crate) static MARK_PERPATTERN_WORK: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct MarkStats {
    calls: u64,
    gate_skips: u64,
    perpattern_work: u64,
}

#[cfg(test)]
thread_local! {
    static MARK_STATS: std::cell::Cell<MarkStats> =
        const { std::cell::Cell::new(MarkStats { calls: 0, gate_skips: 0, perpattern_work: 0 }) };
}

#[inline]
pub(crate) fn record_mark_call() {
    #[cfg(test)]
    MARK_STATS.with(|stats| {
        let mut snapshot = stats.get();
        snapshot.calls += 1;
        stats.set(snapshot);
    });
    #[cfg(not(test))]
    MARK_CALLS.fetch_add(1, Relaxed);
}

#[inline]
pub(crate) fn record_mark_gate_skip() {
    #[cfg(test)]
    MARK_STATS.with(|stats| {
        let mut snapshot = stats.get();
        snapshot.gate_skips += 1;
        stats.set(snapshot);
    });
    #[cfg(not(test))]
    MARK_GATE_SKIPS.fetch_add(1, Relaxed);
}

#[inline]
pub(crate) fn record_mark_perpattern_work() {
    #[cfg(test)]
    MARK_STATS.with(|stats| {
        let mut snapshot = stats.get();
        snapshot.perpattern_work += 1;
        stats.set(snapshot);
    });
    #[cfg(not(test))]
    MARK_PERPATTERN_WORK.fetch_add(1, Relaxed);
}

/// Snapshot `(calls, gate_skips, perpattern_work)` of the no-candidate fast-path
/// counters without resetting them. The SWE-101 regression test reads a delta
/// across a scan to assert that a no-candidate chunk did zero per-pattern work.
#[cfg(test)]
pub(crate) fn phase2_mark_stats() -> (u64, u64, u64) {
    MARK_STATS.with(|stats| {
        let snapshot = stats.get();
        (
            snapshot.calls,
            snapshot.gate_skips,
            snapshot.perpattern_work,
        )
    })
}

/// Reset the no-candidate fast-path counters to zero for test isolation.
#[cfg(test)]
pub(crate) fn phase2_mark_stats_reset() {
    MARK_STATS.with(|stats| stats.set(MarkStats::default()));
}

/// Reset the no-candidate fast-path counters to zero between explicit
/// profiling runs.
#[cfg(not(test))]
pub(crate) fn phase2_mark_stats_reset() {
    MARK_CALLS.store(0, Relaxed);
    MARK_GATE_SKIPS.store(0, Relaxed);
    MARK_PERPATTERN_WORK.store(0, Relaxed);
}
