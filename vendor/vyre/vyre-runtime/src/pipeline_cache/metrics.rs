//! Pipeline-cache instrumentation: the public snapshot type and the
//! internal atomic counter struct shared by every concrete backend.

use std::sync::atomic::{AtomicU64, Ordering};

use vyre_driver::accounting::{checked_add_u64_lazy, checked_mul_u64_lazy};

/// Pipeline-cache instrumentation counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineCacheMetrics {
    /// Lookup attempts.
    pub lookups: u64,
    /// Successful lookups.
    pub hits: u64,
    /// Failed lookups.
    pub misses: u64,
    /// Accepted put attempts.
    pub puts: u64,
    /// Rejected put attempts, usually because a blob exceeds the byte budget.
    pub rejected_puts: u64,
    /// Entries evicted by capacity or byte-budget pressure.
    pub evictions: u64,
    /// Bytes removed by eviction.
    pub evicted_bytes: u64,
    /// Explicit flush attempts.
    pub flushes: u64,
    /// Explicit flush failures.
    pub flush_errors: u64,
    /// Current retained bytes when the backend can report them cheaply.
    pub cached_bytes: u64,
    /// Current retained entries when the backend can report them cheaply.
    pub entries: u64,
}

impl PipelineCacheMetrics {
    /// Cache-hit rate in parts per million.
    #[must_use]
    pub fn hit_rate_ppm(&self) -> u32 {
        if self.lookups == 0 {
            return 0;
        }
        let numerator = checked_mul_u64_lazy(self.hits, 1_000_000, || {
            "pipeline cache hit-rate numerator overflowed u64. Fix: reset cache metrics before counters wrap."
        })
        .unwrap_or_else(|message| panic!("{message}"));
        let value = numerator / self.lookups;
        if value > u64::from(u32::MAX) {
            panic!("pipeline cache hit-rate ppm cannot fit u32. Fix: reset cache metrics before counters wrap.");
        }
        u32::try_from(value).unwrap_or_else(|source| {
            panic!(
                "pipeline cache hit-rate ppm cannot fit u32 after range check: {source}. Fix: reset cache metrics before counters wrap."
            )
        })
    }

    pub(super) fn checked_add(self, rhs: Self) -> Self {
        Self {
            lookups: checked_metric_add(self.lookups, rhs.lookups, "lookups"),
            hits: checked_metric_add(self.hits, rhs.hits, "hits"),
            misses: checked_metric_add(self.misses, rhs.misses, "misses"),
            puts: checked_metric_add(self.puts, rhs.puts, "puts"),
            rejected_puts: checked_metric_add(
                self.rejected_puts,
                rhs.rejected_puts,
                "rejected puts",
            ),
            evictions: checked_metric_add(self.evictions, rhs.evictions, "evictions"),
            evicted_bytes: checked_metric_add(
                self.evicted_bytes,
                rhs.evicted_bytes,
                "evicted bytes",
            ),
            flushes: checked_metric_add(self.flushes, rhs.flushes, "flushes"),
            flush_errors: checked_metric_add(self.flush_errors, rhs.flush_errors, "flush errors"),
            cached_bytes: checked_metric_add(self.cached_bytes, rhs.cached_bytes, "cached bytes"),
            entries: checked_metric_add(self.entries, rhs.entries, "entries"),
        }
    }
}

fn checked_metric_add(lhs: u64, rhs: u64, label: &'static str) -> u64 {
    checked_add_u64_lazy(lhs, rhs, || {
        format!(
            "pipeline cache metric {label} overflowed u64. Fix: reset or shard pipeline cache metrics before aggregation."
        )
    })
    .unwrap_or_else(|message| panic!("{message}"))
}

#[derive(Debug, Default)]
pub(super) struct PipelineCacheCounters {
    pub(super) lookups: AtomicU64,
    pub(super) hits: AtomicU64,
    pub(super) misses: AtomicU64,
    pub(super) puts: AtomicU64,
    pub(super) rejected_puts: AtomicU64,
    pub(super) evictions: AtomicU64,
    pub(super) evicted_bytes: AtomicU64,
    pub(super) flushes: AtomicU64,
    pub(super) flush_errors: AtomicU64,
}

impl PipelineCacheCounters {
    pub(super) fn increment(counter: &AtomicU64, label: &'static str) {
        Self::add(counter, 1, label);
    }

    pub(super) fn add(counter: &AtomicU64, value: u64, label: &'static str) {
        vyre_driver::accounting::checked_atomic_add_u64_with_order(
            counter,
            value,
            Ordering::Relaxed,
            Ordering::Relaxed,
            Ordering::Relaxed,
            |_, _| {
                format!(
                    "pipeline cache counter {label} overflowed u64. Fix: reset cache metrics before counters wrap."
                )
            },
        )
        .unwrap_or_else(|message| panic!("{message}"));
    }

    pub(super) fn snapshot(&self, cached_bytes: u64, entries: u64) -> PipelineCacheMetrics {
        PipelineCacheMetrics {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            puts: self.puts.load(Ordering::Relaxed),
            rejected_puts: self.rejected_puts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            evicted_bytes: self.evicted_bytes.load(Ordering::Relaxed),
            flushes: self.flushes.load(Ordering::Relaxed),
            flush_errors: self.flush_errors.load(Ordering::Relaxed),
            cached_bytes,
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::{PipelineCacheCounters, PipelineCacheMetrics};

    #[test]
    fn pipeline_cache_metrics_generated_hit_rates_are_exact_ppm() {
        for hits in 0..=1024_u64 {
            let metrics = PipelineCacheMetrics {
                lookups: 2048,
                hits,
                ..PipelineCacheMetrics::default()
            };
            assert_eq!(metrics.hit_rate_ppm(), ((hits * 1_000_000) / 2048) as u32);
        }
    }

    #[test]
    #[should_panic(expected = "pipeline cache metric cached bytes overflowed u64")]
    fn pipeline_cache_metric_aggregation_rejects_overflow() {
        let lhs = PipelineCacheMetrics {
            cached_bytes: u64::MAX,
            ..PipelineCacheMetrics::default()
        };
        let rhs = PipelineCacheMetrics {
            cached_bytes: 1,
            ..PipelineCacheMetrics::default()
        };

        let _ = lhs.checked_add(rhs);
    }

    #[test]
    fn pipeline_cache_counter_add_uses_checked_shared_arithmetic() {
        let counter = AtomicU64::new(41);

        PipelineCacheCounters::add(&counter, 1, "generated counter");

        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 42);
    }
}
