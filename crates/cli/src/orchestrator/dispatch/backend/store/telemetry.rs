//! Process-wide accounting for autoroute cache lookups.
//!
//! Every batch that reaches automatic routing asks the persisted cache exactly
//! one question: does this exact workload bucket have a proved route for this
//! binary, host, detector corpus and resolved scan config. Before this module
//! existed the answer was unobservable. A scan reported recovery *events*, so
//! an operator could tell that some batches missed, but never how many asked,
//! never what fraction were answered, and never which of the several distinct
//! reasons a lookup failed. "Is the cache earning its keep" was unanswerable.
//!
//! The counters here are pure observation. They never participate in route
//! selection, and a miss stays a miss: nothing in this file substitutes a
//! backend.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::super::workload::{render_workload_key, WorkloadKey};

/// Why one autoroute cache lookup could not be answered from persisted evidence.
///
/// These are ordered from "the cache was never usable" to "the cache was usable
/// and this exact bucket was not in it", because that is the order an operator
/// has to fix them in. Repairing a rejected cache first is pointless if no
/// cache path is configured at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum AutorouteCacheMiss {
    /// No autoroute cache path resolved for this scan.
    NoCacheConfigured,
    /// The cache file was rejected whole before any bucket lookup: unreadable,
    /// unparseable, or bound to a different build, host, corpus or config.
    CacheRejected,
    /// The batch could not be classified, so it has no bucket to look up.
    WorkloadUnclassified,
    /// The cache loaded, but this exact bucket was never calibrated.
    BucketAbsent,
    /// The bucket exists and carries no route proved for this runtime class.
    RuntimeClassUnproved,
    /// The bucket's route was quarantined by a runtime fault.
    RouteQuarantined,
    /// Route-health state could not be read, so no persisted route is trusted.
    HealthUnavailable,
    /// The persisted GPU route's peer no longer matches the acquired device.
    PeerIdentityChanged,
}

impl AutorouteCacheMiss {
    pub(crate) const ALL: [Self; 8] = [
        Self::NoCacheConfigured,
        Self::CacheRejected,
        Self::WorkloadUnclassified,
        Self::BucketAbsent,
        Self::RuntimeClassUnproved,
        Self::RouteQuarantined,
        Self::HealthUnavailable,
        Self::PeerIdentityChanged,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NoCacheConfigured => "no-cache-configured",
            Self::CacheRejected => "cache-rejected",
            Self::WorkloadUnclassified => "workload-unclassified",
            Self::BucketAbsent => "bucket-absent",
            Self::RuntimeClassUnproved => "runtime-class-unproved",
            Self::RouteQuarantined => "route-quarantined",
            Self::HealthUnavailable => "route-health-unavailable",
            Self::PeerIdentityChanged => "gpu-peer-identity-changed",
        }
    }

    /// The one action that fixes this cause.
    ///
    /// Every miss used to point at `keyhog calibrate-autoroute`, which is the
    /// wrong answer for most of them: recalibrating cannot help when the cache
    /// is rejected wholesale, when no cache path is configured, or when a batch
    /// could not be classified at all.
    pub(crate) fn repair(self) -> &'static str {
        match self {
            Self::NoCacheConfigured => {
                "configure an autoroute cache with --autoroute-cache <path>, then calibrate it"
            }
            Self::CacheRejected => {
                "the cache belongs to a different build, host, detector corpus or scan config; \
                 recalibrate this exact configuration (recalibrating one bucket will not help)"
            }
            Self::WorkloadUnclassified => {
                "report the batch shape; autoroute cannot bucket it, so no calibration can cover it"
            }
            Self::BucketAbsent | Self::RuntimeClassUnproved => {
                "rerun this same scan once with --autoroute-calibrate --autoroute-gpu to cover \
                 every bucket listed above, or run keyhog calibrate-autoroute for the core ladder"
            }
            Self::RouteQuarantined => {
                "a persisted route faulted at runtime and was quarantined; recalibrate after \
                 fixing the fault reported with the quarantine"
            }
            Self::HealthUnavailable => {
                "restart KeyHog, then run keyhog calibrate-autoroute; route-health state could \
                 not be read"
            }
            Self::PeerIdentityChanged => {
                "the GPU peer changed since calibration; recalibrate on the current device"
            }
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        &MISSES[self as usize]
    }
}

static HITS: AtomicU64 = AtomicU64::new(0);
static CALIBRATION_REUSES: AtomicU64 = AtomicU64::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
static MISSES: [AtomicU64; AutorouteCacheMiss::ALL.len()] = [ZERO; AutorouteCacheMiss::ALL.len()];

/// Distinct uncalibrated buckets seen this run, with how many batches each cost.
///
/// A scan announces its autoroute recovery once, so an operator used to learn
/// about exactly one missing bucket no matter how many distinct ones a corpus
/// produced. They would recalibrate, miss a different bucket, and conclude the
/// cache does not work. Collecting the full set turns an unbounded number of
/// repair cycles into one.
static MISSING_BUCKETS: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());
/// Distinct buckets dropped once the ledger hit its cap, so the report can say
/// so rather than quietly under-counting.
static MISSING_BUCKETS_ELIDED: AtomicUsize = AtomicUsize::new(0);

/// Enough distinct buckets to plan one recalibration, few enough that a
/// pathological corpus cannot grow this ledger without bound.
const MAX_TRACKED_MISSING_BUCKETS: usize = 64;

/// One consultation answered from persisted evidence.
///
/// Every outcome is mirrored into the profiler's canonical cache family, so
/// `--profile` reports autoroute decision reuse through the same
/// hit/miss/rate machinery as every other cache. The counters here stay
/// unconditional because operator-visible autoroute status must not depend on
/// whether profiling was requested.
pub(crate) fn record_hit() {
    HITS.fetch_add(1, Ordering::Relaxed);
    keyhog_profile::record_cache_hit(keyhog_profile::CacheId::AutorouteDecision);
}

/// A calibration run answered a bucket from evidence it already holds instead
/// of benchmarking it again. This is deliberately NOT a normal-scan hit: it
/// keeps the hit rate meaning exactly "a scan consumed a persisted decision".
pub(crate) fn record_calibration_reuse() {
    CALIBRATION_REUSES.fetch_add(1, Ordering::Relaxed);
    keyhog_profile::record_cache_hit(keyhog_profile::CacheId::AutorouteCalibration);
}

pub(crate) fn record_miss(cause: AutorouteCacheMiss) {
    cause.counter().fetch_add(1, Ordering::Relaxed);
    keyhog_profile::record_cache_miss(keyhog_profile::CacheId::AutorouteDecision);
}

/// Record a miss that names an exact uncalibrated bucket.
///
/// The rendered key is the same text the fail-closed routing error prints, so
/// an operator can match a summary line to a refused workload field for field.
pub(crate) fn record_bucket_miss(cause: AutorouteCacheMiss, key: &WorkloadKey) {
    record_miss(cause);
    // LAW10: a poisoned ledger loses diagnostics only; it must never change
    // routing, so the miss above is already counted and this returns quietly.
    let Ok(mut buckets) = MISSING_BUCKETS.lock() else {
        return;
    };
    if buckets.len() >= MAX_TRACKED_MISSING_BUCKETS {
        let rendered = render_workload_key(key);
        match buckets.get_mut(&rendered) {
            Some(count) => *count += 1,
            None => {
                MISSING_BUCKETS_ELIDED.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    }
    *buckets.entry(render_workload_key(key)).or_insert(0) += 1;
}

/// One process's complete autoroute cache lookup record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AutorouteCacheStats {
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) by_cause: Vec<(AutorouteCacheMiss, u64)>,
    pub(crate) missing_buckets: Vec<(String, usize)>,
    pub(crate) missing_buckets_elided: usize,
}

impl AutorouteCacheStats {
    pub(crate) fn lookups(&self) -> u64 {
        self.hits + self.misses
    }

    /// Hit rate in percent, or `None` when nothing asked the cache anything.
    /// An empty scan has no hit rate, and reporting 0% for it would be a lie.
    pub(crate) fn hit_rate_percent(&self) -> Option<f64> {
        let lookups = self.lookups();
        (lookups > 0).then(|| (self.hits as f64) * 100.0 / (lookups as f64))
    }

    /// The dominant miss cause, which is the one an operator should fix first.
    pub(crate) fn primary_cause(&self) -> Option<AutorouteCacheMiss> {
        self.by_cause
            .iter()
            .max_by_key(|(cause, count)| (*count, std::cmp::Reverse(*cause)))
            .map(|(cause, _)| *cause)
    }
}

pub(crate) fn snapshot() -> AutorouteCacheStats {
    let by_cause: Vec<(AutorouteCacheMiss, u64)> = AutorouteCacheMiss::ALL
        .into_iter()
        .filter_map(|cause| {
            let count = cause.counter().load(Ordering::Relaxed);
            (count > 0).then_some((cause, count))
        })
        .collect();
    let missing_buckets = MISSING_BUCKETS
        .lock()
        .map(|buckets| {
            buckets
                .iter()
                .map(|(key, count)| (key.clone(), *count))
                .collect()
        })
        // LAW10: a poisoned diagnostic ledger reports no buckets rather than
        // blocking the summary that carries the counted miss total.
        .unwrap_or_default();
    AutorouteCacheStats {
        hits: HITS.load(Ordering::Relaxed),
        misses: by_cause.iter().map(|(_, count)| *count).sum(),
        by_cause,
        missing_buckets,
        missing_buckets_elided: MISSING_BUCKETS_ELIDED.load(Ordering::Relaxed),
    }
}

/// One operator-visible line describing what the cache did this scan.
///
/// Returns `None` only when no batch ever consulted the cache, which is the one
/// case where there is nothing true to say.
pub(crate) fn render_summary(stats: &AutorouteCacheStats) -> Option<String> {
    let rate = stats.hit_rate_percent()?;
    let mut line = format!(
        "autoroute cache: {:.1}% hit ({} hit / {} lookup(s))",
        rate,
        stats.hits,
        stats.lookups()
    );
    if stats.misses > 0 {
        // This line sits next to coverage-gap rows that use the same WARN
        // label, and the two mean opposite things. A cache miss costs speed and
        // nothing else: every byte still gets scanned, through scalar
        // correctness recovery. Say so in the text, because a reader taught to
        // treat a stderr warning as an incomplete scan will otherwise read it
        // as one.
        line.push_str("; every byte was still scanned, this costs speed not coverage");
        let causes = stats
            .by_cause
            .iter()
            .map(|(cause, count)| format!("{}={count}", cause.label()))
            .collect::<Vec<_>>()
            .join(" ");
        line.push_str(&format!("; miss causes: {causes}"));
        let distinct = stats.missing_buckets.len();
        if distinct > 0 {
            line.push_str(&format!(
                "; {distinct} distinct uncalibrated bucket(s){}",
                if stats.missing_buckets_elided > 0 {
                    format!(" (+{} not listed)", stats.missing_buckets_elided)
                } else {
                    String::new()
                }
            ));
        }
        if let Some(cause) = stats.primary_cause() {
            line.push_str(&format!("; repair: {}", cause.repair()));
        }
    }
    Some(line)
}

/// Every distinct uncalibrated bucket, most expensive first, so one
/// recalibration can be planned to cover all of them.
pub(crate) fn render_missing_buckets(stats: &AutorouteCacheStats) -> Vec<String> {
    let mut ordered: Vec<&(String, usize)> = stats.missing_buckets.iter().collect();
    ordered.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ordered
        .into_iter()
        .map(|(key, count)| format!("{count} batch(es): {key}"))
        .collect()
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    HITS.store(0, Ordering::Relaxed);
    CALIBRATION_REUSES.store(0, Ordering::Relaxed);
    for cause in AutorouteCacheMiss::ALL {
        cause.counter().store(0, Ordering::Relaxed);
    }
    MISSING_BUCKETS_ELIDED.store(0, Ordering::Relaxed);
    if let Ok(mut buckets) = MISSING_BUCKETS.lock() {
        // LAW10: test-only telemetry reset tolerates a poisoned metric lock; production routing and findings are untouched.
        buckets.clear();
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/autoroute_telemetry.rs"]
mod tests;
