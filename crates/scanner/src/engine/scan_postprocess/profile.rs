//! Phase-2 post-process PROFILERS (measurement only), extracted
//! from `scan_postprocess.rs` (Law 5). The confirmed-pass per-pattern timing
//! table stays scanner-owned (the profile registry has no per-pattern labeled
//! metric API); the ML batch metrics and decode-recursion counts record
//! through the keyhog-profile runtime's typed counters and batch-size
//! distribution, and this module keeps only the pure snapshot/format helpers
//! the unified profiler renders after one typed drain.
use std::sync::atomic::AtomicU64;
// One `Relaxed` reference for the whole module: the always-compiled
// confirmed-pass counters use it too, so the import is unconditional (no cfg
// gate) and every atomic op spells the ordering the same way.
use std::sync::atomic::Ordering::Relaxed;
use std::sync::OnceLock;
use std::time::Duration;

/// Per-pattern confirmed-pass profiler (measurement only). Enabled by
/// `keyhog scan --profile` to accumulate, per (ac_map ∪ fallback) index, the wall
/// time its whole-chunk extract costs and how many chunks it ran on. Zero-cost
/// when unset.
pub(crate) fn confirmed_prof_enabled() -> bool {
    super::profile::enabled()
}
static CONFIRMED_PAT_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static CONFIRMED_PAT_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static CONFIRMED_STAGE_NS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static CONFIRMED_STAGE_RUNS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[derive(Clone, Copy)]
pub(crate) enum ConfirmedStage {
    SuffixGate = 0,
    AnchorCollect = 1,
    Extract = 2,
    CompanionGate = 3,
}

pub(crate) fn confirmed_prof_record(stage: ConfirmedStage, elapsed: Duration) {
    let idx = stage as usize;
    CONFIRMED_STAGE_NS[idx].fetch_add(elapsed.as_nanos() as u64, Relaxed);
    CONFIRMED_STAGE_RUNS[idx].fetch_add(1, Relaxed);
}

pub(crate) fn confirmed_prof_stage_take() -> [(u64, u64); 4] {
    std::array::from_fn(|idx| {
        (
            CONFIRMED_STAGE_NS[idx].swap(0, Relaxed),
            CONFIRMED_STAGE_RUNS[idx].swap(0, Relaxed),
        )
    })
}

pub(crate) fn confirmed_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = CONFIRMED_PAT_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = CONFIRMED_PAT_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

pub(crate) fn confirmed_prof_reset(len: usize) {
    let (ns, runs) = confirmed_prof_vecs(len);
    for n in ns {
        n.store(0, Relaxed);
    }
    for r in runs {
        r.store(0, Relaxed);
    }
    for n in &CONFIRMED_STAGE_NS {
        n.store(0, Relaxed);
    }
    for r in &CONFIRMED_STAGE_RUNS {
        r.store(0, Relaxed);
    }
}

impl super::CompiledScanner {
    /// Print and reset the per-pattern confirmed-pass profile (top 30 by time).
    pub(crate) fn confirmed_profile_dump(&self, label: &str) {
        // The tables are process-global and sized by whichever scanner asked
        // first, which is not always this one (a probe scanner with a single
        // pattern warms the GPU before the real corpus compiles). Recording
        // already drops out-of-range indices, so the dump reads exactly the
        // rows that exist instead of indexing past them.
        let total = self.ac_map.len() + self.phase2_patterns.len();
        let (ns, runs) = confirmed_prof_vecs(total);
        let mut rows: Vec<(usize, u64, u64)> = (0..total.min(ns.len()).min(runs.len()))
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        eprintln!(
            "=== CONFIRMED per-pattern [{label}] total={:.1} ms over {} triggered patterns ===",
            grand as f64 / 1e6,
            rows.len()
        );
        let stages = confirmed_prof_stage_take();
        let stage_total: u64 = stages.iter().map(|(ns, _)| *ns).sum();
        if stage_total > 0 {
            let labels = ["suffix-gate", "anchor-collect", "extract", "companion-gate"];
            eprintln!(
                "=== CONFIRMED stages [{label}] total={:.1} ms ===",
                stage_total as f64 / 1e6
            );
            for (idx, name) in labels.iter().enumerate() {
                let (ns, runs) = stages[idx];
                if ns == 0 {
                    continue;
                }
                let per = if runs > 0 { ns / runs } else { 0 };
                eprintln!(
                    "  {:<15} {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run",
                    name,
                    ns as f64 / 1e6,
                    100.0 * ns as f64 / stage_total.max(1) as f64,
                    runs,
                    per
                );
            }
        }
        for (i, n, r) in rows.iter().take(30) {
            let src = if *i < self.ac_map.len() {
                self.ac_map[*i].regex.as_str()
            } else {
                self.phase2_patterns[*i - self.ac_map.len()]
                    .0
                    .regex
                    .as_str()
            };
            let per = if *r > 0 { *n / *r } else { 0 };
            let s: String = src.chars().take(60).collect();
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per,
                s
            );
        }
    }

    pub(crate) fn confirmed_profile_reset(&self) {
        confirmed_prof_reset(self.ac_map.len() + self.phase2_patterns.len());
    }
}

/// ML batch-size metrics. Records the actual batch submitted by the
/// single-chunk or coalesced CPU scorer so parallel-threshold engagement and
/// remaining sparse windowed work stay measurable. The keyhog-profile runtime
/// owns every figure: totals are typed counters and the batch-size histogram is
/// the runtime's bounded log-scale distribution (`MetricId::MlBatchSize`),
/// drained once per [`super::profile::dump`]. Recording is a no-op when no
/// profile runtime is active.
#[cfg(feature = "ml")]
use keyhog_profile::{CounterId, MetricId};

/// All ML batch figures drained from one typed-metric batch plus the
/// batch-size distribution buckets as `(lower_bound, upper_bound, count)`.
#[cfg(feature = "ml")]
pub(crate) struct MlBatchProfile {
    pub calls: u64,
    pub candidates: u64,
    pub calls_ge64: u64,
    pub candidates_ge64: u64,
    pub buckets: Vec<(u64, u64, u64)>,
}

/// Record one `apply_ml_batch_scores` call's pending-candidate count.
#[cfg(feature = "ml")]
pub(crate) fn ml_batch_record(n: usize) {
    keyhog_profile::add_counter(CounterId::MlBatchCalls, 1);
    keyhog_profile::add_counter(CounterId::MlBatchCandidates, n as u64);
    if n >= 64 {
        keyhog_profile::add_counter(CounterId::MlBatchCallsGe64, 1);
        keyhog_profile::add_counter(CounterId::MlBatchCandidatesGe64, n as u64);
    }
    keyhog_profile::record_distribution(MetricId::MlBatchSize, n as u64);
}

/// Build the ML batch figures from one drained typed-metric batch and one
/// drained distribution batch. Missing counters read as zero.
#[cfg(feature = "ml")]
pub(crate) fn ml_batch_profile_from_parts(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
    distributions: &[keyhog_profile::MetricDistributionV2],
) -> MlBatchProfile {
    let value = |counter: CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    let buckets = distributions
        .iter()
        .find(|distribution| distribution.metric_id == MetricId::MlBatchSize)
        .map(|distribution| {
            distribution
                .buckets
                .iter()
                .map(|bucket| (bucket.lower_bound, bucket.upper_bound, bucket.count))
                .collect()
        })
        // LAW10: an absent optional ML distribution is represented by zero buckets; scan counters remain intact.
        .unwrap_or_default();
    MlBatchProfile {
        calls: value(CounterId::MlBatchCalls),
        candidates: value(CounterId::MlBatchCandidates),
        calls_ge64: value(CounterId::MlBatchCallsGe64),
        candidates_ge64: value(CounterId::MlBatchCandidatesGe64),
        buckets,
    }
}

/// Render the ML batch-size lines the unified profiler prints (headline plus
/// one line per non-empty distribution bucket). Pure (no I/O) so the
/// formatting is unit-testable.
#[cfg(feature = "ml")]
pub(crate) fn format_ml_batch_profile(p: &MlBatchProfile) -> String {
    let mut out = format!(
        "=== ML batch-size histogram: calls={} candidates={} (avg {:.1}/call) | \
CPU-parallel (>=64): {} calls ({:.1}%), {} candidates ({:.1}% of all ML work) ===",
        p.calls,
        p.candidates,
        p.candidates as f64 / p.calls.max(1) as f64,
        p.calls_ge64,
        100.0 * p.calls_ge64 as f64 / p.calls.max(1) as f64,
        p.candidates_ge64,
        100.0 * p.candidates_ge64 as f64 / p.candidates.max(1) as f64,
    );
    for (lower, upper, count) in &p.buckets {
        let label = if lower == upper {
            format!("{lower}")
        } else {
            format!("{lower}-{upper}")
        };
        out.push_str(&format!("\n  {label:>9}: {count}"));
    }
    out
}

/// Decode-recursion accounting (measurement only). Use `keyhog scan --profile`
/// to accumulate, across a full scan, how many parent
/// chunks entered decode-through, how many decoded sub-chunks were produced and
/// rescanned, and their total byte volume. The keyhog-profile runtime owns all
/// of it: the counts/bytes are typed counters, generation wall time is the
/// `Decode` stage span, and rescan wall time is the decode-attributed share of
/// every leaf span, all drained once per [`super::profile::dump`]. This is the
/// lever behind the ~0.4 MB/s end-to-end ceiling:
/// the per-sub-chunk fixed phase-2 cost (prefilter) is paid once per
/// decoded sub-chunk, so the sub-chunk COUNT is what dominates. Recording is a
/// no-op when no profile runtime is active.
/// Build the decode-recursion counts from one drained typed-metric batch.
/// Missing counters read as zero.
#[cfg(feature = "decode")]
pub(crate) fn decode_recursion_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> (u64, u64, u64) {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    (
        value(keyhog_profile::CounterId::DecodeParentChunks),
        value(keyhog_profile::CounterId::DecodeDerivedChunks),
        value(keyhog_profile::CounterId::DecodeDerivedBytes),
    )
}

/// Render the one-line decode-recursion diagnostic the unified profiler prints.
/// Pure (no I/O) so the formatting is unit-testable. `gen_ms` is the profile
/// runtime's `Decode` stage total (generation); `scan_ms` is the runtime's
/// decode-attributed leaf total (sub-chunk rescans).
#[cfg(feature = "decode")]
pub(crate) fn format_decode_recursion(
    parents: u64,
    subchunks: u64,
    bytes: u64,
    gen_ms: f64,
    scan_ms: f64,
) -> String {
    format!(
        "decode-recursion: parents={parents} subchunks={subchunks} \
         ({:.1} sub/parent) bytes={bytes} gen={gen_ms:.1}ms scan={scan_ms:.1}ms \
         ({:.2} MB/s rescan)",
        if parents > 0 {
            subchunks as f64 / parents as f64
        } else {
            0.0
        },
        if scan_ms > 0.0 {
            (bytes as f64 / 1e6) / (scan_ms / 1e3)
        } else {
            0.0
        },
    )
}

/// Confirmed candidate confirmation and postprocess timing figures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfirmedPostprocessProfile {
    pub suffix_gate_ns: u64,
    pub suffix_gate_calls: u64,
    pub suffix_gate_skips: u64,
    pub companion_gate_ns: u64,
    pub companion_gate_calls: u64,
    pub companion_gate_denials: u64,
    pub anchor_collect_ns: u64,
    pub anchor_collect_calls: u64,
    pub anchor_candidates: u64,
    pub extract_ns: u64,
    pub extract_calls: u64,
    pub anchored_matches: u64,
    pub whole_chunk_matches: u64,
    pub hot_direct_filter_skips: u64,
    pub fragments_ns: u64,
    pub fragments_calls: u64,
    pub fragments_candidates: u64,
    pub fragments_matches: u64,
    pub dedup_ns: u64,
    pub dedup_calls: u64,
}

impl ConfirmedPostprocessProfile {
    pub fn any_recorded(&self) -> bool {
        *self != Self::default()
    }
}

pub fn confirmed_postprocess_profile_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> ConfirmedPostprocessProfile {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    use keyhog_profile::CounterId;
    ConfirmedPostprocessProfile {
        suffix_gate_ns: value(CounterId::ConfirmedSuffixGateNs),
        suffix_gate_calls: value(CounterId::ConfirmedSuffixGateCalls),
        suffix_gate_skips: value(CounterId::ConfirmedSuffixGateSkips),
        companion_gate_ns: value(CounterId::ConfirmedCompanionGateNs),
        companion_gate_calls: value(CounterId::ConfirmedCompanionGateCalls),
        companion_gate_denials: value(CounterId::ConfirmedCompanionGateDenials),
        anchor_collect_ns: value(CounterId::ConfirmedAnchorCollectNs),
        anchor_collect_calls: value(CounterId::ConfirmedAnchorCollectCalls),
        anchor_candidates: value(CounterId::ConfirmedAnchorCandidateCount),
        extract_ns: value(CounterId::ConfirmedExtractNs),
        extract_calls: value(CounterId::ConfirmedExtractCalls),
        anchored_matches: value(CounterId::ConfirmedAnchoredMatches),
        whole_chunk_matches: value(CounterId::ConfirmedWholeChunkMatches),
        hot_direct_filter_skips: value(CounterId::ConfirmedHotDirectFilterSkips),
        fragments_ns: value(CounterId::PostprocessFragmentsNs),
        fragments_calls: value(CounterId::PostprocessFragmentsCalls),
        fragments_candidates: value(CounterId::PostprocessFragmentsCandidates),
        fragments_matches: value(CounterId::PostprocessFragmentsMatches),
        dedup_ns: value(CounterId::PostprocessDedupNs),
        dedup_calls: value(CounterId::PostprocessDedupCalls),
    }
}

pub fn format_confirmed_postprocess_profile(p: &ConfirmedPostprocessProfile) -> String {
    let sg_ms = p.suffix_gate_ns as f64 / 1e6;
    let cg_ms = p.companion_gate_ns as f64 / 1e6;
    let ac_ms = p.anchor_collect_ns as f64 / 1e6;
    let ex_ms = p.extract_ns as f64 / 1e6;
    let frag_ms = p.fragments_ns as f64 / 1e6;
    let dedup_ms = p.dedup_ns as f64 / 1e6;
    format!(
        "=== CONFIRMED postprocess confirmation profile ===\n  \
         suffix-gate: {sg_ms:.1}ms (calls={} skips={})\n  \
         companion-gate: {cg_ms:.1}ms (calls={} denials={})\n  \
         anchor-collect: {ac_ms:.1}ms (calls={} cands={})\n  \
         extract: {ex_ms:.1}ms (calls={} anchored_matches={} whole_chunk_matches={} direct_skips={})\n  \
         fragments: {frag_ms:.1}ms (calls={} cands={} matches={})\n  \
         dedup: {dedup_ms:.1}ms (calls={})",
        p.suffix_gate_calls, p.suffix_gate_skips,
        p.companion_gate_calls, p.companion_gate_denials,
        p.anchor_collect_calls, p.anchor_candidates,
        p.extract_calls, p.anchored_matches, p.whole_chunk_matches, p.hot_direct_filter_skips,
        p.fragments_calls, p.fragments_candidates, p.fragments_matches,
        p.dedup_calls,
    )
}
