//! Phase-2 post-process PROFILERS (measurement only), extracted
//! from `scan_postprocess.rs` (Law 5). Confirmed-pass per-pattern timing, the
//! ML batch-size histogram, and decode-recursion counters. The recorder fns +
//! `DECODE_*` counters are `pub(crate)` because the post-process impl (still in
//! `scan_postprocess.rs`) pokes them inline as it measures; the dumps stay on
//! the public interface, re-exported through `scan_postprocess`. Pure move.
use std::sync::atomic::AtomicU64;
#[cfg(any(feature = "decode", feature = "ml"))]
use std::sync::atomic::Ordering::Relaxed;
use std::sync::OnceLock;

/// Per-pattern confirmed-pass profiler (measurement only). Enabled by
/// `keyhog scan --profile` to accumulate, per (ac_map ∪ fallback) index, the wall
/// time its whole-chunk extract costs and how many chunks it ran on. Zero-cost
/// when unset.
pub(crate) fn confirmed_prof_enabled() -> bool {
    super::profile::enabled()
}
static CONFIRMED_PAT_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static CONFIRMED_PAT_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

pub(crate) fn confirmed_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = CONFIRMED_PAT_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = CONFIRMED_PAT_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

pub(crate) fn confirmed_prof_reset(len: usize) {
    let (ns, runs) = confirmed_prof_vecs(len);
    for n in ns {
        n.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    for r in runs {
        r.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// ML batch-size histogram. Buckets the `ml_pending.len()` seen at each
/// [`CompiledScanner::apply_ml_batch_scores`] call so we can measure how far
/// per-(sub)chunk ML batches sit from the GPU MoE 64-candidate dispatch threshold
/// — the data that decides whether cross-(sub)chunk batch unification is worth
/// the recall-exactness cost. Zero-cost when unset.
///
/// Gated by the unified scanner profile switch (the histogram is dumped as
/// part of [`super::profile::dump`]).
#[cfg(feature = "ml")]
pub(crate) fn ml_batch_prof_enabled() -> bool {
    super::profile::enabled()
}
#[cfg(feature = "ml")]
static ML_BATCH_BUCKETS: [AtomicU64; 10] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
#[cfg(feature = "ml")]
static ML_BATCH_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ml")]
static ML_BATCH_CANDIDATES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ml")]
static ML_BATCH_CALLS_GE64: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ml")]
static ML_BATCH_CANDIDATES_GE64: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "ml")]
fn ml_batch_bucket(n: usize) -> usize {
    match n {
        0 => 0,
        1 => 1,
        2..=7 => 2,
        8..=15 => 3,
        16..=31 => 4,
        32..=63 => 5,
        64..=127 => 6,
        128..=255 => 7,
        256..=1023 => 8,
        _ => 9,
    }
}

/// Record one `apply_ml_batch_scores` call's pending-candidate count.
#[cfg(feature = "ml")]
pub(crate) fn ml_batch_record(n: usize) {
    ML_BATCH_BUCKETS[ml_batch_bucket(n)].fetch_add(1, Relaxed);
    ML_BATCH_CALLS.fetch_add(1, Relaxed);
    ML_BATCH_CANDIDATES.fetch_add(n as u64, Relaxed);
    if n >= 64 {
        ML_BATCH_CALLS_GE64.fetch_add(1, Relaxed);
        ML_BATCH_CANDIDATES_GE64.fetch_add(n as u64, Relaxed);
    }
}

/// Print + reset the ML batch-size histogram. Folded into the unified profiler:
/// called from [`super::profile::dump`] (early-returns when no data was recorded).
#[cfg(feature = "ml")]
pub(crate) fn ml_batch_profile_dump() {
    let calls = ML_BATCH_CALLS.swap(0, Relaxed);
    let cands = ML_BATCH_CANDIDATES.swap(0, Relaxed);
    let calls_ge64 = ML_BATCH_CALLS_GE64.swap(0, Relaxed);
    let cands_ge64 = ML_BATCH_CANDIDATES_GE64.swap(0, Relaxed);
    let buckets: [u64; 10] = std::array::from_fn(|i| ML_BATCH_BUCKETS[i].swap(0, Relaxed));
    if calls == 0 {
        return;
    }
    let names = [
        "0", "1", "2-7", "8-15", "16-31", "32-63", "64-127", "128-255", "256-1023", "1024+",
    ];
    eprintln!(
        "=== ML batch-size histogram: calls={calls} candidates={cands} (avg {:.1}/call) | \
GPU-eligible (>=64): {calls_ge64} calls ({:.1}%), {cands_ge64} candidates ({:.1}% of all ML work) ===",
        cands as f64 / calls as f64,
        100.0 * calls_ge64 as f64 / calls as f64,
        100.0 * cands_ge64 as f64 / cands.max(1) as f64,
    );
    for i in 0..10 {
        eprintln!("  {:>9}: {}", names[i], buckets[i]);
    }
}

#[cfg(feature = "ml")]
pub(crate) fn ml_batch_profile_reset() {
    for bucket in &ML_BATCH_BUCKETS {
        bucket.store(0, Relaxed);
    }
    ML_BATCH_CALLS.store(0, Relaxed);
    ML_BATCH_CANDIDATES.store(0, Relaxed);
    ML_BATCH_CALLS_GE64.store(0, Relaxed);
    ML_BATCH_CANDIDATES_GE64.store(0, Relaxed);
}

#[cfg(not(feature = "ml"))]
pub(crate) fn ml_batch_profile_dump() {}

#[cfg(not(feature = "ml"))]
pub(crate) fn ml_batch_profile_reset() {}

/// Decode-recursion profiler (measurement only). Use `keyhog scan --profile` to
/// accumulate, across a full scan, how many parent
/// chunks entered decode-through, how many decoded sub-chunks were produced and
/// rescanned, their total byte volume, the wall time spent generating them
/// (`decode_chunk`) and the wall time spent rescanning them (`scan_inner` /
/// `scan_windowed`). This is the lever behind the ~0.4 MB/s end-to-end ceiling:
/// the per-sub-chunk fixed phase-2 cost (prefilter) is paid once per
/// decoded sub-chunk, so the sub-chunk COUNT is what dominates. Zero-cost when
/// unset. Dump+reset with [`decode_profile_dump`].
#[cfg(feature = "decode")]
pub(crate) fn decode_prof_enabled() -> bool {
    super::profile::enabled()
}
#[cfg(feature = "decode")]
pub(crate) static DECODE_PARENTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "decode")]
pub(crate) static DECODE_SUBCHUNKS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "decode")]
pub(crate) static DECODE_SUBCHUNK_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "decode")]
pub(crate) static DECODE_GEN_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "decode")]
pub(crate) static DECODE_SCAN_NS: AtomicU64 = AtomicU64::new(0);

/// Print and reset the accumulated decode-recursion counters. Call after a
/// explicit profile run. Returns `(parents, subchunks, bytes, gen_ms,
/// scan_ms)` so a measurement test can assert on it.
#[cfg(feature = "decode")]
pub(crate) fn decode_profile_dump() -> (u64, u64, u64, f64, f64) {
    let parents = DECODE_PARENTS.swap(0, Relaxed);
    let subchunks = DECODE_SUBCHUNKS.swap(0, Relaxed);
    let bytes = DECODE_SUBCHUNK_BYTES.swap(0, Relaxed);
    let gen_ms = DECODE_GEN_NS.swap(0, Relaxed) as f64 / 1e6;
    let scan_ms = DECODE_SCAN_NS.swap(0, Relaxed) as f64 / 1e6;
    if parents == 0 && subchunks == 0 && bytes == 0 && gen_ms == 0.0 && scan_ms == 0.0 {
        return (parents, subchunks, bytes, gen_ms, scan_ms);
    }
    eprintln!(
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
    );
    (parents, subchunks, bytes, gen_ms, scan_ms)
}

#[cfg(feature = "decode")]
pub(crate) fn decode_profile_reset() {
    DECODE_PARENTS.store(0, Relaxed);
    DECODE_SUBCHUNKS.store(0, Relaxed);
    DECODE_SUBCHUNK_BYTES.store(0, Relaxed);
    DECODE_GEN_NS.store(0, Relaxed);
    DECODE_SCAN_NS.store(0, Relaxed);
}

#[cfg(not(feature = "decode"))]
pub(crate) fn decode_profile_dump() -> (u64, u64, u64, f64, f64) {
    (0, 0, 0, 0.0, 0.0)
}

#[cfg(not(feature = "decode"))]
pub(crate) fn decode_profile_reset() {}
