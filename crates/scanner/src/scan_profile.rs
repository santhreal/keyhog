//! Scanner-side view of the profiler: one hierarchical dump over profiler data.
//!
//! No measurement is owned here. The switch is [`keyhog_profile::set_detail`],
//! the clock and the counters are the profile runtime's, and the stage names are
//! [`keyhog_profile::Stage`]'s. This module opens spans on the profiler's behalf
//! and renders the tree the scanner cares about from one drain of profiler
//! state. It used to carry two process-wide `AtomicBool` switches and a second
//! fourteen-name stage vocabulary parallel to `Stage`; both are gone, because a
//! number that drives a decision and a number an operator reads must be the same
//! number.
//!
//! Model: only LEAF stages are timed directly (via the [`span`] RAII guard);
//! parent rows (scan / phase2 / phase2-capture) are SUMS of their leaves in
//! [`dump`].
//! Leaf passes never nest within each other (decode recursion re-enters as fresh
//! leaf recordings that aggregate into the same leaves), so the totals are the
//! elapsed time per pass summed across all rayon workers and all decode depths
//! no double-counting, no per-span stack needed. Accelerator dispatch contributes
//! the host-observed elapsed wait for that pass. Totals can exceed wall-clock
//! because the scan is parallel; read them as proportions.
//!
//! Overhead when off: one cached-bool load per `span()` and a no-op `Drop`; no
//! `Instant::now()` is taken on the hot path.

use keyhog_profile::Stage;
use std::cell::Cell;

/// Leaf stages this dump renders, in print order. Each is a
/// [`keyhog_profile::Stage`] and prints under [`Stage::as_str`], so the scanner
/// keeps no second name for any of them.
const LEAVES: [Stage; 14] = [
    Stage::Preprocess,
    Stage::Phase1Triggers,
    // Accelerator-side trigger preparation and dispatch outside the shared
    // per-chunk phase-1 span (GPU coalescing, upload, kernel, readback, and
    // GPU admission). Zero for CPU-only scans.
    Stage::BackendDispatch,
    Stage::HotPatterns,
    Stage::ConfirmedPatterns,
    // Always-active RegexSet prefilter, the anchorless detectors that run on
    // EVERY chunk (the cost the old label hid).
    Stage::Phase2Prefilter,
    // Keyword Aho-Corasick prefilter (gates keyword-anchored phase-2 patterns).
    Stage::Phase2KeywordAc,
    // Shared-anchor candidate scan (one AC over required-prefix literals).
    Stage::Phase2SharedAc,
    // Anchored verification of shared-anchor candidates.
    Stage::Phase2AnchoredVerify,
    // Whole-chunk extraction for active patterns with no usable anchor.
    Stage::Phase2WholeChunk,
    Stage::GenericDetection,
    Stage::Entropy,
    Stage::MachineLearning,
    // Decode pipeline: detect encoded blobs + spawn/scan decoded sub-chunks
    // (the recursion driver itself, excluding the sub-chunk phase-2 which lands
    // in the leaves above tagged at decode depth).
    Stage::Decode,
];

const N: usize = LEAVES.len();

/// Row index of `stage` in [`LEAVES`], or `None` when this dump does not render
/// it. Source, suppression, verification and reporting stages belong to the
/// operator profile, not to the scanner tree.
fn leaf_index(stage: Stage) -> Option<usize> {
    LEAVES.iter().position(|&leaf| leaf == stage)
}

/// True when stage spans and typed counters are recorded process-wide.
pub(crate) fn enabled() -> bool {
    keyhog_profile::detail().records_stages()
}

/// True when the expensive per-pattern, per-decoder and per-backend
/// decomposition is on. This level pays a clock read per decoder call and per
/// pattern batch, so it is deliberately a step above plain stage recording.
pub(crate) fn diagnostic() -> bool {
    keyhog_profile::detail().is_diagnostic()
}

thread_local! {
    /// Set on the worker while it re-scans a decoded sub-chunk, so leaf times
    /// recorded during that window are also attributed to [`NS_DECODE`].
    static IN_DECODE: Cell<bool> = const { Cell::new(false) };
}

/// Mark/unmark the current thread as inside a decode sub-chunk rescan; returns
/// the previous value so the caller can restore it (decode recursion nests).
#[cfg(feature = "decode")]
pub(crate) fn set_in_decode(on: bool) -> bool {
    let previous = IN_DECODE.with(|cell| cell.replace(on));
    keyhog_profile::set_attribution(if on {
        keyhog_profile::Attribution::Decoded
    } else {
        keyhog_profile::Attribution::Root
    });
    previous
}

/// True while this worker thread is rescanning a DECODED sub-chunk (base64/hex/
/// url/… payload sliced out of an outer chunk). This is not merely a profiling
/// marker: it is the single-owner scan-context signal that a caller (the phase-2
/// prefilter) reads to widen the homoglyph-ASCII skip to ALL decoded content.
/// Homoglyph prefix variants exist to catch unicode look-alikes in SOURCE text;
/// inside a decoded payload a non-ASCII byte run is binary noise (base64/hex of
/// binary), and any homoglyph-variant hit there is structurally a non-credential
/// (a real secret is ASCII/UTF-8 text and is already covered by the base pattern
/// in the lean DB), so the ~2.8k homoglyph NFAs can be skipped on decoded chunks
/// regardless of `is_ascii()`. Always available (returns false without the
/// `decode` feature, where `set_in_decode` never runs and the cell stays false).
#[inline]
pub(crate) fn in_decode() -> bool {
    IN_DECODE.with(Cell::get)
}

pub(crate) type Guard = keyhog_profile::Span;

/// Open a leaf span; records elapsed wall time into `stage` on drop.
#[inline]
#[must_use]
pub(crate) fn span(stage: Stage) -> Guard {
    keyhog_profile::span(stage)
}

/// Record bytes submitted to a completed backend route (for the throughput
/// line). Raw input bytes are recorded once by source adapters at acquisition;
/// recording them here too would double-count every adapter-served scan.
pub(crate) fn add_bytes(bytes: u64) {
    keyhog_profile::add_backend_dispatched_bytes(bytes);
}

/// Record accepted decode-through bytes once per derived chunk.
pub(crate) fn add_derived_decoder_bytes(bytes: u64) {
    keyhog_profile::add_derived_decoder_bytes(bytes);
}

/// Stages this dump reports as "of which" rows: each is INCLUSIVE of leaves
/// recorded underneath it, so summing one into the scan total would double
/// count. Kept out of [`LEAVES`] for exactly that reason.
const INCLUSIVE: [Stage; 2] = [Stage::BoundaryScan, Stage::AutorouteCalibration];

struct Drained {
    ns: [u64; N],
    calls: [u64; N],
    ns_decode: [u64; N],
    inclusive_ns: [u64; INCLUSIVE.len()],
    inclusive_calls: [u64; INCLUSIVE.len()],
    bytes: u64,
    files: u64,
}

fn read_reset() -> Drained {
    let mut drained = Drained {
        ns: [0; N],
        calls: [0; N],
        ns_decode: [0; N],
        inclusive_ns: [0; INCLUSIVE.len()],
        inclusive_calls: [0; INCLUSIVE.len()],
        bytes: 0,
        files: 0,
    };
    for measurement in keyhog_profile::take_stage_measurements() {
        if let Some(index) = leaf_index(measurement.stage) {
            drained.ns[index] = measurement.elapsed_ns;
            drained.calls[index] = measurement.calls;
            drained.ns_decode[index] = measurement.attributed_ns;
        } else if let Some(index) = INCLUSIVE.iter().position(|&s| s == measurement.stage) {
            drained.inclusive_ns[index] = measurement.elapsed_ns;
            drained.inclusive_calls[index] = measurement.calls;
        }
    }
    let (bytes, files) = keyhog_profile::take_input_totals();
    drained.bytes = bytes;
    drained.files = files;
    drained
}

/// Discard all accumulated counters without printing (warm-up between runs).
///
/// One call, because the profile runtime is now the only store: stage
/// counters, input totals, typed counters, distributions, and the indexed
/// per-decoder family all clear together. There is no scanner-side table left
/// to forget.
pub fn reset() {
    keyhog_profile::reset();
}

/// Row index of a leaf this dump names directly. Const so the grouping tables
/// below stay compile-time constants after the `P` enum was deleted.
const fn row(stage: Stage) -> usize {
    let mut index = 0;
    while index < N {
        if LEAVES[index] as usize == stage as usize {
            return index;
        }
        index += 1;
    }
    panic!("dump grouping names a stage that is not a rendered leaf");
}

const PHASE2_CAPTURE_LEAVES: [usize; 5] = [
    row(Stage::Phase2Prefilter),
    row(Stage::Phase2KeywordAc),
    row(Stage::Phase2SharedAc),
    row(Stage::Phase2AnchoredVerify),
    row(Stage::Phase2WholeChunk),
];
const PHASE2_LEAVES: [usize; 9] = [
    row(Stage::HotPatterns),
    row(Stage::ConfirmedPatterns),
    row(Stage::Phase2Prefilter),
    row(Stage::Phase2KeywordAc),
    row(Stage::Phase2SharedAc),
    row(Stage::Phase2AnchoredVerify),
    row(Stage::Phase2WholeChunk),
    row(Stage::GenericDetection),
    row(Stage::Entropy),
];
// `machine-learning` is a phase-2 leaf too, listed separately so the capture
// sub-leaves group.

/// Print and reset the unified profile tree. Safe to call when profiling was off
/// (prints a single "disabled" line).
pub fn dump(label: &str) {
    if !enabled() {
        eprintln!("[profile {label}] scanner profile switch is off; no data");
        return;
    }
    let Drained {
        ns,
        calls,
        ns_decode,
        inclusive_ns,
        inclusive_calls,
        bytes,
        files,
    } = read_reset();
    let ms = |i: usize| ns[i] as f64 / 1e6;
    let sum = |ids: &[usize]| ids.iter().map(|&i| ns[i]).sum::<u64>();

    let phase2_ns = sum(&PHASE2_LEAVES) + ns[row(Stage::MachineLearning)];
    let capture_ns = sum(&PHASE2_CAPTURE_LEAVES);
    let scan_ns = ns[row(Stage::Preprocess)]
        + ns[row(Stage::Phase1Triggers)]
        + ns[row(Stage::BackendDispatch)]
        + phase2_ns
        + ns[row(Stage::Decode)];
    let scan_ms = scan_ns as f64 / 1e6;
    let pct = |part: u64, whole: u64| {
        if whole > 0 {
            100.0 * part as f64 / whole as f64
        } else {
            0.0
        }
    };

    eprintln!("=== keyhog profile [{label}] ===");
    let thru = if scan_ms > 0.0 {
        (bytes as f64 / 1e6) / (scan_ms / 1000.0)
    } else {
        0.0
    };
    eprintln!(
        "SCAN  {scan_ms:>9.1} ms   summed across workers · {} files · {:.2} MiB · {:.1} MB/s (pass-time sum)",
        files,
        bytes as f64 / (1024.0 * 1024.0),
        thru
    );

    let leaf = |i: usize, parent_ns: u64, indent: &str| {
        let c = calls[i];
        let dec = ns_decode[i];
        eprintln!(
            "{indent}{:<24} {:>9.1} ms  {:>5.1}% parent  {:>6.1}% scan  calls={:<8} {:>6.0} ns/call  decode={:>4.1}%",
            LEAVES[i].as_str(),
            ms(i),
            pct(ns[i], parent_ns),
            pct(ns[i], scan_ns),
            c,
            if c > 0 { ns[i] as f64 / c as f64 } else { 0.0 },
            pct(dec, ns[i].max(1)),
        );
    };
    let parent = |name: &str, total: u64, indent: &str| {
        eprintln!(
            "{indent}{:<24} {:>9.1} ms  {:>5.1}% scan",
            name,
            total as f64 / 1e6,
            pct(total, scan_ns),
        );
    };

    // One typed-metric + distribution drain feeds every auxiliary section
    // below (mark decomposition, HS split, decode recursion, extraction,
    // generic bridge, ML batch, ML split). Draining once here, instead of one
    // swap per collector, is what lets the scanner drop every per-collector
    // dump/reset path: the profile runtime is the single store.
    let typed = keyhog_profile::take_typed_metrics();
    // The ML batch-size histogram is the only distribution consumer.
    #[cfg(feature = "ml")]
    let distributions = keyhog_profile::take_metric_distributions();
    // The prefilter call decomposition (gate-skip / HS-served / RegexSet-served)
    // answers whether the `phase2:prefilter` cost is cheap
    // gate-skips averaged with a few brutal RegexSet passes, or uniformly heavy.
    let mark: crate::engine::phase2::MarkSnapshot =
        crate::engine::phase2::mark_snapshot_from_typed(&typed);
    // Internal timing split of the HS-served portion (scan vs dropped host loop).
    // Only printed when HS-mark time was recorded.
    let hs_split: crate::engine::phase2::HsMarkSplit =
        crate::engine::phase2::hs_mark_split_from_typed(&typed);

    leaf(row(Stage::Preprocess), scan_ns, "  ");
    leaf(row(Stage::Phase1Triggers), scan_ns, "  ");
    leaf(row(Stage::BackendDispatch), scan_ns, "  ");
    parent("phase2", phase2_ns, "  ");
    leaf(row(Stage::HotPatterns), phase2_ns, "    ");
    leaf(row(Stage::ConfirmedPatterns), phase2_ns, "    ");
    parent("phase2-capture", capture_ns, "    ");
    for &i in &PHASE2_CAPTURE_LEAVES {
        leaf(i, capture_ns, "      ");
        // Attach the path decomposition directly under the prefilter leaf it
        // describes, so the dominant scan cost is diagnosable in place.
        if i == row(Stage::Phase2Prefilter) && mark.calls > 0 {
            let line = crate::engine::phase2::format_mark_decomposition(&mark);
            if mark.is_consistent() {
                eprintln!("        ↳ {line}");
            } else {
                // Law 10: never print a mis-accounted decomposition as if it were
                // correct. The snapshot is quiescent here (read after the scan
                // joined), so a failed split means a `record_*` path bumped
                // `calls` without its matching sub-counter, every percentage on
                // this line is then wrong. Surface it loudly next to the figures.
                eprintln!(
                    "        ↳ {line}  ⚠ INCONSISTENT: gate-skip + hs + regexset ({}) != calls ({}), prefilter call accounting bug",
                    mark.gate_skips + mark.served_total(),
                    mark.calls
                );
            }
            // Second layer: where the HS-served time went (scan vs dropped host
            // loop). Only present when profiling timed at least one HS mark.
            if hs_split.any_recorded() {
                eprintln!(
                    "          ↳ {}",
                    crate::engine::phase2::format_hs_mark_split(&hs_split)
                );
            }
        }
    }
    leaf(row(Stage::GenericDetection), phase2_ns, "    ");
    leaf(row(Stage::Entropy), phase2_ns, "    ");
    leaf(row(Stage::MachineLearning), phase2_ns, "    ");
    leaf(row(Stage::Decode), scan_ns, "  ");

    let decode_total: u64 = (0..N).map(|i| ns_decode[i]).sum();
    eprintln!(
        "  (of all leaf time, {:.1}% was recorded inside decode sub-chunk rescans)",
        pct(decode_total, scan_ns),
    );

    // Inclusive stages, printed as "of which" so nobody adds them to the tree
    // above. Seam rescan and calibration both re-enter the leaves they sit on
    // top of, and both scale with chunk count rather than input size, so a
    // many-small-files run is where they show up.
    for (index, stage) in INCLUSIVE.iter().enumerate() {
        let stage_ns = inclusive_ns[index];
        if stage_ns == 0 {
            continue;
        }
        eprintln!(
            "  of which {:<22} {:>9.1} ms  {:>5.1}% scan  calls={} (inclusive of the leaves inside it)",
            stage.as_str(),
            stage_ns as f64 / 1e6,
            pct(stage_ns, scan_ns),
            inclusive_calls[index],
        );
    }

    // Fold in the auxiliary figures recorded on the hot path, all sourced from
    // the single typed/distribution drain above. Each section stays silent when
    // its figures are all zero, so an unrelated run prints nothing extra.
    #[cfg(feature = "decode")]
    {
        let (parents, subchunks, derived_bytes) =
            crate::engine::scan_postprocess::decode_recursion_from_typed(&typed);
        let gen_ms = ns[row(Stage::Decode)] as f64 / 1e6;
        let scan_ms = decode_total as f64 / 1e6;
        if parents != 0 || subchunks != 0 || derived_bytes != 0 || gen_ms != 0.0 || scan_ms != 0.0 {
            eprintln!(
                "{}",
                crate::engine::scan_postprocess::format_decode_recursion(
                    parents,
                    subchunks,
                    derived_bytes,
                    gen_ms,
                    scan_ms,
                )
            );
        }
        let (extract_calls, extract_bytes, extract_ns) =
            crate::decode::extract_profile_from_typed(&typed);
        if extract_calls != 0 || extract_bytes != 0 || extract_ns != 0 {
            eprintln!(
                "{}",
                crate::decode::format_extract_profile(extract_calls, extract_bytes, extract_ns)
            );
        }
    }
    // The per-decoder named table has no labeled-metric API in the profile
    // registry, so it stays scanner-owned (and perf-trace gated) for now.
    crate::decode::decoder_profile_dump();
    let generic = crate::engine::phase2_generic::generic_profile_from_typed(&typed);
    if generic.any_recorded() {
        eprintln!(
            "{}",
            crate::engine::phase2_generic::format_generic_profile(&generic)
        );
    }
    #[cfg(feature = "ml")]
    {
        let batch =
            crate::engine::scan_postprocess::ml_batch_profile_from_parts(&typed, &distributions);
        if batch.calls != 0 {
            eprintln!(
                "{}",
                crate::engine::scan_postprocess::format_ml_batch_profile(&batch)
            );
        }
    }
    let (feature_ns, score_ns) = crate::gpu::ml_split_from_typed(&typed);
    if feature_ns != 0 || score_ns != 0 {
        eprintln!("{}", crate::gpu::format_ml_split(feature_ns, score_ns));
    }
}
