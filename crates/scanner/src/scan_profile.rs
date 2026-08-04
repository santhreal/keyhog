//! Unified scan profiler: one explicit switch, one hierarchical dump.
//!
//! Replaces the old scattered per-pass atomic-counter hacks (each in a different
//! file, each with its own incompatible dump) with one scanner-owned switch set
//! explicitly by the CLI/library caller. It captures the whole pipeline in one
//! run and emits one tree showing where every microsecond goes, including inside
//! the phase-2 pass and how much of the cost is decode-recursion.
//!
//! Model: only LEAF passes are timed directly (via the [`span`] RAII guard);
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

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

/// Leaf timing points. The ONLY spans measured directly; the hierarchy in
/// [`dump`] derives parent totals by summing these.
#[derive(Copy, Clone)]
#[repr(usize)]
pub(crate) enum P {
    Preprocess = 0,
    Phase1Triggers,
    /// Accelerator-side trigger preparation and dispatch outside the shared
    /// per-chunk phase-1 span (GPU coalescing, upload, kernel, readback, and
    /// GPU admission). Zero for CPU-only scans.
    BackendDispatch,
    Hot,
    Confirmed,
    /// Always-active RegexSet prefilter, the anchorless detectors that run on
    /// EVERY chunk (the cost the old label hid).
    Phase2Prefilter,
    /// Keyword Aho-Corasick prefilter (gates keyword-anchored phase-2 patterns).
    Phase2KeywordAc,
    /// Shared-anchor candidate scan (one AC over required-prefix literals).
    Phase2SharedAc,
    /// Anchored verification of shared-anchor candidates.
    Phase2AnchoredVerify,
    /// Whole-chunk extraction for active patterns with no usable anchor.
    Phase2WholeChunk,
    Generic,
    Entropy,
    Ml,
    /// Decode pipeline: detect encoded blobs + spawn/scan decoded sub-chunks
    /// (the recursion driver itself, excluding the sub-chunk phase-2 which lands
    /// in the leaves above tagged at decode depth).
    Decode,
}

const N: usize = 14;

const NAMES: [&str; N] = [
    "preprocess",
    "phase1",
    "backend-dispatch",
    "hot",
    "confirmed",
    "phase2:prefilter",
    "phase2:keyword-ac",
    "phase2:shared-ac",
    "phase2:verify",
    "phase2:whole-chunk",
    "generic",
    "entropy",
    "ml",
    "decode",
];

static DETAILED_ENABLED: AtomicBool = AtomicBool::new(false);
static PERF_TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable the scanner's detailed diagnostic profile collector.
///
/// This library API enables fixed stages and expensive per-pattern diagnostics
/// together. The CLI uses it only for `--perf-trace`; `--profile` starts a
/// [`keyhog_profile::Session`] directly so production profiling does not enable
/// per-pattern hot-path accounting.
pub fn set_profile_enabled(enabled: bool) {
    DETAILED_ENABLED.store(enabled, Relaxed);
    keyhog_profile::set_enabled(enabled);
}

/// Enable or disable low-level phase timing traces for this process.
///
/// This is the explicit replacement for the old ambient environment hook used by
/// GPU/perf benches and dispatch diagnostics.
pub fn set_perf_trace_enabled(enabled: bool) {
    PERF_TRACE_ENABLED.store(enabled, Relaxed);
}

pub(crate) fn enabled() -> bool {
    DETAILED_ENABLED.load(Relaxed)
}

pub(crate) fn perf_trace_enabled() -> bool {
    PERF_TRACE_ENABLED.load(Relaxed)
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

fn stage(point: P) -> keyhog_profile::Stage {
    use keyhog_profile::Stage;
    match point {
        P::Preprocess => Stage::Preprocess,
        P::Phase1Triggers => Stage::Phase1Triggers,
        P::BackendDispatch => Stage::BackendDispatch,
        P::Hot => Stage::HotPatterns,
        P::Confirmed => Stage::ConfirmedPatterns,
        P::Phase2Prefilter => Stage::Phase2Prefilter,
        P::Phase2KeywordAc => Stage::Phase2KeywordAc,
        P::Phase2SharedAc => Stage::Phase2SharedAc,
        P::Phase2AnchoredVerify => Stage::Phase2AnchoredVerify,
        P::Phase2WholeChunk => Stage::Phase2WholeChunk,
        P::Generic => Stage::GenericDetection,
        P::Entropy => Stage::Entropy,
        P::Ml => Stage::MachineLearning,
        P::Decode => Stage::Decode,
    }
}

fn point_index(stage: keyhog_profile::Stage) -> Option<usize> {
    use keyhog_profile::Stage;
    Some(match stage {
        Stage::Preprocess => P::Preprocess as usize,
        Stage::Phase1Triggers => P::Phase1Triggers as usize,
        Stage::BackendDispatch => P::BackendDispatch as usize,
        Stage::HotPatterns => P::Hot as usize,
        Stage::ConfirmedPatterns => P::Confirmed as usize,
        Stage::Phase2Prefilter => P::Phase2Prefilter as usize,
        Stage::Phase2KeywordAc => P::Phase2KeywordAc as usize,
        Stage::Phase2SharedAc => P::Phase2SharedAc as usize,
        Stage::Phase2AnchoredVerify => P::Phase2AnchoredVerify as usize,
        Stage::Phase2WholeChunk => P::Phase2WholeChunk as usize,
        Stage::GenericDetection => P::Generic as usize,
        Stage::Entropy => P::Entropy as usize,
        Stage::MachineLearning => P::Ml as usize,
        Stage::Decode => P::Decode as usize,
        Stage::SourceAcquire
        | Stage::SourceWalk
        | Stage::SourceRead
        | Stage::SourceQueueWait
        | Stage::ScannerQueueWait
        | Stage::IncrementalLookup
        | Stage::BackendSelect
        | Stage::ResultMerge
        | Stage::Suppression
        | Stage::LiveVerification
        | Stage::Reporting => return None,
    })
}

/// Open a leaf span; records elapsed wall time into `point` on drop.
#[inline]
#[must_use]
pub(crate) fn span(point: P) -> Guard {
    keyhog_profile::span(stage(point))
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

fn read_reset() -> ([u64; N], [u64; N], [u64; N], u64, u64) {
    let mut ns = [0; N];
    let mut calls = [0; N];
    let mut ns_decode = [0; N];
    for measurement in keyhog_profile::take_stage_measurements() {
        let Some(index) = point_index(measurement.stage) else {
            continue;
        };
        ns[index] = measurement.elapsed_ns;
        calls[index] = measurement.calls;
        ns_decode[index] = measurement.attributed_ns;
    }
    let (bytes, files) = keyhog_profile::take_input_totals();
    (ns, calls, ns_decode, bytes, files)
}

/// Discard all accumulated counters without printing (warm-up between runs).
/// `keyhog_profile::reset` clears the stage counters, input totals, typed
/// counters, and distributions; only the per-decoder named table (no labeled
/// metric API exists for it) is still scanner-owned.
pub fn reset() {
    keyhog_profile::reset();
    crate::decode::decoder_profile_reset();
}

const PHASE2_CAPTURE_LEAVES: [usize; 5] = [
    P::Phase2Prefilter as usize,
    P::Phase2KeywordAc as usize,
    P::Phase2SharedAc as usize,
    P::Phase2AnchoredVerify as usize,
    P::Phase2WholeChunk as usize,
];
const PHASE2_LEAVES: [usize; 9] = [
    P::Hot as usize,
    P::Confirmed as usize,
    P::Phase2Prefilter as usize,
    P::Phase2KeywordAc as usize,
    P::Phase2SharedAc as usize,
    P::Phase2AnchoredVerify as usize,
    P::Phase2WholeChunk as usize,
    P::Generic as usize,
    P::Entropy as usize,
];
// `ml` is a phase-2 leaf too, listed separately so capture sub-leaves group.

/// Print and reset the unified profile tree. Safe to call when profiling was off
/// (prints a single "disabled" line).
pub fn dump(label: &str) {
    if !enabled() {
        eprintln!("[profile {label}] scanner profile switch is off; no data");
        return;
    }
    let (ns, calls, ns_decode, bytes, files) = read_reset();
    let ms = |i: usize| ns[i] as f64 / 1e6;
    let sum = |ids: &[usize]| ids.iter().map(|&i| ns[i]).sum::<u64>();

    let phase2_ns = sum(&PHASE2_LEAVES) + ns[P::Ml as usize];
    let capture_ns = sum(&PHASE2_CAPTURE_LEAVES);
    let scan_ns = ns[P::Preprocess as usize]
        + ns[P::Phase1Triggers as usize]
        + ns[P::BackendDispatch as usize]
        + phase2_ns
        + ns[P::Decode as usize];
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
            "{indent}{:<16} {:>9.1} ms  {:>5.1}% parent  {:>6.1}% scan  calls={:<8} {:>6.0} ns/call  decode={:>4.1}%",
            NAMES[i],
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
            "{indent}{:<16} {:>9.1} ms  {:>5.1}% scan",
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

    leaf(P::Preprocess as usize, scan_ns, "  ");
    leaf(P::Phase1Triggers as usize, scan_ns, "  ");
    leaf(P::BackendDispatch as usize, scan_ns, "  ");
    parent("phase2", phase2_ns, "  ");
    leaf(P::Hot as usize, phase2_ns, "    ");
    leaf(P::Confirmed as usize, phase2_ns, "    ");
    parent("phase2-capture", capture_ns, "    ");
    for &i in &PHASE2_CAPTURE_LEAVES {
        leaf(i, capture_ns, "      ");
        // Attach the path decomposition directly under the prefilter leaf it
        // describes, so the dominant scan cost is diagnosable in place.
        if i == P::Phase2Prefilter as usize && mark.calls > 0 {
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
    leaf(P::Generic as usize, phase2_ns, "    ");
    leaf(P::Entropy as usize, phase2_ns, "    ");
    leaf(P::Ml as usize, phase2_ns, "    ");
    leaf(P::Decode as usize, scan_ns, "  ");

    let decode_total: u64 = (0..N).map(|i| ns_decode[i]).sum();
    eprintln!(
        "  (of all leaf time, {:.1}% was recorded inside decode sub-chunk rescans)",
        pct(decode_total, scan_ns),
    );

    // Fold in the auxiliary figures recorded on the hot path, all sourced from
    // the single typed/distribution drain above. Each section stays silent when
    // its figures are all zero, so an unrelated run prints nothing extra.
    #[cfg(feature = "decode")]
    {
        let (parents, subchunks, derived_bytes) =
            crate::engine::scan_postprocess::decode_recursion_from_typed(&typed);
        let gen_ms = ns[P::Decode as usize] as f64 / 1e6;
        let scan_ms = decode_total as f64 / 1e6;
        if parents != 0 || subchunks != 0 || derived_bytes != 0 || gen_ms != 0.0 || scan_ms != 0.0
        {
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
        let batch = crate::engine::scan_postprocess::ml_batch_profile_from_parts(
            &typed,
            &distributions,
        );
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
