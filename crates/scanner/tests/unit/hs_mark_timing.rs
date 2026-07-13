//! Unit contract for the HS-mark timing split (`engine::phase2::hs_mark_timing`).
//!
//! `#68` decomposes a single HS-served prefilter call's time into the SIMD scan
//! vs the dropped HS-incompatible host-regex loop, so the dominant sub-cost of
//! the 84.8%-of-scan `phase2:prefilter` pass is identifiable. The live timing
//! accumulators are profile-gated process-wide atomics (not unit-tested, timing
//! is nondeterministic, like `POPULATE_PREFILTER_NS`); this suite pins the PURE
//! surface that turns those nanoseconds into the operator-facing line: the
//! `HsMarkSplit` percentage/total helpers (incl. divide-by-zero safety) and the
//! exact `format_hs_mark_split` output.

use keyhog_scanner::engine::phase2::{format_hs_mark_split, HsMarkSplit};

/// A fully-specified split for the pure helper/format tests.
fn split(scan_ns: u64, dropped_ns: u64) -> HsMarkSplit {
    HsMarkSplit {
        scan_ns,
        dropped_ns,
    }
}

// ---------------------------------------------------------------------------
// HsMarkSplit helpers.
// ---------------------------------------------------------------------------

#[test]
fn total_ns_sums_scan_and_dropped() {
    assert_eq!(split(900, 100).total_ns(), 1000);
}

#[test]
fn total_ns_is_zero_for_default() {
    assert_eq!(HsMarkSplit::default().total_ns(), 0);
}

#[test]
fn scan_pct_is_fraction_of_total() {
    assert!((split(900, 100).scan_pct() - 90.0).abs() < 1e-9);
}

#[test]
fn dropped_pct_is_fraction_of_total() {
    assert!((split(900, 100).dropped_pct() - 10.0).abs() < 1e-9);
}

#[test]
fn pcts_sum_to_100_when_both_nonzero() {
    let s = split(1234, 5678);
    assert!((s.scan_pct() + s.dropped_pct() - 100.0).abs() < 1e-9);
}

#[test]
fn scan_pct_is_zero_on_empty_no_div_by_zero() {
    assert_eq!(HsMarkSplit::default().scan_pct(), 0.0);
}

#[test]
fn dropped_pct_is_zero_on_empty_no_div_by_zero() {
    assert_eq!(HsMarkSplit::default().dropped_pct(), 0.0);
}

#[test]
fn any_recorded_false_for_default() {
    assert!(!HsMarkSplit::default().any_recorded());
}

#[test]
fn any_recorded_true_when_scan_only() {
    assert!(split(5, 0).any_recorded());
}

#[test]
fn any_recorded_true_when_dropped_only() {
    assert!(split(0, 5).any_recorded());
}

#[test]
fn all_scan_gives_100_0_split() {
    let s = split(4096, 0);
    assert!((s.scan_pct() - 100.0).abs() < 1e-9);
    assert!((s.dropped_pct() - 0.0).abs() < 1e-9);
}

#[test]
fn all_dropped_gives_0_100_split() {
    let s = split(0, 4096);
    assert!((s.scan_pct() - 0.0).abs() < 1e-9);
    assert!((s.dropped_pct() - 100.0).abs() < 1e-9);
}

#[test]
fn default_equals_zeroed_split() {
    assert_eq!(HsMarkSplit::default(), split(0, 0));
}

#[test]
fn split_is_copy_and_independent() {
    let a = split(7, 11);
    let b = a; // Copy
    assert_eq!(a, b);
    assert_eq!(a.scan_ns, 7);
    assert_eq!(b.dropped_ns, 11);
}

// ---------------------------------------------------------------------------
// format_hs_mark_split (the exact one-line diagnostic the profiler prints).
// ---------------------------------------------------------------------------

#[test]
fn format_renders_exact_line_for_clean_split() {
    // 900_000_000 ns = 900.0 ms (90%); 100_000_000 ns = 100.0 ms (10%).
    let s = split(900_000_000, 100_000_000);
    assert_eq!(
        format_hs_mark_split(&s),
        "hs-mark: scan=900.0 ms (90.0%)  dropped-host-loop=100.0 ms (10.0%)"
    );
}

#[test]
fn format_converts_ns_to_ms() {
    // 1_500_000 ns = 1.5 ms.
    let line = format_hs_mark_split(&split(1_500_000, 0));
    assert!(line.contains("scan=1.5 ms"), "{line}");
}

#[test]
fn format_contains_both_pcts() {
    // 8_100_000_000 / 8_380_000_000 = 96.66% -> 96.7%; the rest 3.34% -> 3.3%.
    let line = format_hs_mark_split(&split(8_100_000_000, 280_000_000));
    assert!(line.contains("(96.7%)"), "scan pct rounding: {line}");
    assert!(line.contains("(3.3%)"), "dropped pct rounding: {line}");
}

#[test]
fn format_empty_split_has_no_nan() {
    let line = format_hs_mark_split(&HsMarkSplit::default());
    assert!(!line.contains("NaN"), "{line}");
    assert!(line.contains("scan=0.0 ms (0.0%)"), "{line}");
    assert!(line.contains("dropped-host-loop=0.0 ms (0.0%)"), "{line}");
}

#[test]
fn format_is_deterministic() {
    let s = split(42_000_000, 7_000_000);
    assert_eq!(format_hs_mark_split(&s), format_hs_mark_split(&s));
}

#[test]
fn format_all_scan_shows_full_scan_dominance() {
    // The expected shape on a homoglyph-heavy DB: the SIMD scan is ~everything.
    let line = format_hs_mark_split(&split(5_000_000_000, 0));
    assert!(line.contains("scan=5000.0 ms (100.0%)"), "{line}");
    assert!(line.contains("dropped-host-loop=0.0 ms (0.0%)"), "{line}");
}

#[test]
fn format_dropped_dominant_case_is_legible() {
    // The shape that would justify a dropped-loop RegexSet batch.
    let line = format_hs_mark_split(&split(100_000_000, 900_000_000));
    assert!(line.contains("scan=100.0 ms (10.0%)"), "{line}");
    assert!(
        line.contains("dropped-host-loop=900.0 ms (90.0%)"),
        "{line}"
    );
}
