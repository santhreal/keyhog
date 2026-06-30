//! Unit contract for the phase-2 prefilter call-accounting counters
//! (`engine::phase2::mark_stats`).
//!
//! These counters decompose the `phase2:prefilter` profiler leaf — the single
//! most expensive pass in a real scan — into gate-skip / HS-served /
//! RegexSet-served calls, so the dominant scan cost is diagnosable instead of an
//! opaque "N calls, M ns/call" aggregate. This suite pins:
//!   * each `record_*` increments exactly its own counter (no cross-talk),
//!   * the snapshot reader and reset are exact,
//!   * the derived percentage/total helpers are correct (incl. divide-by-zero
//!     safety), and
//!   * the pure `format_mark_decomposition` line the profiler prints is exact.
//!
//! Under `cfg(test)` the counters are thread-local, so each `#[test]` (run on its
//! own libtest thread) owns a private copy — no mutex or serialization needed for
//! the direct-record tests below. Every test still resets first as a guard
//! against any thread reuse.

use keyhog_scanner::engine::phase2::{
    format_mark_decomposition, phase2_mark_stats, phase2_mark_stats_reset, record_mark_call,
    record_mark_gate_skip, record_mark_hs_served, record_mark_perpattern_work,
    record_mark_regexset_served, MarkSnapshot,
};

/// A fully-specified snapshot for the pure helper/format tests (no counter I/O).
fn snap(calls: u64, gate_skips: u64, perpattern_work: u64, hs: u64, regexset: u64) -> MarkSnapshot {
    MarkSnapshot {
        calls,
        gate_skips,
        perpattern_work,
        hs_served: hs,
        regexset_served: regexset,
    }
}

// ---------------------------------------------------------------------------
// Counter recording — each record_* touches exactly one field.
// ---------------------------------------------------------------------------

#[test]
fn fresh_snapshot_is_all_zero_after_reset() {
    phase2_mark_stats_reset();
    let s = phase2_mark_stats();
    assert_eq!(s.calls, 0);
    assert_eq!(s.gate_skips, 0);
    assert_eq!(s.perpattern_work, 0);
    assert_eq!(s.hs_served, 0);
    assert_eq!(s.regexset_served, 0);
}

#[test]
fn record_mark_call_increments_only_calls() {
    phase2_mark_stats_reset();
    record_mark_call();
    let s = phase2_mark_stats();
    assert_eq!(s.calls, 1, "calls must increment");
    assert_eq!(s.gate_skips, 0);
    assert_eq!(s.perpattern_work, 0);
    assert_eq!(s.hs_served, 0);
    assert_eq!(s.regexset_served, 0);
}

#[test]
fn record_mark_gate_skip_increments_only_gate_skips() {
    phase2_mark_stats_reset();
    record_mark_gate_skip();
    let s = phase2_mark_stats();
    assert_eq!(s.gate_skips, 1, "gate_skips must increment");
    assert_eq!(s.calls, 0);
    assert_eq!(s.perpattern_work, 0);
    assert_eq!(s.hs_served, 0);
    assert_eq!(s.regexset_served, 0);
}

#[test]
fn record_mark_perpattern_work_increments_only_perpattern() {
    phase2_mark_stats_reset();
    record_mark_perpattern_work();
    let s = phase2_mark_stats();
    assert_eq!(s.perpattern_work, 1, "perpattern_work must increment");
    assert_eq!(s.calls, 0);
    assert_eq!(s.gate_skips, 0);
    assert_eq!(s.hs_served, 0);
    assert_eq!(s.regexset_served, 0);
}

#[test]
fn record_mark_hs_served_increments_only_hs() {
    phase2_mark_stats_reset();
    record_mark_hs_served();
    let s = phase2_mark_stats();
    assert_eq!(s.hs_served, 1, "hs_served must increment");
    assert_eq!(s.calls, 0);
    assert_eq!(s.gate_skips, 0);
    assert_eq!(s.perpattern_work, 0);
    assert_eq!(s.regexset_served, 0);
}

#[test]
fn record_mark_regexset_served_increments_only_regexset() {
    phase2_mark_stats_reset();
    record_mark_regexset_served();
    let s = phase2_mark_stats();
    assert_eq!(s.regexset_served, 1, "regexset_served must increment");
    assert_eq!(s.calls, 0);
    assert_eq!(s.gate_skips, 0);
    assert_eq!(s.perpattern_work, 0);
    assert_eq!(s.hs_served, 0);
}

#[test]
fn multiple_records_accumulate_exact_counts() {
    phase2_mark_stats_reset();
    for _ in 0..7 {
        record_mark_call();
    }
    for _ in 0..3 {
        record_mark_gate_skip();
    }
    for _ in 0..4 {
        record_mark_perpattern_work();
    }
    for _ in 0..2 {
        record_mark_hs_served();
    }
    for _ in 0..5 {
        record_mark_regexset_served();
    }
    let s = phase2_mark_stats();
    assert_eq!(s.calls, 7);
    assert_eq!(s.gate_skips, 3);
    assert_eq!(s.perpattern_work, 4);
    assert_eq!(s.hs_served, 2);
    assert_eq!(s.regexset_served, 5);
}

#[test]
fn reset_zeroes_all_five_counters() {
    phase2_mark_stats_reset();
    record_mark_call();
    record_mark_gate_skip();
    record_mark_perpattern_work();
    record_mark_hs_served();
    record_mark_regexset_served();
    // Sanity: something was recorded.
    assert_eq!(phase2_mark_stats().calls, 1);
    phase2_mark_stats_reset();
    let s = phase2_mark_stats();
    assert_eq!(
        (s.calls, s.gate_skips, s.perpattern_work, s.hs_served, s.regexset_served),
        (0, 0, 0, 0, 0),
        "reset must zero every counter"
    );
}

#[test]
fn snapshot_does_not_reset_on_read() {
    phase2_mark_stats_reset();
    record_mark_call();
    let first = phase2_mark_stats();
    let second = phase2_mark_stats();
    assert_eq!(first.calls, 1);
    assert_eq!(second.calls, 1, "reading the snapshot must not reset counters");
}

// ---------------------------------------------------------------------------
// MarkSnapshot derived helpers.
// ---------------------------------------------------------------------------

#[test]
fn served_total_sums_hs_and_regexset() {
    let s = snap(100, 25, 75, 60, 15);
    assert_eq!(s.served_total(), 75);
}

#[test]
fn served_total_equals_perpattern_for_consistent_snapshot() {
    let s = snap(100, 25, 75, 60, 15);
    assert_eq!(
        s.served_total(),
        s.perpattern_work,
        "in a consistent snapshot every per-pattern call is served by exactly one path"
    );
}

#[test]
fn gate_skips_plus_served_equals_calls() {
    let s = snap(100, 25, 75, 60, 15);
    assert_eq!(
        s.gate_skips + s.served_total(),
        s.calls,
        "gate_skips + hs + regexset must equal total calls"
    );
}

#[test]
fn gate_skip_pct_is_fraction_of_calls() {
    let s = snap(100, 25, 75, 60, 15);
    assert!((s.gate_skip_pct() - 25.0).abs() < 1e-9);
}

#[test]
fn perpattern_pct_is_fraction_of_calls() {
    let s = snap(100, 25, 75, 60, 15);
    assert!((s.perpattern_pct() - 75.0).abs() < 1e-9);
}

#[test]
fn hs_served_pct_is_fraction_of_perpattern_not_calls() {
    // 60 of 75 per-pattern calls = 80% — NOT 60% of total calls. The denominator
    // is per-pattern work, so the reader sees "of the expensive calls, how many
    // took the fast path".
    let s = snap(100, 25, 75, 60, 15);
    assert!(
        (s.hs_served_pct() - 80.0).abs() < 1e-9,
        "hs% must be over per-pattern work, got {}",
        s.hs_served_pct()
    );
}

#[test]
fn regexset_served_pct_is_fraction_of_perpattern() {
    let s = snap(100, 25, 75, 60, 15);
    assert!((s.regexset_served_pct() - 20.0).abs() < 1e-9);
}

#[test]
fn call_pcts_sum_to_100_when_calls_split() {
    let s = snap(100, 25, 75, 60, 15);
    assert!((s.gate_skip_pct() + s.perpattern_pct() - 100.0).abs() < 1e-9);
}

#[test]
fn served_pcts_sum_to_100_when_perpattern_split() {
    let s = snap(100, 25, 75, 60, 15);
    assert!((s.hs_served_pct() + s.regexset_served_pct() - 100.0).abs() < 1e-9);
}

#[test]
fn pct_helpers_return_zero_on_empty_snapshot() {
    let s = MarkSnapshot::default();
    // No NaN / no divide-by-zero — all percentages are a clean 0.0.
    assert_eq!(s.gate_skip_pct(), 0.0);
    assert_eq!(s.perpattern_pct(), 0.0);
    assert_eq!(s.hs_served_pct(), 0.0);
    assert_eq!(s.regexset_served_pct(), 0.0);
    assert_eq!(s.served_total(), 0);
}

#[test]
fn hs_pct_is_zero_when_perpattern_zero_even_with_calls() {
    // All gate-skips: per-pattern is 0, so the served percentages must not divide
    // by zero — they report 0.0, and the call-level split is still meaningful.
    let s = snap(100, 100, 0, 0, 0);
    assert_eq!(s.hs_served_pct(), 0.0);
    assert_eq!(s.regexset_served_pct(), 0.0);
    assert!((s.gate_skip_pct() - 100.0).abs() < 1e-9);
    assert!((s.perpattern_pct() - 0.0).abs() < 1e-9);
}

// ---------------------------------------------------------------------------
// MarkSnapshot value semantics.
// ---------------------------------------------------------------------------

#[test]
fn default_snapshot_equals_all_zero() {
    assert_eq!(MarkSnapshot::default(), snap(0, 0, 0, 0, 0));
}

#[test]
fn snapshot_is_copy_and_independent() {
    let a = snap(1, 2, 3, 4, 5);
    let b = a; // Copy
    assert_eq!(a, b, "Copy must duplicate every field");
    assert_eq!(a.calls, 1);
    assert_eq!(b.regexset_served, 5);
}

// ---------------------------------------------------------------------------
// format_mark_decomposition — the exact one-line diagnostic the profiler prints.
// ---------------------------------------------------------------------------

#[test]
fn format_renders_exact_line_for_clean_split() {
    let s = snap(100, 25, 75, 60, 15);
    assert_eq!(
        format_mark_decomposition(&s),
        "mark: calls=100  gate-skip=25 (25.0%)  per-pattern=75 (75.0%)  \
         [hs=60 (80.0%)  regexset=15 (20.0%)]"
    );
}

#[test]
fn format_contains_every_raw_count() {
    let s = snap(10123, 120, 10003, 8800, 1203);
    let line = format_mark_decomposition(&s);
    assert!(line.contains("calls=10123"), "{line}");
    assert!(line.contains("gate-skip=120"), "{line}");
    assert!(line.contains("per-pattern=10003"), "{line}");
    assert!(line.contains("hs=8800"), "{line}");
    assert!(line.contains("regexset=1203"), "{line}");
}

#[test]
fn format_renders_percentages_to_one_decimal() {
    // 120/10123 = 1.185..% -> "1.2%"; 8800/10003 = 87.97..% -> "88.0%".
    let s = snap(10123, 120, 10003, 8800, 1203);
    let line = format_mark_decomposition(&s);
    assert!(line.contains("(1.2%)"), "gate-skip pct rounded wrong: {line}");
    assert!(line.contains("(98.8%)"), "per-pattern pct rounded wrong: {line}");
    assert!(line.contains("(88.0%)"), "hs pct rounded wrong: {line}");
    assert!(line.contains("(12.0%)"), "regexset pct rounded wrong: {line}");
}

#[test]
fn format_empty_snapshot_has_no_nan() {
    let line = format_mark_decomposition(&MarkSnapshot::default());
    assert!(!line.contains("NaN"), "empty snapshot must not render NaN: {line}");
    assert!(line.contains("calls=0"), "{line}");
    assert!(line.contains("(0.0%)"), "{line}");
}

#[test]
fn format_is_deterministic() {
    let s = snap(42, 10, 32, 20, 12);
    assert_eq!(format_mark_decomposition(&s), format_mark_decomposition(&s));
}

#[test]
fn format_all_gate_skip_corpus_shows_zero_served() {
    // A sparse corpus: every call is a cheap gate-skip. The line must make that
    // obvious — per-pattern 0, both served paths 0.
    let s = snap(500, 500, 0, 0, 0);
    let line = format_mark_decomposition(&s);
    assert!(line.contains("gate-skip=500 (100.0%)"), "{line}");
    assert!(line.contains("per-pattern=0 (0.0%)"), "{line}");
    assert!(line.contains("[hs=0 (0.0%)  regexset=0 (0.0%)]"), "{line}");
}

#[test]
fn format_all_regexset_corpus_shows_full_slow_path() {
    // A dense, large-chunk corpus with HS disengaged: every per-pattern call is
    // RegexSet-served. This is the shape that flags the prefilter as the slow path.
    let s = snap(1000, 0, 1000, 0, 1000);
    let line = format_mark_decomposition(&s);
    assert!(line.contains("per-pattern=1000 (100.0%)"), "{line}");
    assert!(line.contains("hs=0 (0.0%)"), "{line}");
    assert!(line.contains("regexset=1000 (100.0%)"), "{line}");
}
