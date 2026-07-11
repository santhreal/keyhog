//! Algorithmic-DoS + correctness lock for private-key-block nesting suppression
//! (task #124).
//!
//! `resolution::suppress_matches_nested_in_private_key_blocks` drops any
//! non-block match whose `[offset, offset+len)` span is fully nested inside a
//! `-----BEGIN … PRIVATE KEY-----` block, so a base64/entropy fragment of the
//! key body is never double-reported alongside the block finding.
//!
//! The hazard it used to carry: for every match it scanned EVERY private-key
//! span (`spans.iter().any(...)`) — O(matches × spans). A crafted file packed
//! with thousands of tiny PEM blocks (each a private-key-block match) and
//! thousands of nested fragments drives that product into the billions: a
//! single-file algorithmic-DoS (Law 7 — avoidable O(n²) is a production bug at
//! scale). The fix indexes spans per file as (sorted starts, prefix-max end)
//! and answers each containment query with one binary search — O((M+P) log P).
//!
//! This suite is the regression guard. It pins (1) the exact containment
//! semantics across every boundary the prefix-max index has to get right —
//! inclusive bounds, off-by-one rejects, overlapping spans, the wide-early-span
//! case a naive "last span with start ≤ q" check gets WRONG, cross-file
//! isolation, and (2) the DoS bound itself: 40 000 spans + 40 000 nested
//! fragments must resolve in well under the seconds the quadratic scan would
//! take. Reintroducing the O(M×P) scan turns the boundary tests' correctness
//! green but blows the time ceiling red.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::resolution::resolve_matches;
use sha2::{Digest, Sha256};

/// A detector id classified as a private-key BLOCK detector (see
/// its detector-TOML `private_key_block` flag): its matches define
/// the suppression spans and are themselves never suppressed.
const SPAN_ID: &str = "private-key";
/// A generic (non-block, non-entropy) probe detector id: its matches are the
/// ones the nesting pass may suppress, and the entropy-near-named pass leaves
/// them alone, so survival is decided ONLY by the nesting check under test.
const PROBE_ID: &str = "generic-password";

fn credential_hash(credential: &str) -> [u8; 32] {
    Sha256::digest(credential.as_bytes()).into()
}

/// Build a match of `width` credential bytes at `offset` on its own `line`, so
/// its span is exactly `[offset, offset + width)` and the group-by-(file,line)
/// resolution pass never merges two probes (every match gets a unique line).
fn at(detector_id: &str, file: &str, offset: usize, width: usize, line: usize) -> RawMatch {
    let credential = "x".repeat(width);
    let hash = credential_hash(&credential);
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: hash.into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from(file)),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.5),
    }
}

/// A private-key BLOCK span covering `[start, start+width)` in `file`.
fn span(file: &str, start: usize, width: usize) -> RawMatch {
    // Unique line per span keyed off its start; offsets are unique within a test.
    at(SPAN_ID, file, start, width, start + 1)
}

/// A generic probe covering `[start, start+width)` in `file`.
fn probe(file: &str, start: usize, width: usize) -> RawMatch {
    at(PROBE_ID, file, start, width, start + 1)
}

/// Is a probe that started at `offset` present in the resolved set?
fn probe_kept(resolved: &[RawMatch], offset: usize) -> bool {
    resolved
        .iter()
        .any(|m| m.detector_id.as_ref() == PROBE_ID && m.location.offset == offset)
}

/// Is the block span that started at `offset` present in the resolved set?
fn span_kept(resolved: &[RawMatch], offset: usize) -> bool {
    resolved
        .iter()
        .any(|m| m.detector_id.as_ref() == SPAN_ID && m.location.offset == offset)
}

fn count_probes(resolved: &[RawMatch]) -> usize {
    resolved
        .iter()
        .filter(|m| m.detector_id.as_ref() == PROBE_ID)
        .count()
}

fn count_spans(resolved: &[RawMatch]) -> usize {
    resolved
        .iter()
        .filter(|m| m.detector_id.as_ref() == SPAN_ID)
        .count()
}

const FILE: &str = "keys.pem";

// ── nested → suppressed ─────────────────────────────────────────────────────

#[test]
fn nested_probe_in_single_span_is_suppressed() {
    // span [100, 300); probe [120, 170) is strictly inside.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 120, 50)]);
    assert!(span_kept(&resolved, 100), "the block span itself survives");
    assert!(
        !probe_kept(&resolved, 120),
        "a probe fully nested in the private-key block must be suppressed"
    );
}

#[test]
fn probe_at_exact_span_bounds_is_suppressed() {
    // start == block_start AND end == block_end: containment is inclusive.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 100, 200)]);
    assert!(
        !probe_kept(&resolved, 100),
        "a probe coextensive with the span (inclusive bounds) is nested → suppressed"
    );
}

#[test]
fn probe_at_span_start_boundary_is_suppressed() {
    // start == block_start, end < block_end.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 100, 50)]);
    assert!(!probe_kept(&resolved, 100), "left-aligned nested probe is suppressed");
}

#[test]
fn probe_at_span_end_boundary_is_suppressed() {
    // end == block_end (100+200 == 290+10), start > block_start.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 290, 10)]);
    assert!(!probe_kept(&resolved, 290), "right-aligned nested probe is suppressed");
}

#[test]
fn nested_probe_in_one_of_many_spans_is_suppressed() {
    // Three disjoint spans; probe nested in the MIDDLE one.
    let resolved = resolve_matches(vec![
        span(FILE, 0, 100),
        span(FILE, 1000, 100),
        span(FILE, 2000, 100),
        probe(FILE, 1020, 50),
    ]);
    assert_eq!(count_spans(&resolved), 3, "all three block spans survive");
    assert!(
        !probe_kept(&resolved, 1020),
        "a probe nested in any one of the spans is suppressed"
    );
}

// ── prefix-max correctness: the case a naive last-start check gets WRONG ─────

#[test]
fn wide_early_span_suppresses_probe_past_a_narrow_later_span_start() {
    // span A [0, 1000) is wide; span B [500, 510) starts LATER but is narrow.
    // probe [505, 900): its start (505) is past B's start, so a naive "rightmost
    // span whose start ≤ 505" picks B [500,510), which does NOT contain it — a
    // false KEEP. The prefix-max index takes max(end) over all starts ≤ 505 =
    // 1000 (from A) ≥ 900 → correctly nested.
    let resolved = resolve_matches(vec![
        span(FILE, 0, 1000),
        span(FILE, 500, 10),
        probe(FILE, 505, 395),
    ]);
    assert!(
        !probe_kept(&resolved, 505),
        "the wide early span must suppress a probe whose start is past a narrow later span"
    );
}

#[test]
fn probe_contained_in_both_overlapping_spans_is_suppressed() {
    // Overlapping spans A [0, 1000), B [500, 1500); probe [600, 700) sits in both.
    let resolved = resolve_matches(vec![
        span(FILE, 0, 1000),
        span(FILE, 500, 1000),
        probe(FILE, 600, 100),
    ]);
    assert!(!probe_kept(&resolved, 600), "a probe inside overlapping spans is suppressed");
}

// ── not nested → kept ───────────────────────────────────────────────────────

#[test]
fn probe_entirely_before_span_is_kept() {
    // probe [0, 50) ends at 50, span starts at 100.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 0, 50)]);
    assert!(probe_kept(&resolved, 0), "a probe before the span is not nested → kept");
}

#[test]
fn probe_entirely_after_span_is_kept() {
    // span [100, 300); probe [400, 450) is past the end.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 400, 50)]);
    assert!(probe_kept(&resolved, 400), "a probe after the span is not nested → kept");
}

#[test]
fn probe_extending_one_byte_past_span_end_is_kept() {
    // span [100, 300); probe [150, 301) — one byte past block_end (300).
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 150, 151)]);
    assert!(
        probe_kept(&resolved, 150),
        "a probe whose end exceeds the span by one byte is NOT contained → kept"
    );
}

#[test]
fn probe_starting_one_byte_before_span_is_kept() {
    // span [100, 300); probe [99, 200) — starts one byte before block_start (100).
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 99, 101)]);
    assert!(
        probe_kept(&resolved, 99),
        "a probe starting one byte before the span is NOT contained → kept"
    );
}

#[test]
fn probe_straddling_span_left_edge_is_kept() {
    // probe [50, 150) straddles the span's start (100): partial overlap, not nested.
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 50, 100)]);
    assert!(probe_kept(&resolved, 50), "left-straddling probe is not nested → kept");
}

#[test]
fn probe_straddling_span_right_edge_is_kept() {
    // probe [250, 350) straddles the span's end (300).
    let resolved = resolve_matches(vec![span(FILE, 100, 200), probe(FILE, 250, 100)]);
    assert!(probe_kept(&resolved, 250), "right-straddling probe is not nested → kept");
}

#[test]
fn probe_enclosing_two_separate_spans_is_kept() {
    // Two disjoint spans A [100,200), B [400,500); probe [50, 600) encloses BOTH
    // but is contained in NEITHER.
    let resolved = resolve_matches(vec![
        span(FILE, 100, 100),
        span(FILE, 400, 100),
        probe(FILE, 50, 550),
    ]);
    assert!(
        probe_kept(&resolved, 50),
        "a probe enclosing the spans is contained in neither → kept"
    );
}

// ── cross-file isolation ────────────────────────────────────────────────────

#[test]
fn span_in_other_file_does_not_suppress_probe() {
    // Probe in a.txt at the SAME offset a span occupies in b.txt: containment is
    // per-file, so the cross-file span must NOT touch the probe.
    let resolved = resolve_matches(vec![span("b.txt", 100, 200), probe("a.txt", 120, 50)]);
    assert!(
        probe_kept(&resolved, 120),
        "a private-key span in a different file must not suppress this file's probe"
    );
}

#[test]
fn only_same_file_span_suppresses_when_two_files_each_have_a_span() {
    // a.txt span [0,500); b.txt span [0,500). Probe nested in a.txt is suppressed;
    // an identically-offset probe in c.txt (no span) is kept.
    let resolved = resolve_matches(vec![
        span("a.txt", 0, 500),
        span("b.txt", 0, 500),
        probe("a.txt", 100, 50),
        probe("c.txt", 100, 50),
    ]);
    assert!(
        !resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == PROBE_ID
                && m.location.file_path.as_deref() == Some("a.txt")),
        "the probe in a.txt (which has a covering span) is suppressed"
    );
    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == PROBE_ID
                && m.location.file_path.as_deref() == Some("c.txt")),
        "the probe in c.txt (no span) is kept"
    );
}

#[test]
fn probe_without_file_path_is_kept() {
    // A match with no file_path has no span → it can never be nested → kept.
    let mut no_path = probe(FILE, 120, 50);
    no_path.location.file_path = None;
    let resolved = resolve_matches(vec![span(FILE, 100, 200), no_path]);
    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == PROBE_ID && m.location.file_path.is_none()),
        "a probe with no file path is never nested → kept"
    );
}

// ── block detectors are never self-suppressed ───────────────────────────────

#[test]
fn block_detector_nested_in_another_block_is_not_suppressed() {
    // A second block-detector match nested inside the first block's span is a
    // block detector itself, so the nesting pass leaves it (the early
    // `retain.push(true)` for block detectors); both survive (distinct lines).
    let mut inner = at(SPAN_ID, FILE, 120, 50, 99_999);
    inner.detector_id = Arc::from("ssh-private-key");
    inner.detector_name = Arc::from("ssh-private-key");
    let resolved = resolve_matches(vec![span(FILE, 100, 200), inner]);
    assert!(span_kept(&resolved, 100), "outer block span kept");
    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "ssh-private-key"),
        "a nested BLOCK detector is never suppressed by the nesting pass"
    );
}

// ── no spans → nothing suppressed ───────────────────────────────────────────

#[test]
fn no_private_key_spans_keeps_every_probe() {
    // No block detectors at all → the early return leaves all probes in place.
    let resolved = resolve_matches(vec![
        probe(FILE, 0, 50),
        probe(FILE, 1000, 50),
        probe(FILE, 2000, 50),
    ]);
    assert_eq!(count_probes(&resolved), 3, "with no spans, every probe is kept");
}

#[test]
fn single_match_is_returned_unchanged() {
    // The resolver short-circuits a one-element set before any pass runs.
    let resolved = resolve_matches(vec![probe(FILE, 120, 50)]);
    assert_eq!(resolved.len(), 1);
    assert!(probe_kept(&resolved, 120));
}

// ── order independence / determinism ────────────────────────────────────────

#[test]
fn suppression_is_independent_of_input_order() {
    let forward = vec![
        span(FILE, 0, 100),
        span(FILE, 1000, 100),
        probe(FILE, 20, 30),
        probe(FILE, 1020, 30),
        probe(FILE, 5000, 30),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();

    let a = resolve_matches(forward);
    let b = resolve_matches(reversed);
    // The (file,line) group sort makes the resolved set canonical regardless of
    // input order, so both orderings yield byte-identical result vectors.
    assert_eq!(a, b, "resolution must be order-independent");
    // And the outcome is the expected partition: the two nested probes gone,
    // the outside probe and both spans kept.
    assert!(!probe_kept(&a, 20) && !probe_kept(&a, 1020));
    assert!(probe_kept(&a, 5000));
    assert_eq!(count_spans(&a), 2);
}

// ── correctness at scale ────────────────────────────────────────────────────

#[test]
fn many_spans_each_with_a_nested_probe_suppresses_all_probes() {
    const N: usize = 2_000;
    let mut input = Vec::with_capacity(N * 2);
    for i in 0..N {
        let start = i * 1_000;
        input.push(span(FILE, start, 200));
        input.push(probe(FILE, start + 20, 50)); // nested
    }
    let resolved = resolve_matches(input);
    assert_eq!(count_spans(&resolved), N, "every block span survives");
    assert_eq!(count_probes(&resolved), 0, "every nested probe is suppressed");
}

#[test]
fn interleaved_nested_and_outside_probes_partition_correctly() {
    const N: usize = 1_000;
    let mut input = Vec::with_capacity(N * 3);
    for i in 0..N {
        let start = i * 1_000;
        input.push(span(FILE, start, 200));
        input.push(probe(FILE, start + 20, 50)); // nested → suppressed
        input.push(probe(FILE, start + 500, 50)); // in the gap → kept
    }
    let resolved = resolve_matches(input);
    assert_eq!(count_spans(&resolved), N, "all spans kept");
    assert_eq!(
        count_probes(&resolved),
        N,
        "exactly the N gap probes survive; the N nested probes are gone"
    );
    // Spot-check the partition holds per index, not just in aggregate.
    for i in [0usize, N / 2, N - 1] {
        let start = i * 1_000;
        assert!(!probe_kept(&resolved, start + 20), "nested probe {i} suppressed");
        assert!(probe_kept(&resolved, start + 500), "gap probe {i} kept");
    }
}

// ── the algorithmic-DoS bound itself ────────────────────────────────────────

#[test]
fn adversarial_many_spans_and_nested_probes_resolve_within_time_bound() {
    // 40 000 private-key spans + 40 000 nested probes in ONE file. The previous
    // O(matches × spans) scan would do ~1.6e9 containment comparisons here
    // (multiple seconds); the prefix-max index does ~80 000·log₂(40 000) ≈ 1.3M.
    // Build the input OUTSIDE the timer so it measures resolution only.
    const N: usize = 40_000;
    let mut input = Vec::with_capacity(N * 2);
    for i in 0..N {
        let start = i * 1_000;
        input.push(span(FILE, start, 200));
        input.push(probe(FILE, start + 20, 50));
    }

    let begin = Instant::now();
    let resolved = resolve_matches(input);
    let elapsed = begin.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "nesting suppression over {N} spans + {N} probes took {elapsed:?}; the prefix-max \
         index resolves this in milliseconds — exceeding 5s means the O(matches × spans) \
         scan was reintroduced (algorithmic-DoS, Law 7)"
    );
    // The bound is only meaningful alongside correctness: the work was real.
    assert_eq!(count_spans(&resolved), N, "all {N} spans survive the fast path");
    assert_eq!(count_probes(&resolved), 0, "all {N} nested probes are suppressed");
}
