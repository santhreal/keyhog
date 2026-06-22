//! Adversarial SPEED / OPTIMIZATION audit (KEY: speed).
//!
//! Each test pins a redundant-work / avoidable-O(n^2) regression on a scanner
//! hot path. Every test FAILS on the current tree (documenting the defect) and
//! is expected to PASS once the underlying hot-path inefficiency is fixed. The
//! thresholds carry large headroom (10x-100x) so ordinary machine/CI variance
//! never flips them; only the asymptotic/constant-factor blowup they target
//! trips them.
//!
//! These are throughput TRIPWIRES, not micro-benchmarks. They run under the
//! default `cargo test` (debug) profile, so the floors are set against
//! debug-profile timings (the slowest case) with headroom for slower CI hosts.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::testing::compute_line_offsets;
use keyhog_scanner::testing::{line_number_for_offset, record_window_match};
use keyhog_scanner::testing::{CompiledCompanion, ScannerPreprocessedText};
use regex::Regex;

/// AUD-speed-1 — `find_companion` does an O(L) LINEAR scan of `preprocessed.mappings`
/// per call, where the sibling lookup is already O(log L).
///
/// Evidence:
///   crates/scanner/src/pipeline/context_window.rs:191  `line_window_offsets`
///     ```
///     for mapping in &preprocessed.mappings {            // O(L) over EVERY line
///         if start_offset.is_none() && mapping.line_number >= start_line { ... }
///         if mapping.line_number <= end_line { end_offset = Some(...); }
///     }
///     ```
///   This walks all `L` line-mappings on every call, regardless of where the
///   companion window sits in the file. `find_companion`
///   (context_window.rs:102) calls it once per surviving match of every
///   detector that declares companions (twilio-auth-token, etc.), so on an
///   L-line file with N companion-bearing matches the cost is O(N*L).
///
///   The mappings are stored in `line_number`-monotonic, contiguous order —
///   the SAME invariant the sibling `PreprocessedText::line_for_offset`
///   (crates/scanner/src/multiline/config.rs:50 and src/types.rs:133)
///   already relies on to resolve its lookup with `partition_point` in
///   O(log L). `line_window_offsets` left the linear walk in place.
///
/// Measured (debug, dev box): 2000 `find_companion` calls over a 500k-line
/// preprocessed text = ~2807 ms. The same 2000 calls resolved with the
/// existing `line_for_offset` binary search = ~0.22 ms (a ~12,800x gap).
///
/// Expected fix: replace the linear `for mapping in &preprocessed.mappings`
/// walk in `line_window_offsets` with two `partition_point` binary searches
/// (first mapping with `line_number >= start_line` for the start offset; last
/// mapping with `line_number <= end_line` for the end offset), mirroring
/// `line_for_offset`. Output must be byte-identical; only the asymptotics
/// change (O(L) -> O(log L)).
///
/// Threshold 500 ms: current ~2807 ms fails by >5x even before CI slowdown;
/// the fixed binary-search path (~0.2 ms) passes with >2000x headroom.
#[test]
fn find_companion_window_lookup_is_not_linear_in_file_lines() {
    const LINES: usize = 500_000;
    const CALLS: usize = 2_000;
    const FLOOR_MS: f64 = 500.0;

    // Build an L-line text. Each line is a short token; offsets are monotonic.
    let mut text = String::with_capacity(LINES * 8);
    for i in 0..LINES {
        text.push_str("ln");
        text.push_str(&i.to_string());
        text.push('\n');
    }
    let pp = ScannerPreprocessedText::passthrough(&text);
    assert!(
        pp.mappings.len() >= LINES,
        "fixture should produce >= {LINES} line-mappings, got {}",
        pp.mappings.len()
    );

    // Companion with a 3-line window pinned at the TOP of the file (primary on
    // line 2, within_lines = 1 => lines 1..=3). The haystack the regex scans is
    // therefore tiny (~12 bytes), so any time spent is dominated by the
    // `line_window_offsets` scan, NOT regex work. The regex never matches, so
    // we exercise the full window-resolution path on every call.
    let companion = CompiledCompanion {
        name: "audit-companion".to_string(),
        regex: Regex::new("ZZZ_NO_MATCH_ZZZ").expect("valid regex"),
        capture_group: None,
        within_lines: 1,
        required: false,
    };

    let start = Instant::now();
    let mut sink = 0usize;
    for _ in 0..CALLS {
        let found = keyhog_scanner::testing::find_companion(&pp, 2, &companion);
        sink = sink.wrapping_add(found.map(|s| s.len()).unwrap_or(0));
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    // Pin the correctness invariant the optimization must preserve: the regex
    // never matches inside the top-of-file window, so the companion is absent.
    assert_eq!(sink, 0, "companion fixture should never match");

    eprintln!(
        "AUD-speed-1: {CALLS} find_companion calls over {LINES} lines = {elapsed_ms:.1} ms \
         (floor {FLOOR_MS:.0} ms)"
    );
    assert!(
        elapsed_ms < FLOOR_MS,
        "find_companion is O(file-lines) per call: {CALLS} calls over {LINES} lines took \
         {elapsed_ms:.1} ms (floor {FLOOR_MS:.0} ms). `line_window_offsets` \
         (crates/scanner/src/pipeline/context_window.rs:191) linearly scans ALL \
         `preprocessed.mappings` on every call; the monotonic-mappings invariant that \
         `PreprocessedText::line_for_offset` already exploits with `partition_point` makes \
         a binary search correct here. Replace the `for mapping in &preprocessed.mappings` \
         walk with two `partition_point` searches (start_line lower-bound, end_line \
         upper-bound).",
    );
}

/// AUD-speed-2 — windowed per-match line attribution was O(offset) per match.
///
/// `record_window_match` (crates/scanner/src/engine/windowed.rs) used to call
/// `line_number_for_offset(full_text, offset)`, which counts newlines from the
/// buffer start on EVERY match. `scan_windowed` runs it once per surviving match
/// of a chunk larger than `MAX_SCAN_CHUNK_BYTES` (1 MiB), so on a match-dense
/// multi-MiB buffer (a minified bundle, a credentials dump, a generated blob)
/// the cost is Σ O(offsetᵢ) = O(n²). Measured on the real scanner this showed
/// as cpu ns/byte jumping 988 → 2227 at the 1 MiB windowing boundary.
///
/// Fix: `scan_windowed` precomputes `compute_line_offsets(chunk_text)` once and
/// `record_window_match` resolves each match's line with `partition_point`
/// (O(log L)) — byte-identical to the newline count, proven below against the
/// `line_number_for_offset` reference.
///
/// This drives the real `record_window_match` with end-of-buffer offsets (the
/// old path's worst case). The O(log L) path finishes in well under the floor;
/// the old O(L)-per-call path over 500k lines would take seconds.
#[test]
fn windowed_line_attribution_is_not_linear_in_offset() {
    const LINES: usize = 500_000;
    const CALLS: usize = 5_000;
    const FLOOR_MS: f64 = 300.0;

    let mut text = String::with_capacity(LINES * 8);
    for i in 0..LINES {
        text.push_str("ln");
        text.push_str(&i.to_string());
        text.push('\n');
    }
    let line_offsets = compute_line_offsets(&text);
    assert!(
        line_offsets.len() >= LINES,
        "fixture should produce >= {LINES} line starts, got {}",
        line_offsets.len()
    );

    let mut seen = HashSet::new();
    let mut seen_order = VecDeque::new();

    // Differential correctness: the fast path must agree with the slow
    // newline-count reference for a worst-case (near-end) offset.
    let probe_offset = text.len() - 1;
    let mut probe = demo_window_match(probe_offset);
    assert!(record_window_match(
        &line_offsets,
        0,
        0,
        text.len(),
        &mut probe,
        &mut seen,
        &mut seen_order
    ));
    assert_eq!(
        probe.location.line,
        Some(line_number_for_offset(&text, probe_offset)),
        "partition_point line attribution must equal the newline-count reference"
    );

    // Speed: many matches near the end of the buffer (each a distinct offset so
    // dedup keeps them) — the regime where the old O(offset) walk blew up.
    let start = Instant::now();
    let mut sink = 0usize;
    for k in 0..CALLS {
        let off = probe_offset.saturating_sub(k);
        let mut m = demo_window_match(off);
        if record_window_match(
            &line_offsets,
            0,
            0,
            text.len(),
            &mut m,
            &mut seen,
            &mut seen_order,
        ) {
            sink = sink.wrapping_add(m.location.line.unwrap_or(0));
        }
    }
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert!(sink > 0, "matches should resolve to non-zero line numbers");

    eprintln!(
        "AUD-speed-2: {CALLS} record_window_match calls over {LINES} lines = {elapsed_ms:.1} ms \
         (floor {FLOOR_MS:.0} ms)"
    );
    assert!(
        elapsed_ms < FLOOR_MS,
        "windowed line attribution is O(offset) per match: {CALLS} calls over {LINES} lines took \
         {elapsed_ms:.1} ms (floor {FLOOR_MS:.0} ms). `record_window_match` must resolve the line \
         via `partition_point` over precomputed `compute_line_offsets`, not re-count newlines from \
         the buffer start (`line_number_for_offset`).",
    );
}

fn demo_window_match(offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("aud-speed-2"),
        detector_name: Arc::from("aud-speed-2"),
        service: Arc::from("test"),
        severity: Severity::Low,
        credential: keyhog_core::SensitiveString::from("cred"),
        credential_hash: [7u8; 32],
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: Some(1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}
