//! Production-path validation: a detector whose declared capture `group` is
//! out of range for its compiled regex is rejected at COMPILE time, for ANY
//! detector source (the embedded corpus or a user `--detectors` overlay).
//!
//! `detector_capture_group_integrity.rs` is a CI guard that locks the EMBEDDED
//! corpus clean. It cannot see a user-supplied overlay. The real defense is in
//! `compiler_compile::compile_pattern`, which now checks
//! `group < regex.captures_len()` and fails closed with
//! `ScanError::CaptureGroupOutOfRange`. Without it, an out-of-range group is not
//! a regex error — the pattern compiles — but at scan time
//! `extract_grouped_matches` does `locs.get(group).unwrap_or((full_start,
//! full_end))` and SILENTLY captures the whole match (keyword + separator +
//! value) instead of the secret (Law 10: no silent fallback).
//!
//! These tests drive the real public `CompiledScanner::compile` / `scan` path
//! (not a private seam), so they prove the shipped behaviour, and assert real
//! captured values (Law 6).

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanError};

/// A single-pattern detector with the given regex and declared capture group.
fn detector(regex: &str, group: Option<usize>) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "test-detector".into(),
        name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..Default::default()
    }
}

/// Compile a one-pattern detector and report whether it built.
fn compiles(regex: &str, group: Option<usize>) -> bool {
    CompiledScanner::compile(vec![detector(regex, group)]).is_ok()
}

/// Compile and return the error (panics if it unexpectedly built).
fn compile_err(regex: &str, group: Option<usize>) -> ScanError {
    CompiledScanner::compile(vec![detector(regex, group)])
        .err()
        .expect("expected compile to fail for an out-of-range capture group")
}

// ── accepts: in-bounds (and whole-match) groups ─────────────────────────────

#[test]
fn accepts_no_declared_group() {
    assert!(compiles(r"AKIA[0-9A-Z]{16}", None));
}

#[test]
fn accepts_group_zero_whole_match() {
    // Group 0 is always valid: the implicit whole-match group.
    assert!(compiles(r"AKIA[0-9A-Z]{16}", Some(0)));
}

#[test]
fn accepts_group_one_on_a_one_group_regex() {
    assert!(compiles(r"secret=(\w+)", Some(1)));
}

#[test]
fn accepts_group_two_on_a_two_group_regex() {
    assert!(compiles(r"(\w+)=(\w+)", Some(2)));
}

#[test]
fn accepts_group_at_the_exact_upper_edge() {
    // captures_len 3 (group0 + 2 explicit); group 2 is the highest valid index.
    assert!(compiles(r"(\w+)-(\w+)", Some(2)));
}

#[test]
fn accepts_named_capture_group() {
    assert!(compiles(r"secret=(?P<value>\w+)", Some(1)));
}

#[test]
fn accepts_group_one_after_a_leading_non_capturing_group() {
    // `(?:secret|token)` does not capture, so the real group 1 is `(\w+)`.
    assert!(compiles(r"(?:secret|token)=(\w+)", Some(1)));
}

// ── rejects: out-of-range groups (fail closed) ──────────────────────────────

#[test]
fn rejects_group_two_on_a_one_group_regex() {
    // The headline silent-mis-capture bug.
    assert!(!compiles(r"secret=(\w+)", Some(2)));
}

#[test]
fn rejects_group_one_on_a_zero_group_regex() {
    assert!(!compiles(r"AKIA[0-9A-Z]{16}", Some(1)));
}

#[test]
fn rejects_a_far_out_of_range_group() {
    assert!(!compiles(r"(\w+)=(\w+)", Some(5)));
}

#[test]
fn rejects_group_one_past_the_upper_edge() {
    // captures_len 3; group 3 does not exist.
    assert!(!compiles(r"(\w+)-(\w+)", Some(3)));
}

#[test]
fn rejects_group_equal_to_captures_len() {
    // captures_len 2 => valid indices {0,1}; group 2 == captures_len is invalid.
    assert!(!compiles(r"secret=(\w+)", Some(2)));
}

#[test]
fn rejects_group_when_only_non_capturing_groups_are_present() {
    // `(?:...)` never captures, so captures_len is 1 and group 1 is invalid.
    assert!(!compiles(r"(?:secret)(?:token)[0-9]{10}", Some(1)));
}

// ── error contract (context + fix) ──────────────────────────────────────────

#[test]
fn error_is_the_capture_group_out_of_range_variant() {
    let err = compile_err(r"secret=(\w+)", Some(2));
    assert!(matches!(err, ScanError::CaptureGroupOutOfRange { .. }));
}

#[test]
fn error_carries_the_declared_group_and_captures_len() {
    let err = compile_err(r"secret=(\w+)", Some(2));
    match err {
        ScanError::CaptureGroupOutOfRange { group, captures_len, .. } => {
            assert_eq!(group, 2, "declared group must be reported verbatim");
            assert_eq!(captures_len, 2, "one-group regex has captures_len 2 (group0 + group1)");
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn error_message_names_the_detector_id() {
    let err = compile_err(r"secret=(\w+)", Some(2));
    assert!(
        err.to_string().contains("test-detector"),
        "error must name the offending detector: {err}"
    );
}

#[test]
fn error_message_includes_a_fix_hint() {
    let err = compile_err(r"secret=(\w+)", Some(2));
    assert!(err.to_string().contains("Fix:"), "error must include a Fix hint: {err}");
}

// ── multi-pattern: the offending pattern index is reported ──────────────────

#[test]
fn multi_pattern_detector_reports_the_offending_pattern_index() {
    // Pattern 0 is valid; pattern 1 declares an out-of-range group. The error
    // must point at index 1, not 0.
    let det = DetectorSpec {
        tests: Vec::new(),
        id: "multi".into(),
        name: "Multi".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![
            PatternSpec {
                regex: r"secret=(\w+)".into(),
                description: None,
                group: Some(1),
                client_safe: false,
            },
            PatternSpec {
                regex: r"token=(\w+)".into(),
                description: None,
                group: Some(2),
                client_safe: false,
            },
        ],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..Default::default()
    };
    match CompiledScanner::compile(vec![det]).err() {
        Some(ScanError::CaptureGroupOutOfRange { index, group, .. }) => {
            assert_eq!(index, 1, "must report the second pattern as the offender");
            assert_eq!(group, 2);
        }
        other => panic!("expected CaptureGroupOutOfRange at index 1, got {other:?}"),
    }
}

// ── the embedded corpus still compiles (no clean detector broken) ───────────

#[test]
fn embedded_corpus_still_compiles_after_group_validation() {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus must load");
    assert!(
        CompiledScanner::compile(detectors).is_ok(),
        "the group-bound validation must not reject any embedded detector"
    );
}

// ── behavioural: an in-bounds group captures the group value, not the match ─

#[test]
fn in_bounds_group_captures_the_group_value_not_the_whole_match() {
    // group 1 is `([A-Za-z0-9]{20,})`; the captured credential must be the value
    // alone, never the whole `secret = <value>` match. The value carries no
    // known prefix (so no checksum gate drops it) and no placeholder word.
    let value = "Qz7mWp2RkLx9Vn4Bt6Hs8";
    let scanner = CompiledScanner::compile(vec![detector(
        r"(?i)secret\s*=\s*([A-Za-z0-9]{20,})",
        Some(1),
    )])
    .expect("valid detector compiles");
    let chunk = Chunk {
        data: format!("secret = {value}\n").into(),
        metadata: ChunkMetadata {
            path: Some("config.env".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == value),
        "expected credential {value:?}, got {:?}",
        matches.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
    assert!(
        !matches.iter().any(|m| m.credential.as_ref().contains("secret =")),
        "credential must not include the keyword/separator (whole-match capture)"
    );
}
