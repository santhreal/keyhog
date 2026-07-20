//! Production-path validation: a detector whose declared capture `group` is
//! out of range for its compiled regex is rejected at COMPILE time, for ANY
//! detector source (the embedded corpus or a user `--detectors` overlay).
//!
//! `detector_capture_group_integrity.rs` locks the embedded corpus clean. The
//! production defense is `CompiledScanner::compile`, which runs the detector
//! corpus quality gate before
//! compiling regex programs. The gate rejects `group` values outside the
//! regex capture range and reports the detector, pattern index, declared group,
//! and explicit capture count. This prevents a malformed programmatic detector
//! from reaching any backend.
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
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
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
fn error_is_a_corpus_quality_gate_configuration_error() {
    let err = compile_err(r"secret=(\w+)", Some(2));
    assert!(matches!(err, ScanError::Config(_)));
}

#[test]
fn error_carries_the_declared_group_and_explicit_capture_count() {
    let error = compile_err(r"secret=(\w+)", Some(2)).to_string();
    assert!(
        error.contains("capture group 2 is out of range"),
        "declared group must be reported verbatim: {error}"
    );
    assert!(
        error.contains("regex has 1 capture groups (valid group indexes are 0..1)"),
        "explicit capture count and valid indexes must be reported: {error}"
    );
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
    assert!(
        err.to_string().contains("Fix:"),
        "error must include a Fix hint: {err}"
    );
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
                required_literals: Vec::new(),
                client_safe: false,
                weak_anchor: false,
                structural_password_slot: false,
            },
            PatternSpec {
                regex: r"token=(\w+)".into(),
                description: None,
                group: Some(2),
                required_literals: Vec::new(),
                client_safe: false,
                weak_anchor: false,
                structural_password_slot: false,
            },
        ],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let error = CompiledScanner::compile(vec![det])
        .err()
        .expect("second pattern must fail capture validation")
        .to_string();
    assert!(
        error.contains("pattern 1 capture group 2 is out of range"),
        "error must identify the second pattern and invalid group: {error}"
    );
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
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
    assert!(
        !matches
            .iter()
            .any(|m| m.credential.as_ref().contains("secret =")),
        "credential must not include the keyword/separator (whole-match capture)"
    );
}
