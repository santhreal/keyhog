//! Regression: `Severity::from_filter_label`: the CLI/`.keyhogignore.toml`
//! filter-label parse.
//!
//! `Severity::from_filter_label` is `pub(crate)`, so it is exercised here
//! through its public consumer: a `[[suppress]]` table's `severity = "<label>"`
//! field. That field flows label -> `normalise_severity` -> `from_filter_label`
//! (crates/core/src/spec.rs:486) and, on success, compiles into a
//! `FieldInSet { field: "severity", set: [<canonical as_str>] }` predicate.
//! A finding therefore matches (is suppressed) IFF its severity's kebab-case
//! `as_str` equals the label the parser resolved to, which lets each test pin
//! the EXACT `Severity` variant a label parsed to by observing which findings
//! `RuleSuppressor::matches` drops.
//!
//! Everything below is host-independent: pure enum parsing + vyre's CPU rule
//! evaluator, no Hyperscan/SIMD/GPU backend, so every assertion holds
//! identically on an accelerator-less CI box.
//!
//! Distinct from `regression_severity_ordering` (enum `Ord`) and
//! `regression_severity_threshold_suppress` (the `severity_lte` rank expansion):
//! this file pins the `severity` EQUALS label parse and the exact
//! `RuleSuppressorError::Schema` produced on an unknown label.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    CredentialHash, MatchLocation, RuleSuppressor, RuleSuppressorError, Severity,
    VerificationResult, VerifiedFinding,
};

/// The exact expected-labels list `normalise_severity` appends to its error
/// (mirrors `Severity::FILTER_EXPECTED_LABELS` in spec.rs). Pinned as a literal
/// so a drift in the ordering/spelling of the labels fails this test.
const EXPECTED_LABELS: &str = "info|client-safe|low|medium|high|critical";

/// Minimal `VerifiedFinding` carrying an exact severity. Every other field is a
/// fixed, suppression-irrelevant placeholder. All fields are public and the
/// struct is not `#[non_exhaustive]`, so this literal is the construction path.
fn finding(severity: Severity) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test-service"),
        severity,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: CredentialHash::ZERO,
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("src/main.rs")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    }
}

/// Parse a full `.keyhogignore.toml` body through the public `FromStr` surface,
/// panicking with the parse error on a malformed fixture.
fn suppressor(body: &str) -> RuleSuppressor {
    body.parse::<RuleSuppressor>()
        .unwrap_or_else(|e| panic!("suppressor parse failed: {e}"))
}

/// Build a suppressor whose single rule is `severity = "<label>"`.
fn severity_eq(label: &str) -> RuleSuppressor {
    suppressor(&format!("[[suppress]]\nseverity = \"{label}\"\n"))
}

// ---------------------------------------------------------------------------
// Positive: each canonical label parses to EXACTLY its own variant.
// A label that parsed to the right variant suppresses that severity and NO
// neighbouring severity.
// ---------------------------------------------------------------------------

#[test]
fn label_critical_parses_to_critical_variant_only() {
    let s = severity_eq("critical");
    assert!(s.matches(&finding(Severity::Critical)));
    // Neighbours and extremes must NOT match, proves it resolved to exactly
    // Critical, not "critical-or-anything-else".
    assert!(!s.matches(&finding(Severity::High)));
    assert!(!s.matches(&finding(Severity::Medium)));
    assert!(!s.matches(&finding(Severity::Info)));
    assert!(!s.matches(&finding(Severity::ClientSafe)));
}

#[test]
fn label_high_parses_to_high_variant_only() {
    let s = severity_eq("high");
    assert!(s.matches(&finding(Severity::High)));
    assert!(!s.matches(&finding(Severity::Critical)));
    assert!(!s.matches(&finding(Severity::Medium)));
}

#[test]
fn label_medium_parses_to_medium_variant_only() {
    let s = severity_eq("medium");
    assert!(s.matches(&finding(Severity::Medium)));
    assert!(!s.matches(&finding(Severity::High)));
    assert!(!s.matches(&finding(Severity::Low)));
}

#[test]
fn label_low_parses_to_low_variant_not_client_safe_below_it() {
    let s = severity_eq("low");
    assert!(s.matches(&finding(Severity::Low)));
    assert!(!s.matches(&finding(Severity::Medium)));
    // Adversarial twin: ClientSafe ranks BELOW Low but is a DISTINCT tier, so an
    // EQUALS match on "low" must not leak into client-safe (unlike severity_lte).
    assert!(!s.matches(&finding(Severity::ClientSafe)));
    assert!(!s.matches(&finding(Severity::Info)));
}

#[test]
fn label_info_parses_to_info_variant_not_client_safe_above_it() {
    let s = severity_eq("info");
    assert!(s.matches(&finding(Severity::Info)));
    // ClientSafe ranks just ABOVE Info (an EQUALS "info" must not catch it).
    assert!(!s.matches(&finding(Severity::ClientSafe)));
    assert!(!s.matches(&finding(Severity::Low)));
}

// ---------------------------------------------------------------------------
// Alias: `client_safe` (underscore) and `client-safe` (hyphen) both resolve to
// the same ClientSafe variant, and neither leaks into Low/Info.
// ---------------------------------------------------------------------------

#[test]
fn alias_client_safe_underscore_parses_to_client_safe_variant() {
    let s = severity_eq("client_safe");
    assert!(s.matches(&finding(Severity::ClientSafe)));
    assert!(!s.matches(&finding(Severity::Low)));
    assert!(!s.matches(&finding(Severity::Info)));
}

#[test]
fn alias_client_safe_hyphen_matches_underscore_alias_exactly() {
    let hyphen = severity_eq("client-safe");
    let underscore = severity_eq("client_safe");
    // Both aliases must agree on every tier: same match verdict everywhere.
    for tier in [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(
            hyphen.matches(&finding(tier)),
            underscore.matches(&finding(tier)),
            "alias disagreement on {tier:?}"
        );
    }
    // And both suppress exactly ClientSafe.
    assert!(hyphen.matches(&finding(Severity::ClientSafe)));
    assert!(underscore.matches(&finding(Severity::ClientSafe)));
    assert!(!hyphen.matches(&finding(Severity::Info)));
}

// ---------------------------------------------------------------------------
// Case + whitespace handling: `from_filter_label` trims then lowercases.
// ---------------------------------------------------------------------------

#[test]
fn uppercase_label_parses_same_as_lowercase() {
    let upper = severity_eq("CRITICAL");
    assert!(upper.matches(&finding(Severity::Critical)));
    assert!(!upper.matches(&finding(Severity::High)));
}

#[test]
fn mixed_case_label_parses_to_expected_variant() {
    let mixed = severity_eq("MeDiUm");
    assert!(mixed.matches(&finding(Severity::Medium)));
    assert!(!mixed.matches(&finding(Severity::Low)));
    assert!(!mixed.matches(&finding(Severity::High)));
}

#[test]
fn surrounding_whitespace_is_trimmed_before_parse() {
    let padded = severity_eq("   high   ");
    assert!(padded.matches(&finding(Severity::High)));
    assert!(!padded.matches(&finding(Severity::Critical)));
}

// ---------------------------------------------------------------------------
// Negative / adversarial: unknown labels error with the EXACT Schema message.
// ---------------------------------------------------------------------------

#[test]
fn unknown_label_errors_with_exact_schema_message_and_index_zero() {
    let err = "[[suppress]]\nseverity = \"urgent\"\n"
        .parse::<RuleSuppressor>()
        .expect_err("unknown severity label must be rejected");
    // Display first (borrows) so the value can then be matched (moves).
    let display = err.to_string();
    assert_eq!(
        display,
        "schema error in [[suppress]] entry 0: \
         unknown severity \"urgent\"; expected info|client-safe|low|medium|high|critical"
    );
    match err {
        RuleSuppressorError::Schema {
            rule_index,
            message,
        } => {
            assert_eq!(rule_index, 0);
            assert_eq!(
                message,
                format!("unknown severity \"urgent\"; expected {EXPECTED_LABELS}")
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

#[test]
fn unknown_label_error_message_reflects_lowercased_trimmed_input() {
    // `normalise_severity` echoes the input as `{:?}` of its trimmed+lowercased
    // form (so "  URGENT  " reports as "urgent", not "  URGENT  ").
    let err = "[[suppress]]\nseverity = \"  URGENT  \"\n"
        .parse::<RuleSuppressor>()
        .expect_err("unknown severity label must be rejected");
    match err {
        RuleSuppressorError::Schema { message, .. } => {
            assert_eq!(
                message,
                format!("unknown severity \"urgent\"; expected {EXPECTED_LABELS}")
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

#[test]
fn empty_label_is_unknown_and_errors_exactly() {
    let err = "[[suppress]]\nseverity = \"\"\n"
        .parse::<RuleSuppressor>()
        .expect_err("empty severity label must be rejected");
    match err {
        RuleSuppressorError::Schema {
            rule_index,
            message,
        } => {
            assert_eq!(rule_index, 0);
            assert_eq!(
                message,
                format!("unknown severity \"\"; expected {EXPECTED_LABELS}")
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

#[test]
fn client_safe_without_separator_is_unknown_negative_twin() {
    // Negative twin of the valid `client-safe`/`client_safe` aliases: dropping
    // the separator is NOT accepted.
    let err = "[[suppress]]\nseverity = \"clientsafe\"\n"
        .parse::<RuleSuppressor>()
        .expect_err("`clientsafe` (no separator) must be rejected");
    match err {
        RuleSuppressorError::Schema { message, .. } => {
            assert_eq!(
                message,
                format!("unknown severity \"clientsafe\"; expected {EXPECTED_LABELS}")
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

#[test]
fn unknown_label_in_second_entry_reports_rule_index_one() {
    // First entry is valid (parses fine); the unknown label is in entry index 1,
    // so the Schema error must carry rule_index == 1, not 0.
    let err = concat!(
        "[[suppress]]\n",
        "detector = \"aws-access-key\"\n",
        "\n",
        "[[suppress]]\n",
        "severity = \"bogus\"\n",
    )
    .parse::<RuleSuppressor>()
    .expect_err("second-entry unknown severity must be rejected");
    match err {
        RuleSuppressorError::Schema {
            rule_index,
            message,
        } => {
            assert_eq!(rule_index, 1);
            assert_eq!(
                message,
                format!("unknown severity \"bogus\"; expected {EXPECTED_LABELS}")
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}
