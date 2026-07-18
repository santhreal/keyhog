//! Regression: `.keyhogignore.toml` rule-suppression path/detector predicates.
//!
//! Every assertion pins an exact suppression bool or error variant.
//!
//! This is an EXTERNAL integration crate: it uses only the public API surface
//! re-exported from `keyhog_core` (via `api::*`), never `#[cfg(test)]` helpers.

use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use keyhog_core::{
    MatchLocation, RuleSuppressor, RuleSuppressorError, Severity, VerificationResult,
    VerifiedFinding,
};

fn finding(
    detector: &str,
    service: &str,
    sev: Severity,
    path: &str,
    hash: &str,
) -> VerifiedFinding {
    finding_opt_path(detector, service, sev, Some(path), hash)
}

fn finding_opt_path(
    detector: &str,
    service: &str,
    sev: Severity,
    path: Option<&str>,
    hash: &str,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: sev,
        credential_redacted: Cow::Borrowed("REDACTED"),
        credential_hash: {
            let mut bytes = [0u8; 32];
            let hb = hash.as_bytes();
            let len = hb.len().min(bytes.len());
            bytes[..len].copy_from_slice(&hb[..len]);
            bytes.into()
        },
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: path.map(Arc::from),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        confidence: Some(0.9),
    }
}

fn parse(toml: &str) -> RuleSuppressor {
    RuleSuppressor::from_str(toml).expect("suppressor should parse")
}

/// A detector-only rule matches exactly the named detector and nothing else.
#[test]
fn detector_predicate_matches_only_that_detector() {
    let s = parse("[[suppress]]\ndetector = \"aws-access-key\"\n");
    let aws = finding("aws-access-key", "aws", Severity::Critical, "x.rs", "h1");
    let ghp = finding("github-pat", "github", Severity::Critical, "x.rs", "h2");
    assert!(s.matches(&aws));
    assert!(!s.matches(&ghp));
}

/// `detector` + `path_contains` in ONE table combine with AND: the finding is
/// suppressed iff BOTH hold. All four truth-table corners are pinned.
#[test]
fn detector_and_path_combine_with_and() {
    let s = parse("[[suppress]]\ndetector = \"aws-access-key\"\npath_contains = \"/tests/\"\n");
    let both = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "src/tests/x.rs",
        "h",
    );
    let det_only = finding("aws-access-key", "aws", Severity::High, "src/main.rs", "h");
    let path_only = finding(
        "github-pat",
        "github",
        Severity::High,
        "src/tests/x.rs",
        "h",
    );
    let neither = finding("github-pat", "github", Severity::High, "src/main.rs", "h");
    assert!(s.matches(&both)); // detector AND path
    assert!(!s.matches(&det_only)); // detector but not path
    assert!(!s.matches(&path_only)); // path but not detector
    assert!(!s.matches(&neither)); // neither
}

/// Two path predicates in ONE table AND together: only a path satisfying both
/// prefix and suffix is suppressed.
#[test]
fn path_predicates_and_within_one_table() {
    let s = parse("[[suppress]]\npath_starts_with = \"src/\"\npath_ends_with = \".rs\"\n");
    assert!(s.matches(&finding("d", "s", Severity::Low, "src/main.rs", "h")));
    assert!(!s.matches(&finding("d", "s", Severity::Low, "src/main.py", "h"))); // wrong suffix
    assert!(!s.matches(&finding("d", "s", Severity::Low, "lib/main.rs", "h"))); // wrong prefix
}

/// Separate `[[suppress]]` tables combine with OR: each matches its own path
/// shape; a path matching none is kept.
#[test]
fn multiple_suppress_tables_combine_with_or() {
    let toml = "[[suppress]]\npath_starts_with = \"vendor/\"\n\n\
                [[suppress]]\npath_ends_with = \".min.js\"\n\n\
                [[suppress]]\npath_regex = \"^docs/[a-z]+\\\\.md$\"\n";
    let s = parse(toml);
    assert!(s.matches(&finding("d", "s", Severity::High, "vendor/lib/foo.rs", "h")));
    assert!(s.matches(&finding("d", "s", Severity::High, "dist/app.min.js", "h")));
    assert!(s.matches(&finding("d", "s", Severity::High, "docs/readme.md", "h")));
    assert!(!s.matches(&finding("d", "s", Severity::High, "src/main.rs", "h")));
}

/// `path_eq` is a WHOLE-string equality, not a substring/prefix test.
#[test]
fn path_eq_is_exact_not_substring() {
    let s = parse("[[suppress]]\npath_eq = \"fixtures/stripe.yml\"\n");
    assert!(s.matches(&finding(
        "d",
        "s",
        Severity::Low,
        "fixtures/stripe.yml",
        "h"
    )));
    // A superstring that merely CONTAINS the eq value must NOT match.
    assert!(!s.matches(&finding(
        "d",
        "s",
        Severity::Low,
        "a/fixtures/stripe.yml",
        "h"
    )));
    assert!(!s.matches(&finding(
        "d",
        "s",
        Severity::Low,
        "fixtures/stripe.yml.bak",
        "h"
    )));
}

/// `path_regex` respects its anchors: `^tests/.*\.rs$` matches only anchored.
#[test]
fn path_regex_anchors_exact() {
    let s = parse("[[suppress]]\npath_regex = \"^tests/.*\\\\.rs$\"\n");
    assert!(s.matches(&finding("d", "s", Severity::Low, "tests/a/b.rs", "h")));
    assert!(!s.matches(&finding("d", "s", Severity::Low, "x/tests/a.rs", "h"))); // not at start
    assert!(!s.matches(&finding("d", "s", Severity::Low, "tests/a.rst", "h"))); // suffix mismatch
}

/// `service` exact and `severity_lte` rank boundary combine with AND.
#[test]
fn service_and_severity_lte_boundary() {
    let s = parse("[[suppress]]\nservice = \"stripe\"\nseverity_lte = \"medium\"\n");
    // Right service, rank <= medium -> suppressed.
    assert!(s.matches(&finding("d", "stripe", Severity::Medium, "f.rs", "h")));
    assert!(s.matches(&finding("d", "stripe", Severity::Low, "f.rs", "h")));
    // Right service but rank ABOVE medium -> kept.
    assert!(!s.matches(&finding("d", "stripe", Severity::High, "f.rs", "h")));
    // Rank ok but wrong service -> kept (AND fails).
    assert!(!s.matches(&finding("d", "github", Severity::Low, "f.rs", "h")));
}

/// `severity` is an EXACT equality on the tier, not `<=`.
#[test]
fn severity_predicate_is_exact_equality() {
    let s = parse("[[suppress]]\nseverity = \"high\"\n");
    assert!(s.matches(&finding("d", "s", Severity::High, "f.rs", "h")));
    assert!(!s.matches(&finding("d", "s", Severity::Critical, "f.rs", "h")));
    assert!(!s.matches(&finding("d", "s", Severity::Medium, "f.rs", "h")));
}

/// `credential_hash` matches on the lower-case 64-char hex of the raw digest.
/// The builder writes ASCII "h1" (0x68,0x31) into the first two bytes, so the
/// hex form is exactly "6831" followed by 60 zeros.
#[test]
fn credential_hash_exact_hex_match() {
    let hex = format!("6831{}", "0".repeat(60));
    assert_eq!(hex.len(), 64);
    let s = parse(&format!("[[suppress]]\ncredential_hash = \"{hex}\"\n"));
    let f = finding("d", "s", Severity::Low, "f.rs", "h1");
    assert!(s.matches(&f));
    // A different hash (all zeros) must NOT match the same finding.
    let other = parse(&format!(
        "[[suppress]]\ncredential_hash = \"{}\"\n",
        "0".repeat(64)
    ));
    assert!(!other.matches(&f));
}

/// A finding with NO file_path (`None`) is recall-safe: path-scoped rules see
/// the empty string and do NOT suppress it, but non-path rules still apply.
#[test]
fn missing_file_path_is_recall_safe() {
    let path_rule = parse("[[suppress]]\npath_contains = \"src\"\n");
    let det_rule = parse("[[suppress]]\ndetector = \"aws-access-key\"\n");
    let f = finding_opt_path("aws-access-key", "aws", Severity::High, None, "h");
    assert!(!path_rule.matches(&f)); // path predicate cannot suppress a pathless finding
    assert!(det_rule.matches(&f)); // detector predicate still fires
}

/// An empty suppressor (no rules) suppresses nothing.
#[test]
fn empty_suppressor_matches_nothing() {
    let s = parse("");
    assert!(!s.matches(&finding(
        "aws-access-key",
        "aws",
        Severity::Critical,
        "x.rs",
        "h"
    )));
}

/// A `[[suppress]]` table with no conditions is a Schema error at rule 0 with
/// the canonical "no conditions" message (never a match-everything rule).
#[test]
fn empty_suppress_entry_is_schema_error() {
    let err = RuleSuppressor::from_str("[[suppress]]\n").expect_err("empty entry must error");
    match err {
        RuleSuppressorError::Schema {
            rule_index,
            message,
        } => {
            assert_eq!(rule_index, 0);
            assert!(
                message.contains("no conditions specified"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

/// An unknown field is rejected (schema is `deny_unknown_fields`) as a Toml
/// error (a typo'd predicate name fails closed rather than silently no-op).
#[test]
fn unknown_field_is_rejected() {
    // `path_contain` (missing trailing s) is a typo of `path_contains`.
    let err = RuleSuppressor::from_str("[[suppress]]\npath_contain = \"x\"\n")
        .expect_err("unknown field must error");
    match err {
        RuleSuppressorError::Toml(_) => {}
        other => panic!("expected Toml error, got {other:?}"),
    }
}

/// The deliberately noisy escape hatch documented in the parser error really
/// is unconditional. This proves behavior, not merely schema acceptance.
#[test]
fn literal_true_explicitly_suppresses_every_finding() {
    let suppressor = parse("[[suppress]]\nliteral_true = true\n");
    let finding = finding(
        "github-pat",
        "github",
        Severity::Critical,
        "src/production.rs",
        "unique-hash",
    );
    assert!(suppressor.matches(&finding));
}

/// `literal_true = false` is not a condition and cannot smuggle an empty,
/// match-everything rule through the empty-table guard.
#[test]
fn literal_true_false_alone_is_rejected() {
    let error = RuleSuppressor::from_str("[[suppress]]\nliteral_true = false\n")
        .expect_err("false is not an unconditional predicate");
    assert!(matches!(
        error,
        RuleSuppressorError::Schema { rule_index: 0, .. }
    ));
}
