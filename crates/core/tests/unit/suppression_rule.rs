//! Unit tests for declarative rule suppression logic.

use keyhog_core::suppression::RuleSuppressor;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

fn test_finding(path: &str, sev: Severity) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-det"),
        detector_name: Arc::from("test-det"),
        service: Arc::from("test-svc"),
        severity: sev,
        credential_redacted: Cow::Borrowed("REDACTED"),
        credential_hash: [0u8; 32].into(),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path)),
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
        evidence_score: Some(0.9),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

#[test]
fn test_suppression_rule_preserves_whitespace_verbatim() {
    let toml = r#"
[[suppress]]
detector = "  spaced-detector  "

[[suppress]]
service = "  spaced-service  "

[[suppress]]
path_contains = " with spaces "
"#;
    let s: RuleSuppressor = toml.parse().expect("rule should parse");

    // Rule with spaced detector should NOT match finding with trimmed detector
    let mut finding_trimmed_det = test_finding("src/lib.rs", Severity::Low);
    finding_trimmed_det.detector_id = "spaced-detector".into();
    assert!(!s.matches(&finding_trimmed_det));

    // Rule with spaced detector MUST match finding with exact spaced detector
    let mut finding_exact_det = test_finding("src/lib.rs", Severity::Low);
    finding_exact_det.detector_id = "  spaced-detector  ".into();
    assert!(s.matches(&finding_exact_det));

    // Rule with path_contains = " with spaces " should only match paths containing " with spaces "
    let finding_no_spaces = test_finding("src/with_underscores/file.rs", Severity::Low);
    let finding_without_surrounding_spaces = test_finding("src/with spaces/file.rs", Severity::Low);
    let finding_with_surrounding_spaces =
        test_finding("src/path with spaces in name/file.rs", Severity::Low);
    assert!(!s.matches(&finding_no_spaces));
    assert!(!s.matches(&finding_without_surrounding_spaces));
    assert!(s.matches(&finding_with_surrounding_spaces));
}

#[test]
fn test_severity_suppression_matching() {
    let toml = r#"
[[suppress]]
severity = "low"

[[suppress]]
severity_lte = "medium"
"#;
    let s: RuleSuppressor = toml.parse().expect("rule should parse");
    let low_f = test_finding("src/main.rs", Severity::Low);
    let med_f = test_finding("src/main.rs", Severity::Medium);
    let crit_f = test_finding("src/main.rs", Severity::Critical);

    assert!(s.matches(&low_f));
    assert!(s.matches(&med_f));
    assert!(!s.matches(&crit_f));
}

#[test]
fn test_exact_literal_path_regex_optimization() {
    let toml = r#"
[[suppress]]
path_regex = "^fixtures/exact.yml$"
"#;
    let s: RuleSuppressor = toml.parse().expect("rule should parse");
    let match_f = test_finding("fixtures/exact.yml", Severity::Low);
    let no_match_f = test_finding("fixtures/exact.yml.other", Severity::Low);
    let no_match_prefix = test_finding("other/fixtures/exact.yml", Severity::Low);

    assert!(s.matches(&match_f));
    assert!(!s.matches(&no_match_f));
    assert!(!s.matches(&no_match_prefix));
}

#[test]
fn test_prefix_and_suffix_path_regex_optimization() {
    let toml = r#"
[[suppress]]
path_regex = "^vendor/.*"

[[suppress]]
path_regex = ".*\\.min\\.js$"
"#;
    let s: RuleSuppressor = toml.parse().expect("rule should parse");
    let vendor_f = test_finding("vendor/bundle.js", Severity::Low);
    let min_js_f = test_finding("dist/app.min.js", Severity::Low);
    let other_f = test_finding("src/app.js", Severity::Low);

    assert!(s.matches(&vendor_f));
    assert!(s.matches(&min_js_f));
    assert!(!s.matches(&other_f));
}
