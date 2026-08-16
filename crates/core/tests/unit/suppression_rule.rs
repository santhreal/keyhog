//! Unit tests for zero-allocation byte slicing and rule suppression logic.

use keyhog_core::suppression::rule::{
    split_byte_tokens, trim_ascii_str, trim_ascii_whitespace, RuleSuppressor,
};
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
fn test_trim_ascii_whitespace_and_str() {
    assert_eq!(
        trim_ascii_whitespace(b"   hello world  \r\n"),
        b"hello world"
    );
    assert_eq!(trim_ascii_whitespace(b""), b"");
    assert_eq!(trim_ascii_whitespace(b"   \t\r\n"), b"");
    assert_eq!(trim_ascii_whitespace(b"no_space"), b"no_space");

    assert_eq!(trim_ascii_str("   hello world  \r\n"), "hello world");
    assert_eq!(trim_ascii_str(""), "");
    assert_eq!(trim_ascii_str("   \t\r\n"), "");
    assert_eq!(trim_ascii_str("no_space"), "no_space");
}

#[test]
fn test_split_byte_tokens() {
    let raw = b"  token1 ;  token2 ; token3  ";
    let tokens: Vec<&[u8]> = split_byte_tokens(raw, b';').collect();
    assert_eq!(tokens, vec![&b"token1"[..], &b"token2"[..], &b"token3"[..]]);

    let empty = b"  ; ;  ";
    let tokens_empty: Vec<&[u8]> = split_byte_tokens(empty, b';').collect();
    assert!(tokens_empty.is_empty());
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
