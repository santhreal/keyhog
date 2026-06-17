//! Standalone coverage for keyhog-core allowlist + detector-spec public API:
//! `Allowlist::{empty,parse,is_path_ignored,is_allowed,is_hash_ignored,
//! is_raw_hash_ignored,is_hash_allowed}`, glob normalization edge cases,
//! `validate_detector` / `QualityIssue`, `load_detectors_from_str`, and
//! `DetectorSpec` / `PatternSpec` serde + defaults.
//!
//! Assertions check concrete values: which path is suppressed, which detector id
//! collapses, exact quality-issue variants, the parsed detector id/severity.

use keyhog_core::allowlist::Allowlist;
use keyhog_core::testing::load_detectors_from_str;
use keyhog_core::{
    hex_encode, validate_detector, DetectorSpec, MatchLocation, PatternSpec, QualityIssue,
    Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;

fn sha256(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

fn finding(detector_id: &str, file: &str, hash: [u8; 32]) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Name"),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential_redacted: "abc...wxyz".into(),
        credential_hash: hash,
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from(file)),
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

// ---------------------------------------------------------------------------
// Allowlist::empty / parse basics
// ---------------------------------------------------------------------------

#[test]
fn allowlist_empty_suppresses_nothing() {
    let al = Allowlist::empty();
    assert!(al.ignored_paths.is_empty());
    assert!(al.ignored_detectors.is_empty());
    assert!(al.credential_hashes.is_empty());
    assert!(!al.is_path_ignored("anything/at/all.rs"));
}

#[test]
fn allowlist_parse_detector_and_path_buckets() {
    let al = keyhog_core::testing::allowlist_parse("detector:demo-token\npath:**/*.md\n");
    assert!(al.ignored_detectors.contains("demo-token"));
    assert_eq!(al.ignored_paths, vec!["**/*.md".to_string()]);
}

#[test]
fn allowlist_parse_skips_comments_and_blank_lines() {
    let al = keyhog_core::testing::allowlist_parse("# a comment\n\n  \ndetector:keep\n");
    assert_eq!(al.ignored_detectors.len(), 1);
    assert!(al.ignored_detectors.contains("keep"));
}

// ---------------------------------------------------------------------------
// Path glob matching
// ---------------------------------------------------------------------------

#[test]
fn allowlist_path_glob_doublestar_matches_nested() {
    let al = keyhog_core::testing::allowlist_parse("path:**/*.md\n");
    assert!(al.is_path_ignored("docs/README.md"));
    assert!(al.is_path_ignored("a/b/c/notes.md"));
    assert!(al.is_path_ignored("top.md"));
    assert!(!al.is_path_ignored("docs/README.txt"));
}

#[test]
fn allowlist_path_glob_literal_anchor() {
    let al = keyhog_core::testing::allowlist_parse("path:node_modules/**\n");
    assert!(al.is_path_ignored("node_modules/left-pad/index.js"));
    assert!(!al.is_path_ignored("src/node_modules_lookalike.js"));
}

#[test]
fn allowlist_bare_gitignore_style_glob_is_path() {
    // A bare line with no prefix and not a hash is treated as a path glob.
    let al = keyhog_core::testing::allowlist_parse("*.log\nvendor/**/*.json\n");
    assert!(al.is_path_ignored("server.log"));
    assert!(al.is_path_ignored("vendor/aws/config.json"));
    assert!(!al.is_path_ignored("server.txt"));
}

#[test]
fn allowlist_path_normalizes_backslashes_and_dotdot() {
    let al = keyhog_core::testing::allowlist_parse("path:a/b.rs\n");
    // Windows separators normalize to '/'.
    assert!(al.is_path_ignored("a\\b.rs"));
    // `./` and resolvable `..` are normalized away.
    assert!(al.is_path_ignored("a/x/../b.rs"));
    assert!(al.is_path_ignored("./a/b.rs"));
}

#[test]
fn allowlist_single_star_does_not_cross_segment() {
    let al = keyhog_core::testing::allowlist_parse("path:src/*.rs\n");
    assert!(al.is_path_ignored("src/main.rs"));
    // `*` is single-segment: it must NOT match a nested path.
    assert!(!al.is_path_ignored("src/sub/main.rs"));
}

#[test]
fn allowlist_mutating_ignored_paths_directly_rebuilds_index() {
    // Public field mutation after construction must still be honored
    // (length-mismatch rebuild path).
    let mut al = Allowlist::empty();
    al.ignored_paths.push("secret/**".to_string());
    assert!(
        al.is_path_ignored("secret/keys/id_rsa"),
        "directly-pushed glob must suppress (index rebuilds on len mismatch)"
    );
}

// ---------------------------------------------------------------------------
// Hash suppression
// ---------------------------------------------------------------------------

#[test]
fn allowlist_hash_prefix_entry_suppresses_matching_hash() {
    let h = sha256("AKIAIOSFODNN7EXAMPLE");
    let hex = hex_encode(&h);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hex}\n"));
    assert!(al.is_hash_ignored(&h));
    assert!(keyhog_core::testing::allowlist_is_raw_hash_ignored(
        &al, &hex
    ));
    // A different hash is not suppressed.
    assert!(!al.is_hash_ignored(&sha256("other")));
}

#[test]
fn allowlist_bare_64hex_treated_as_hash() {
    let h = sha256("some-credential");
    let hex = hex_encode(&h);
    // 64-char hex with no prefix => credential hash, not a path.
    let al = keyhog_core::testing::allowlist_parse(&format!("{hex}\n"));
    assert!(al.credential_hashes.contains(&h));
    assert!(al.is_hash_ignored(&h));
    assert!(al.ignored_paths.is_empty());
}

#[test]
fn allowlist_invalid_hash_is_not_inserted() {
    // Too-short "hash:" value is rejected (logged), not inserted, and is not a path.
    let al = keyhog_core::testing::allowlist_parse("hash:deadbeef\n");
    assert!(al.credential_hashes.is_empty());
    assert!(al.ignored_paths.is_empty());
}

#[test]
fn allowlist_is_hash_allowed_takes_hex_string() {
    let h = sha256("cred-value");
    let hex = hex_encode(&h);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hex}\n"));
    assert!(keyhog_core::testing::allowlist_is_hash_allowed(&al, &hex));
    assert!(!keyhog_core::testing::allowlist_is_hash_allowed(
        &al,
        &hex_encode(&sha256("nope"))
    ));
    // A non-hex input simply is not allowed (no panic on odd boundaries).
    assert!(!keyhog_core::testing::allowlist_is_hash_allowed(
        &al,
        "not-a-hash"
    ));
}

// ---------------------------------------------------------------------------
// is_allowed end-to-end (detector / path / hash)
// ---------------------------------------------------------------------------

#[test]
fn allowlist_is_allowed_by_detector() {
    let al = keyhog_core::testing::allowlist_parse("detector:demo-token\n");
    let f = finding("demo-token", "src/main.rs", sha256("x"));
    assert!(keyhog_core::testing::allowlist_is_allowed(&al, &f));
    let other = finding("keep-me", "src/main.rs", sha256("x"));
    assert!(!keyhog_core::testing::allowlist_is_allowed(&al, &other));
}

#[test]
fn allowlist_is_allowed_by_path() {
    let al = keyhog_core::testing::allowlist_parse("path:**/*.md\n");
    let f = finding("any", "docs/README.md", sha256("x"));
    assert!(keyhog_core::testing::allowlist_is_allowed(&al, &f));
    let code = finding("any", "src/main.rs", sha256("x"));
    assert!(!keyhog_core::testing::allowlist_is_allowed(&al, &code));
}

#[test]
fn allowlist_is_allowed_by_hash() {
    let h = sha256("leaked-value");
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{}\n", hex_encode(&h)));
    let f = finding("any", "src/main.rs", h);
    assert!(keyhog_core::testing::allowlist_is_allowed(&al, &f));
    let f2 = finding("any", "src/main.rs", sha256("different"));
    assert!(!keyhog_core::testing::allowlist_is_allowed(&al, &f2));
}

#[test]
fn allowlist_expired_entry_is_dropped() {
    // An entry whose `expires` is in the past must not be loaded.
    let al = keyhog_core::testing::allowlist_parse("detector:gone; expires=2000-01-01\n");
    assert!(
        !al.ignored_detectors.contains("gone"),
        "past-expiry entry must be dropped"
    );
}

#[test]
fn allowlist_future_expiry_entry_is_kept() {
    let al = keyhog_core::testing::allowlist_parse("detector:stay; expires=2999-12-31\n");
    assert!(al.ignored_detectors.contains("stay"));
}

// ---------------------------------------------------------------------------
// validate_detector / QualityIssue
// ---------------------------------------------------------------------------

fn detector(id: &str, regex: &str, keywords: Vec<String>) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: id.into(),
        service: id.into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords,
        min_confidence: None,
        tests: Vec::new(),
    }
}

#[test]
fn validate_clean_detector_has_no_issues() {
    let d = detector("demo", "demo_[A-Z0-9]{8}", vec!["demo_".into()]);
    assert!(
        validate_detector(&d).is_empty(),
        "well-formed detector should pass the quality gate"
    );
}

#[test]
fn validate_no_patterns_is_error() {
    let mut d = detector("demo", "x", vec!["demo".into()]);
    d.patterns.clear();
    let issues = validate_detector(&d);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, QualityIssue::Error(m) if m.contains("no patterns"))),
        "empty patterns must be an Error: {issues:?}"
    );
}

#[test]
fn validate_pure_character_class_without_group_is_error() {
    // `[A-Z0-9]{32}` with no capture group is too broad => Error.
    let d = detector("broad", "[A-Z0-9]{32}", vec!["k".into()]);
    let issues = validate_detector(&d);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, QualityIssue::Error(m) if m.contains("pure character class"))),
        "pure char class without anchor must be an Error: {issues:?}"
    );
}

#[test]
fn validate_uncompilable_regex_is_error() {
    let d = detector("bad", "demo_[A-Z", vec!["demo_".into()]);
    let issues = validate_detector(&d);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, QualityIssue::Error(m) if m.contains("does not compile"))),
        "unparsable regex must be an Error: {issues:?}"
    );
}

#[test]
fn validate_missing_keywords_is_warning() {
    let d = detector("demo", "demo_[A-Z0-9]{8}", Vec::new());
    let issues = validate_detector(&d);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, QualityIssue::Warning(m) if m.contains("no keywords"))),
        "missing keywords must yield a Warning: {issues:?}"
    );
}

#[test]
fn quality_issue_serde_shape() {
    let warn = QualityIssue::Warning("w".into());
    let json = serde_json::to_string(&warn).unwrap();
    assert_eq!(json, r#"{"Warning":"w"}"#);
    let err = QualityIssue::Error("e".into());
    assert_eq!(serde_json::to_string(&err).unwrap(), r#"{"Error":"e"}"#);
}

// ---------------------------------------------------------------------------
// load_detectors_from_str + DetectorSpec serde
// ---------------------------------------------------------------------------

#[test]
fn load_detectors_from_str_parses_minimal_detector() {
    // keywords / min_confidence MUST sit inside the [detector] table, i.e.
    // BEFORE the first [[detector.patterns]] array element. A bare key after an
    // array-of-tables header binds to that table, and PatternSpec is
    // deny_unknown_fields, so misplacing `keywords` is a parse error.
    let toml = r#"
[detector]
id = "my-token"
name = "My Token"
service = "myservice"
severity = "high"
keywords = ["mytok_"]

[[detector.patterns]]
regex = "mytok_[A-Za-z0-9]{20}"
"#;
    let dets = load_detectors_from_str(toml).unwrap();
    assert_eq!(dets.len(), 1);
    let d = &dets[0];
    assert_eq!(d.id, "my-token");
    assert_eq!(d.service, "myservice");
    assert_eq!(d.severity, Severity::High);
    assert_eq!(d.patterns.len(), 1);
    assert_eq!(d.patterns[0].regex, "mytok_[A-Za-z0-9]{20}");
    assert_eq!(d.keywords, vec!["mytok_".to_string()]);
    // Defaults.
    assert!(d.companions.is_empty());
    assert!(d.verify.is_none());
    assert_eq!(d.min_confidence, None);
}

#[test]
fn load_detectors_from_str_rejects_unknown_field() {
    // deny_unknown_fields: a typo'd field must fail to parse.
    let toml = r#"
[detector]
id = "x"
name = "X"
service = "x"
severity = "low"
bogus_field = true

[[detector.patterns]]
regex = "x_[0-9]{5}"
"#;
    let err = load_detectors_from_str(toml);
    assert!(
        err.is_err(),
        "unknown field must be rejected by deny_unknown_fields"
    );
}

#[test]
fn load_detectors_from_str_rejects_bad_toml() {
    let err = load_detectors_from_str("this is not = valid toml {{{");
    assert!(err.is_err());
}

#[test]
fn detector_spec_default_severity_is_info_via_serde() {
    // severity is required in the struct but defaults via Severity::default()
    // when constructed with ..Default::default(); confirm the enum default.
    let d = DetectorSpec::default();
    assert_eq!(d.severity, Severity::Info);
    assert!(d.id.is_empty());
    assert!(d.patterns.is_empty());
}

#[test]
fn pattern_spec_client_safe_defaults_false_and_roundtrips() {
    let p = PatternSpec {
        regex: "pk_live_[0-9]{10}".into(),
        client_safe: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: PatternSpec = serde_json::from_str(&json).unwrap();
    assert!(back.client_safe);
    assert_eq!(back.regex, "pk_live_[0-9]{10}");
    // Default is false.
    assert!(!PatternSpec::default().client_safe);
}

#[test]
fn detector_spec_roundtrip_preserves_min_confidence() {
    let toml = r#"
[detector]
id = "low-floor"
name = "Low Floor"
service = "svc"
severity = "medium"
min_confidence = 0.25
keywords = ["sgp_"]

[[detector.patterns]]
regex = "sgp_[0-9a-f]{40}"
"#;
    let dets = load_detectors_from_str(toml).unwrap();
    assert_eq!(dets[0].min_confidence, Some(0.25));
    assert_eq!(dets[0].severity, Severity::Medium);
}
