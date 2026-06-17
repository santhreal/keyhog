/// Extended allowlist tests: boundary conditions on globs, hash format edge
/// cases, metadata field parsing, oversized paths, bare-hash shortcuts,
/// bare-glob (gitignore-style) shortcuts, expired entries, future entries,
/// empty detector id rejection, and the is_allowed aggregation path.
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;

fn verified_finding(detector: &str, path: Option<&str>) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential_redacted: "abcd...wxyz".into(),
        credential_hash: [0; 32],
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: path.map(Arc::from),
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

// ── parse: basic entries ───────────────────────────────────────────────────────

#[test]
fn parse_empty_content_produces_empty_allowlist() {
    let al = keyhog_core::testing::allowlist_parse("");
    assert!(al.credential_hashes.is_empty());
    assert!(al.ignored_detectors.is_empty());
    assert!(al.ignored_paths.is_empty());
}

#[test]
fn parse_only_comments_and_blank_lines_produces_empty() {
    let content = "# This is a comment\n\n# Another comment\n   \n";
    let al = keyhog_core::testing::allowlist_parse(content);
    assert!(al.credential_hashes.is_empty());
    assert!(al.ignored_detectors.is_empty());
    assert!(al.ignored_paths.is_empty());
}

#[test]
fn parse_multiple_detector_entries() {
    let content = "detector:entropy\ndetector:aws-access-key\ndetector:github-pat\n";
    let al = keyhog_core::testing::allowlist_parse(content);
    assert_eq!(al.ignored_detectors.len(), 3);
    assert!(al.ignored_detectors.contains("entropy"));
    assert!(al.ignored_detectors.contains("aws-access-key"));
    assert!(al.ignored_detectors.contains("github-pat"));
}

#[test]
fn parse_duplicate_detector_entries_deduplicated() {
    let content = "detector:entropy\ndetector:entropy\n";
    let al = keyhog_core::testing::allowlist_parse(content);
    assert_eq!(al.ignored_detectors.len(), 1);
}

#[test]
fn parse_empty_detector_id_rejected() {
    // "detector:" with no ID should produce no entry
    let al = keyhog_core::testing::allowlist_parse("detector:\n");
    assert!(al.ignored_detectors.is_empty());
}

// ── hash entries ──────────────────────────────────────────────────────────────

#[test]
fn parse_valid_64_hex_hash() {
    let hash = "a".repeat(64);
    let content = format!("hash:{hash}");
    let al = keyhog_core::testing::allowlist_parse(&content);
    assert_eq!(al.credential_hashes.len(), 1);
}

#[test]
fn parse_63_hex_chars_rejected() {
    let hash = "a".repeat(63);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hash}"));
    assert!(al.credential_hashes.is_empty());
}

#[test]
fn parse_65_hex_chars_rejected() {
    let hash = "a".repeat(65);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hash}"));
    assert!(al.credential_hashes.is_empty());
}

#[test]
fn parse_non_hex_chars_in_hash_rejected() {
    // 63 valid hex + 'g' = invalid
    let hash = "a".repeat(63) + "g";
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hash}"));
    assert!(al.credential_hashes.is_empty());
}

#[test]
fn bare_64_hex_hash_parses_without_prefix() {
    // gitignore-style: bare SHA-256 without "hash:" prefix
    let hash = "b".repeat(64);
    let al = keyhog_core::testing::allowlist_parse(&hash);
    assert_eq!(al.credential_hashes.len(), 1);
}

// ── path entries ──────────────────────────────────────────────────────────────

#[test]
fn parse_path_glob_added_to_ignored_paths() {
    let al = keyhog_core::testing::allowlist_parse("path:tests/**\n");
    assert_eq!(al.ignored_paths.len(), 1);
    assert_eq!(al.ignored_paths[0], "tests/**");
}

#[test]
fn bare_glob_parses_gitignore_style() {
    let al = keyhog_core::testing::allowlist_parse("*.env\n");
    assert_eq!(al.ignored_paths.len(), 1);
    assert_eq!(al.ignored_paths[0], "*.env");
}

#[test]
fn empty_path_glob_rejected() {
    let al = keyhog_core::testing::allowlist_parse("path:\n");
    assert!(al.ignored_paths.is_empty());
}

// ── is_path_ignored ────────────────────────────────────────────────────────────

#[test]
fn exact_path_match() {
    let al = keyhog_core::testing::allowlist_parse("path:config/secrets.yml\n");
    assert!(al.is_path_ignored("config/secrets.yml"));
    assert!(!al.is_path_ignored("config/other.yml"));
}

#[test]
fn glob_double_star_matches_nested() {
    let al = keyhog_core::testing::allowlist_parse("path:**/fixtures/**\n");
    assert!(al.is_path_ignored("tests/unit/fixtures/cred.env"));
    assert!(al.is_path_ignored("fixtures/cred.env"));
}

#[test]
fn single_star_does_not_cross_directory() {
    let al = keyhog_core::testing::allowlist_parse("path:src/*.rs\n");
    // Direct child match
    assert!(al.is_path_ignored("src/main.rs"));
    // Nested child must NOT match single-star
    assert!(!al.is_path_ignored("src/sub/main.rs"));
}

#[test]
fn backslash_path_sep_matches_forward_slash_glob() {
    let al = keyhog_core::testing::allowlist_parse("path:tests/**\n");
    // Windows-style path separator
    assert!(al.is_path_ignored("tests\\fixtures\\key.env"));
}

#[test]
fn dot_components_normalized_away() {
    let al = keyhog_core::testing::allowlist_parse("path:tests/**\n");
    assert!(al.is_path_ignored("./tests/fixtures/../fixtures/key.env"));
}

// ── is_hash_allowed ────────────────────────────────────────────────────────────

#[test]
fn hash_allowed_requires_exact_64_hex_match() {
    let hash = "c".repeat(64);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hash}"));
    assert!(keyhog_core::testing::allowlist_is_hash_allowed(&al, &hash));
}

#[test]
fn hash_allowed_case_insensitive() {
    let lower = "d".repeat(64);
    let upper = "D".repeat(64);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{lower}"));
    // Both should match since hex digits are case-insensitive
    assert!(keyhog_core::testing::allowlist_is_hash_allowed(&al, &lower));
    assert!(keyhog_core::testing::allowlist_is_hash_allowed(&al, &upper));
}

#[test]
fn hash_not_allowed_different_value() {
    let hash_a = "e".repeat(64);
    let hash_b = "f".repeat(64);
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{hash_a}"));
    assert!(!keyhog_core::testing::allowlist_is_hash_allowed(
        &al, &hash_b
    ));
}

#[test]
fn hash_not_allowed_non_hex_string() {
    let al = keyhog_core::testing::allowlist_parse(&format!("hash:{}", "a".repeat(64)));
    // Input that isn't 64 hex chars → always false
    assert!(!keyhog_core::testing::allowlist_is_hash_allowed(
        &al,
        "not_a_hash"
    ));
}

// ── is_allowed aggregation ────────────────────────────────────────────────────

#[test]
fn is_allowed_by_detector() {
    let al = keyhog_core::testing::allowlist_parse("detector:aws-access-key\n");
    let finding = verified_finding("aws-access-key", Some("code.py"));
    assert!(keyhog_core::testing::allowlist_is_allowed(&al, &finding));
}

#[test]
fn is_allowed_different_detector_not_suppressed() {
    let al = keyhog_core::testing::allowlist_parse("detector:github-pat\n");
    let finding = verified_finding("stripe-key", Some("code.py"));
    assert!(!keyhog_core::testing::allowlist_is_allowed(&al, &finding));
}

#[test]
fn is_allowed_by_path_glob() {
    let al = keyhog_core::testing::allowlist_parse("path:tests/**\n");
    let finding = verified_finding("any-detector", Some("tests/fixtures/key.env"));
    assert!(keyhog_core::testing::allowlist_is_allowed(&al, &finding));
}

#[test]
fn is_allowed_no_path_in_finding_not_path_suppressed() {
    let al = keyhog_core::testing::allowlist_parse("path:tests/**\n");
    let finding = verified_finding("any-detector", None);
    // No file path in finding → path rule cannot match
    assert!(!keyhog_core::testing::allowlist_is_allowed(&al, &finding));
}

#[test]
fn is_allowed_detector_or_path_either_suffices() {
    let content = "detector:stripe-key\npath:tests/**\n";
    let al = keyhog_core::testing::allowlist_parse(content);
    // Stripe finding outside tests
    let finding_stripe = verified_finding("stripe-key", Some("src/payments.rs"));
    assert!(keyhog_core::testing::allowlist_is_allowed(
        &al,
        &finding_stripe
    ));
    // Non-stripe finding inside tests
    let finding_tests = verified_finding("npm-token", Some("tests/fixtures/key.env"));
    assert!(keyhog_core::testing::allowlist_is_allowed(
        &al,
        &finding_tests
    ));
}

// ── oversized glob guard ──────────────────────────────────────────────────────

#[test]
fn oversized_glob_does_not_panic() {
    // 257-segment path — above the MAX_GLOB_SEGMENTS=256 limit
    let long_path: String = (0..257).map(|_| "seg").collect::<Vec<_>>().join("/");
    let al = keyhog_core::testing::allowlist_parse("path:**\n");
    // Must not panic — just silently skip the oversized match
    let _ = al.is_path_ignored(&long_path);
}

// ── metadata fields ───────────────────────────────────────────────────────────

#[test]
fn allowlist_entry_with_reason_field_parses() {
    let content = "detector:entropy; reason=\"noise reduction\"\n";
    let al = keyhog_core::testing::allowlist_parse(content);
    // The entry should still be accepted
    assert!(al.ignored_detectors.contains("entropy"));
}

#[test]
fn allowlist_entry_with_approved_by_field_parses() {
    let content = "path:tests/**; approved_by=\"alice\"\n";
    let al = keyhog_core::testing::allowlist_parse(content);
    assert_eq!(al.ignored_paths.len(), 1);
}
