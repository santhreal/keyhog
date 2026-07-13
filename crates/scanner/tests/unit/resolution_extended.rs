/// Extended unit tests for `keyhog_scanner::resolution`.
///
/// Covers: entropy suppression near named detectors, multiple named detectors
/// on the same line, line adjacency window boundary, empty input, single match
/// passthrough, and priority score ordering.
use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::resolution::{resolve_matches, try_resolve_matches_with_private_key_blocks};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

fn credential_hash(credential: &str) -> [u8; 32] {
    Sha256::digest(credential.as_bytes()).into()
}

fn make_match_at(
    detector_id: &str,
    credential: &str,
    confidence: Option<f64>,
    file: &str,
    line: usize,
) -> RawMatch {
    make_match_at_offset(detector_id, credential, confidence, file, line, 0)
}

fn make_match_at_offset(
    detector_id: &str,
    credential: &str,
    confidence: Option<f64>,
    file: &str,
    line: usize,
    offset: usize,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: credential_hash(credential).into(),
        companions: HashMap::new(),
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
        confidence,
    }
}

#[test]
fn single_match_is_returned_unchanged() {
    let m = make_match_at(
        "github-pat",
        "ghp_FAKE0000000000000000000000000000000",
        Some(0.9),
        "a.env",
        1,
    );
    let resolved = resolve_matches(vec![m.clone()]);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "github-pat");
}

#[test]
fn line_free_matches_at_distinct_offsets_do_not_compete() {
    let mut first = make_match_at_offset(
        "service-a-token",
        "first-secret-value",
        Some(0.95),
        "firmware.bin",
        1,
        128,
    );
    let mut second = make_match_at_offset(
        "service-b-token",
        "second-secret-value",
        Some(0.40),
        "firmware.bin",
        1,
        4096,
    );
    first.location.line = None;
    second.location.line = None;

    let resolved = resolve_matches(vec![first, second]);
    assert_eq!(resolved.len(), 2);
    assert!(
        resolved.iter().any(|m| m.location.offset == 128)
            && resolved.iter().any(|m| m.location.offset == 4096),
        "line-free findings at different binary offsets are distinct secrets"
    );
}

#[test]
fn overlapping_line_free_matches_still_compete() {
    let mut broad = make_match_at_offset(
        "generic-secret",
        "prefix-overlapping-secret",
        Some(0.40),
        "firmware.bin",
        1,
        100,
    );
    let mut specific = make_match_at_offset(
        "service-token",
        "overlapping-secret",
        Some(0.95),
        "firmware.bin",
        1,
        107,
    );
    broad.location.line = None;
    specific.location.line = None;

    let resolved = resolve_matches(vec![broad, specific]);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "service-token");
}

#[test]
fn disjoint_matches_on_one_line_remain_independent_findings() {
    let first = make_match_at_offset(
        "service-a-token",
        "first-secret-value",
        Some(0.95),
        "config.json",
        1,
        16,
    );
    let second = make_match_at_offset(
        "service-b-token",
        "second-secret-value",
        Some(0.40),
        "config.json",
        1,
        128,
    );

    let resolved = resolve_matches(vec![first, second]);

    assert_eq!(resolved.len(), 2);
    assert!(resolved.iter().any(|m| m.location.offset == 16));
    assert!(resolved.iter().any(|m| m.location.offset == 128));
}

#[test]
fn overlapping_matches_on_one_line_still_compete() {
    let broad = make_match_at_offset(
        "generic-secret",
        "prefix-overlapping-secret",
        Some(0.40),
        "config.json",
        1,
        100,
    );
    let specific = make_match_at_offset(
        "service-token",
        "overlapping-secret",
        Some(0.95),
        "config.json",
        1,
        107,
    );

    let forward = resolve_matches(vec![broad.clone(), specific.clone()]);
    let reverse = resolve_matches(vec![specific, broad]);

    assert_eq!(
        forward, reverse,
        "resolution must not depend on input order"
    );
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].detector_id.as_ref(), "service-token");
}

#[test]
fn touching_matches_on_one_line_do_not_compete() {
    let first = make_match_at_offset(
        "service-a-token",
        "first-secret",
        Some(0.95),
        "config.json",
        1,
        32,
    );
    let second = make_match_at_offset(
        "service-b-token",
        "second-secret",
        Some(0.40),
        "config.json",
        1,
        32 + "first-secret".len(),
    );

    let resolved = resolve_matches(vec![second, first]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn transitively_overlapping_matches_form_one_component() {
    let first = make_match_at_offset("short-a", "aaaaaaaaaa", Some(0.10), "config.json", 1, 0);
    let bridge = make_match_at_offset("short-b", "bbbbbbbbbb", Some(0.20), "config.json", 1, 8);
    let winner = make_match_at_offset(
        "service-highest-priority-token",
        "cccccccccc",
        Some(0.99),
        "config.json",
        1,
        16,
    );

    for input in [
        vec![winner.clone(), first.clone(), bridge.clone()],
        vec![bridge, winner, first],
    ] {
        let resolved = resolve_matches(input);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].detector_id.as_ref(),
            "service-highest-priority-token"
        );
    }
}

#[test]
fn empty_input_produces_empty_output() {
    let resolved = resolve_matches(vec![]);
    assert!(resolved.is_empty());
}

#[test]
fn entropy_suppressed_when_named_on_same_line() {
    let named = make_match_at(
        "aws-access-key",
        "AKIA_FAKE_KEY_0000000",
        Some(0.8),
        "creds.env",
        3,
    );
    let entropy = make_match_at(
        "entropy",
        "AKIA_FAKE_KEY_0000000",
        Some(0.95),
        "creds.env",
        3,
    );
    let resolved = resolve_matches(vec![named, entropy]);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "aws-access-key");
}

#[test]
fn entropy_suppressed_on_adjacent_line_within_window() {
    // The same source span is attributed to adjacent lines by two detector
    // paths. Overlapping occurrence evidence makes this one duplicate.
    let named = make_match_at(
        "stripe-key",
        "sk_test_FAKEKEYVALUE000000000000",
        Some(0.8),
        "a.py",
        5,
    );
    let entropy = make_match_at(
        "entropy",
        "sk_test_FAKEKEYVALUE000000000000",
        Some(0.95),
        "a.py",
        6,
    );
    let resolved = resolve_matches(vec![named, entropy]);
    assert!(
        resolved.iter().all(|m| m.detector_id.as_ref() != "entropy"),
        "overlapping entropy evidence should be suppressed near the named detector"
    );
}

#[test]
fn repeated_credential_on_adjacent_lines_remains_two_occurrences() {
    let credential = "sk_test_REPEATED000000000000000000";
    let named = make_match_at_offset("stripe-key", credential, Some(0.8), "a.py", 5, 100);
    let entropy = make_match_at_offset("entropy", credential, Some(0.95), "a.py", 6, 200);

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn entropy_on_distant_line_not_suppressed() {
    // Named detector on line 1, entropy on line 10 (well outside window)
    let named = make_match_at(
        "stripe-key",
        "sk_test_FAKEKEYVALUE000000000000",
        Some(0.8),
        "a.py",
        1,
    );
    let entropy = make_match_at(
        "entropy",
        "different_FAKEHIGHENTROPY_value",
        Some(0.95),
        "a.py",
        10,
    );
    let resolved = resolve_matches(vec![named, entropy]);
    // entropy on a distant line with a different credential must survive
    assert!(
        resolved.iter().any(|m| m.detector_id.as_ref() == "entropy"),
        "entropy on distant line with different credential should survive"
    );
}

#[test]
fn unrelated_entropy_on_named_line_is_not_suppressed() {
    let named = make_match_at_offset(
        "stripe-key",
        "sk_test_FAKEVALUE0000000000000000",
        Some(0.8),
        "a.py",
        5,
        0,
    );
    let entropy = make_match_at_offset(
        "entropy",
        "unrelated-high-entropy-value-4QaxS6lotTs9Li9",
        Some(0.95),
        "a.py",
        5,
        128,
    );

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 2);
    assert!(resolved
        .iter()
        .any(|matched| matched.detector_id.as_ref() == "entropy"));
}

#[test]
fn nested_entropy_duplicate_on_named_line_is_suppressed() {
    let url = "postgres://user:leFamejio5QaxS6lotTs9Li9@example.org/db";
    let password = "leFamejio5QaxS6lotTs9Li9";
    let named = make_match_at_offset(
        "postgresql-connection-string",
        url,
        Some(0.8),
        "a.py",
        5,
        64,
    );
    let entropy = make_match_at_offset(
        "entropy",
        password,
        Some(0.95),
        "a.py",
        5,
        64 + url.find(password).unwrap(),
    );

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 1);
    assert_eq!(
        resolved[0].detector_id.as_ref(),
        "postgresql-connection-string"
    );
}

#[test]
fn touching_named_and_entropy_spans_both_survive() {
    let named_credential = "sk_test_TOUCHING00000000000000000";
    let named = make_match_at_offset("stripe-key", named_credential, Some(0.8), "a.py", 5, 64);
    let entropy = make_match_at_offset(
        "entropy",
        "unrelated-high-entropy-value",
        Some(0.95),
        "a.py",
        5,
        64 + named_credential.len(),
    );

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn empty_named_span_does_not_suppress_enclosing_entropy() {
    let named = make_match_at_offset("stripe-key", "", Some(0.8), "a.py", 5, 80);
    let entropy = make_match_at_offset(
        "entropy",
        "unrelated-high-entropy-value",
        Some(0.95),
        "a.py",
        5,
        64,
    );

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn higher_confidence_named_detector_wins_over_lower() {
    let high_conf = make_match_at("stripe-key", "sk_test_SAMECRED", Some(0.95), "a.py", 1);
    let low_conf = make_match_at("generic-key", "sk_test_SAMECRED", Some(0.3), "a.py", 1);
    let resolved = resolve_matches(vec![low_conf, high_conf]);
    // The winner should be stripe-key (named + high confidence)
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "stripe-key");
}

#[test]
fn service_detector_wins_over_higher_confidence_generic_password_on_same_line() {
    let url = "postgres://tkoyplem:leFamejio5QaxS6lotTs9Li9@qlohkubwfkqj.example.org";
    let service = make_match_at(
        "postgresql-connection-string",
        url,
        Some(0.22),
        "secret.yaml",
        7,
    );
    let generic = make_match_at(
        "generic-password",
        "leFamejio5QaxS6lotTs9Li9",
        Some(0.70),
        "secret.yaml",
        7,
    );

    let resolved = resolve_matches(vec![generic, service]);

    assert_eq!(resolved.len(), 1);
    assert_eq!(
        resolved[0].detector_id.as_ref(),
        "postgresql-connection-string"
    );
    assert_eq!(resolved[0].credential.as_ref(), url);
}

#[test]
fn private_key_block_retains_parent_over_decoded_child_match() {
    let child_credential = "AIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb";
    let private_key = format!(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque-bytes-{child_credential}-more-opaque-bytes\n-----END PGP PRIVATE KEY BLOCK-----"
    );
    let block_offset = 100;
    let child_offset = block_offset
        + private_key
            .find(child_credential)
            .expect("fixture contains child credential");
    let parent = make_match_at_offset(
        "private-key",
        &private_key,
        Some(0.8),
        "secret.pem",
        1,
        block_offset,
    );
    let mut child = make_match_at_offset(
        "google-api-key",
        child_credential,
        Some(0.95),
        "secret.pem",
        1,
        child_offset,
    );
    child.location.source = Arc::from("test/base64/caesar");

    let resolved = resolve_matches(vec![child, parent]);

    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "private-key");
    assert_eq!(resolved[0].credential.as_ref(), private_key);
}

#[test]
fn private_key_block_does_not_suppress_same_file_match_outside_block() {
    let private_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque-bytes\n-----END PGP PRIVATE KEY BLOCK-----";
    let parent = make_match_at_offset("private-key", private_key, Some(0.8), "secret.pem", 1, 100);
    let outside = make_match_at_offset(
        "google-api-key",
        "AIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb",
        Some(0.95),
        "secret.pem",
        40,
        100 + private_key.len() + 20,
    );

    let resolved = resolve_matches(vec![outside, parent]);

    assert_eq!(resolved.len(), 2);
    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "private-key"),
        "private-key parent must survive"
    );
    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "google-api-key"),
        "outside same-file child must survive"
    );
}

#[test]
fn active_custom_private_key_block_policy_controls_resolution() {
    let private_key =
        "-----BEGIN CUSTOM PRIVATE KEY-----\nopaque-child-value\n-----END CUSTOM PRIVATE KEY-----";
    let block_offset = 100;
    let child_credential = "opaque-child-value";
    let child_offset = block_offset + private_key.find(child_credential).unwrap();
    let parent = make_match_at_offset(
        "custom-private-key",
        private_key,
        Some(0.8),
        "secret.pem",
        1,
        block_offset,
    );
    let child = make_match_at_offset(
        "custom-child",
        child_credential,
        Some(0.95),
        "secret.pem",
        2,
        child_offset,
    );
    let active = HashSet::from(["custom-private-key".to_string()]);

    let resolved = try_resolve_matches_with_private_key_blocks(vec![child, parent], &active)
        .expect("active resolution policy is valid");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "custom-private-key");
}

#[test]
fn entropy_detector_with_prefix_treated_as_entropy() {
    // Detectors starting with "entropy-" should also be suppressed near named
    let named = make_match_at(
        "npm-token",
        "npm_FAKECRED0000000000000000000000000000",
        Some(0.9),
        "b.env",
        2,
    );
    let entropy_variant = make_match_at(
        "entropy-high",
        "npm_FAKECRED0000000000000000000000000000",
        Some(0.99),
        "b.env",
        2,
    );
    let resolved = resolve_matches(vec![named, entropy_variant]);
    assert_eq!(resolved.len(), 1);
    assert_ne!(resolved[0].detector_id.as_ref(), "entropy-high");
}

#[test]
fn different_files_not_cross_suppressed() {
    // Named detector in file1, entropy in file2, different files must not interact
    let named = make_match_at("aws-key", "AKIAFAKE00000000000X", Some(0.8), "file1.env", 1);
    let entropy = make_match_at("entropy", "AKIAFAKE00000000000X", Some(0.9), "file2.env", 1);
    let resolved = resolve_matches(vec![named, entropy]);
    // Both should survive because they're in different files
    assert_eq!(resolved.len(), 2);
}

#[test]
fn same_coordinates_from_different_source_backends_do_not_compete() {
    let mut filesystem = make_match_at_offset(
        "stripe-key",
        "sk_test_FILESYSTEM000000000000000",
        Some(0.95),
        "shared.env",
        1,
        16,
    );
    filesystem.location.source = Arc::from("filesystem");
    let mut git = make_match_at_offset(
        "npm-token",
        "npm_GIT0000000000000000000000000000000000",
        Some(0.40),
        "shared.env",
        1,
        16,
    );
    git.location.source = Arc::from("git");

    let forward = resolve_matches(vec![filesystem.clone(), git.clone()]);
    let reverse = resolve_matches(vec![git, filesystem]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 2);
}

#[test]
fn slash_bearing_source_namespaces_do_not_share_an_implicit_root() {
    let mut first = make_match_at_offset(
        "stripe-key",
        "sk_test_PROVIDERA00000000000000000",
        Some(0.95),
        "shared.env",
        1,
        16,
    );
    first.location.source = Arc::from("provider/a");
    let mut second = make_match_at_offset(
        "npm-token",
        "npm_PROVIDERB000000000000000000000000000",
        Some(0.40),
        "shared.env",
        1,
        16,
    );
    second.location.source = Arc::from("provider/b");

    let resolved = resolve_matches(vec![first, second]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn git_tag_and_unreachable_namespaces_do_not_compete() {
    let mut tag = make_match_at_offset(
        "stripe-key",
        "sk_test_TAG000000000000000000000000",
        Some(0.95),
        ".git/message",
        1,
        16,
    );
    tag.location.source = Arc::from("git/tag");
    let mut unreachable = make_match_at_offset(
        "npm-token",
        "npm_UNREACHABLE000000000000000000000000",
        Some(0.40),
        ".git/message",
        1,
        16,
    );
    unreachable.location.source = Arc::from("git/unreachable");

    let resolved = resolve_matches(vec![tag, unreachable]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn entropy_overlap_from_different_source_backend_is_not_suppressed() {
    let mut named = make_match_at_offset(
        "stripe-key",
        "sk_test_SHARED0000000000000000000",
        Some(0.95),
        "shared.env",
        1,
        16,
    );
    named.location.source = Arc::from("filesystem");
    let mut entropy = make_match_at_offset(
        "entropy",
        "sk_test_SHARED0000000000000000000",
        Some(0.40),
        "shared.env",
        1,
        16,
    );
    entropy.location.source = Arc::from("git");

    let resolved = resolve_matches(vec![named, entropy]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn same_coordinates_from_different_commits_do_not_compete() {
    let mut earlier = make_match_at_offset(
        "stripe-key",
        "sk_test_EARLIER0000000000000000000",
        Some(0.95),
        "shared.env",
        1,
        16,
    );
    earlier.location.source = Arc::from("git");
    earlier.location.commit = Some(Arc::from("commit-a"));
    let mut later = make_match_at_offset(
        "entropy",
        "different-high-entropy-value-from-later-commit",
        Some(0.40),
        "shared.env",
        1,
        16,
    );
    later.location.source = Arc::from("git");
    later.location.commit = Some(Arc::from("commit-b"));

    let forward = resolve_matches(vec![earlier.clone(), later.clone()]);
    let reverse = resolve_matches(vec![later, earlier]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 2);
}

#[test]
fn private_key_span_does_not_suppress_match_from_another_commit() {
    let private_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque-bytes\n-----END PGP PRIVATE KEY BLOCK-----";
    let mut parent =
        make_match_at_offset("private-key", private_key, Some(0.8), "shared.pem", 1, 100);
    parent.location.source = Arc::from("git");
    parent.location.commit = Some(Arc::from("commit-a"));
    let mut child = make_match_at_offset(
        "google-api-key",
        "AIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb",
        Some(0.95),
        "shared.pem",
        1,
        120,
    );
    child.location.source = Arc::from("git");
    child.location.commit = Some(Arc::from("commit-b"));

    let resolved = resolve_matches(vec![parent, child]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn private_key_span_does_not_suppress_match_from_another_source_backend() {
    let private_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque-bytes\n-----END PGP PRIVATE KEY BLOCK-----";
    let mut parent =
        make_match_at_offset("private-key", private_key, Some(0.8), "shared.pem", 1, 100);
    parent.location.source = Arc::from("filesystem");
    let mut child = make_match_at_offset(
        "google-api-key",
        "AIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb",
        Some(0.95),
        "shared.pem",
        1,
        120,
    );
    child.location.source = Arc::from("git");

    let resolved = resolve_matches(vec![parent, child]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn private_key_span_does_not_suppress_empty_child_capture() {
    let private_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque-bytes\n-----END PGP PRIVATE KEY BLOCK-----";
    let parent = make_match_at_offset("private-key", private_key, Some(0.8), "shared.pem", 1, 100);
    let child = make_match_at_offset("google-api-key", "", Some(0.95), "shared.pem", 1, 120);

    let resolved = resolve_matches(vec![parent, child]);

    assert_eq!(resolved.len(), 2);
}

#[test]
fn multiple_named_detectors_both_survive_on_different_lines() {
    let m1 = make_match_at(
        "stripe-key",
        "sk_test_FAKEVALUEONE0000000000000",
        Some(0.8),
        "c.py",
        1,
    );
    let m2 = make_match_at(
        "npm-token",
        "npm_FAKEVALUETWO00000000000000000000000000",
        Some(0.85),
        "c.py",
        5,
    );
    let resolved = resolve_matches(vec![m1, m2]);
    assert_eq!(resolved.len(), 2);
}
