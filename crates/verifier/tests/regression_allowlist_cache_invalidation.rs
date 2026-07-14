//! Regression coverage for allowlist *cache invalidation*, the precompiled
//! `path_index` (a pure function of the PUBLIC, mutable `ignored_paths` Vec)
//! and the hash/detector suppression sets that back the real
//! `Allowlist::is_allowed` decision.
//!
//! This is deliberately DISTINCT from:
//!   - `regression_verifier_allowlist_expiry.rs` (expiry + reason/approval
//!     governance parsing), and
//!   - `new_verifier_allowlist_cache.rs` (the verifier's TTL `VerificationCache`
//!     + domain allowlist).
//!
//! Contract under test (all four legs the area demands):
//!   1. An allowlisted value (path glob / credential hash) IS suppressed.
//!   2. Changing the allowlist SET changes the decision, the precompiled
//!      `path_index` cache invalidates on a directly-mutated `ignored_paths`,
//!      INCLUDING an in-place same-length replacement that a length-only guard
//!      would miss (see `PathGlobIndex::matches_sources`).
//!   3. An expired allowlist entry NO LONGER suppresses (it is never compiled
//!      into the live index/sets).
//!   4. A non-listed value passes through (not suppressed).
//!
//! Every assertion pins a concrete `bool` / integer / exact Vec, never a bare
//! `is_empty()` / `is_ok()`.

use std::borrow::Cow;
use std::collections::HashMap;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    hex_encode, sha256_hash, CredentialHash, MatchLocation, Severity, VerificationResult,
    VerifiedFinding,
};

/// A clearly-past expiry: earlier than any sane host clock's "today".
const PAST: &str = "1970-01-01";
/// A clearly-future expiry: later than any sane host clock's "today".
const FUTURE: &str = "9999-12-31";

/// All-zero 64-hex digest, a valid SHA-256 hex shape not equal to any real
/// credential hash used below.
fn zero_hex() -> String {
    "0".repeat(64)
}

/// Minimal `VerifiedFinding` so the integrated `is_allowed` decision can be
/// exercised through the public `testing` facade.
fn finding(
    detector: &str,
    file_path: Option<&str>,
    credential_hash: CredentialHash,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector.into(),
        detector_name: "n".into(),
        service: "s".into(),
        severity: Severity::default(),
        credential_redacted: Cow::Borrowed("****"),
        credential_hash,
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: file_path.map(|p| p.into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Positive: an allowlisted path glob suppresses a matching value.
// ---------------------------------------------------------------------------

#[test]
fn allowlisted_path_value_is_suppressed() {
    let al = TestApi.allowlist_parse("path:secrets/*.env\n");
    assert_eq!(al.ignored_paths, vec!["secrets/*.env".to_string()]);
    assert_eq!(al.is_path_ignored("secrets/prod.env"), true);
}

// ---------------------------------------------------------------------------
// 4. Negative twin: non-listed values pass through the same allowlist.
// ---------------------------------------------------------------------------

#[test]
fn non_listed_path_passes_through() {
    let al = TestApi.allowlist_parse("path:secrets/*.env\n");
    // Different first segment (own bucket, no wildcard rule) => not suppressed.
    assert_eq!(al.is_path_ignored("config/app.yaml"), false);
    // Same directory, non-matching extension => not suppressed.
    assert_eq!(al.is_path_ignored("secrets/prod.txt"), false);
}

// ---------------------------------------------------------------------------
// 2a. Clearing the set invalidates the precompiled index.
// ---------------------------------------------------------------------------

#[test]
fn clearing_allowlist_set_invalidates_cache() {
    let mut al = TestApi.allowlist_parse("path:secrets/*.env\n");
    assert_eq!(al.is_path_ignored("secrets/prod.env"), true);

    // Mutate the PUBLIC field directly; the precompiled `path_index` is now
    // stale and must be rebuilt to an empty matcher on the next check.
    al.ignored_paths.clear();
    assert_eq!(al.ignored_paths.len(), 0);
    assert_eq!(al.is_path_ignored("secrets/prod.env"), false);
}

// ---------------------------------------------------------------------------
// 2b. THE adversarial case: in-place, SAME-LENGTH replacement. A length-only
//     staleness guard would keep the old (wrong) decision; `matches_sources`
//     compares the Vec by value and forces a rebuild.
// ---------------------------------------------------------------------------

#[test]
fn in_place_same_length_replacement_invalidates_cache() {
    let mut al = TestApi.allowlist_parse("path:secrets/*.env\n");
    assert_eq!(al.is_path_ignored("secrets/prod.env"), true);
    assert_eq!(al.is_path_ignored("logs/app.txt"), false);
    assert_eq!(al.ignored_paths.len(), 1);

    // Replace the single entry with a DIFFERENT glob of the same Vec length.
    al.ignored_paths[0] = "logs/*.txt".to_string();
    assert_eq!(al.ignored_paths.len(), 1); // length unchanged on purpose

    // Decision must follow the new set, not the cached old one.
    assert_eq!(al.is_path_ignored("secrets/prod.env"), false);
    assert_eq!(al.is_path_ignored("logs/app.txt"), true);
}

// ---------------------------------------------------------------------------
// 2c. Extending the set: a newly pushed pattern starts suppressing; the
//     original still does.
// ---------------------------------------------------------------------------

#[test]
fn pushing_new_pattern_invalidates_cache() {
    let mut al = TestApi.allowlist_parse("path:secrets/*.env\n");
    assert_eq!(al.is_path_ignored("vault/keys.json"), false);

    al.ignored_paths.push("vault/**".to_string());
    assert_eq!(al.ignored_paths.len(), 2);
    // Newly added pattern now suppresses.
    assert_eq!(al.is_path_ignored("vault/keys.json"), true);
    // Original pattern is unaffected by the rebuild.
    assert_eq!(al.is_path_ignored("secrets/prod.env"), true);
}

// ---------------------------------------------------------------------------
// 3. Expired path entry is never compiled in; a live twin in the same file is.
// ---------------------------------------------------------------------------

#[test]
fn expired_path_entry_is_not_in_the_compiled_index() {
    let content =
        format!("path:stale/*.env ; expires={PAST}\npath:live/*.key ; expires={FUTURE}\n");
    let al = TestApi.allowlist_parse(&content);

    // Only the live pattern survives into the compiled index.
    assert_eq!(al.ignored_paths, vec!["live/*.key".to_string()]);
    // Expired path no longer suppresses.
    assert_eq!(al.is_path_ignored("stale/prod.env"), false);
    // Live twin does suppress.
    assert_eq!(al.is_path_ignored("live/prod.key"), true);
}

// ---------------------------------------------------------------------------
// 1 + 4 (hash leg): a real credential's hash is suppressed; others pass through.
// ---------------------------------------------------------------------------

#[test]
fn allowlisted_credential_hash_value_is_suppressed() {
    let credential = "AKIAIOSFODNN7EXAMPLE";
    let hex = hex_encode(sha256_hash(credential));
    let content = format!("hash:{hex}\n");
    let al = TestApi.allowlist_parse(&content);

    assert_eq!(al.credential_hashes.len(), 1);
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &hex), true);
    assert_eq!(TestApi.allowlist_is_raw_hash_ignored(&al, &hex), true);
}

#[test]
fn non_listed_credential_hash_passes_through() {
    let hex = hex_encode(sha256_hash("AKIAIOSFODNN7EXAMPLE"));
    let al = TestApi.allowlist_parse(&format!("hash:{hex}\n"));

    // A different (all-zero) valid hex digest is not in the set.
    let other = zero_hex();
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &other), false);
    assert_eq!(TestApi.allowlist_is_raw_hash_ignored(&al, &other), false);
}

// ---------------------------------------------------------------------------
// 2 (hash leg): mutating the hash SET flips the decision.
// ---------------------------------------------------------------------------

#[test]
fn changing_hash_set_changes_decision() {
    let listed_hex = "a".repeat(64);
    let mut al = TestApi.allowlist_parse(&format!("hash:{listed_hex}\n"));

    let zeros = zero_hex();
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &zeros), false);

    // Add the zero hash directly to the public set.
    al.credential_hashes.insert(CredentialHash::from([0u8; 32]));
    assert_eq!(al.credential_hashes.len(), 2);

    // Decision flips for the newly added value; the original stays suppressed.
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &zeros), true);
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &listed_hex), true);
}

// ---------------------------------------------------------------------------
// 3 (hash leg): an expired hash entry is dropped and never suppresses.
// ---------------------------------------------------------------------------

#[test]
fn expired_hash_entry_no_longer_suppresses() {
    let hex = zero_hex();
    let al = TestApi.allowlist_parse(&format!("hash:{hex} ; expires={PAST}\n"));

    assert_eq!(al.credential_hashes.len(), 0);
    assert_eq!(TestApi.allowlist_is_hash_allowed(&al, &hex), false);
}

// ---------------------------------------------------------------------------
// 1 + 2 (detector leg): allowlisted detector suppresses; removing it flips.
// ---------------------------------------------------------------------------

#[test]
fn allowlisted_detector_suppresses_and_removal_flips() {
    let mut al = TestApi.allowlist_parse("detector:leaked-aws\n");
    assert_eq!(al.ignored_detectors.contains("leaked-aws"), true);
    // A non-listed detector is never suppressed.
    assert_eq!(al.ignored_detectors.contains("other-detector"), false);

    al.ignored_detectors.remove("leaked-aws");
    assert_eq!(al.ignored_detectors.contains("leaked-aws"), false);
    assert_eq!(al.ignored_detectors.len(), 0);
}

// ---------------------------------------------------------------------------
// Integrated `is_allowed` decision: hash-suppressed finding, then set cleared.
// ---------------------------------------------------------------------------

#[test]
fn is_allowed_finding_suppressed_by_hash_then_flips_when_set_cleared() {
    let hex = zero_hex();
    let mut al = TestApi.allowlist_parse(&format!("hash:{hex}\n"));
    // Finding whose credential hash is the all-zero digest; nothing else matches.
    let vf = finding("det-x", Some("notes.txt"), CredentialHash::from([0u8; 32]));

    assert_eq!(TestApi.allowlist_is_allowed(&al, &vf), true);

    // Clear the hash set: no leg (detector/path/hash) matches anymore.
    al.credential_hashes.clear();
    assert_eq!(TestApi.allowlist_is_allowed(&al, &vf), false);
}

// ---------------------------------------------------------------------------
// Integrated `is_allowed`: path-suppressed finding vs an off-list finding.
// ---------------------------------------------------------------------------

#[test]
fn is_allowed_finding_suppressed_by_path_and_offlist_finding_passes() {
    let al = TestApi.allowlist_parse("path:vault/**\n");

    let inside = finding(
        "det-y",
        Some("vault/keys.json"),
        CredentialHash::from([7u8; 32]),
    );
    assert_eq!(TestApi.allowlist_is_allowed(&al, &inside), true);

    let outside = finding(
        "det-y",
        Some("src/main.rs"),
        CredentialHash::from([7u8; 32]),
    );
    assert_eq!(TestApi.allowlist_is_allowed(&al, &outside), false);
}

// ---------------------------------------------------------------------------
// Boundary: a directory-style glob (`dir/`) expands to `dir/**` and matches
// nested paths but not a sibling with the directory name as a prefix.
// ---------------------------------------------------------------------------

#[test]
fn directory_glob_matches_nested_but_not_sibling_prefix() {
    let al = TestApi.allowlist_parse("path:node_modules/\n");
    assert_eq!(al.is_path_ignored("node_modules/pkg/index.js"), true);
    // A file whose first segment merely starts with the directory name must
    // NOT be suppressed (segment-boundary, not substring).
    assert_eq!(al.is_path_ignored("node_modules_notreal.js"), false);
}
