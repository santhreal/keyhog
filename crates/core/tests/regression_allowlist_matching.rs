//! Regression coverage for core allowlist matching decisions:
//! bare SHA-256-hex hash suppression of the exact matching credential,
//! gitignore-style path globs, expiry drop/fail-closed behavior, future-dated
//! entries loading, and unknown-metadata-key handling (non-fatal at parse,
//! fail-closed at governance load).
//!
//! Every assertion is a concrete value: exact bool suppression decisions,
//! exact set/vec counts, exact `std::io::ErrorKind`, and specific message
//! substrings. No `is_empty()`/`is_ok()`-only assertions.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    hex_encode, Allowlist, CredentialHash, MatchLocation, Severity, VerificationResult,
    VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

fn parse(content: &str) -> Allowlist {
    CoreTestApi::allowlist_parse(&TestApi, content)
}

fn is_allowed(al: &Allowlist, finding: &VerifiedFinding) -> bool {
    CoreTestApi::allowlist_is_allowed(&TestApi, al, finding)
}

fn is_raw_hash_ignored(al: &Allowlist, hex: &str) -> bool {
    CoreTestApi::allowlist_is_raw_hash_ignored(&TestApi, al, hex)
}

fn finding(detector_id: &str, file: &str, hash: CredentialHash) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Name"),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential_redacted: "abc...wxyz".into(),
        credential_hash: hash,
        companions_redacted: std::collections::HashMap::new(),
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

fn write_allowlist(contents: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(".keyhogignore");
    std::fs::write(&path, contents).expect("write allowlist");
    (dir, path)
}

// ---------------------------------------------------------------------------
// Bare SHA-256-hex hash suppression
// ---------------------------------------------------------------------------

#[test]
fn bare_sha256_hex_suppresses_exact_matching_value() {
    let value = "AKIAIOSFODNN7EXAMPLE";
    let h = sha256(value);
    let hex = hex_encode(&h);
    let al = parse(&format!("{hex}\n"));

    // Exactly one hash loaded, no paths/detectors.
    assert_eq!(al.credential_hashes.len(), 1);
    assert_eq!(al.ignored_paths.len(), 0);
    assert_eq!(al.ignored_detectors.len(), 0);
    assert!(al.credential_hashes.contains(&h));

    // The exact matching value is suppressed end-to-end regardless of detector/path.
    let f = finding("any-detector", "src/deploy.sh", h);
    assert_eq!(is_allowed(&al, &f), true);
    assert_eq!(is_raw_hash_ignored(&al, &hex), true);
}

#[test]
fn bare_sha256_hex_negative_twin_not_suppressed() {
    let h = sha256("AKIAIOSFODNN7EXAMPLE");
    let hex = hex_encode(&h);
    let al = parse(&format!("{hex}\n"));

    // A one-char-different credential hashes to a different digest => not suppressed.
    let other = sha256("AKIAIOSFODNN7EXAMPLF");
    assert!(!al.credential_hashes.contains(&other));
    let f = finding("any-detector", "src/deploy.sh", other);
    assert_eq!(is_allowed(&al, &f), false);
    assert_eq!(is_raw_hash_ignored(&al, &hex_encode(&other)), false);
}

#[test]
fn hash_prefix_and_bare_hex_are_equivalent() {
    let h = sha256("shared-credential");
    let hex = hex_encode(&h);
    let prefixed = parse(&format!("hash:{hex}\n"));
    let bare = parse(&format!("{hex}\n"));

    assert_eq!(prefixed.credential_hashes.len(), 1);
    assert_eq!(bare.credential_hashes.len(), 1);
    assert!(prefixed.credential_hashes.contains(&h));
    assert!(bare.credential_hashes.contains(&h));
    // Both suppress the same finding.
    let f = finding("d", "f", h);
    assert_eq!(is_allowed(&prefixed, &f), true);
    assert_eq!(is_allowed(&bare, &f), true);
}

#[test]
fn uppercase_hash_hex_suppresses_same_value() {
    // Adversarial: hex_encode emits lowercase; a hand-edited uppercase digest
    // must decode to the identical [u8; 32] and suppress the same value.
    let h = sha256("mixed-case-target");
    let hex_upper = hex_encode(&h).to_ascii_uppercase();
    let al = parse(&format!("hash:{hex_upper}\n"));

    assert_eq!(al.credential_hashes.len(), 1);
    assert!(al.credential_hashes.contains(&h));
    let f = finding("d", "f", h);
    assert_eq!(is_allowed(&al, &f), true);
    // The canonical lowercase hex still resolves to the same suppressed hash.
    assert_eq!(is_raw_hash_ignored(&al, &hex_encode(&h)), true);
}

#[test]
fn hash_entry_with_surrounding_whitespace_still_suppresses() {
    // `hash:` value is trimmed before decode.
    let h = sha256("padded-value");
    let hex = hex_encode(&h);
    let al = parse(&format!("hash:   {hex}   \n"));
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(al.credential_hashes.contains(&h));
}

// ---------------------------------------------------------------------------
// gitignore-style path globs
// ---------------------------------------------------------------------------

#[test]
fn glob_bare_gitignore_matches_and_negative_twin() {
    // Bare (unprefixed, non-hash) lines are gitignore-style path globs.
    let al = parse("*.log\nvendor/**/*.json\n");
    assert_eq!(al.ignored_paths.len(), 2);
    assert_eq!(al.credential_hashes.len(), 0);
    assert_eq!(al.is_path_ignored("server.log"), true);
    assert_eq!(al.is_path_ignored("vendor/aws/config.json"), true);
    // Negative twins.
    assert_eq!(al.is_path_ignored("server.txt"), false);
    assert_eq!(al.is_path_ignored("vendor/aws/config.yaml"), false);
}

#[test]
fn glob_path_prefix_doublestar_matches_nested() {
    let al = parse("path:**/*.env\n");
    assert_eq!(al.ignored_paths, vec!["**/*.env".to_string()]);
    assert_eq!(al.is_path_ignored("config/prod/.env"), true);
    assert_eq!(al.is_path_ignored("top.env"), true);
    // `.env.sample` does not end in `.env` as a glob-terminal segment match.
    assert_eq!(al.is_path_ignored("config/prod/env.sample"), false);
}

#[test]
fn glob_single_star_does_not_cross_segment() {
    // Boundary: a single `*` is single-segment only.
    let al = parse("path:src/*.rs\n");
    assert_eq!(al.is_path_ignored("src/main.rs"), true);
    assert_eq!(al.is_path_ignored("src/sub/main.rs"), false);
    assert_eq!(al.is_path_ignored("main.rs"), false);
}

#[test]
fn is_allowed_axes_are_independent() {
    // Path-only allowlist: suppression must hinge solely on the path axis,
    // independent of detector id or credential hash.
    let al = parse("path:secrets/**\n");
    let hit = finding("unrelated-detector", "secrets/keys/id_rsa", sha256("v"));
    assert_eq!(is_allowed(&al, &hit), true);
    // Same detector + hash but off the ignored path => not suppressed.
    let miss = finding("unrelated-detector", "src/main.rs", sha256("v"));
    assert_eq!(is_allowed(&al, &miss), false);
}

// ---------------------------------------------------------------------------
// Expiry: drop at parse, fail-closed at load
// ---------------------------------------------------------------------------

#[test]
fn expired_entry_does_not_suppress_via_parse() {
    // A past `expires` date drops the entry entirely; nothing is loaded.
    let al = parse("detector:gone; expires=2000-01-01\n");
    assert_eq!(al.ignored_detectors.len(), 0);
    assert!(!al.ignored_detectors.contains("gone"));
    let f = finding("gone", "src/main.rs", sha256("v"));
    assert_eq!(is_allowed(&al, &f), false);
}

#[test]
fn expired_entry_fails_closed_on_load() {
    let (_dir, path) = write_allowlist("detector:aws-access-key; expires=2000-01-01\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("expired suppression must fail the load closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("expired allowlist policy at line 1")
            && msg.contains("expired on 2000-01-01")
            && msg.contains("refusing to scan with stale suppressions"),
        "expired-load error must be actionable; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Future-dated entries load
// ---------------------------------------------------------------------------

#[test]
fn future_dated_detector_entry_loads() {
    let (_dir, path) = write_allowlist("detector:stay; expires=2999-12-31\n");
    let al = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect("future-dated entry must load");
    assert_eq!(al.ignored_detectors.len(), 1);
    assert!(al.ignored_detectors.contains("stay"));
}

#[test]
fn future_dated_hash_entry_loads_and_suppresses() {
    let h = sha256("future-approved-secret");
    let hex = hex_encode(&h);
    let (_dir, path) = write_allowlist(&format!("hash:{hex}; expires=2999-12-31\n"));
    let al = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect("future-dated hash entry must load");
    assert_eq!(al.credential_hashes.len(), 1);
    let f = finding("any", "src/x.rs", h);
    assert_eq!(is_allowed(&al, &f), true);
}

// ---------------------------------------------------------------------------
// Unknown metadata key: non-fatal at parse, fail-closed at governance load
// ---------------------------------------------------------------------------

#[test]
fn unknown_metadata_key_is_nonfatal_at_parse() {
    // The unknown key is recorded as a violation but the suppression entry is
    // still applied (recall-safe): parse never panics and keeps the detector.
    let al = parse("detector:keep; frobnicate=\"x\"; reason=\"noise\"\n");
    assert_eq!(al.ignored_detectors.len(), 1);
    assert!(al.ignored_detectors.contains("keep"));
    let f = finding("keep", "src/main.rs", sha256("v"));
    assert_eq!(is_allowed(&al, &f), true);
}

#[test]
fn unknown_metadata_key_fails_closed_at_load() {
    let (_dir, path) =
        write_allowlist("detector:aws-access-key; reasno=\"typo\"; reason=\"noise\"\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("unknown metadata key must fail the load closed");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("unknown key `reasno`")
            && msg.contains("supported keys are reason, expires, approved_by"),
        "unknown-key load error must name the typo and supported fields; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Mixed corpus: exact per-axis counts
// ---------------------------------------------------------------------------

#[test]
fn mixed_entries_have_exact_axis_counts() {
    let h1 = hex_encode(&sha256("cred-one"));
    let h2 = hex_encode(&sha256("cred-two"));
    let content = format!(
        "# heading comment\n\
         detector:one\n\
         detector:two\n\
         path:build/**\n\
         *.tmp\n\
         hash:{h1}\n\
         {h2}\n"
    );
    let al = parse(&content);
    assert_eq!(al.ignored_detectors.len(), 2);
    assert_eq!(al.ignored_paths.len(), 2);
    assert_eq!(al.credential_hashes.len(), 2);
    assert!(al.ignored_detectors.contains("one"));
    assert!(al.ignored_detectors.contains("two"));
    assert_eq!(al.is_path_ignored("build/out/app.js"), true);
    assert_eq!(al.is_path_ignored("scratch.tmp"), true);
    assert_eq!(al.is_path_ignored("src/keep.rs"), false);
}
