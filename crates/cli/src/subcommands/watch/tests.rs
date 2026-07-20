//! Unit tests for `subcommands::watch`. Split into a separate `tests.rs`
//! module (rather than an inline `#[cfg(test)] mod tests {}` block) so the
//! `no_inline_tests_in_src` gate stays green while these still reach the parent
//! module's PRIVATE constants (`FNV_OFFSET_BASIS`, `FNV_PRIME`) and helper
//! (`content_hash`) via `use super::*`.

use super::*;

fn finding(hash_byte: u8, source: &str, path: &str) -> keyhog_core::RawMatch {
    keyhog_core::RawMatch {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS access key".into(),
        service: "aws".into(),
        severity: keyhog_core::Severity::High,
        credential: "redacted-test-value".into(),
        credential_hash: [hash_byte; 32].into(),
        companions: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: source.into(),
            file_path: Some(path.into()),
            line: Some(1),
            offset: 17,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}

#[test]
fn fnv_constants_are_the_canonical_64_bit_values() {
    // The pre-scan content filter must remain byte-compatible with the shared
    // scanner FNV implementation.
    assert_eq!(FNV_OFFSET_BASIS, 0xcbf2_9ce4_8422_2325);
    assert_eq!(FNV_PRIME, 0x0000_0100_0000_01b3);
}

#[test]
fn content_hash_matches_reference_fnv1a() {
    // Empty input hashes to the offset basis (FNV-1a base case).
    assert_eq!(content_hash(b""), FNV_OFFSET_BASIS);
    // Concrete reference vectors computed from the canonical FNV-1a 64 algorithm
    // these lock the const-hoist to byte-identical behavior.
    assert_eq!(content_hash(b"keyhog"), 0x061a_b633_9fdc_03fa);
    assert_eq!(content_hash(b"PASSWORD=hunter2"), 0x2a02_5e63_1b56_f2ad);
}

#[test]
fn content_hash_distinguishes_distinct_content() {
    assert_ne!(content_hash(b"keyhog"), content_hash(b"KEYHOG"));
}

#[test]
fn finding_fingerprint_keeps_credential_and_complete_location_identity() {
    let original = finding(0x11, "filesystem", "watched.env");
    let replacement = finding(0x22, "filesystem", "watched.env");
    let other_source = finding(0x11, "git", "watched.env");
    let other_path = finding(0x11, "filesystem", "nested/watched.env");

    let original_fingerprint = findings_fingerprint(std::slice::from_ref(&original));
    assert_ne!(
        original_fingerprint,
        findings_fingerprint(&[replacement]),
        "credential replacement at one span is a new watch event"
    );
    assert_ne!(original_fingerprint, findings_fingerprint(&[other_source]));
    assert_ne!(original_fingerprint, findings_fingerprint(&[other_path]));
    assert_ne!(
        findings_fingerprint(&[original.clone(), original]),
        findings_fingerprint(&[]),
        "duplicate finding identities must not XOR-cancel into the empty set"
    );
}

// ---------------------------------------------------------------------------
// End-to-end suppression parity: `keyhog watch` must route scanner matches
// through the SAME `.keyhog.toml` / `.keyhogignore` / inline pipeline that
// `keyhog scan` uses. Each test drives the real scan+filter path over a file on
// disk and asserts on the SURVIVING detector ids (never `!is_empty`).
// ---------------------------------------------------------------------------

/// A real AWS access-key id that fires the `aws-access-key` detector on the CPU
/// backend (shared with the CLI backend-matrix regression fixtures). It has no
/// checksum gate, so it survives without a fabricated-token pitfall.
const AKIA: &str = "AKIAQYLPMN5HFIQR7XYA";
const AKIA_DETECTOR: &str = "aws-access-key";

#[test]
fn watch_reports_aws_key_without_any_suppression() {
    // Adversarial twin / baseline: with no config or ignore file, the key IS a
    // finding. If this ever stops firing, the suppression tests below would pass
    // vacuously (this pins that they don't).
    let dir = tempfile::TempDir::new().expect("tempdir");
    let body = format!("AWS_ACCESS_KEY_ID = \"{AKIA}\"\n");
    let ids =
        testing::scan_file_surviving_detector_ids(dir.path(), "secrets.env", &body).expect("scan");
    assert!(
        ids.iter().any(|id| id == AKIA_DETECTOR),
        "baseline watch scan must surface {AKIA_DETECTOR}, got {ids:?}"
    );
}

#[test]
fn watch_honors_keyhogignore_path_exclusion() {
    // A `.keyhogignore` path glob that matches the changed file must drop the
    // finding in `watch` exactly as it does in `scan`.
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join(".keyhogignore"), "path:**/*.env\n").expect("write ignore");
    let body = format!("AWS_ACCESS_KEY_ID = \"{AKIA}\"\n");
    let ids =
        testing::scan_file_surviving_detector_ids(dir.path(), "secrets.env", &body).expect("scan");
    assert!(
        !ids.iter().any(|id| id == AKIA_DETECTOR),
        "watch must honor the .keyhogignore path exclusion, but {AKIA_DETECTOR} survived: {ids:?}"
    );
}

#[test]
fn watch_honors_keyhogignore_toml_rule_suppressor() {
    // Declarative `.keyhogignore.toml` must drop findings under `watch` the same
    // way `keyhog scan` does after finalize (KH-1329).
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhogignore.toml"),
        "[[suppress]]\ndetector = \"aws-access-key\"\npath_contains = \".env\"\n",
    )
    .expect("write toml ignore");
    let body = format!("AWS_ACCESS_KEY_ID = \"{AKIA}\"\n");
    let ids =
        testing::scan_file_surviving_detector_ids(dir.path(), "secrets.env", &body).expect("scan");
    assert!(
        !ids.iter().any(|id| id == AKIA_DETECTOR),
        "watch must honor .keyhogignore.toml RuleSuppressor, but {AKIA_DETECTOR} survived: {ids:?}"
    );
}

#[test]
fn watch_honors_inline_ignore_suppression() {
    // An inline `keyhog:ignore` directive on the secret line must suppress the
    // finding in `watch` (the shared pipeline re-reads the file for the directive).
    let dir = tempfile::TempDir::new().expect("tempdir");
    let body = format!("AWS_ACCESS_KEY_ID = \"{AKIA}\"  # keyhog:ignore\n");
    let ids =
        testing::scan_file_surviving_detector_ids(dir.path(), "app.env", &body).expect("scan");
    assert!(
        !ids.iter().any(|id| id == AKIA_DETECTOR),
        "watch must honor the inline keyhog:ignore directive, but {AKIA_DETECTOR} survived: {ids:?}"
    );
}

#[test]
fn watch_honors_disabled_detector_config() {
    // `.keyhog.toml` `[detector.<id>] enabled = false` must be resolved by
    // `setup_default_scan_runtime` and drop the detector before it ever fires
    // proving the config is no longer silently ignored by the watch runtime.
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        format!("[detector.{AKIA_DETECTOR}]\nenabled = false\n"),
    )
    .expect("write config");
    let body = format!("AWS_ACCESS_KEY_ID = \"{AKIA}\"\n");
    let ids =
        testing::scan_file_surviving_detector_ids(dir.path(), "creds.env", &body).expect("scan");
    assert!(
        !ids.iter().any(|id| id == AKIA_DETECTOR),
        "watch must honor .keyhog.toml [detector] enabled=false, but {AKIA_DETECTOR} fired: {ids:?}"
    );
}

#[test]
fn multi_root_suppressor_selects_longest_prefix_root() {
    // KH-1433: nested or multi-root watch must apply the deepest matching
    // root's RuleSuppressor, not always the primary.
    use keyhog_core::RuleSuppressor;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let root_a = PathBuf::from("/tmp/watch-a");
    let root_b = PathBuf::from("/tmp/watch-a/nested");
    let roots = vec![root_a.clone(), root_b.clone()];
    let mut map = HashMap::new();
    map.insert(root_a.clone(), RuleSuppressor::default());
    map.insert(root_b.clone(), RuleSuppressor::default());

    let deep = PathBuf::from("/tmp/watch-a/nested/file.env");
    let selected = testing::rule_suppressor_for_path(&deep, &roots, &map);
    assert!(
        std::ptr::eq(selected, map.get(&root_b).unwrap()),
        "nested path must pick the nested root suppressor"
    );

    let shallow = PathBuf::from("/tmp/watch-a/other.env");
    let selected = testing::rule_suppressor_for_path(&shallow, &roots, &map);
    assert!(
        std::ptr::eq(selected, map.get(&root_a).unwrap()),
        "sibling path must pick the parent root suppressor"
    );
}
