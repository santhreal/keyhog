//! Unit tests for `subcommands::watch`. Split into a separate `tests.rs`
//! module (rather than an inline `#[cfg(test)] mod tests {}` block) so the
//! `no_inline_tests_in_src` gate stays green while these still reach the parent
//! module's PRIVATE constants (`FNV_OFFSET_BASIS`, `FNV_PRIME`) and helper
//! (`content_hash`) via `use super::*`.

use super::*;

#[test]
fn fnv_constants_are_the_canonical_64_bit_values() {
    // The two constants MUST be the standard FNV-1a 64-bit offset basis and
    // prime; a drift here silently changes both the raw-content hash and the
    // finding-set fingerprint, breaking burst dedup.
    assert_eq!(FNV_OFFSET_BASIS, 0xcbf2_9ce4_8422_2325);
    assert_eq!(FNV_PRIME, 0x0000_0100_0000_01b3);
}

#[test]
fn content_hash_matches_reference_fnv1a() {
    // Empty input hashes to the offset basis (FNV-1a base case).
    assert_eq!(content_hash(b""), FNV_OFFSET_BASIS);
    // Concrete reference vectors computed from the canonical FNV-1a 64 algorithm
    //: these lock the const-hoist to byte-identical behavior.
    assert_eq!(content_hash(b"keyhog"), 0x061a_b633_9fdc_03fa);
    assert_eq!(content_hash(b"PASSWORD=hunter2"), 0x2a02_5e63_1b56_f2ad);
}

#[test]
fn content_hash_distinguishes_distinct_content() {
    assert_ne!(content_hash(b"keyhog"), content_hash(b"KEYHOG"));
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
