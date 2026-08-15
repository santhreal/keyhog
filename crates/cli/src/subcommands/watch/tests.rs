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
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
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

/// A directory that appears in a watched tree must contribute every regular
/// file it already contains. inotify reports one event for the directory and
/// none for its contents, so without this walk `mv secrets/ watched/` was a
/// silent false clean: the watcher stayed healthy and printed nothing.
#[test]
fn appearing_directory_contributes_its_existing_files_recursively() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().join("moved_in");
    std::fs::create_dir_all(root.join("nested/deeper")).expect("tree");
    std::fs::write(root.join("top.txt"), "top").expect("write");
    std::fs::write(root.join("nested/deep.txt"), "deep").expect("write");
    std::fs::write(root.join("nested/deeper/deepest.txt"), "deepest").expect("write");

    let skip_dirs = SkipDirPolicy::load().expect("skip policy");
    let mut out = Vec::new();
    collect_directory_files(&root, &skip_dirs, &mut out, "hint");

    let mut names: Vec<String> = out
        .iter()
        .map(|path| {
            path.strip_prefix(&root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "nested/deep.txt".to_string(),
            "nested/deeper/deepest.txt".to_string(),
            "top.txt".to_string(),
        ]
    );
}

/// The walk must not leave the watched tree through a symlinked directory, and
/// must honor the same component skip policy the event path applies.
#[test]
fn appearing_directory_walk_skips_symlinked_dirs_and_skipped_components() {
    let temp = tempfile::tempdir().expect("temp dir");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(outside.join("escaped.txt"), "escaped").expect("write");

    let root = temp.path().join("appeared");
    std::fs::create_dir_all(root.join("node_modules/pkg")).expect("tree");
    std::fs::write(root.join("kept.txt"), "kept").expect("write");
    std::fs::write(root.join("node_modules/pkg/dep.js"), "dep").expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");

    let skip_dirs = SkipDirPolicy::load().expect("skip policy");
    let mut out = Vec::new();
    collect_directory_files(&root, &skip_dirs, &mut out, "hint");

    let names: Vec<String> = out
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["kept.txt".to_string()]);
}

/// A path `keyhog scan` also declines to read must not be charged to the
/// consecutive-failure budget. Counting them exited the watcher after a handful
/// of ordinary symlinks, so a vendored link farm became an outage.
#[test]
#[cfg(unix)]
fn symlink_read_failure_is_policy_skip_not_engine_failure() {
    let temp = tempfile::tempdir().expect("temp dir");
    let target = temp.path().join("target.txt");
    std::fs::write(&target, "secret").expect("write");
    let link = temp.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let error = read_watched_file(&link, keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES)
        .expect_err("O_NOFOLLOW must refuse a symlink");
    assert_eq!(
        read_error_outcome(&link, &error),
        WatchScanOutcome::PolicySkip
    );
}

/// A file that exists, is in policy, and still cannot be read IS a coverage
/// loss, so it must keep counting toward the failure budget.
#[test]
fn unreadable_regular_file_stays_an_engine_failure() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("regular.txt");
    std::fs::write(&path, "content").expect("write");
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        read_error_outcome(&path, &denied),
        WatchScanOutcome::EngineFailure
    );
}

/// An oversized file is a documented policy skip shared with `keyhog scan`, not
/// a scanner fault: a directory of large artifacts must not exit the watcher.
#[test]
fn oversize_file_is_policy_skip() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("big.bin");
    std::fs::write(&path, vec![b'a'; 4096]).expect("write");
    let error = read_watched_file(&path, 16).expect_err("cap must reject");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        read_error_outcome(&path, &error),
        WatchScanOutcome::PolicySkip
    );
}
