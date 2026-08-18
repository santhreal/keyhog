//! MatcherArtifact cache: persist eager compile state, fail closed on mismatch.

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::execution_pack::{
    CanonicalDetectorExecutionIr, CompiledRouteMatcherSections, ExecutionPackBackend,
};
use keyhog_scanner::{load_matcher_artifact, store_matcher_artifact, MatcherArtifactIdentity};

fn allowlisted_tempdir() -> tempfile::TempDir {
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:\t")
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "0".to_owned());
    let root = std::env::temp_dir().join(format!("keyhog-cache-{uid}"));
    // Refuse a pre-existing symlink to prevent TOCTOU: a local attacker
    // can pre-create keyhog-cache-<uid> as a symlink pointing elsewhere.
    if let Ok(meta) = std::fs::symlink_metadata(&root) {
        assert!(
            !meta.file_type().is_symlink(),
            "allowlisted root must not be a symlink"
        );
    }
    // create_dir (not create_dir_all) only creates the final component,
    // so it will not follow a symlink planted on a parent directory.
    std::fs::create_dir(&root)
        .or_else(|_| {
            // Already exists: the symlink check above passed, so reuse it.
            Ok::<(), std::io::Error>(())
        })
        .expect("create allowlisted root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("tighten root permissions");
    }
    let dir = tempfile::Builder::new()
        .prefix("matcher-artifact-")
        .tempdir_in(&root)
        .expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("tighten tempdir permissions");
    }
    dir
}

fn sample_detectors() -> Vec<DetectorSpec> {
    vec![DetectorSpec {
        id: "cache-fixture".to_owned(),
        name: "cache fixture".to_owned(),
        service: "fixture".to_owned(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"FIX_([A-Z0-9]{8})".to_owned(),
            group: Some(1),
            required_literals: vec!["FIX_".to_owned()],
            ..Default::default()
        }],
        keywords: vec!["FIX_".to_owned()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }]
}

#[test]
fn second_load_reuses_exact_matcher_bytes() {
    let dir = allowlisted_tempdir();
    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let sections =
        CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu).expect("sections");
    let identity = MatcherArtifactIdentity::new(
        ir.digest(),
        [9u8; 32],
        None,
        ExecutionPackBackend::Cpu,
        None,
    )
    .expect("identity");
    store_matcher_artifact(dir.path(), &identity, &sections).expect("store");
    let loaded = load_matcher_artifact(dir.path(), &identity).expect("load");
    assert_eq!(loaded.content_digest(), sections.content_digest());
    assert_eq!(loaded.literal_index, sections.literal_index);
    assert_eq!(loaded.regex_programs, sections.regex_programs);
}

#[test]
fn mismatched_binary_identity_never_loads() {
    let dir = allowlisted_tempdir();
    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let sections =
        CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu).expect("sections");
    let identity = MatcherArtifactIdentity::new(
        ir.digest(),
        [7u8; 32],
        None,
        ExecutionPackBackend::Cpu,
        None,
    )
    .expect("identity");
    store_matcher_artifact(dir.path(), &identity, &sections).expect("store");

    let mut foreign = identity.clone();
    foreign.binary_digest = "0".repeat(64);
    let error = load_matcher_artifact(dir.path(), &foreign).expect_err("foreign identity");
    assert!(
        error.contains("identity") || error.contains("miss") || error.contains("digest"),
        "expected fail-closed identity error, got {error}"
    );
}

#[test]
fn mismatched_config_digest_never_loads() {
    let dir = allowlisted_tempdir();
    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let sections =
        CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu).expect("sections");
    let identity = MatcherArtifactIdentity::new(
        ir.digest(),
        [1u8; 32],
        None,
        ExecutionPackBackend::Cpu,
        None,
    )
    .expect("identity");
    store_matcher_artifact(dir.path(), &identity, &sections).expect("store");

    let foreign = MatcherArtifactIdentity::new(
        ir.digest(),
        [2u8; 32],
        None,
        ExecutionPackBackend::Cpu,
        None,
    )
    .expect("foreign identity");
    let error = load_matcher_artifact(dir.path(), &foreign).expect_err("config mismatch");
    assert!(
        error.contains("miss") || error.contains("identity") || error.contains("digest"),
        "expected fail-closed config mismatch, got {error}"
    );
}

#[test]
fn hyperscan_db_filename_is_not_a_matcher_artifact() {
    // Proof gate: Hyperscan `--cache-dir` shards use `hs-*.db` and cannot satisfy
    // MatcherArtifact reuse. A directory that only contains HS DB files must miss.
    let dir = allowlisted_tempdir();
    let hs_shard = dir.path().join("hs-deadbeef.db");
    std::fs::write(&hs_shard, b"KHHS\x02\x00\x00\x00not-a-matcher").expect("write hs db");
    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let identity = MatcherArtifactIdentity::new(
        ir.digest(),
        [3u8; 32],
        None,
        ExecutionPackBackend::Cpu,
        None,
    )
    .expect("identity");
    let error = load_matcher_artifact(dir.path(), &identity).expect_err("hs db alone");
    assert!(
        error.contains("miss"),
        "HS .db alone must not satisfy MatcherArtifact; got {error}"
    );
    assert!(
        !identity.cache_filename().ends_with(".db"),
        "MatcherArtifact filenames must not collide with Hyperscan .db shards"
    );
}

#[test]
fn matcher_artifact_cache_evicts_oldest_when_capacity_exceeded() {
    let dir = allowlisted_tempdir();
    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let sections =
        CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu).expect("sections");

    // Store 12 distinct artifacts (max capacity is 8)
    for i in 0..12u8 {
        let mut config_digest = [0u8; 32];
        config_digest[0] = i;
        let identity = MatcherArtifactIdentity::new(
            ir.digest(),
            config_digest,
            None,
            ExecutionPackBackend::Cpu,
            None,
        )
        .expect("identity");
        store_matcher_artifact(dir.path(), &identity, &sections).expect("store");
    }

    // Count remaining .khm files
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .flatten()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("khm"))
        .collect();

    assert!(
        entries.len() <= 8,
        "MatcherArtifact cache entries must not exceed 8, found {}",
        entries.len()
    );
}

/// WHY: cache directory creation must end at mode 0700 regardless of the active
/// process umask (such as 0o002 or 0o022) and regardless of race conditions among
/// concurrent writers creating the cache directory simultaneously.
///
/// What it does not catch: filesystems that do not support POSIX permission bits
/// or Windows ACL permission models.
#[test]
#[cfg(unix)]
fn matcher_artifact_cache_dir_creation_ends_at_mode_0700_regardless_of_umask_and_concurrency() {
    use std::os::unix::fs::MetadataExt;

    let detectors = sample_detectors();
    let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("ir");
    let sections =
        CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu).expect("sections");

    // Dynamically sweep standard umasks: 0o002 (group-writable) and 0o022 (standard).
    for test_umask in [0o002u32, 0o022u32] {
        let old_umask = unsafe { libc::umask(test_umask as libc::mode_t) };
        let temp_parent = allowlisted_tempdir();
        let cache_dir = temp_parent.path().join("concurrent-cache-test");

        // Spawn concurrent threads attempting to store artifacts simultaneously into a fresh cache dir.
        let thread_count = 8;
        let mut handles = Vec::new();
        for i in 0..thread_count {
            let dir = cache_dir.clone();
            let identity = MatcherArtifactIdentity::new(
                ir.digest(),
                [i as u8; 32],
                None,
                ExecutionPackBackend::Cpu,
                None,
            )
            .expect("identity");
            let sec = sections.clone();
            handles.push(std::thread::spawn(move || {
                store_matcher_artifact(&dir, &identity, &sec)
            }));
        }

        for handle in handles {
            handle.join().expect("thread join").expect("store");
        }

        // Restore umask before assertions
        unsafe { libc::umask(old_umask) };

        let meta = std::fs::symlink_metadata(&cache_dir).expect("stat cache dir");
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "cache directory created under umask {test_umask:#o} must end at mode 0700, got {mode:#o}"
        );
    }
}

/// WHY: a cache directory with loose permissions must be auto-tightened to mode 0700
/// when validated on default paths, and must report an operator-visible repair command
/// `chmod 700` when validation fails.
///
/// What it does not catch: non-POSIX permission errors on foreign mounts.
#[test]
#[cfg(unix)]
fn validate_and_tighten_repairs_existing_loose_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_parent = allowlisted_tempdir();
    let cache_dir = temp_parent.path().join("loose-cache-dir");
    std::fs::create_dir(&cache_dir).expect("create dir");
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o775))
        .expect("set loose mode");

    // Strict validation without auto-tighten refuses the directory and includes the chmod repair command.
    let err = keyhog_scanner::validate_matcher_artifact_cache_dir(&cache_dir)
        .expect_err("strict validate must fail on 0775");
    assert!(
        err.contains("chmod 700"),
        "validation error must include repair command `chmod 700`, got: {err}"
    );

    // Auto-tighten repairs the mode in place.
    keyhog_scanner::validate_and_tighten_matcher_artifact_cache_dir(&cache_dir, true)
        .expect("auto-tighten must succeed");

    let meta = std::fs::symlink_metadata(&cache_dir).expect("stat repaired cache dir");
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "cache directory must be tightened to 0700, got {mode:#o}"
    );
}
