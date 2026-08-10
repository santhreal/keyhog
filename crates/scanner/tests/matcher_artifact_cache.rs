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
    std::fs::create_dir_all(&root).expect("allowlisted root");
    tempfile::Builder::new()
        .prefix("matcher-artifact-")
        .tempdir_in(&root)
        .expect("tempdir")
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
