use super::{load_autoroute_cache, test_host, test_rules_digest, AUTOROUTE_CACHE_VERSION};

/// An outdated cache (older `version`, written before a field was added to the
/// schema) must be rejected on its schema version with a clear, actionable
/// message: NOT the opaque serde "missing field …" error a naive full
/// deserialize emits. Reproduces the real upgrade-path symptom: a stale on-disk
/// cache leaked `missing field decode_density_bucket` into every default scan
/// instead of a clean "unsupported autoroute cache version" verdict, because the
/// version gate sat after the full deserialize and could never run.
#[test]
fn autoroute_cache_rejects_outdated_schema_with_clear_version_error() {
    let dir = tempfile::tempdir().expect("autoroute outdated cache tempdir");
    let path = dir.path().join("autoroute.json");
    // A genuinely old cache: version 1, structurally incompatible with the
    // current schema (no `decode_density_bucket`, no `binary_version`, …).
    let outdated = br#"{
        "version": 1,
        "detector_digest": 123,
        "decisions": [
            [
                {"bytes_bucket": 1, "chunks_bucket": 1, "max_file_bucket": 1, "pattern_bucket": 13},
                "simd-regex"
            ]
        ]
    }"#;
    std::fs::write(&path, outdated).expect("write outdated cache");

    let host = test_host(None);
    let err = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0u64,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEFu64,
        &host,
    )
    .expect_err("outdated-schema cache must be rejected")
    .to_string();

    assert!(
        err.contains("unsupported autoroute cache version"),
        "outdated cache must be rejected on its schema version, got: {err:?}"
    );
    assert!(
        !err.contains("missing field"),
        "version gate must fire BEFORE the full deserialize; a serde 'missing field' \
         error must not leak to the operator, got: {err:?}"
    );
}

#[test]
fn autoroute_cache_rejects_v25_decode_density_identity_before_payload_decode() {
    let dir = tempfile::tempdir().expect("v25 autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    std::fs::write(
        &path,
        br#"{"version":25,"configs":[{"decisions":[[{"decode_density_bucket":3},{}]]}]}"#,
    )
    .expect("write v25 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v25 decode-density identity must never be reused as current decoder work")
    .to_string();

    assert!(
        error.contains("unsupported autoroute cache version 25")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v25 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v25 payload must not reach the current workload deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v28_before_phase1_identity_decode() {
    let dir = tempfile::tempdir().expect("v28 autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    std::fs::write(
        &path,
        br#"{"version":28,"configs":[{"decisions":[[{"bytes_bucket":23,"chunks_bucket":0,"max_file_bucket":23,"pattern_bucket":9,"decode_kind_mask":0,"decode_candidate_count_bucket":0,"decode_candidate_bytes_bucket":0,"decode_sample_bytes_bucket":0,"source_class_hash":1},{}]]}]}"#,
    )
    .expect("write v28 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v28 identity must never be reused without phase-one admission classes")
    .to_string();

    assert!(
        error.contains("unsupported autoroute cache version 28")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v28 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v28 payload must not reach the current phase-one identity deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v29_before_source_mixture_decode() {
    let dir = tempfile::tempdir().expect("v29 autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    std::fs::write(
        &path,
        br#"{"version":29,"configs":[{"decisions":[[{"source_class_hash":1},{}]]}]}"#,
    )
    .expect("write v29 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v29 identity must never be reused without exact source mixtures")
    .to_string();

    assert!(
        error.contains("unsupported autoroute cache version 29")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v29 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v29 payload must not reach the current source-mixture deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v30_before_workload_binding_decode() {
    let dir = tempfile::tempdir().expect("v30 autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    std::fs::write(
        &path,
        br#"{"version":30,"configs":[{"decisions":[[{"source_mixture":{"entries":[]}},{}]]}]}"#,
    )
    .expect("write v30 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v30 decisions must never be reused without workload binding")
    .to_string();

    assert!(
        error.contains("unsupported autoroute cache version 30")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v30 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v30 payload must not reach the current workload-binding deserializer: {error}"
    );
}
