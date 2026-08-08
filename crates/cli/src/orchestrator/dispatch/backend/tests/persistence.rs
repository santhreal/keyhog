use super::fixtures::*;
use super::fixtures::decode_workload_sketch;
use super::fixtures::workload_key;
use super::super::evidence::*;
use super::super::host::*;
use super::super::store::*;
use super::super::workload::*;
use super::super::workload::decode_workload_sketch as decode_workload_sketch_with_plan;
use super::super::workload::workload_key as workload_key_with_plan;
use super::super::*;
use keyhog_core::*;
use keyhog_scanner::*;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::result::Result as StdResult;

/// An outdated cache (older `version`, written before a field was added to the
/// schema) must be rejected on its schema version with a clear, actionable
/// message: NOT the opaque serde "missing field …" error a naive full
/// deserialize emits. Reproduces the real upgrade-path symptom: a stale on-disk
/// cache leaked `missing field decode_density_bucket` into every default scan
/// instead of a clean "unsupported autoroute cache version" verdict, because the
/// version gate sat after the full deserialize and could never run.
#[test]
fn autoroute_cache_rejects_outdated_schema_with_clear_version_error() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_outdated_{}.json",
        std::process::id()
    ));
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
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

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
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v25_decode_density_{}.json",
        std::process::id()
    ));
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
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

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
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v28_phase1_{}.json",
        std::process::id()
    ));
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
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

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
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v29_source_mixture_{}.json",
        std::process::id()
    ));
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
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

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
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v30_workload_binding_{}.json",
        std::process::id()
    ));
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
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

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
