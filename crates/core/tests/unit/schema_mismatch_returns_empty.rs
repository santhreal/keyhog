//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn schema_mismatch_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    let bad = serde_json::json!({
        "version": 99,
        "detectors": { "x": { "alpha": 5, "beta": 5 } }
    });
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let strict = Calibration::try_load(&path).expect_err("strict load must reject schema mismatch");
    assert!(
        strict.to_string().contains("schema version 99"),
        "strict load must name the schema mismatch; got {strict}"
    );
    let loaded = keyhog_core::testing::CoreTestApi::calibration_load_tolerant(
        &keyhog_core::testing::TestApi,
        &path,
    );
    assert_eq!(loaded.entries().len(), 0);
}

#[test]
fn zero_counter_cache_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    let bad = serde_json::json!({
        "version": 1,
        "detectors": { "aws-access-key": { "alpha": 0, "beta": 1 } }
    });
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();

    let strict = Calibration::try_load(&path).expect_err("strict load must reject zero counters");
    assert!(
        strict.to_string().contains("invalid counters")
            && strict.to_string().contains("aws-access-key")
            && strict.to_string().contains("alpha=0")
            && strict.to_string().contains("counters must be >= 1"),
        "strict load must name the invalid counter invariant; got {strict}"
    );
    let loaded = keyhog_core::testing::CoreTestApi::calibration_load_tolerant(
        &keyhog_core::testing::TestApi,
        &path,
    );
    assert_eq!(loaded.entries().len(), 0);
}

#[test]
fn empty_detector_id_cache_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    let bad = serde_json::json!({
        "version": 1,
        "detectors": { "": { "alpha": 1, "beta": 1 } }
    });
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();

    let strict = Calibration::try_load(&path).expect_err("strict load must reject empty ids");
    assert!(
        strict.to_string().contains("empty detector id"),
        "strict load must name the empty-id invariant; got {strict}"
    );
    let loaded = keyhog_core::testing::CoreTestApi::calibration_load_tolerant(
        &keyhog_core::testing::TestApi,
        &path,
    );
    assert_eq!(loaded.entries().len(), 0);
}

#[test]
fn unknown_calibration_fields_return_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    let bad = serde_json::json!({
        "version": 1,
        "detectors": { "aws-access-key": { "alpha": 1, "beta": 1, "confidence": 99 } }
    });
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();

    let strict = Calibration::try_load(&path).expect_err("strict load must reject unknown fields");
    assert!(
        strict.to_string().contains("not valid JSON")
            && strict.to_string().contains("unknown field"),
        "strict load must reject schema drift; got {strict}"
    );
    let loaded = keyhog_core::testing::CoreTestApi::calibration_load_tolerant(
        &keyhog_core::testing::TestApi,
        &path,
    );
    assert_eq!(loaded.entries().len(), 0);
}
