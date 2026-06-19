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
    let loaded = Calibration::load(&path);
    assert_eq!(loaded.entries().len(), 0);
}
