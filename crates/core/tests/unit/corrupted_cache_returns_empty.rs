//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn corrupted_cache_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    std::fs::write(&path, b"this is not json").unwrap();
    let strict = Calibration::try_load(&path).expect_err("strict load must reject corrupt JSON");
    assert!(
        strict.to_string().contains("not valid JSON"),
        "strict load must name the parse failure; got {strict}"
    );
    let loaded = Calibration::load(&path);
    assert_eq!(loaded.entries().len(), 0);
}
