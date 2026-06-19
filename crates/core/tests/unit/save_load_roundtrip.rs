//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");

    let c = Calibration::default();
    c.record_outcome("aws-access-key", true);
    c.record_outcome("aws-access-key", false);
    c.record_outcome("github-pat", true);
    c.save(&path).unwrap();

    let loaded = keyhog_core::testing::CoreTestApi::calibration_load_tolerant(
        &keyhog_core::testing::TestApi,
        &path,
    );
    let aws = loaded.counters("aws-access-key");
    assert_eq!(aws.alpha, 2);
    assert_eq!(aws.beta, 2);
    let gh = loaded.counters("github-pat");
    assert_eq!(gh.alpha, 2);
    assert_eq!(gh.beta, 1);
}
