//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
fn save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");

    let c = Calibration::empty();
    c.record_true_positive("aws-access-key");
    c.record_false_positive("aws-access-key");
    c.record_true_positive("github-pat");
    c.save(&path).unwrap();

    let loaded = Calibration::load(&path);
    let aws = loaded.counters("aws-access-key");
    assert_eq!(aws.alpha, 2);
    assert_eq!(aws.beta, 2);
    let gh = loaded.counters("github-pat");
    assert_eq!(gh.alpha, 2);
    assert_eq!(gh.beta, 1);
}
