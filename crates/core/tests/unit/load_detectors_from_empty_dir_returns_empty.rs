//! Migrated from `src/spec/load.rs` inline tests.
#[test]
fn load_detectors_from_empty_dir_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let specs = keyhog_core::testing::CoreTestApi::load_detectors_with_gate(
        &keyhog_core::testing::TestApi,
        dir.path(),
        true,
    )
    .unwrap();
    assert!(specs.is_empty());
}
