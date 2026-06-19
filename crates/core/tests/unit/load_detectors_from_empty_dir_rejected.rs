//! Migrated from `src/spec/load.rs` inline tests.
#[test]
fn load_detectors_from_empty_dir_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let err = keyhog_core::testing::CoreTestApi::load_detectors_with_gate(
        &keyhog_core::testing::TestApi,
        dir.path(),
        true,
    )
    .expect_err("empty detector directory must not look like a valid empty corpus");

    let text = err.to_string();
    assert!(
        text.contains("no detector TOML files") && text.contains("refusing to scan"),
        "empty detector corpus error must explain the fix; got: {text}"
    );
}
