//! Migrated from `src/spec/load.rs` inline tests.
use keyhog_core::SpecError;
#[test]
fn load_detectors_from_str_rejects_invalid_toml() {
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        "not valid toml [[[[",
    )
    .unwrap_err();
    assert!(matches!(err, SpecError::InvalidToml { .. }));
}
