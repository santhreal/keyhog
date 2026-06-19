//! Migrated from `src/registry.rs` inline tests.
#[test]
fn source_registry_missing_name_returns_none() {
    assert!(keyhog_core::testing::CoreTestApi::source_registry_missing(
        &keyhog_core::testing::TestApi,
        "missing"
    ));
}
