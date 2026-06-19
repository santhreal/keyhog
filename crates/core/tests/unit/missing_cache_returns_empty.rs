//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::Path;
#[test]
fn missing_cache_returns_empty() {
    let loaded = keyhog_core::testing::CoreTestApi::merkle_load(
        &keyhog_core::testing::TestApi,
        Path::new("/definitely/does/not/exist.idx"),
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
