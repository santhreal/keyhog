//! Migrated from `src/registry.rs` inline tests.
use keyhog_core::{Chunk, Source, SourceError};
use std::sync::Arc;
struct MockSource;
impl Source for MockSource {
    fn name(&self) -> &str {
        "mock"
    }
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(std::iter::empty())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[test]
fn source_registry_overwrite_same_name() {
    assert!(
        keyhog_core::testing::CoreTestApi::source_registry_register_twice_has(
            &keyhog_core::testing::TestApi,
            Arc::new(MockSource),
            Arc::new(MockSource),
            "mock"
        )
    );
}
