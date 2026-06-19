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
fn source_registry_register_and_get() {
    let source = Arc::new(MockSource);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::source_registry_registered_name(
            &keyhog_core::testing::TestApi,
            source,
            "mock"
        )
        .as_deref(),
        Some("mock")
    );
}

#[tokio::test]
async fn verifier_registry_register_and_get() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::verifier_registry_registered_name(
            &keyhog_core::testing::TestApi,
            "mock-v"
        )
        .as_deref(),
        Some("mock-v")
    );
}
