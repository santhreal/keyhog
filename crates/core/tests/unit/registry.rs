use keyhog_core::registry::{CustomVerifier, SourceRegistry, VerifierRegistry};
use keyhog_core::{Chunk, DedupedMatch, Source, SourceError, VerificationResult};
use std::collections::HashMap;
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
    let registry = SourceRegistry::new(); // Assuming we added a new() for testing or use global
    let source = Arc::new(MockSource);
    registry.register(source.clone());

    let retrieved = registry.get("mock").unwrap();
    assert_eq!(retrieved.name(), "mock");
}

struct MockVerifier;
#[async_trait::async_trait]
impl CustomVerifier for MockVerifier {
    fn name(&self) -> &str {
        "mock-v"
    }
    async fn verify(&self, _m: &DedupedMatch) -> (VerificationResult, HashMap<String, String>) {
        (VerificationResult::Live, HashMap::new())
    }
}

#[tokio::test]
async fn verifier_registry_register_and_get() {
    let registry = VerifierRegistry::new();
    let verifier = Arc::new(MockVerifier);
    registry.register(verifier.clone());

    let retrieved = registry.get("mock-v").unwrap();
    assert_eq!(retrieved.name(), "mock-v");
}
