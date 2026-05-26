//! Migrated from `src/registry.rs` inline tests.
use keyhog_core::registry::{CustomVerifier, SourceRegistry, VerifierRegistry};
use keyhog_core::{Chunk, DedupedMatch, Source, SourceError, VerificationResult};
use std::collections::HashMap;
use std::sync::Arc;
struct MockSource;
impl Source for MockSource {
    fn name(&self) -> &str { "mock" }
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(std::iter::empty())
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct MockVerifier;
#[async_trait::async_trait]
impl CustomVerifier for MockVerifier {
    fn name(&self) -> &str { "mock-v" }
    async fn verify(&self, _m: &DedupedMatch) -> (VerificationResult, HashMap<String, String>) {
        (VerificationResult::Skipped, HashMap::new())
    }
}
#[test]
    fn source_registry_missing_name_returns_none() {
        let registry = SourceRegistry::new();
        assert!(registry.get("missing").is_none());
    }
