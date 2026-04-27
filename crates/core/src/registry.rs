//! Global registry for pluggable components (Sources, Verifiers).
//! This allows adding new features in a single file without modifying the core.

use crate::{DedupedMatch, Source, VerificationResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// A registry for input sources.
#[derive(Default)]
pub struct SourceRegistry {
    sources: RwLock<HashMap<String, Arc<dyn Source + Send + Sync>>>,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, source: Arc<dyn Source + Send + Sync>) {
        let mut lock = self.sources.write();
        lock.insert(source.name().to_string(), source);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Source + Send + Sync>> {
        let lock = self.sources.read();
        lock.get(name).cloned()
    }
}

pub static SOURCE_REGISTRY: OnceLock<SourceRegistry> = OnceLock::new();

pub fn get_source_registry() -> &'static SourceRegistry {
    SOURCE_REGISTRY.get_or_init(|| SourceRegistry {
        sources: RwLock::new(HashMap::new()),
    })
}

/// A trait for custom verification logic (OAuth2, multi-step, etc).
#[async_trait::async_trait]
pub trait CustomVerifier: Send + Sync {
    fn name(&self) -> &str;
    async fn verify(&self, group: &DedupedMatch) -> (VerificationResult, HashMap<String, String>);
}

/// A registry for custom verifiers.
#[derive(Default)]
pub struct VerifierRegistry {
    verifiers: RwLock<HashMap<String, Arc<dyn CustomVerifier>>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, verifier: Arc<dyn CustomVerifier>) {
        let mut lock = self.verifiers.write();
        lock.insert(verifier.name().to_string(), verifier);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn CustomVerifier>> {
        let lock = self.verifiers.read();
        lock.get(name).cloned()
    }
}

pub static VERIFIER_REGISTRY: OnceLock<VerifierRegistry> = OnceLock::new();

pub fn get_verifier_registry() -> &'static VerifierRegistry {
    VERIFIER_REGISTRY.get_or_init(|| VerifierRegistry {
        verifiers: RwLock::new(HashMap::new()),
    })
}
