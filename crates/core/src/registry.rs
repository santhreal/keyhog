//! Local registry primitives for source and verifier ownership tests.

// Debt bucket: 10 items predating the crate floor raising `missing_docs` to
// `warn`. Remove this allow once each registry item carries a doc line.
#![allow(missing_docs)]

use crate::Source;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// A registry for input sources.
#[derive(Default)]
pub(crate) struct SourceRegistry {
    sources: RwLock<HashMap<String, Arc<dyn Source + Send + Sync>>>,
}

impl SourceRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, source: Arc<dyn Source + Send + Sync>) {
        let mut lock = self.sources.write();
        lock.insert(source.name().to_string(), source);
    }

    pub(crate) fn get(&self, name: &str) -> Option<Arc<dyn Source + Send + Sync>> {
        let lock = self.sources.read();
        lock.get(name).cloned()
    }
}

/// A trait for custom verification logic (OAuth2, multi-step, etc).
pub(crate) trait CustomVerifier: Send + Sync {
    fn name(&self) -> &str;
}

/// A registry for custom verifiers.
#[derive(Default)]
pub(crate) struct VerifierRegistry {
    verifiers: RwLock<HashMap<String, Arc<dyn CustomVerifier>>>,
}

impl VerifierRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, verifier: Arc<dyn CustomVerifier>) {
        let mut lock = self.verifiers.write();
        lock.insert(verifier.name().to_string(), verifier);
    }

    pub(crate) fn get(&self, name: &str) -> Option<Arc<dyn CustomVerifier>> {
        let lock = self.verifiers.read();
        lock.get(name).cloned()
    }
}
