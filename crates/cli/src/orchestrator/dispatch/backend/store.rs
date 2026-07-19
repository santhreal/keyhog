//! Persistent autoroute calibration cache schema and validation.

mod artifact_identity;
mod build_identity;
mod codec;
mod inspection;
mod persistence;
mod schema;
mod validation;

pub(super) use codec::autoroute_cache_file_presence;
pub(crate) use inspection::{inspect_autoroute_cache, AutorouteReadiness};
pub(super) use persistence::{
    load_autoroute_cache, save_autoroute_cache, AutorouteCacheSaveOutcome,
};
// Staged cache is used by `calibrate_autoroute` via orchestrator re-export.
pub(crate) use persistence::StagedAutorouteCache;

#[cfg(test)]
pub(super) use codec::AUTOROUTE_CACHE_FILE_BYTES;
#[cfg(test)]
pub(super) use schema::{AutorouteBuildFeatures, AutorouteCache};

#[cfg(test)]
use keyhog_scanner::hw_probe::ScanBackend;
#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
use super::evidence::AutorouteDecision;
#[cfg(test)]
use super::workload::WorkloadKey;

// --- Exact bucket resolution (test facade) ----------------------------------
//
// Autoroute evidence is scoped to the complete workload key. Neighbouring size
// buckets do not prove which backend is fastest for this one, even when their
// CPU decisions agree, so a miss must remain unresolved.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(super) enum BucketResolution {
    /// The exact workload bucket was calibrated.
    Exact(ScanBackend),
    /// No exact decision exists (the caller must fail closed).
    Unresolved,
}

#[cfg(test)]
pub(super) fn resolve_bucket(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
) -> BucketResolution {
    if let Some(backend) = decisions.get(key).and_then(AutorouteDecision::backend) {
        return BucketResolution::Exact(backend);
    }
    BucketResolution::Unresolved
}
