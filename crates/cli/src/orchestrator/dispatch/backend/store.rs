//! Persistent autoroute calibration cache schema and validation.

mod artifact_identity;
mod build_identity;
mod codec;
mod inspection;
mod persistence;
mod schema;
mod telemetry;
mod validation;

pub(super) use codec::autoroute_cache_file_presence;
#[allow(unused_imports)]
pub(crate) use inspection::{inspect_autoroute_cache, AutorouteReadiness};
pub(super) use persistence::{
    load_autoroute_cache, save_autoroute_cache, AutorouteCacheSaveOutcome,
};
pub(crate) use telemetry::{
    record_bucket_miss, record_calibration_reuse, record_hit, record_miss, render_missing_buckets,
    render_summary, snapshot, AutorouteCacheMiss,
};
// Staged cache is used by `calibrate_autoroute` via orchestrator re-export.
pub(crate) use persistence::{
    bind_autoroute_cache_to_execution_packs, load_execution_pack_generation_binding,
    StagedAutorouteCache,
};

pub(super) fn current_engine_identity() -> String {
    schema::AutorouteBuildFeatures::current().describe()
}

pub(super) fn current_executable_identity(
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>> {
    artifact_identity::current_executable_sha256()
}

#[cfg(test)]
pub(super) use artifact_identity::installed_gpu_sidecar_digest;
#[cfg(test)]
pub(super) use codec::AUTOROUTE_CACHE_FILE_BYTES;
#[cfg(test)]
pub(super) use schema::{AutorouteBuildFeatures, AutorouteCache};
#[cfg(test)]
pub(super) use validation::{
    validate_decision_route_evidence, validate_ordered_device_route_bindings,
    validate_ordered_device_set_stability,
};

#[cfg(test)]
use keyhog_scanner::hw_probe::ScanBackend;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
pub(super) use validation::decision_requires_gpu_artifact_identity;

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
