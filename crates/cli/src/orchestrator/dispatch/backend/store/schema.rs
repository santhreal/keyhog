//! Versioned on-disk autoroute cache schema.

use serde::{Deserialize, Serialize};

use super::super::evidence::AutorouteDecision;
use super::super::host::AutorouteHostProfile;
use super::super::workload::WorkloadKey;

/// Minimal front matter parsed before the version-specific payload.
#[derive(Deserialize)]
pub(crate) struct AutorouteCacheVersionEnvelope {
    #[serde(default)]
    pub(super) version: u32,
}

/// On-disk autoroute calibration cache. Only build and corpus identity is shared;
/// each resolved scan configuration owns its projected host and workload routes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutorouteCache {
    pub(crate) version: u32,
    pub(crate) binary_version: String,
    pub(crate) git_hash: String,
    pub(crate) executable_sha256: String,
    pub(crate) build_features: AutorouteBuildFeatures,
    pub(crate) detector_digest: u64,
    pub(crate) rules_digest: String,
    pub(crate) configs: Vec<AutorouteConfigDecisions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutorouteConfigDecisions {
    pub(crate) config_digest: u64,
    pub(crate) host: AutorouteHostProfile,
    pub(crate) decisions: Vec<PersistedAutorouteDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedAutorouteDecision {
    pub(crate) workload: WorkloadKey,
    pub(crate) decision: AutorouteDecision,
    pub(crate) workload_digest: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutorouteBuildFeatures {
    pub(crate) cli_features: Vec<String>,
    pub(crate) scanner_features: Vec<String>,
    pub(crate) sources_features: Vec<String>,
    pub(crate) verifier_features: Vec<String>,
}
