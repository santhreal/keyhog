//! Compiled-artifact class model and canonical identity contracts.
//!
//! Every compiled artifact class that KeyHog persists or maps (GPU literal set,
//! Phase-2 GPU DFA catalog, Hyperscan database, detector plan, execution pack,
//! matcher artifact) belongs to this registered enumeration.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The complete enumeration of compiled artifact classes used by KeyHog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledArtifactClass {
    /// GPU literal match tables and kernel parameters.
    GpuLiteralSet,
    /// GPU Phase-2 deterministic finite automaton state transition graph.
    Phase2GpuDfaCatalog,
    /// Hyperscan / Vectorscan compiled regex database shards.
    HyperscanDatabase,
    /// Precompiled detector plan containing regexes and literal indices.
    DetectorPlan,
    /// Authenticated self-contained execution pack.
    ExecutionPack,
    /// Persistent matcher artifact graph (`.khm`).
    MatcherArtifact,
}

impl CompiledArtifactClass {
    /// List all registered compiled artifact classes.
    pub const ALL: &'static [CompiledArtifactClass] = &[
        CompiledArtifactClass::GpuLiteralSet,
        CompiledArtifactClass::Phase2GpuDfaCatalog,
        CompiledArtifactClass::HyperscanDatabase,
        CompiledArtifactClass::DetectorPlan,
        CompiledArtifactClass::ExecutionPack,
        CompiledArtifactClass::MatcherArtifact,
    ];

    /// Operator-facing label for the compiled artifact class.
    pub const fn label(self) -> &'static str {
        match self {
            Self::GpuLiteralSet => "gpu-literal-set",
            Self::Phase2GpuDfaCatalog => "phase2-gpu-dfa-catalog",
            Self::HyperscanDatabase => "hyperscan-database",
            Self::DetectorPlan => "detector-plan",
            Self::ExecutionPack => "execution-pack",
            Self::MatcherArtifact => "matcher-artifact",
        }
    }

    /// Compile owner / subsystem responsible for producing this artifact.
    pub const fn compile_owner(self) -> &'static str {
        match self {
            Self::GpuLiteralSet => "keyhog-scanner::gpu_literal_artifacts",
            Self::Phase2GpuDfaCatalog => "keyhog-scanner::engine::phase2_gpu_dfa",
            Self::HyperscanDatabase => "keyhog-scanner::simd::backend",
            Self::DetectorPlan => "keyhog-scanner::compiled_scanner",
            Self::ExecutionPack => "keyhog-scanner::execution_pack",
            Self::MatcherArtifact => "keyhog-scanner::matcher_artifact_cache",
        }
    }
}

impl fmt::Display for CompiledArtifactClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Canonical compiled artifact identity binding.
///
/// Shared definition of compiled artifact identity across all caching and
/// execution layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledArtifactIdentity {
    /// The class of compiled artifact.
    pub artifact_class: CompiledArtifactClass,
    /// Digest of the running binary executable.
    pub binary_digest: String,
    /// Digest of the active detector corpus.
    pub detector_digest: String,
    /// Digest of the active resolved configuration.
    pub config_digest: String,
    /// Target platform string (`os-arch`).
    pub platform: String,
    /// Optional target accelerator / adapter descriptor.
    pub adapter_identity: Option<String>,
}
