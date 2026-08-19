//! Install-time compilation and scan-time loading of immutable execution packs.
//!
//! [`compiler`] owns serialization from validated detector execution data. The
//! scan-time [`runtime`] module can only map and validate a published pack. It
//! has no detector parser or compiler entrypoint, which makes runtime
//! compilation an architectural error instead of a fallback.

pub mod compiler;
pub mod cpu_program;
pub mod detector_plan;
mod format;
pub mod generation;
pub mod ir;
pub mod matcher_sections;
pub mod parity;
pub mod runtime;
pub mod selection;
pub mod signature;
#[cfg(feature = "simd")]
pub mod simd_program;
#[cfg(feature = "gpu")]
pub mod vyre_program;

pub use compiler::{
    compile_execution_pack, compose_policy_execution_pack, BackendPlan, CompileSection,
    CompiledExecutionPack, ExecutionPackCompileInput, PolicyPlanSections,
};
pub use cpu_program::{
    ScalarCpuExecutionProgram, ScalarCpuPatternProgram, SCALAR_CPU_PROGRAM_VERSION,
};
pub use detector_plan::{CompiledDetectorPlanSection, DETECTOR_PLAN_SECTION_VERSION};
pub use format::{
    ExecutionPackBackend, ExecutionPackIdentity, ExecutionPackPolicy, ExecutionPackSectionKind,
    EXECUTION_PACK_COMPILER_ABI, EXECUTION_PACK_FORMAT_VERSION, EXECUTION_PACK_HEADER_LEN,
};
#[cfg(feature = "gpu")]
pub use generation::CompiledVyreBackendProgram;
pub use generation::{
    compile_deep_policy_execution_packs, compile_default_policy_execution_packs,
    compile_fast_policy_execution_packs, compile_policy_execution_packs,
    compile_precision_policy_execution_packs, BackendExecutionArtifact, BackendProgramArtifact,
    CompiledBackendExecutionPack, CompiledNativeBackendPrograms, CompiledPolicyExecutionPacks,
    PackGenerationIdentity,
};
pub use ir::{
    CanonicalDetectorExecutionIr, DecodedDetectorExecutionIr, DetectorMetadataRecord,
    EntropyFallbackMetadataRecord, NormalizedDetectorMetadata, DETECTOR_EXECUTION_IR_VERSION,
};
pub use matcher_sections::{CompiledRouteMatcherSections, ROUTE_MATCHER_SECTION_VERSION};
pub use parity::{PackFindingParityEvidence, PACK_FINDING_PARITY_VERSION};
pub use runtime::{
    ExecutionPack, ExecutionPackByteLedger, ResidentByteOwner, ResidentByteOwnership,
};
pub use selection::{
    select_execution_pack, ExecutionPackCandidate, PersistedRouteDecision, RouteSelectionContext,
    SelectedExecutionPack, ROUTE_DECISION_VERSION,
};
pub use signature::{
    ExecutionPackSignature, ExecutionPackSigningKey, EXECUTION_PACK_SIGNATURE_VERSION,
};
#[cfg(feature = "simd")]
pub use simd_program::{
    HyperscanPatternProgram, HyperscanSimdExecutionProgram, HYPERSCAN_SIMD_PROGRAM_VERSION,
};
#[cfg(feature = "gpu")]
pub use vyre_program::{
    VyreExecutionIdentity, VyreOrchestrationProgram, VYRE_ORCHESTRATION_PROGRAM_VERSION,
};

#[derive(Debug)]
pub enum ExecutionPackError {
    InvalidCompilerInput(String),
    InvalidPack(String),
    Incompatible(String),
    Io {
        operation: &'static str,
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for ExecutionPackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCompilerInput(message)
            | Self::InvalidPack(message)
            | Self::Incompatible(message) => formatter.write_str(message),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} execution pack {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ExecutionPackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
impl Clone for ExecutionPackError {
    fn clone(&self) -> Self {
        match self {
            Self::InvalidCompilerInput(message) => Self::InvalidCompilerInput(message.clone()),
            Self::InvalidPack(message) => Self::InvalidPack(message.clone()),
            Self::Incompatible(message) => Self::Incompatible(message.clone()),
            Self::Io {
                operation,
                path,
                source,
            } => Self::Io {
                operation,
                path: path.clone(),
                source: std::io::Error::new(source.kind(), source.to_string()),
            },
        }
    }
}
