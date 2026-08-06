//! Public scanner lifecycle and backend-readiness types.

#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use crate::gpu::load_dynamic_library;
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use crate::gpu::probe_cuda_peer;
pub use crate::gpu::GpuBackendAvailability;
pub(crate) use crate::gpu::{GpuBackendAcquisitionFailure, GpuBackendPeers, SelectedGpuPeer};
use crate::hw_probe::ScanBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuInitPolicy {
    /// Honor the resolved GPU runtime policy.
    FromRuntimePolicy,
    /// Census GPU peers regardless of the disabled-GPU policy. The selected
    /// execution backend is still materialized lazily.
    ForceEnabled,
    /// Compile for one route selected before scanner construction. CPU and SIMD
    /// skip GPU state; GPU routes retain only their named VYRE peer.
    SelectedBackend(ScanBackend),
    /// Skip CUDA, Metal, and WGPU census and acquisition. Used when the selected CLI path
    /// cannot route to GPU, avoiding startup and RSS overhead without changing
    /// scan results.
    ForceDisabled,
}

#[cfg(all(test, feature = "gpu", target_os = "linux"))]
#[path = "../../tests/unit/compiled_scanner_cuda_driver_preflight.rs"]
mod cuda_driver_preflight_tests;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuBackendCandidateStatus {
    pub backend: ScanBackend,
    /// Whether the lightweight host census found a hardware peer with enough
    /// identity to participate in autoroute.
    pub available: bool,
    /// Whether this process has materialized the execution backend.
    pub acquired: bool,
    pub driver_id: Option<&'static str>,
    pub driver_version: Option<&'static str>,
    pub device_identity: Option<String>,
    pub runtime_identity: Option<String>,
    pub is_software: bool,
    pub acquisition_error: Option<String>,
}

impl GpuBackendCandidateStatus {
    #[must_use]
    pub fn has_complete_identity(&self) -> bool {
        self.driver_id.is_some_and(|value| !value.trim().is_empty())
            && self
                .driver_version
                .is_some_and(|value| !value.trim().is_empty())
            && self
                .device_identity
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            && self
                .runtime_identity
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
    }

    /// Whether the lightweight census found hardware with complete identity.
    /// This makes the peer eligible for materialization, but does not prove
    /// that device acquisition has succeeded.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.available && !self.is_software && self.has_complete_identity()
    }

    /// Whether this exact peer has materialized and retains complete identity.
    #[must_use]
    pub fn is_acquired_eligible(&self) -> bool {
        self.acquired && self.is_eligible()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledScannerRuntime {
    pub detector_count: usize,
    pub pattern_count: usize,
    /// Versioned 64-bit projection of the canonical 256-bit scan-execution
    /// hash. Autoroute also persists the complete hash as its rules identity.
    pub detector_digest: u64,
    /// Complete BLAKE3 identity for the compiled detector and decoder execution plan.
    pub compiled_plan_digest: [u8; 32],
    /// Backend used by the no-backend library APIs. CLI calibrated routing is a
    /// separate persisted per-workload decision and is never inferred here.
    pub preferred_backend: &'static str,
    pub gpu_backends: GpuBackendAvailability,
    pub gpu_degrade_count: u64,
}

/// One context relation after detector compilation has resolved capture selection and defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledEvidenceRelation<'a> {
    pub name: &'a str,
    pub regex: &'a str,
    pub capture_group: Option<usize>,
    pub within_lines: usize,
    pub within_bytes: Option<usize>,
    pub direction: keyhog_core::EvidenceDirection,
    pub scope: keyhog_core::EvidenceScope,
    pub requirement: keyhog_core::EvidenceRequirement,
    pub value_relation: keyhog_core::EvidenceValueRelation,
}

/// One cross-detector relation after target validation and cycle checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledDetectorEvidenceRelation<'a> {
    pub detector_id: &'a str,
    pub kind: keyhog_core::DetectorRelationKind,
    pub within_lines: usize,
    pub within_bytes: Option<usize>,
    pub direction: keyhog_core::EvidenceDirection,
}

/// Compiled local and cross-detector evidence exactly as the scanner will execute it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledEvidencePlan<'a> {
    pub detector_id: &'a str,
    pub relations: Vec<CompiledEvidenceRelation<'a>>,
    pub detector_relations: Vec<CompiledDetectorEvidenceRelation<'a>>,
}
