//! Public scanner lifecycle and backend-readiness types.

use crate::hw_probe::ScanBackend;
pub use crate::gpu::GpuBackendAvailability;
pub(crate) use crate::gpu::{GpuBackendAcquisitionFailure, GpuBackendPeers};
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use crate::gpu::probe_cuda_peer;
#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use crate::gpu::load_dynamic_library;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuInitPolicy {
    /// Honor the resolved GPU runtime policy.
    FromRuntimePolicy,
    /// Census GPU peers regardless of the disabled-GPU policy. The selected
    /// execution backend is still materialized lazily.
    ForceEnabled,
    /// Skip CUDA/WGPU census and acquisition. Used when the selected CLI path
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
    /// Backend used by the no-backend library APIs. CLI calibrated routing is a
    /// separate persisted per-workload decision and is never inferred here.
    pub preferred_backend: &'static str,
    pub gpu_backends: GpuBackendAvailability,
    pub gpu_degrade_count: u64,
}
