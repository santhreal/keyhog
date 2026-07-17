//! Public scanner lifecycle and backend-readiness types.

use crate::hw_probe::ScanBackend;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpuInitPolicy {
    /// Honor the resolved GPU runtime policy.
    FromRuntimePolicy,
    /// Acquire a GPU backend when hardware is present, regardless of the
    /// disabled-GPU policy. Used when the operator explicitly forces GPU.
    ForceEnabled,
    /// Skip CUDA/wgpu acquisition. Used when the selected CLI path cannot
    /// route to GPU, avoiding startup and RSS overhead without changing scan
    /// results.
    ForceDisabled,
}

#[derive(Default)]
pub(crate) struct GpuBackendPeers {
    pub(crate) cuda: Option<Arc<dyn vyre::VyreBackend>>,
    pub(crate) wgpu: Option<Arc<dyn vyre::VyreBackend>>,
    pub(crate) cuda_device_identity: Option<String>,
    pub(crate) cuda_runtime_identity: Option<String>,
    pub(crate) wgpu_device_identity: Option<String>,
    pub(crate) wgpu_runtime_identity: Option<String>,
    pub(crate) wgpu_is_software: bool,
}

impl GpuBackendPeers {
    pub(crate) fn get(&self, backend: ScanBackend) -> Option<&Arc<dyn vyre::VyreBackend>> {
        match backend {
            ScanBackend::GpuCuda => self.cuda.as_ref(),
            ScanBackend::GpuWgpu => self.wgpu.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn availability(&self) -> GpuBackendAvailability {
        GpuBackendAvailability {
            cuda: self.cuda.is_some(),
            wgpu: self.wgpu.is_some(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuBackendAvailability {
    pub cuda: bool,
    pub wgpu: bool,
}

impl GpuBackendAvailability {
    #[must_use]
    pub const fn any(self) -> bool {
        self.cuda || self.wgpu
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuBackendAcquisitionFailure {
    pub backend: &'static str,
    pub diagnostic: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuBackendCandidateStatus {
    pub backend: ScanBackend,
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

    /// Whether this peer is executable hardware with complete reproducibility
    /// identity. Autoroute and health paths consume this single eligibility
    /// contract instead of combining acquisition with unrelated global probes.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.acquired && !self.is_software && self.has_complete_identity()
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
