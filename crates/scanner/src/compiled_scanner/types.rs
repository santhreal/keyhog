//! Public scanner lifecycle and backend-readiness types.

use crate::hw_probe::ScanBackend;
use std::sync::{Arc, OnceLock};

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

pub(crate) struct GpuBackendPeers {
    cuda: OnceLock<Result<Arc<dyn vyre::VyreBackend>, String>>,
    wgpu: OnceLock<Result<Arc<dyn vyre::VyreBackend>, String>>,
    pub(crate) cuda_available: bool,
    pub(crate) wgpu_available: bool,
    pub(crate) cuda_device_identity: Option<String>,
    pub(crate) cuda_runtime_identity: Option<String>,
    pub(crate) wgpu_device_identity: Option<String>,
    pub(crate) wgpu_runtime_identity: Option<String>,
    pub(crate) wgpu_is_software: bool,
}

impl Default for GpuBackendPeers {
    fn default() -> Self {
        Self {
            cuda: OnceLock::new(),
            wgpu: OnceLock::new(),
            cuda_available: false,
            wgpu_available: false,
            cuda_device_identity: None,
            cuda_runtime_identity: None,
            wgpu_device_identity: None,
            wgpu_runtime_identity: None,
            wgpu_is_software: false,
        }
    }
}

impl GpuBackendPeers {
    pub(crate) fn get(&self, backend: ScanBackend) -> Option<&Arc<dyn vyre::VyreBackend>> {
        match backend {
            ScanBackend::GpuCuda if self.cuda_available => {
                self.cuda.get_or_init(acquire_cuda_peer).as_ref().ok()
            }
            ScanBackend::GpuWgpu if self.wgpu_available => {
                self.wgpu.get_or_init(acquire_wgpu_peer).as_ref().ok()
            }
            _ => None,
        }
    }

    pub(crate) fn initialized(&self, backend: ScanBackend) -> Option<&Arc<dyn vyre::VyreBackend>> {
        match backend {
            ScanBackend::GpuCuda => self.cuda.get().and_then(|result| result.as_ref().ok()),
            ScanBackend::GpuWgpu => self.wgpu.get().and_then(|result| result.as_ref().ok()),
            _ => None,
        }
    }

    pub(crate) fn initialization_error(&self, backend: ScanBackend) -> Option<&str> {
        match backend {
            ScanBackend::GpuCuda => self.cuda.get(),
            ScanBackend::GpuWgpu => self.wgpu.get(),
            _ => None,
        }
        .and_then(|result| result.as_ref().err().map(String::as_str))
    }

    pub(crate) fn availability(&self) -> GpuBackendAvailability {
        GpuBackendAvailability {
            cuda: self.cuda_available,
            wgpu: self.wgpu_available,
        }
    }
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
fn acquire_cuda_peer() -> Result<Arc<dyn vyre::VyreBackend>, String> {
    let cuda = vyre_driver_cuda::backend::CudaBackend::acquire()?;
    let boxed: Box<dyn vyre::VyreBackend> =
        Box::new(vyre_driver_cuda::CudaBackendRegistration::new(cuda));
    tracing::info!(target: "keyhog::routing", "selected CUDA peer backend acquired");
    Ok(Arc::from(boxed))
}

#[cfg(not(all(feature = "gpu", target_os = "linux")))]
fn acquire_cuda_peer() -> Result<Arc<dyn vyre::VyreBackend>, String> {
    Err("CUDA peer is not compiled for this platform".to_string())
}

#[cfg(feature = "gpu")]
fn acquire_wgpu_peer() -> Result<Arc<dyn vyre::VyreBackend>, String> {
    vyre_driver_wgpu::WgpuBackend::shared()
        .map(|backend| {
            tracing::info!(target: "keyhog::routing", "selected WGPU peer backend acquired");
            let backend: Arc<dyn vyre::VyreBackend> = backend;
            backend
        })
        .map_err(|error| error.to_string())
}

#[cfg(not(feature = "gpu"))]
fn acquire_wgpu_peer() -> Result<Arc<dyn vyre::VyreBackend>, String> {
    Err("WGPU peer is not compiled in this build".to_string())
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

    /// Whether this peer is executable hardware with complete reproducibility
    /// identity. Autoroute and health paths consume this single eligibility
    /// contract instead of combining acquisition with unrelated global probes.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.available && !self.is_software && self.has_complete_identity()
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
