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
    cuda: OnceLock<Result<AcquiredGpuPeer, String>>,
    wgpu: OnceLock<Result<AcquiredGpuPeer, String>>,
    pub(crate) cuda_available: bool,
    pub(crate) wgpu_available: bool,
    pub(crate) cuda_device_identity: Option<String>,
    pub(crate) cuda_runtime_identity: Option<String>,
    pub(crate) wgpu_device_identity: Option<String>,
    pub(crate) wgpu_runtime_identity: Option<String>,
    pub(crate) wgpu_is_software: bool,
}

pub(crate) struct AcquiredGpuPeer {
    pub(crate) backend: Arc<dyn vyre::VyreBackend>,
    pub(crate) device_identity: Option<String>,
    pub(crate) is_software: bool,
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
            ScanBackend::GpuCuda if self.cuda_available => self
                .cuda
                .get_or_init(acquire_cuda_peer)
                .as_ref()
                // LAW10: acquisition failures remain stored in this `Result` and are exposed by runtime diagnostics; this accessor only asks whether a usable peer exists.
                .ok()
                .map(|peer| &peer.backend),
            ScanBackend::GpuWgpu if self.wgpu_available => self
                .wgpu
                .get_or_init(acquire_wgpu_peer)
                .as_ref()
                // LAW10: acquisition failures remain stored in this `Result` and are exposed by runtime diagnostics; this accessor only asks whether a usable peer exists.
                .ok()
                .map(|peer| &peer.backend),
            _ => None,
        }
    }

    pub(crate) fn initialized(&self, backend: ScanBackend) -> Option<&AcquiredGpuPeer> {
        match backend {
            // LAW10: acquisition errors remain stored for diagnostics; this accessor intentionally returns only successfully acquired peers.
            ScanBackend::GpuCuda => self.cuda.get().and_then(|result| result.as_ref().ok()),
            // LAW10: WGPU acquisition errors remain stored for runtime diagnostics; this accessor returns only a successfully acquired peer.
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
fn acquire_cuda_peer() -> Result<AcquiredGpuPeer, String> {
    let backend = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let cuda = vyre_driver_cuda::backend::CudaBackend::acquire()?;
        let boxed: Box<dyn vyre::VyreBackend> =
            Box::new(vyre_driver_cuda::CudaBackendRegistration::new(cuda));
        Ok::<Arc<dyn vyre::VyreBackend>, String>(Arc::from(boxed))
    }))
    .map_err(|panic| {
        format!(
            "CUDA backend acquisition panicked: {}. Fix: repair the CUDA driver/runtime or select another calibrated backend",
            crate::error::panic_payload_detail(panic)
        )
    })??;
    tracing::info!(target: "keyhog::routing", "selected CUDA peer backend acquired");
    Ok(AcquiredGpuPeer {
        backend,
        device_identity: None,
        is_software: false,
    })
}

#[cfg(not(all(feature = "gpu", target_os = "linux")))]
fn acquire_cuda_peer() -> Result<AcquiredGpuPeer, String> {
    Err("CUDA peer is not compiled for this platform".to_string())
}

#[cfg(feature = "gpu")]
fn acquire_wgpu_peer() -> Result<AcquiredGpuPeer, String> {
    let backend = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        vyre_driver_wgpu::WgpuBackend::shared,
    ))
    .map_err(|panic| {
        format!(
            "WGPU backend acquisition panicked: {}. Fix: repair the graphics driver/runtime or select another calibrated backend",
            crate::error::panic_payload_detail(panic)
        )
    })?
    .map_err(|error| error.to_string())?;
    let info = backend.adapter_info();
    let device_identity =
        crate::gpu::gpu_adapter_device_identity(info, backend.device_limits().max_buffer_size);
    let is_software = crate::gpu::is_software_adapter(info);
    tracing::info!(
        target: "keyhog::routing",
        device_identity,
        "selected WGPU peer backend acquired"
    );
    let backend: Arc<dyn vyre::VyreBackend> = backend;
    Ok(AcquiredGpuPeer {
        backend,
        device_identity: Some(device_identity),
        is_software,
    })
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) fn probe_cuda_peer() -> Result<vyre_driver_cuda::device::CudaDeviceCaps, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vyre_driver_cuda::device::CudaDeviceCaps::probe(0)
    }))
    .map_err(|panic| {
        format!(
            "CUDA device probe panicked: {}. Fix: repair the CUDA driver/runtime before enabling this backend",
            crate::error::panic_payload_detail(panic)
        )
    })?
    .map_err(|error| error.to_string())
}

#[cfg(not(feature = "gpu"))]
fn acquire_wgpu_peer() -> Result<AcquiredGpuPeer, String> {
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
