//! Lazy CUDA, Metal, and WGPU acquisition behind the scanner GPU boundary.

#[cfg(feature = "gpu")]
use super::artifact::{load_moe_artifacts, MoeArtifacts};
#[cfg(feature = "gpu")]
use super::diagnostics::{on_gpu_init_failed, GpuBackendError, GpuInitError};
use crate::hw_probe::ScanBackend;
#[cfg(feature = "gpu")]
use std::sync::LazyLock;
use std::sync::{Arc, OnceLock};

pub(crate) struct AcquiredGpuPeer {
    pub(crate) backend: Arc<dyn vyre::VyreBackend>,
    pub(crate) device_identity: Option<String>,
    pub(crate) is_software: bool,
    // Populated and read only by the GPU dispatch path. A build without the
    // `gpu` feature can never construct a peer, so these facets would be dead
    // storage in every portable binary.
    #[cfg(feature = "gpu")]
    pub(crate) resident_timed_dispatch_supported: bool,
    /// PCI vendor id where the backend exposes one; 0 means unknown.
    #[cfg(feature = "gpu")]
    pub(crate) adapter_vendor: u32,
    /// PCI device id where the backend exposes one; 0 means unknown.
    #[cfg(feature = "gpu")]
    pub(crate) adapter_device: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuBackendAvailability {
    pub cuda: bool,
    pub metal: bool,
    pub wgpu: bool,
}

impl GpuBackendAvailability {
    #[must_use]
    pub const fn any(self) -> bool {
        self.cuda || self.metal || self.wgpu
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuBackendAcquisitionFailure {
    pub backend: &'static str,
    pub diagnostic: String,
}

pub(crate) struct GpuBackendPeers {
    cuda: OnceLock<Result<AcquiredGpuPeer, String>>,
    metal: OnceLock<Result<AcquiredGpuPeer, String>>,
    wgpu: OnceLock<Result<AcquiredGpuPeer, String>>,
    pub(crate) cuda_available: bool,
    pub(crate) metal_available: bool,
    pub(crate) wgpu_available: bool,
    pub(crate) cuda_device_identity: Option<String>,
    pub(crate) cuda_runtime_identity: Option<String>,
    pub(crate) metal_device_identity: Option<String>,
    pub(crate) metal_runtime_identity: Option<String>,
    pub(crate) wgpu_device_identity: Option<String>,
    pub(crate) wgpu_runtime_identity: Option<String>,
    pub(crate) wgpu_is_software: bool,
}

pub(crate) struct SelectedGpuPeer {
    backend: ScanBackend,
    acquisition: OnceLock<Result<AcquiredGpuPeer, String>>,
    pub(crate) available: bool,
    pub(crate) device_identity: Option<String>,
    pub(crate) runtime_identity: Option<String>,
    pub(crate) is_software: bool,
    initialization_error: Option<String>,
}

impl SelectedGpuPeer {
    pub(crate) fn new(backend: ScanBackend) -> Self {
        debug_assert!(backend.is_gpu());
        Self {
            backend,
            acquisition: OnceLock::new(),
            available: false,
            device_identity: None,
            runtime_identity: None,
            is_software: false,
            initialization_error: None,
        }
    }

    pub(crate) fn mark_available(
        &mut self,
        device_identity: String,
        runtime_identity: Option<String>,
        is_software: bool,
    ) {
        self.available = true;
        self.device_identity = Some(device_identity);
        self.runtime_identity = runtime_identity;
        self.is_software = is_software;
        self.initialization_error = None;
    }

    pub(crate) fn mark_unavailable(&mut self, diagnostic: String) {
        self.available = false;
        self.initialization_error = Some(diagnostic);
    }

    pub(crate) fn backend(&self) -> ScanBackend {
        self.backend
    }

    pub(crate) fn get(&self, backend: ScanBackend) -> Option<&Arc<dyn vyre::VyreBackend>> {
        if backend != self.backend {
            return None;
        }
        let result = lazy_acquire(self.available, &self.acquisition, || acquire_peer(backend))?;
        match result {
            Ok(peer) => Some(&peer.backend),
            Err(error) => {
                tracing::error!(
                    target: "keyhog::routing",
                    ?backend,
                    diagnostic = %error,
                    "selected GPU backend acquisition failed"
                );
                None
            }
        }
    }

    pub(crate) fn initialized(&self, backend: ScanBackend) -> Option<&AcquiredGpuPeer> {
        if backend != self.backend {
            return None;
        }
        self.acquisition.get()?.as_ref().ok()
    }

    pub(crate) fn initialization_error(&self, backend: ScanBackend) -> Option<&str> {
        if backend != self.backend {
            return None;
        }
        self.acquisition
            .get()
            .and_then(|result| result.as_ref().err().map(String::as_str))
            .or(self.initialization_error.as_deref())
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn resident_timed_dispatch_supported(&self, backend: ScanBackend) -> bool {
        self.initialized(backend)
            .is_some_and(|peer| peer.resident_timed_dispatch_supported)
    }
}

impl Default for GpuBackendPeers {
    fn default() -> Self {
        Self {
            cuda: OnceLock::new(),
            metal: OnceLock::new(),
            wgpu: OnceLock::new(),
            cuda_available: false,
            metal_available: false,
            wgpu_available: false,
            cuda_device_identity: None,
            metal_device_identity: None,
            metal_runtime_identity: None,
            cuda_runtime_identity: None,
            wgpu_device_identity: None,
            wgpu_runtime_identity: None,
            wgpu_is_software: false,
        }
    }
}

pub(super) fn lazy_acquire<T, E>(
    available: bool,
    slot: &OnceLock<Result<T, E>>,
    acquire: impl FnOnce() -> Result<T, E>,
) -> Option<&Result<T, E>> {
    if !available {
        return None;
    }
    Some(slot.get_or_init(acquire))
}

fn acquire_peer(backend: ScanBackend) -> Result<AcquiredGpuPeer, String> {
    match backend {
        ScanBackend::GpuCuda => acquire_cuda_peer(),
        ScanBackend::GpuMetal => acquire_metal_peer(),
        ScanBackend::GpuWgpu => acquire_wgpu_peer(),
        _ => Err(format!("{} is not a GPU backend", backend.label())),
    }
}

impl GpuBackendPeers {
    pub(crate) fn get(&self, backend: ScanBackend) -> Option<&Arc<dyn vyre::VyreBackend>> {
        let result = match backend {
            ScanBackend::GpuCuda => {
                lazy_acquire(self.cuda_available, &self.cuda, acquire_cuda_peer)
            }
            ScanBackend::GpuMetal => {
                lazy_acquire(self.metal_available, &self.metal, acquire_metal_peer)
            }
            ScanBackend::GpuWgpu => {
                lazy_acquire(self.wgpu_available, &self.wgpu, acquire_wgpu_peer)
            }
            _ => None,
        }?;
        match result {
            Ok(peer) => Some(&peer.backend),
            Err(error) => {
                tracing::error!(
                    target: "keyhog::routing",
                    ?backend,
                    diagnostic = %error,
                    "selected GPU backend acquisition failed"
                );
                None
            }
        }
    }

    pub(crate) fn initialized(&self, backend: ScanBackend) -> Option<&AcquiredGpuPeer> {
        let result = match backend {
            ScanBackend::GpuCuda => self.cuda.get(),
            ScanBackend::GpuMetal => self.metal.get(),
            ScanBackend::GpuWgpu => self.wgpu.get(),
            _ => None,
        }?;
        // LAW10: diagnostics retain the complete error in the slot; this status
        // accessor distinguishes initialized success without consuming it.
        match result {
            Ok(peer) => Some(peer),
            Err(_) => None, // LAW10: status projection only; initialization_error retains the typed diagnostic and execution logs it before refusing this backend.
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn resident_timed_dispatch_supported(&self, backend: ScanBackend) -> bool {
        self.initialized(backend)
            .is_some_and(|peer| peer.resident_timed_dispatch_supported)
    }

    pub(crate) fn initialization_error(&self, backend: ScanBackend) -> Option<&str> {
        match backend {
            ScanBackend::GpuCuda => self.cuda.get(),
            ScanBackend::GpuMetal => self.metal.get(),
            ScanBackend::GpuWgpu => self.wgpu.get(),
            _ => None,
        }
        .and_then(|result| result.as_ref().err().map(String::as_str))
    }

    pub(crate) fn availability(&self) -> GpuBackendAvailability {
        GpuBackendAvailability {
            cuda: self.cuda_available,
            metal: self.metal_available,
            wgpu: self.wgpu_available,
        }
    }
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(super) fn run_cuda_after_preflight<T>(
    preflight: impl FnOnce() -> Result<(), String>,
    acquire: impl FnOnce() -> Result<T, String>,
    operation: &'static str,
) -> Result<T, String> {
    preflight()?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(acquire)).map_err(|panic| {
        format!(
            "CUDA {operation} panicked: {}. Fix: repair the CUDA driver/runtime{}",
            crate::error::panic_payload_detail(panic),
            if operation == "backend acquisition" {
                " or select another calibrated backend"
            } else {
                " before enabling this backend"
            }
        )
    })?
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
fn acquire_cuda_peer() -> Result<AcquiredGpuPeer, String> {
    let backend = run_cuda_after_preflight(
        ensure_cuda_driver_library_loadable,
        || {
            let cuda = vyre_driver_cuda::backend::CudaBackend::acquire()?;
            let boxed: Box<dyn vyre::VyreBackend> =
                Box::new(vyre_driver_cuda::CudaBackendRegistration::new(cuda));
            Ok::<Arc<dyn vyre::VyreBackend>, String>(Arc::from(boxed))
        },
        "backend acquisition",
    )?;
    tracing::info!(target: "keyhog::routing", "selected CUDA peer backend acquired");
    Ok(AcquiredGpuPeer {
        backend,
        device_identity: None,
        is_software: false,
        resident_timed_dispatch_supported: true,
        // CUDA implies an NVIDIA device; the CUDA caps API does not expose a
        // PCI device id, so the device facet stays 0 (unknown).
        adapter_vendor: 0x10de,
        adapter_device: 0,
    })
}

#[cfg(not(all(feature = "gpu", target_os = "linux")))]
fn acquire_cuda_peer() -> Result<AcquiredGpuPeer, String> {
    Err("CUDA peer is not compiled for this platform".to_string())
}

#[cfg(all(feature = "gpu", target_os = "macos"))]
fn acquire_metal_peer() -> Result<AcquiredGpuPeer, String> {
    let backend = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        vyre_driver_metal::acquire,
    ))
    .map_err(|panic| {
        format!(
            "Metal backend acquisition panicked: {}. Fix: repair Metal.framework or select another calibrated backend",
            crate::error::panic_payload_detail(panic)
        )
    })?
    .map_err(|error| error.to_string())?;
    let device_identity = crate::gpu::gpu_adapter_probe()
        .map(|probe| probe.device_identity)
        .ok_or_else(|| {
            "native Metal peer acquired but its exact adapter identity is unavailable".to_string()
        })?;
    tracing::info!(target: "keyhog::routing", "selected native Metal peer backend acquired");
    Ok(AcquiredGpuPeer {
        backend: Arc::from(backend),
        device_identity: Some(device_identity),
        is_software: false,
        resident_timed_dispatch_supported: false,
        // Metal implies an Apple device; the Metal acquisition API does not
        // expose a PCI device id, so the device facet stays 0 (unknown).
        adapter_vendor: 0x106b,
        adapter_device: 0,
    })
}

#[cfg(not(all(feature = "gpu", target_os = "macos")))]
fn acquire_metal_peer() -> Result<AcquiredGpuPeer, String> {
    Err("native Metal peer is not compiled for this platform".to_string())
}

#[cfg(feature = "gpu")]
fn wgpu_resident_timed_dispatch_supported(features: wgpu::Features) -> bool {
    features
        .contains(wgpu::Features::TIMESTAMP_QUERY | wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS)
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
    let resident_timed_dispatch_supported =
        wgpu_resident_timed_dispatch_supported(backend.device_queue().0.features());
    tracing::info!(
        target: "keyhog::routing",
        device_identity,
        "selected WGPU peer backend acquired"
    );
    let adapter_vendor = info.vendor;
    let adapter_device = info.device;
    let backend: Arc<dyn vyre::VyreBackend> = backend;
    Ok(AcquiredGpuPeer {
        backend,
        device_identity: Some(device_identity),
        is_software,
        resident_timed_dispatch_supported,
        adapter_vendor,
        adapter_device,
    })
}

#[cfg(not(feature = "gpu"))]
fn acquire_wgpu_peer() -> Result<AcquiredGpuPeer, String> {
    Err("WGPU peer is not compiled in this build".to_string())
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) fn load_dynamic_library(name: &std::ffi::CStr) -> Result<(), String> {
    // SAFETY: `name` is NUL-terminated for `dlopen`; a successful handle is
    // closed before returning, and `dlerror` remains valid until the next
    // dynamic-loader call on this thread.
    unsafe {
        let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let error = libc::dlerror();
            let detail = if error.is_null() {
                "unknown dynamic-loader error".to_owned()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            };
            return Err(format!("{}: {detail}", name.to_string_lossy()));
        }
        libc::dlclose(handle);
    }
    Ok(())
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
fn ensure_cuda_driver_library_loadable() -> Result<(), String> {
    let first_error = match load_dynamic_library(c"libcuda.so.1") {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    let second_error = match load_dynamic_library(c"libcuda.so") {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    Err(format!(
        "CUDA driver library is unavailable ({second_error}; first attempt: {first_error}). Fix: install or expose the NVIDIA driver libcuda.so before enabling this backend"
    ))
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) fn probe_cuda_peer() -> Result<vyre_driver_cuda::device::CudaDeviceCaps, String> {
    run_cuda_after_preflight(
        ensure_cuda_driver_library_loadable,
        || vyre_driver_cuda::device::CudaDeviceCaps::probe(0).map_err(|error| error.to_string()),
        "device probe",
    )
}

#[cfg(feature = "gpu")]
pub(crate) struct GpuContext {
    pub(super) device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
    pub(super) adapter_info: wgpu::AdapterInfo,
    pub(super) device_limits: wgpu::Limits,
    pub(super) artifacts: MoeArtifacts,
}

#[cfg(feature = "gpu")]
impl GpuContext {
    pub(crate) fn vram_mb(&self) -> Option<u64> {
        const SANE_CAP_MB: u64 = 256 * 1024;
        Some((self.device_limits.max_buffer_size / (1024 * 1024)).min(SANE_CAP_MB))
    }

    pub(crate) fn gpu_name(&self) -> &str {
        &self.adapter_info.name
    }

    pub(super) fn device(&self) -> &wgpu::Device {
        &self.device_queue.0
    }

    pub(super) fn queue(&self) -> &wgpu::Queue {
        &self.device_queue.1
    }

    pub(super) fn artifacts(&self) -> &MoeArtifacts {
        &self.artifacts
    }
}

#[cfg(feature = "gpu")]
static GPU: LazyLock<Result<Option<GpuContext>, GpuBackendError>> =
    LazyLock::new(|| match init_moe_gpu() {
        Ok(context) => {
            tracing::info!("GPU MoE inference initialized (shared device)");
            Ok(Some(context))
        }
        Err(error) => {
            on_gpu_init_failed(
                &error,
                crate::gpu::gpu_disabled_by_policy(),
                crate::gpu::gpu_required_by_policy(),
            )?;
            Ok(None)
        }
    });

#[cfg(feature = "gpu")]
fn init_moe_gpu() -> Result<GpuContext, GpuInitError> {
    let vyre_backend = vyre_driver_wgpu::WgpuBackend::shared().map_err(|error| {
        GpuInitError::no_adapter(format!("vyre WgpuBackend unavailable: {error}"))
    })?;
    let adapter_info = vyre_backend.adapter_info().clone();
    if crate::gpu::is_software_adapter(&adapter_info) {
        return Err(GpuInitError::no_adapter(format!(
            "GPU adapter is a software fallback ({} on {:?}); refusing to use",
            adapter_info.name, adapter_info.backend
        )));
    }
    let device_limits = vyre_backend.device_limits().clone();
    let device_queue = vyre_backend.device_queue();
    tracing::info!(
        gpu = %adapter_info.name,
        backend = ?adapter_info.backend,
        device_type = ?adapter_info.device_type,
        driver = %adapter_info.driver,
        "GPU MoE: reusing vyre shared device"
    );
    let artifacts = load_moe_artifacts(&device_queue.0, &adapter_info, &device_limits)
        .map_err(GpuInitError::adapter_unusable)?;
    Ok(GpuContext {
        device_queue,
        adapter_info,
        device_limits,
        artifacts,
    })
}

#[cfg(feature = "gpu")]
pub(crate) fn get_gpu() -> Result<Option<&'static GpuContext>, GpuBackendError> {
    match &*GPU {
        Ok(context) => Ok(context.as_ref()),
        Err(error) => Err(error.clone()),
    }
}

#[cfg(all(test, feature = "gpu"))]
#[path = "../../../tests/unit/gpu_backend_acquisition.rs"]
mod tests;
