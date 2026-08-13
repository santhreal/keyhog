//! Lazy CUDA, Metal, and WGPU acquisition behind the scanner GPU boundary.

use crate::hw_probe::ScanBackend;
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

    #[cfg(feature = "gpu")]
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
        // LAW10: acquisition errors are retained by initialization_error and logged by get; this status accessor returns only successful peers.
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
        result.as_ref().ok() // LAW10: status projection only; initialization_error retains the typed diagnostic and execution logs it before refusing this backend.
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
        .map(|probe| probe.device_identity.clone())
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
pub fn enumerate_gpu_device_census() -> Result<crate::gpu::device_set::GpuAdapterCensus, String> {
    let mut failures = Vec::new();
    let mut exposures = match crate::gpu::adapter_probe::probe_wgpu_device_exposures() {
        Ok(exposures) => exposures,
        Err(reason) => {
            failures.push(crate::gpu::device_set::GpuApiCensusFailure {
                api: crate::gpu::device_set::GpuApi::Wgpu,
                reason,
            });
            Vec::new()
        }
    };
    #[cfg(all(feature = "gpu", target_os = "linux"))]
    match run_cuda_after_preflight(
        ensure_cuda_driver_library_loadable,
        vyre_driver_cuda::device::CudaDeviceCaps::probe_all,
        "device census",
    ) {
        Ok(caps) => {
            exposures
                .try_reserve(caps.len())
                .map_err(|error| format!("CUDA device census reserve failed: {error}"))?;
            let runtime_identity = cuda_runtime_identity();
            for caps in caps {
                let topology = cuda_pci_bus_id(caps.ordinal).ok().and_then(|pci_bus_id| {
                    crate::gpu::adapter_probe::linux_nvidia_pci_identity(&pci_bus_id)
                });
                let (physical_identity, topology_identity, device_id, os_driver) = topology
                    .unwrap_or_else(|| {
                        let fallback = format!("cuda:ordinal={}", caps.ordinal);
                        (fallback.clone(), fallback, 0, "unavailable".to_string())
                    });
                let mut ineligible_reason = None;
                if physical_identity.starts_with("cuda:ordinal=") {
                    ineligible_reason =
                        Some("stable CUDA PCI topology identity is unavailable".to_string());
                }
                if runtime_identity.is_err() {
                    ineligible_reason =
                        Some("exact CUDA driver/runtime identity is unavailable".to_string());
                }
                exposures.push(crate::gpu::device_set::GpuDeviceExposure {
                    api: crate::gpu::device_set::GpuApi::Cuda,
                    api_ordinal: caps.ordinal,
                    physical_identity,
                    topology_identity,
                    name: caps.name,
                    vendor_id: 0x10de,
                    device_id,
                    driver_identity: format!(
                        "os-driver={os_driver};{}",
                        runtime_identity.as_deref().unwrap_or("runtime-unavailable")
                    ),
                    runtime_identity: format!(
                        "vyre-cuda={};{}",
                        env!("KEYHOG_VYRE_CUDA_VERSION"),
                        runtime_identity.as_deref().unwrap_or("runtime-unavailable")
                    ),
                    capacity_bytes: caps.total_memory,
                    is_software: false,
                    is_display_only: false,
                    ineligible_reason,
                });
            }
        }
        Err(reason) => failures.push(crate::gpu::device_set::GpuApiCensusFailure {
            api: crate::gpu::device_set::GpuApi::Cuda,
            reason,
        }),
    }
    let mut census = crate::gpu::device_set::deduplicate_gpu_exposures(exposures)?;
    census.failures = failures;
    Ok(census)
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
fn cuda_runtime_identity() -> Result<String, String> {
    let version = std::fs::read_to_string("/proc/driver/nvidia/version")
        .map_err(|error| format!("cannot read NVIDIA driver identity: {error}"))?;
    let normalized = version.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        Err("NVIDIA driver identity is empty".to_string())
    } else {
        Ok(format!("nvidia-kernel:{normalized}"))
    }
}

#[cfg(all(feature = "gpu", target_os = "linux"))]
fn cuda_pci_bus_id(ordinal: usize) -> Result<String, String> {
    type CuInit = unsafe extern "C" fn(u32) -> i32;
    type CuDeviceGet = unsafe extern "C" fn(*mut i32, i32) -> i32;
    type CuDeviceGetPciBusId = unsafe extern "C" fn(*mut std::ffi::c_char, i32, i32) -> i32;

    struct DriverHandle(*mut std::ffi::c_void);
    impl Drop for DriverHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `dlopen` in this function.
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }

    unsafe fn symbol<T: Copy>(
        handle: *mut std::ffi::c_void,
        name: &std::ffi::CStr,
    ) -> Result<T, String> {
        // SAFETY: `handle` is live and `name` is NUL-terminated.
        let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if address.is_null() {
            return Err(format!(
                "CUDA driver symbol {} is unavailable",
                name.to_string_lossy()
            ));
        }
        if std::mem::size_of::<T>() != std::mem::size_of_val(&address) {
            return Err(
                "CUDA driver function pointer has an unsupported representation".to_string(),
            );
        }
        // SAFETY: CUDA's stable driver ABI defines each requested symbol with `T`.
        Ok(unsafe { std::mem::transmute_copy(&address) })
    }

    let mut first_error = None;
    let handle = [c"libcuda.so.1", c"libcuda.so"]
        .into_iter()
        .find_map(|name| {
            // SAFETY: each static C string is NUL-terminated.
            let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                if first_error.is_none() {
                    first_error = Some(name.to_string_lossy().into_owned());
                }
                None
            } else {
                Some(DriverHandle(handle))
            }
        })
        .ok_or_else(|| {
            format!(
                "CUDA driver library is unavailable while resolving PCI identity{}",
                first_error
                    .as_deref()
                    .map(|name| format!(" (first attempted {name})"))
                    .unwrap_or_default()
            )
        })?;
    // SAFETY: the symbols are resolved from the live CUDA driver handle and are
    // called with their documented driver-API signatures.
    unsafe {
        let cu_init: CuInit = symbol(handle.0, c"cuInit")?;
        let cu_device_get: CuDeviceGet = symbol(handle.0, c"cuDeviceGet")?;
        let cu_device_get_pci_bus_id: CuDeviceGetPciBusId =
            symbol(handle.0, c"cuDeviceGetPCIBusId")?;
        let init_status = cu_init(0);
        if init_status != 0 {
            return Err(format!(
                "CUDA driver initialization failed with status {init_status}"
            ));
        }
        let ordinal =
            i32::try_from(ordinal).map_err(|_| "CUDA device ordinal exceeds i32".to_string())?;
        let mut device = 0i32;
        let device_status = cu_device_get(&mut device, ordinal);
        if device_status != 0 {
            return Err(format!(
                "CUDA device {ordinal} lookup failed with status {device_status}"
            ));
        }
        let mut pci_bus_id = [0 as std::ffi::c_char; 32];
        let pci_status =
            cu_device_get_pci_bus_id(pci_bus_id.as_mut_ptr(), pci_bus_id.len() as i32, device);
        if pci_status != 0 {
            return Err(format!(
                "CUDA device {ordinal} PCI identity failed with status {pci_status}"
            ));
        }
        let pci_bus_id = std::ffi::CStr::from_ptr(pci_bus_id.as_ptr())
            .to_str()
            .map_err(|_| format!("CUDA device {ordinal} PCI identity is not UTF-8"))?
            .trim();
        if pci_bus_id.is_empty() {
            return Err(format!("CUDA device {ordinal} PCI identity is empty"));
        }
        Ok(pci_bus_id.to_string())
    }
}

#[cfg(feature = "gpu")]
/// Acquire every device in an already authenticated ordered route. Acquisition
/// is all-or-nothing; one required device failure drops successful siblings.
pub fn acquire_ordered_gpu_device_set(
    route: &crate::gpu::device_set::OrderedGpuDeviceRoute,
) -> Result<AcquiredGpuDeviceSet, String> {
    let live = enumerate_gpu_device_census()?;
    route.validate_live_set(&live)?;
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(route.devices.len())
        .map_err(|error| format!("ordered GPU backend set reserve failed: {error}"))?;
    for (position, device) in route.devices.iter().enumerate() {
        let (backend, resident_timed_dispatch_supported) =
            acquire_peer_ordinal(device.api, device.api_ordinal).map_err(|error| {
                format!(
                    "required GPU device {position} acquisition failed: {error}; the ordered device-set route is invalid"
                )
            })?;
        devices.push(AcquiredGpuDevice {
            backend,
            resident_timed_dispatch_supported,
            resident_literal: std::sync::Mutex::new(
                super::resident_evidence::GpuResidentLiteralSlot::Empty,
            ),
        });
    }
    let post_acquisition = enumerate_gpu_device_census()
        .map_err(|error| format!("post-acquisition GPU census failed: {error}"))?;
    route.validate_live_set(&post_acquisition).map_err(|error| {
        format!(
            "ordered GPU device set changed during acquisition: {error}; all acquired devices were released"
        )
    })?;
    Ok(AcquiredGpuDeviceSet {
        device_set_identity_digest: route.device_set_identity_digest(),
        dispatch: std::sync::Mutex::new(()),
        devices,
    })
}

#[cfg(feature = "gpu")]
struct AcquiredGpuDevice {
    backend: Arc<dyn vyre::VyreBackend>,
    resident_timed_dispatch_supported: bool,
    resident_literal: std::sync::Mutex<super::resident_evidence::GpuResidentLiteralSlot>,
}

#[cfg(feature = "gpu")]
pub struct AcquiredGpuDeviceSet {
    device_set_identity_digest: String,
    dispatch: std::sync::Mutex<()>,
    devices: Vec<AcquiredGpuDevice>,
}

#[cfg(feature = "gpu")]
impl std::fmt::Debug for AcquiredGpuDeviceSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredGpuDeviceSet")
            .field(
                "device_set_identity_digest",
                &self.device_set_identity_digest,
            )
            .field("devices", &self.devices.len())
            .finish()
    }
}

#[cfg(feature = "gpu")]
impl AcquiredGpuDeviceSet {
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn device_set_identity_digest(&self) -> &str {
        &self.device_set_identity_digest
    }

    pub(crate) fn lock_complete_dispatch(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.dispatch
            .lock()
            .map_err(|_| "ordered GPU dispatch lock is unavailable after an internal panic".into())
    }

    #[must_use]
    pub fn backend(&self, position: usize) -> Option<&Arc<dyn vyre::VyreBackend>> {
        self.devices.get(position).map(|device| &device.backend)
    }

    #[must_use]
    pub(crate) fn resident_timed_dispatch_supported(&self, position: usize) -> Option<bool> {
        self.devices
            .get(position)
            .map(|device| device.resident_timed_dispatch_supported)
    }

    #[must_use]
    pub(crate) fn resident_literal(
        &self,
        position: usize,
    ) -> Option<&std::sync::Mutex<super::resident_evidence::GpuResidentLiteralSlot>> {
        self.devices
            .get(position)
            .map(|device| &device.resident_literal)
    }
}

#[cfg(feature = "gpu")]
fn acquire_peer_ordinal(
    api: crate::gpu::device_set::GpuApi,
    ordinal: usize,
) -> Result<(Arc<dyn vyre::VyreBackend>, bool), String> {
    match api {
        crate::gpu::device_set::GpuApi::Wgpu => {
            let backend = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                vyre_driver_wgpu::WgpuBackend::acquire_adapter(ordinal)
            }))
            .map_err(|panic| {
                format!(
                    "WGPU adapter {ordinal} acquisition panicked: {}",
                    crate::error::panic_payload_detail(panic)
                )
            })?
            .map_err(|error| error.to_string())?;
            let resident_timed_dispatch_supported =
                wgpu_resident_timed_dispatch_supported(backend.device_queue().0.features());
            Ok((Arc::new(backend), resident_timed_dispatch_supported))
        }
        crate::gpu::device_set::GpuApi::Cuda => {
            #[cfg(all(feature = "gpu", target_os = "linux"))]
            {
                let backend = run_cuda_after_preflight(
                    ensure_cuda_driver_library_loadable,
                    || {
                        vyre_driver_cuda::backend::CudaBackend::acquire_ordinal(ordinal).map(
                            |cuda| {
                                Arc::new(vyre_driver_cuda::CudaBackendRegistration::new(cuda))
                                    as Arc<dyn vyre::VyreBackend>
                            },
                        )
                    },
                    "ordered device acquisition",
                )?;
                Ok((backend, true))
            }
            #[cfg(not(all(feature = "gpu", target_os = "linux")))]
            {
                let _ = ordinal;
                Err("CUDA ordered-device acquisition is unavailable on this platform".to_string())
            }
        }
        crate::gpu::device_set::GpuApi::Metal => {
            if ordinal != 0 {
                return Err(format!(
                    "Metal adapter ordinal {ordinal} is not enumerable through the current VYRE API"
                ));
            }
            acquire_metal_peer().map(|peer| (peer.backend, peer.resident_timed_dispatch_supported))
        }
    }
}

#[cfg(all(test, feature = "gpu"))]
#[path = "../../../tests/unit/gpu_backend_acquisition.rs"]
mod tests;
