use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use vyre_driver::error::{Error, Result};

/// Snapshot of features that were actually enabled when the cached
/// device was created. Consumed by `WgpuBackend::supports_*` methods
/// so the VyreBackend capability reports are *honest* — a feature bit
/// is reported only if it was both advertised by the adapter AND
/// requested at device creation.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct EnabledFeatures {
    /// Wgpu timestamp queries feature.
    pub timestamp_query: bool,
    /// Wgpu subgroup feature.
    pub subgroup: bool,
    /// Wgpu shader f16 feature.
    pub shader_f16: bool,
    /// Wgpu pipeline cache feature.
    pub pipeline_cache: bool,
    /// Wgpu push constants feature.
    pub push_constants: bool,
    /// Wgpu indirect first instance feature.
    pub indirect_first_instance: bool,
    /// Wgpu adapter max workgroup size limit.
    pub max_workgroup_size: [u32; 3],
    /// Wgpu adapter max storage buffer binding size limit.
    pub max_storage_buffer_binding_size: u64,
    /// Wgpu adapter max subgroup size.
    pub max_subgroup_size: u32,
    /// Wgpu adapter minimum subgroup size (I.6). `0` means the
    /// adapter did not report a subgroup size; consumers treat that
    /// as "unknown" and fall back to a default workgroup heuristic.
    pub min_subgroup_size: u32,
}

static CACHED_DEVICE: OnceLock<Result<Arc<(wgpu::Device, wgpu::Queue)>>> = OnceLock::new();
static CACHED_ADAPTER_INFO: OnceLock<Result<wgpu::AdapterInfo>> = OnceLock::new();

/// Acquire the singleton device/queue pair.
///
/// ⚠ **Test / convenience helper — not the production path.**
///
/// Production backends construct their own `wgpu::Device` via
/// [`WgpuBackend::acquire`](crate::WgpuBackend::acquire), which routes
/// through [`init_device`] and returns a fresh device per call. Using
/// `cached_device()` from production code forces every consumer to
/// share one process-wide GPU handle, which prevents:
///
/// - running two backends against two different physical GPUs;
/// - using a dedicated discrete GPU while a test fixture is holding
///   the integrated GPU singleton;
/// - recovering from device loss (recovery swaps the backend's local
///   device; the singleton's `OnceLock` cannot be replaced in-place).
///
/// The singleton survives because a handful of test fixtures want one
/// shared GPU handle across all tests to amortize init cost. Consumers
/// that actually need a GPU runtime should construct a `WgpuBackend`
/// instead.
///
/// # Errors
///
/// Returns an error if the GPU adapter or device cannot be initialized.
#[inline]
pub fn cached_device() -> Result<Arc<(wgpu::Device, wgpu::Queue)>> {
    CACHED_DEVICE
        .get_or_init(|| {
            let ((device, queue), _info, _enabled) = init_device()?;
            Ok(Arc::new((device, queue)))
        })
        .clone()
}

/// Acquire adapter info for the singleton runtime device.
///
/// # Errors
///
/// Returns an error if the GPU adapter or device cannot be initialized.
#[inline]
pub fn cached_adapter_info() -> Result<&'static wgpu::AdapterInfo> {
    CACHED_ADAPTER_INFO
        .get_or_init(|| {
            let (_pair, info, _enabled) = init_device()?;
            Ok(info)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Return true when the device is the singleton cached device.
#[cfg(test)]
#[inline]
pub(crate) fn is_cached_device(device: &wgpu::Device) -> bool {
    CACHED_DEVICE
        .get()
        .and_then(|res| res.as_ref().ok())
        .map(|arc| &arc.0 == device)
        .unwrap_or(false)
}

/// Initialize a new GPU device and queue.
///
/// # Errors
///
/// Returns an actionable GPU error if no compatible adapter is available, if
/// the selected adapter is CPU-backed, or if device creation fails.
#[inline]
pub fn init_device() -> Result<(
    (wgpu::Device, wgpu::Queue),
    wgpu::AdapterInfo,
    EnabledFeatures,
)> {
    let gpu = wait_for_gpu(acquire_gpu())?;
    Ok(gpu)
}

/// Asynchronously initialize a new GPU device and queue.
///
/// # Errors
///
/// Returns an actionable GPU error if no compatible adapter is available, if
/// the selected adapter is CPU-backed, or if device creation fails.
#[inline]
pub async fn acquire_gpu() -> Result<(
    (wgpu::Device, wgpu::Queue),
    wgpu::AdapterInfo,
    EnabledFeatures,
)> {
    if let Some(index) = super::selector::adapter_index_from_env() {
        return super::selector::acquire_gpu_for_adapter(index).await;
    }

    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());
    let mut candidates = adapters
        .iter()
        .filter_map(|adapter| {
            let info = adapter.get_info();
            let rank = real_gpu_rank(info.device_type);
            (rank > 0).then_some((adapter, info, rank))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| right.2.cmp(&left.2));

    let mut failures = Vec::new();
    for (adapter, info, _) in candidates {
        match request_device_for_adapter(adapter, "vyre device").await {
            Ok(device) => return Ok(device),
            Err(error) => failures.push(format!("{} ({:?}): {error}", info.name, info.device_type)),
        }
    }

    let probed = adapters
        .iter()
        .map(|adapter| {
            let info = adapter.get_info();
            format!(
                "{} ({:?}, backend={:?})",
                info.name, info.device_type, info.backend
            )
        })
        .collect::<Vec<_>>();
    Err(Error::Gpu {
        message: format!(
            "no real GPU adapter could create a wgpu device. Probed adapters: [{}]. Device failures: [{}]. Fix: expose a discrete, integrated, or virtual GPU through a wgpu-supported driver before running vyre.",
            probed.join(", "),
            failures.join("; ")
        ),
    })
}

pub(super) async fn request_device_for_adapter(
    adapter: &wgpu::Adapter,
    label: &'static str,
) -> Result<(
    (wgpu::Device, wgpu::Queue),
    wgpu::AdapterInfo,
    EnabledFeatures,
)> {
    let adapter_info = adapter.get_info();
    // Opt into every feature the adapter advertises that we know how to
    // lower against. Each feature is additive: enabling it unlocks the
    // corresponding VyreBackend capability report (see
    // `WgpuBackend::supports_subgroup_ops`, `supports_f16`, etc.) and
    // costs nothing at runtime if no lowering emits the corresponding
    // intrinsic. Features we do NOT lower against (e.g. mesh shaders,
    // ray tracing) are deliberately omitted — enabling them would be a
    // LAW 9 evasion (claiming support that the lowering path does not
    // deliver).
    let adapter_features = adapter.features();
    let adapter_limits = adapter.limits();
    let (features, mut enabled) = enabled_features_for_adapter(adapter_features, &adapter_limits);

    let device_queue = adapter
        .request_device(
            &wgpu::DeviceDescriptor {
                label: Some(label),
                required_features: features,
                required_limits: wgpu::Limits {
                    max_compute_workgroup_size_x: adapter_limits.max_compute_workgroup_size_x,
                    max_compute_workgroup_size_y: adapter_limits.max_compute_workgroup_size_y,
                    max_compute_workgroup_size_z: adapter_limits.max_compute_workgroup_size_z,
                    max_compute_invocations_per_workgroup: adapter_limits
                        .max_compute_invocations_per_workgroup,
                    max_compute_workgroups_per_dimension: adapter_limits
                        .max_compute_workgroups_per_dimension,
                    max_compute_workgroup_storage_size: adapter_limits
                        .max_compute_workgroup_storage_size,
                    max_storage_buffer_binding_size: adapter_limits.max_storage_buffer_binding_size,
                    min_subgroup_size: if enabled.subgroup {
                        adapter_limits.min_subgroup_size
                    } else {
                        0
                    },
                    max_subgroup_size: if enabled.subgroup {
                        adapter_limits.max_subgroup_size
                    } else {
                        0
                    },
                    max_storage_buffers_per_shader_stage:
                        adapter_limits.max_storage_buffers_per_shader_stage,
                    max_push_constant_size: if enabled.push_constants {
                        adapter_limits.max_push_constant_size
                    } else {
                        0
                    },
                    ..wgpu::Limits::default()
                },
                memory_hints: wgpu::MemoryHints::default(),
            },
            None,
        )
        .await
        .map_err(|error| Error::Gpu {
            message: format!("failed to acquire device for adapter `{}`: {error}. Fix: check requested wgpu limits/features against the adapter and update the GPU driver if limits are unexpectedly low.", adapter_info.name),
        })?;
    let device_limits = device_queue.0.limits();
    enabled.max_workgroup_size = [
        device_limits.max_compute_workgroup_size_x,
        device_limits.max_compute_workgroup_size_y,
        device_limits.max_compute_workgroup_size_z,
    ];
    enabled.max_storage_buffer_binding_size =
        u64::from(device_limits.max_storage_buffer_binding_size);
    enabled.max_subgroup_size = device_limits.max_subgroup_size;
    enabled.min_subgroup_size = device_limits.min_subgroup_size;

    if enabled.subgroup && !subgroup_smoke_compiles(&device_queue.0) {
        tracing::warn!(
            target: "vyre.device",
            adapter = %adapter_info.name,
            "adapter advertises SUBGROUP but rejects a subgroup compute pipeline; reporting supports_subgroup_ops=false"
        );
        enabled.subgroup = false;
    }

    Ok((device_queue, adapter_info, enabled))
}

pub(super) fn enabled_features_for_adapter(
    adapter_features: wgpu::Features,
    adapter_limits: &wgpu::Limits,
) -> (wgpu::Features, EnabledFeatures) {
    let mut features = wgpu::Features::empty();
    let mut enabled = EnabledFeatures::default();
    if adapter_features.contains(wgpu::Features::TIMESTAMP_QUERY) {
        features |= wgpu::Features::TIMESTAMP_QUERY;
        enabled.timestamp_query = true;
    }
    if crate::capabilities::supports_subgroup_for_adapter(adapter_features, adapter_limits) {
        features |= wgpu::Features::SUBGROUP;
        enabled.subgroup = true;
    }
    if adapter_features.contains(wgpu::Features::SHADER_F16) {
        features |= wgpu::Features::SHADER_F16;
        enabled.shader_f16 = true;
    }
    if adapter_features.contains(wgpu::Features::PIPELINE_CACHE) {
        features |= wgpu::Features::PIPELINE_CACHE;
        enabled.pipeline_cache = true;
    }
    if adapter_features.contains(wgpu::Features::PUSH_CONSTANTS) {
        features |= wgpu::Features::PUSH_CONSTANTS;
        enabled.push_constants = true;
    }
    if adapter_features.contains(wgpu::Features::INDIRECT_FIRST_INSTANCE) {
        features |= wgpu::Features::INDIRECT_FIRST_INSTANCE;
        enabled.indirect_first_instance = true;
    }

    enabled.max_workgroup_size = [
        adapter_limits.max_compute_workgroup_size_x,
        adapter_limits.max_compute_workgroup_size_y,
        adapter_limits.max_compute_workgroup_size_z,
    ];
    enabled.max_storage_buffer_binding_size =
        u64::from(adapter_limits.max_storage_buffer_binding_size);
    enabled.max_subgroup_size = adapter_limits.max_subgroup_size;
    enabled.min_subgroup_size = adapter_limits.min_subgroup_size;
    (features, enabled)
}

fn real_gpu_rank(device_type: wgpu::DeviceType) -> u8 {
    match device_type {
        wgpu::DeviceType::DiscreteGpu => 3,
        wgpu::DeviceType::IntegratedGpu => 2,
        wgpu::DeviceType::VirtualGpu => 1,
        wgpu::DeviceType::Cpu | wgpu::DeviceType::Other => 0,
    }
}

fn subgroup_smoke_compiles(device: &wgpu::Device) -> bool {
    const WGSL: &str = r#"
@compute @workgroup_size(32)
fn main(@builtin(subgroup_invocation_id) lane: u32, @builtin(subgroup_size) size: u32) {
    let total = subgroupAdd(lane + size);
    if (total == 0u) {
        return;
    }
}
"#;

    device.push_error_scope(wgpu::ErrorFilter::Validation);
    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("vyre subgroup capability probe"),
        source: wgpu::ShaderSource::Wgsl(WGSL.into()),
    });
    let _pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("vyre subgroup capability probe"),
        layout: None,
        module: &module,
        entry_point: Some("main"),
        compilation_options: wgpu::PipelineCompilationOptions::default(),
        cache: None,
    });
    #[allow(unreachable_patterns)]
    match device.poll(wgpu::Maintain::Wait) {
        wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        _other => {
            tracing::error!(
                "subgroup capability probe poll returned unexpected result (maintain failed)"
            );
            return false;
        }
    }
    pollster::block_on(device.pop_error_scope()).is_none()
}

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn wait_for_gpu<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cached-device helper now returns a stable singleton.
    #[test]
    fn cached_device_is_singleton() {
        let first = cached_device().expect("Fix: GPU must be available for runtime tests");
        let second = cached_device().expect("Fix: GPU must be available for runtime tests");
        assert!(
            Arc::ptr_eq(&first, &second),
            "cached_device must return the same Arc after singleton initialization"
        );
        assert!(
            is_cached_device(&first.0),
            "legacy shared APIs must still recognize cached_device-created devices"
        );
    }
}
