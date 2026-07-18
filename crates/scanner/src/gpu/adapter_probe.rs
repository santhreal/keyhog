//! Backend-neutral GPU census used before autoroute selects an execution peer.

use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuAdapterProbe {
    pub(crate) name: String,
    pub(crate) buffer_limit_mb: u64,
    pub(crate) runtime_identity: String,
    pub(crate) is_software: bool,
}

#[derive(Debug)]
struct AdapterSnapshot {
    info: wgpu::AdapterInfo,
    max_buffer_size: u64,
}

static PROBE: OnceLock<Option<GpuAdapterProbe>> = OnceLock::new();

pub(crate) fn gpu_adapter_probe() -> Option<&'static GpuAdapterProbe> {
    PROBE.get_or_init(probe).as_ref()
}

fn probe() -> Option<GpuAdapterProbe> {
    let instance = wgpu::Instance::default();
    let mut adapters = instance
        .enumerate_adapters(wgpu::Backends::all())
        .into_iter()
        .map(|adapter| AdapterSnapshot {
            info: adapter.get_info(),
            max_buffer_size: adapter.limits().max_buffer_size,
        })
        .collect::<Vec<_>>();
    if adapters.is_empty() {
        return None;
    }

    adapters.sort_by(|left, right| adapter_identity(left).cmp(&adapter_identity(right)));
    let runtime_identity =
        serde_json::to_string(&adapters.iter().map(adapter_identity).collect::<Vec<_>>())
            .expect("WGPU adapter census contains only serializable primitive fields");

    let selected = adapters
        .iter()
        .filter(|adapter| !is_software(&adapter.info))
        .max_by_key(|adapter| {
            (
                device_priority(adapter.info.device_type),
                adapter.max_buffer_size,
            )
        })
        .or_else(|| adapters.first())?;

    const SANE_BUFFER_LIMIT_MB: u64 = 256 * 1024;
    Some(GpuAdapterProbe {
        name: selected.info.name.clone(),
        buffer_limit_mb: (selected.max_buffer_size / (1024 * 1024)).min(SANE_BUFFER_LIMIT_MB),
        runtime_identity,
        is_software: is_software(&selected.info),
    })
}

fn adapter_identity(snapshot: &AdapterSnapshot) -> (String, u32, u32, String, String, String, u64) {
    let info = &snapshot.info;
    (
        info.name.clone(),
        info.vendor,
        info.device,
        format!("{:?}", info.device_type),
        format!("{:?}", info.backend),
        format!("{}:{}", info.driver, info.driver_info),
        snapshot.max_buffer_size,
    )
}

fn device_priority(device_type: wgpu::DeviceType) -> u8 {
    match device_type {
        wgpu::DeviceType::DiscreteGpu => 4,
        wgpu::DeviceType::IntegratedGpu => 3,
        wgpu::DeviceType::VirtualGpu => 2,
        wgpu::DeviceType::Other => 1,
        wgpu::DeviceType::Cpu => 0,
    }
}

fn is_software(info: &wgpu::AdapterInfo) -> bool {
    if info.device_type == wgpu::DeviceType::Cpu {
        return true;
    }
    let name = info.name.to_ascii_lowercase();
    name.contains("llvmpipe") || name.contains("lavapipe") || name.contains("swiftshader")
}
