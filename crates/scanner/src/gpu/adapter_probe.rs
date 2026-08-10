//! Backend-neutral GPU census used before autoroute selects an execution peer.

use std::sync::LazyLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuAdapterProbe {
    pub(crate) name: String,
    pub(crate) device_identity: String,
    pub(crate) buffer_limit_mb: u64,
    pub(crate) runtime_identity: String,
    pub(crate) is_software: bool,
}

#[derive(Debug)]
struct AdapterSnapshot {
    adapter_index: usize,
    info: wgpu::AdapterInfo,
    max_buffer_size: u64,
}

#[derive(Clone, Debug)]
struct LinuxPciGpu {
    bdf: String,
    vendor: u32,
    device: u32,
    numa_node: String,
    driver: String,
    capacity_bytes: Option<u64>,
}

static PROBE: LazyLock<Option<GpuAdapterProbe>> = LazyLock::new(probe);

pub(crate) fn gpu_adapter_probe() -> Option<&'static GpuAdapterProbe> {
    PROBE.as_ref()
}

fn probe() -> Option<GpuAdapterProbe> {
    let instance = wgpu::Instance::default();
    let mut adapters = instance
        .enumerate_adapters(wgpu::Backends::all())
        .into_iter()
        .enumerate()
        .map(|(adapter_index, adapter)| AdapterSnapshot {
            adapter_index,
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
        .filter(|adapter| !is_software_adapter(&adapter.info))
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
        device_identity: gpu_adapter_device_identity(&selected.info, selected.max_buffer_size),
        buffer_limit_mb: (selected.max_buffer_size / (1024 * 1024)).min(SANE_BUFFER_LIMIT_MB),
        runtime_identity,
        is_software: is_software_adapter(&selected.info),
    })
}

pub(crate) fn probe_wgpu_device_exposures(
) -> Result<Vec<super::device_set::GpuDeviceExposure>, String> {
    let instance = wgpu::Instance::default();
    let mut adapters = instance
        .enumerate_adapters(wgpu::Backends::all())
        .into_iter()
        .enumerate()
        .map(|(adapter_index, adapter)| AdapterSnapshot {
            adapter_index,
            info: adapter.get_info(),
            max_buffer_size: adapter.limits().max_buffer_size,
        })
        .collect::<Vec<_>>();
    if adapters.len() > super::device_set::MAX_GPU_ROUTE_DEVICES.saturating_mul(8) {
        return Err(format!(
            "WGPU enumerated {} API exposures, above the bounded census limit of {}",
            adapters.len(),
            super::device_set::MAX_GPU_ROUTE_DEVICES * 8
        ));
    }
    adapters.sort_by(|left, right| adapter_identity(left).cmp(&adapter_identity(right)));
    #[cfg(target_os = "linux")]
    let pci = linux_pci_gpus();
    let mut occurrences = std::collections::BTreeMap::<(String, u32, u32), usize>::new();
    let mut exposures = Vec::new();
    exposures
        .try_reserve_exact(adapters.len())
        .map_err(|error| format!("WGPU device census reserve failed: {error}"))?;
    for snapshot in adapters {
        let api_ordinal = snapshot.adapter_index;
        let info = snapshot.info;
        let backend_identity = format!("{:?}", info.backend);
        let occurrence = occurrences
            .entry((backend_identity.clone(), info.vendor, info.device))
            .or_default();
        #[cfg(target_os = "linux")]
        let physical = pci
            .iter()
            .filter(|device| device.vendor == info.vendor && device.device == info.device)
            .nth(*occurrence);
        #[cfg(not(target_os = "linux"))]
        let physical: Option<&LinuxPciGpu> = None;
        let fallback_identity = format!(
            "wgpu:{backend_identity}:{:08x}:{:08x}:ordinal={api_ordinal}",
            info.vendor, info.device
        );
        let (physical_identity, topology_identity, capacity_bytes, sysfs_driver) =
            if let Some(physical) = physical {
                (
                    format!("pci:{}", physical.bdf),
                    format!("pci:{}/numa:{}", physical.bdf, physical.numa_node),
                    physical.capacity_bytes.unwrap_or(0),
                    physical.driver.as_str(),
                )
            } else {
                (
                    fallback_identity.clone(),
                    fallback_identity,
                    0,
                    "unavailable",
                )
            };
        *occurrence = occurrence.saturating_add(1);
        let ineligible_reason = (capacity_bytes == 0).then(|| {
            "stable physical VRAM capacity is unavailable for this WGPU exposure".to_string()
        });
        let is_software = is_software_adapter(&info);
        exposures.push(super::device_set::GpuDeviceExposure {
            api: super::device_set::GpuApi::Wgpu,
            api_ordinal,
            physical_identity,
            topology_identity,
            name: info.name,
            vendor_id: info.vendor,
            device_id: info.device,
            driver_identity: format!(
                "wgpu={}:{};os-driver={sysfs_driver}",
                info.driver, info.driver_info
            ),
            runtime_identity: format!(
                "wgpu=25.0.2;vyre-wgpu={};backend={backend_identity}",
                env!("KEYHOG_VYRE_WGPU_VERSION")
            ),
            capacity_bytes,
            is_software,
            is_display_only: false,
            ineligible_reason,
        });
    }
    Ok(exposures)
}

#[cfg(target_os = "linux")]
fn linux_pci_gpus() -> Vec<LinuxPciGpu> {
    const MAX_PCI_DEVICES: usize = 256;
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return Vec::new();
    };
    let mut devices = Vec::new();
    let _ = devices.try_reserve(MAX_PCI_DEVICES);
    for entry in entries.flatten().take(MAX_PCI_DEVICES) {
        let path = entry.path();
        let Some(vendor) = read_hex_u32(path.join("vendor")) else {
            continue;
        };
        let Some(device) = read_hex_u32(path.join("device")) else {
            continue;
        };
        let Some(class) = read_hex_u32(path.join("class")) else {
            continue;
        };
        if (class >> 16) != 0x03 {
            continue;
        }
        let bdf = entry.file_name().to_string_lossy().into_owned();
        let numa_node = std::fs::read_to_string(path.join("numa_node"))
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let driver = std::fs::read_link(path.join("driver"))
            .ok()
            .and_then(|driver| driver.file_name().map(|name| name.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "unavailable".to_string());
        let capacity_bytes = [
            "mem_info_vram_total",
            "mem_info_vis_vram_total",
        ]
        .into_iter()
        .find_map(|name| {
            std::fs::read_to_string(path.join(name))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|bytes| *bytes > 0)
        });
        devices.push(LinuxPciGpu {
            bdf,
            vendor,
            device,
            numa_node,
            driver,
            capacity_bytes,
        });
    }
    devices.sort_by(|left, right| left.bdf.cmp(&right.bdf));
    devices
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_nvidia_pci_identity(
    ordinal: usize,
) -> Option<(String, String, u32, String)> {
    let device = linux_pci_gpus()
        .into_iter()
        .filter(|device| device.vendor == 0x10de)
        .nth(ordinal)?;
    Some((
        format!("pci:{}", device.bdf),
        format!("pci:{}/numa:{}", device.bdf, device.numa_node),
        device.device,
        device.driver,
    ))
}

#[cfg(target_os = "linux")]
fn read_hex_u32(path: std::path::PathBuf) -> Option<u32> {
    let value = std::fs::read_to_string(path).ok()?;
    u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()
}

pub(crate) fn gpu_adapter_device_identity(
    info: &wgpu::AdapterInfo,
    max_buffer_size: u64,
) -> String {
    format!(
        "name={:?}:vendor={:08x}:device={:08x}:type={:?}:backend={:?}:driver={:?}:driver_info={:?}:max_buffer_size={max_buffer_size}",
        info.name,
        info.vendor,
        info.device,
        info.device_type,
        info.backend,
        info.driver,
        info.driver_info,
    )
}

fn adapter_identity(
    snapshot: &AdapterSnapshot,
) -> (String, u32, u32, String, String, String, u64, usize) {
    let info = &snapshot.info;
    (
        info.name.clone(),
        info.vendor,
        info.device,
        format!("{:?}", info.device_type),
        format!("{:?}", info.backend),
        format!("{}:{}", info.driver, info.driver_info),
        snapshot.max_buffer_size,
        snapshot.adapter_index,
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

pub(crate) fn is_software_adapter(info: &wgpu::AdapterInfo) -> bool {
    // VYRE accepts only discrete, integrated, and virtual GPU adapters.
    // `Other` is not proof of hardware compute and must not enter the same
    // autoroute candidate census that VYRE will later execute.
    if matches!(
        info.device_type,
        wgpu::DeviceType::Cpu | wgpu::DeviceType::Other
    ) {
        return true;
    }
    let name = info.name.to_ascii_lowercase();
    name.contains("llvmpipe") || name.contains("lavapipe") || name.contains("swiftshader")
}
