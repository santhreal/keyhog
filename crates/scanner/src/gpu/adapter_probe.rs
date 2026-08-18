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
    adapter: wgpu::Adapter,
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
    super::evidence::record_gpu_api_initialized(super::evidence::GpuApiKind::Wgpu);
    let instance = wgpu::Instance::default();
    let mut adapters = instance
        .into_iter()
        .enumerate()
        .map(|(adapter_index, adapter)| {
            let info = adapter.get_info();
            let max_buffer_size = adapter.limits().max_buffer_size;
            AdapterSnapshot {
                adapter,
                adapter_index,
                info,
                max_buffer_size,
            }
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
    super::evidence::record_gpu_api_initialized(super::evidence::GpuApiKind::Wgpu);
    let instance = wgpu::Instance::default();
        .enumerate_adapters(wgpu::Backends::all())
        .into_iter()
        .enumerate()
        .map(|(adapter_index, adapter)| {
            let info = adapter.get_info();
            let max_buffer_size = adapter.limits().max_buffer_size;
            AdapterSnapshot {
                adapter,
                adapter_index,
                info,
                max_buffer_size,
            }
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
    let mut exposures = Vec::new();
    exposures
        .try_reserve_exact(adapters.len())
        .map_err(|error| format!("WGPU device census reserve failed: {error}"))?;
    for snapshot in adapters {
        let api_ordinal = snapshot.adapter_index;
        let info = snapshot.info;
        let backend_identity = format!("{:?}", info.backend);
        #[cfg(target_os = "linux")]
        let physical = linux_vulkan_physical_identity(&snapshot.adapter).or_else(|| {
            let mut matches = pci
                .iter()
                .filter(|device| device.vendor == info.vendor && device.device == info.device);
            let first = matches.next();
            if first.is_some() && matches.next().is_none() {
                first.map(|device| {
                    (
                        format!("pci:{}", device.bdf),
                        format!("pci:{}/numa:{}", device.bdf, device.numa_node),
                        device.capacity_bytes.unwrap_or(0),
                        device.driver.clone(),
                    )
                })
            } else {
                None
            }
        });
        #[cfg(not(target_os = "linux"))]
        let physical: Option<(String, String, u64, String)> = None;
        let fallback_identity = format!(
            "wgpu:{backend_identity}:{:08x}:{:08x}:ordinal={api_ordinal}",
            info.vendor, info.device
        );
        let physical_available = physical.is_some();
        let (physical_identity, topology_identity, capacity_bytes, physical_driver) = physical
            .unwrap_or_else(|| {
                (
                    fallback_identity.clone(),
                    fallback_identity,
                    0,
                    "unavailable".to_string(),
                )
            });
        let ineligible_reason = if !physical_available {
            Some(
                "stable physical topology mapping is unavailable for this WGPU exposure"
                    .to_string(),
            )
        } else if capacity_bytes == 0 {
            Some("stable physical VRAM capacity is unavailable for this WGPU exposure".to_string())
        } else {
            None
        };
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
                "wgpu={}:{};physical-driver={physical_driver}",
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
fn linux_vulkan_physical_identity(
    adapter: &wgpu::Adapter,
) -> Option<(String, String, u64, String)> {
    if adapter.get_info().backend != wgpu::Backend::Vulkan {
        return None;
    }
    // SAFETY: the callback only performs read-only Vulkan property queries
    // through the instance and physical-device handle owned by this live adapter.
    unsafe {
        adapter.as_hal::<wgpu::hal::api::Vulkan, _, _>(|hal| {
            let hal = hal?;
            let mut identity = ash::vk::PhysicalDeviceIDProperties::default();
            let mut properties =
                ash::vk::PhysicalDeviceProperties2::default().push_next(&mut identity);
            let raw_instance = hal.shared_instance().raw_instance();
            raw_instance
                .get_physical_device_properties2(hal.raw_physical_device(), &mut properties);
            if identity.device_uuid.iter().all(|byte| *byte == 0) {
                return None;
            }
            let memory =
                raw_instance.get_physical_device_memory_properties(hal.raw_physical_device());
            let heap_count = (memory.memory_heap_count as usize).min(memory.memory_heaps.len());
            let capacity_bytes = memory.memory_heaps[..heap_count]
                .iter()
                .filter(|heap| heap.flags.contains(ash::vk::MemoryHeapFlags::DEVICE_LOCAL))
                .try_fold(0u64, |total, heap| total.checked_add(heap.size))?;
            let pci_identity = if hal
                .physical_device_capabilities()
                .supports_extension(ash::ext::pci_bus_info::NAME)
            {
                let mut pci = ash::vk::PhysicalDevicePCIBusInfoPropertiesEXT::default();
                let mut properties =
                    ash::vk::PhysicalDeviceProperties2::default().push_next(&mut pci);
                raw_instance
                    .get_physical_device_properties2(hal.raw_physical_device(), &mut properties);
                Some(format!(
                    "pci:{:04x}:{:02x}:{:02x}.{}",
                    pci.pci_domain, pci.pci_bus, pci.pci_device, pci.pci_function
                ))
            } else {
                None
            };
            let uuid = keyhog_core::hex_encode(&identity.device_uuid);
            let physical_identity = pci_identity
                .clone()
                .unwrap_or_else(|| format!("vulkan-device-uuid:{uuid}"));
            let topology_identity = pci_identity.map_or_else(
                || format!("vulkan-device-uuid:{uuid}"),
                |pci| format!("{pci}/vulkan-device-uuid:{uuid}"),
            );
            Some((
                physical_identity,
                topology_identity,
                capacity_bytes,
                "vulkan".to_string(),
            ))
        })
    }
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
            .and_then(|driver| {
                driver
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "unavailable".to_string());
        let capacity_bytes = ["mem_info_vram_total", "mem_info_vis_vram_total"]
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
pub(crate) fn linux_nvidia_pci_identity(pci_bus_id: &str) -> Option<(String, String, u32, String)> {
    let normalized = pci_bus_id.trim().to_ascii_lowercase();
    let device = linux_pci_gpus()
        .into_iter()
        .find(|device| device.vendor == 0x10de && device.bdf.to_ascii_lowercase() == normalized)?;
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

#[cfg(all(target_os = "linux", feature = "gpu"))]
pub(crate) fn linux_cuda_runtime_identity() -> std::result::Result<String, String> {
    let version = std::fs::read_to_string("/proc/driver/nvidia/version")
        .map_err(|error| format!("cannot read /proc/driver/nvidia/version: {error}"))?;
    let version = version.split_whitespace().collect::<Vec<_>>().join(" ");
    if version.is_empty() {
        Err("/proc/driver/nvidia/version contains no runtime identity".to_owned())
    } else {
        Ok(format!("nvidia-kernel:{version}"))
    }
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
