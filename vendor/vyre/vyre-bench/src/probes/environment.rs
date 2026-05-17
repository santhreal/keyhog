use serde::{Deserialize, Serialize};
use std::process::Command;

const MAX_CPUINFO_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentData {
    pub os: String,
    pub architecture: String,
    #[serde(default)]
    pub cpu_model: Option<String>,
    pub cpu_cores: usize,
    pub has_gpu: bool,
    #[serde(default)]
    pub gpu_devices: Vec<GpuDeviceInfo>,
    #[serde(default)]
    pub nvidia_driver_version: Option<String>,
    #[serde(default)]
    pub nvidia_cuda_version: Option<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDeviceInfo {
    pub name: String,
    pub driver_version: String,
    pub memory_total_mib: Option<u64>,
}

pub fn capture_environment() -> EnvironmentData {
    // Collect host information
    let os = std::env::consts::OS.to_string();
    let architecture = std::env::consts::ARCH.to_string();

    // Attempt to query CPU cores
    let cpu_cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let mut features = vec!["vyre-bench".to_string()];
    let gpu_devices = nvidia_smi_gpu_devices();
    let nvidia_versions = nvidia_smi_versions();
    let nvidia_gpu = !gpu_devices.is_empty();
    if nvidia_gpu {
        features.push("gpu.nvidia_smi".to_string());
    }
    if nvidia_versions.cuda_version.is_some() {
        features.push("gpu.nvidia_smi.cuda_version".to_string());
    }
    let linked_dispatch_backends = vyre_driver::backend::registered_backends_by_precedence_slice()
        .iter()
        .filter(|backend| vyre_driver::backend::backend_dispatches(backend.id))
        .map(|backend| backend.id)
        .collect::<Vec<_>>();
    for backend in &linked_dispatch_backends {
        features.push(format!("backend.linked.{backend}"));
    }
    let mut usable_gpu_backend = false;
    for backend in linked_dispatch_backends {
        match vyre_driver::backend::acquire(backend) {
            Ok(_) if backend != "cpu-ref" => {
                usable_gpu_backend = true;
                features.push(format!("backend.usable.{backend}"));
            }
            Ok(_) => features.push(format!("backend.usable.{backend}")),
            Err(error) => features.push(format!("backend.unusable.{backend}:{error}")),
        }
    }
    let has_gpu = nvidia_gpu || usable_gpu_backend;

    EnvironmentData {
        os,
        architecture,
        cpu_model: cpu_model(),
        cpu_cores,
        has_gpu,
        nvidia_driver_version: nvidia_versions.driver_version.or_else(|| {
            gpu_devices
                .first()
                .map(|device| device.driver_version.clone())
        }),
        nvidia_cuda_version: nvidia_versions.cuda_version,
        gpu_devices,
        features,
    }
}

fn cpu_model() -> Option<String> {
    if let Ok(cpuinfo) = read_cpuinfo_bounded() {
        for line in cpuinfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key.trim() == "model name" {
                let model = value.trim();
                if !model.is_empty() {
                    return Some(model.to_string());
                }
            }
        }
    }
    let output = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if model.is_empty() {
        None
    } else {
        Some(model)
    }
}

fn read_cpuinfo_bounded() -> std::io::Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open("/proc/cpuinfo")?;
    let mut text = String::new();
    file.by_ref()
        .take(MAX_CPUINFO_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CPUINFO_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "/proc/cpuinfo exceeded bounded read limit",
        ));
    }
    Ok(text)
}

fn nvidia_smi_gpu_devices() -> Vec<GpuDeviceInfo> {
    let Ok(output) = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_nvidia_smi_device)
        .collect()
}

struct NvidiaSmiVersions {
    driver_version: Option<String>,
    cuda_version: Option<String>,
}

fn nvidia_smi_versions() -> NvidiaSmiVersions {
    let Ok(output) = Command::new("nvidia-smi").output() else {
        return NvidiaSmiVersions {
            driver_version: None,
            cuda_version: None,
        };
    };
    if !output.status.success() {
        return NvidiaSmiVersions {
            driver_version: None,
            cuda_version: None,
        };
    }
    let text = String::from_utf8_lossy(&output.stdout);
    NvidiaSmiVersions {
        driver_version: parse_nvidia_smi_header_value(&text, "Driver Version"),
        cuda_version: parse_nvidia_smi_header_value(&text, "CUDA Version"),
    }
}

fn parse_nvidia_smi_header_value(text: &str, label: &str) -> Option<String> {
    let (_, tail) = text.split_once(&format!("{label}:"))?;
    let value = tail.split_whitespace().next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn parse_nvidia_smi_device(line: &str) -> Option<GpuDeviceInfo> {
    let mut fields = line.split(',').map(str::trim);
    let name = fields.next()?.to_string();
    let driver_version = fields.next()?.to_string();
    let memory_total_mib = fields.next().and_then(|value| value.parse::<u64>().ok());
    if name.is_empty() {
        return None;
    }
    Some(GpuDeviceInfo {
        name,
        driver_version,
        memory_total_mib,
    })
}
