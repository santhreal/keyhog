//! Host identity captured in autoroute calibration records.

use keyhog_scanner::hw_probe::HardwareCaps;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AutorouteHostProfile {
    pub(super) os: String,
    pub(super) arch: String,
    pub(super) cpu_model: Option<String>,
    pub(super) physical_cores: usize,
    pub(super) logical_cores: usize,
    pub(super) has_avx2: bool,
    pub(super) has_avx512: bool,
    pub(super) has_neon: bool,
    pub(super) hyperscan_available: bool,
    pub(super) gpu_name: Option<String>,
    pub(super) gpu_runtime_backend: Option<String>,
    pub(super) gpu_driver_runtime_identity: Option<String>,
    pub(super) gpu_is_software: bool,
    pub(super) total_memory_mb: Option<u64>,
}

impl AutorouteHostProfile {
    pub(super) fn from_caps(
        caps: &HardwareCaps,
        gpu_runtime_backend: Option<&'static str>,
        gpu_supported_by_build: bool,
    ) -> Self {
        // A build compiled WITHOUT GPU support never routes to the GPU, so a
        // physically present GPU is NOT part of THIS build's scan identity:
        // collapse the whole GPU dimension (device/runtime/driver/software)
        // instead of recording a present-but-unusable device. This is not a
        // silent degrade (Law 10), the build feature set (`push_feature!("gpu")`)
        // already stamps the cache identity, so a GPU-capable build's cache can
        // never collide with this one; and a GPU-CAPABLE build whose runtime
        // probe fails keeps `hardware_gpu_present` true below and still fails
        // closed in `require_exact_identity`. Without this, a portable/no-gpu
        // binary can never calibrate on a workstation that HAS a GPU: the hw
        // probe sees the card (`caps.gpu_available`) but no wgpu runtime is
        // compiled, so the runtime-backend requirement can never be satisfied.
        // Preserve a present-but-unidentified GPU as `Some("")` so
        // `require_exact_identity` rejects the failed probe. Collapsing it to
        // `None` would be indistinguishable from genuinely absent hardware and
        // could trust calibration across an unknown device/driver change.
        let gpu_device_identity =
            (gpu_supported_by_build && caps.gpu_available).then(|| match &caps.gpu_name {
                Some(name) => name.clone(),
                None => String::new(),
            });
        let hardware_gpu_present = gpu_device_identity
            .as_deref()
            .map(str::trim)
            .is_some_and(|name| !name.is_empty())
            && !caps.gpu_is_software;
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_model: detect_cpu_model(),
            physical_cores: caps.physical_cores,
            logical_cores: caps.logical_cores,
            has_avx2: caps.has_avx2,
            has_avx512: caps.has_avx512,
            has_neon: caps.has_neon,
            hyperscan_available: caps.hyperscan_available,
            gpu_name: gpu_device_identity,
            gpu_runtime_backend: hardware_gpu_present
                .then(|| gpu_runtime_backend.map(str::to_string))
                .flatten(),
            gpu_driver_runtime_identity: hardware_gpu_present
                .then(|| caps.gpu_runtime_identity.clone())
                .flatten(),
            gpu_is_software: gpu_supported_by_build && caps.gpu_is_software,
            total_memory_mb: caps.total_memory_mb,
        }
    }

    pub(super) fn require_exact_identity(&self) -> Result<(), &'static str> {
        if !field_is_present_nonblank(&self.cpu_model) {
            return Err("CPU model string is unavailable");
        }
        if self.physical_cores == 0
            || self.logical_cores == 0
            || self.logical_cores < self.physical_cores
        {
            return Err("CPU core topology is unavailable");
        }
        match self.total_memory_mb {
            Some(memory_mb) if memory_mb > 0 => {}
            _ => return Err("system memory size is unavailable"),
        }
        // A Some("") / Some("  ") field is a PROBE BUG, distinct from an honest
        // None (no device): present-but-blank never validates.
        let gpu_name_present = field_is_present_nonblank(&self.gpu_name);
        if self.gpu_name.is_some() && !gpu_name_present {
            return Err("GPU device identity is unavailable");
        }
        let hardware_gpu_present = gpu_name_present && !self.gpu_is_software;
        let gpu_runtime_backend_present = field_is_present_nonblank(&self.gpu_runtime_backend);
        if self.gpu_runtime_backend.is_some() && !gpu_runtime_backend_present {
            return Err("GPU runtime backend identity is unavailable");
        }
        if gpu_runtime_backend_present && self.gpu_name.is_none() {
            return Err("GPU runtime backend is present without GPU device identity");
        }
        if hardware_gpu_present && !gpu_runtime_backend_present {
            return Err("GPU runtime backend identity is unavailable");
        }
        if (hardware_gpu_present || gpu_runtime_backend_present)
            && !field_is_present_nonblank(&self.gpu_driver_runtime_identity)
        {
            return Err("GPU driver/runtime identity is unavailable");
        }
        Ok(())
    }
}

/// True when an optional identity field is `Some` with non-blank content 
/// the ONE definition of "this probe field actually resolved" shared by every
/// `require_exact_identity` check (a `Some("")` is a probe bug, not identity).
fn field_is_present_nonblank(field: &Option<String>) -> bool {
    field
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn detect_cpu_model() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Some(model) = linux_cpu_model() {
            return Some(model);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let sysctl = keyhog_core::resolve_safe_bin("sysctl")?;
        if let Some(model) =
            command_first_nonempty_stdout_line(&sysctl, &["-n", "machdep.cpu.brand_string"])
        {
            return Some(model);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(model) = windows_cpu_model() {
            return Some(model);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_cpu_model() -> Option<String> {
    let content = std::fs::read_to_string("/proc/cpuinfo").ok()?; // LAW10: host identity probe failure is surfaced by autoroute identity validation before cache trust
    parse_cpuinfo_model(&content)
}

#[cfg(target_os = "linux")]
pub(super) fn parse_cpuinfo_model(content: &str) -> Option<String> {
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if matches!(key.as_str(), "model name" | "hardware" | "processor") {
            let value = value.trim();
            if key == "processor" && value.parse::<usize>().is_ok() {
                continue;
            }
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_cpu_model() -> Option<String> {
    keyhog_core::resolve_safe_bin("powershell")
        .and_then(|ps| {
            command_first_nonempty_stdout_line(
                &ps,
                &[
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
                ],
            )
        })
        .or_else(|| {
        let wmic = keyhog_core::resolve_safe_bin("wmic")?;
        command_first_nonempty_stdout_line(&wmic, &["cpu", "get", "Name", "/value"]).and_then(
            |line| {
                line.strip_prefix("Name=")
                    .map(str::trim)
                    .map(str::to_string)
            },
        )
        })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn command_first_nonempty_stdout_line(bin: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(bin).args(args).output().ok()?; // LAW10: host identity probe failure is surfaced by autoroute identity validation before cache trust
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}
