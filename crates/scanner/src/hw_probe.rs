//! Hardware capability probing with once-cached results.
//!
//! Detects CPU features (AVX-512, AVX2, NEON), GPU compute (wgpu/Vulkan),
//! Hyperscan availability, io_uring support, memory, and core counts.
//! All detection is done once at startup and cached for the process lifetime.

use std::sync::OnceLock;

/// Scan execution backend selected for a given workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanBackend {
    /// GPU pattern matching via vyre's literal-set engine
    /// (`GpuLiteralSet`). The default GPU path; <~1500 patterns,
    /// literal-prefix matching only.
    Gpu,
    /// GPU regex multimatch via vyre's `RulePipeline` mega-scan
    /// pipeline (NFA-based). Activated by `KEYHOG_BACKEND=mega-scan`;
    /// the regex-completion path that handles patterns
    /// `GpuLiteralSet`'s literal prefix can't reduce to a literal.
    MegaScan,
    /// Hyperscan NFA multi-pattern matching + SIMD prefilter.
    /// This is the primary high-throughput path on all platforms.
    SimdCpu,
    /// Pure CPU: vyre AC + regex. No Hyperscan, no GPU.
    CpuFallback,
}

impl ScanBackend {
    /// Stable label for logs and CLI startup banner.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Gpu => "gpu-zero-copy",
            Self::MegaScan => "gpu-mega-scan",
            Self::SimdCpu => "simd-regex",
            Self::CpuFallback => "cpu-fallback",
        }
    }
}

/// Hardware capabilities detected at startup.
#[derive(Debug, Clone)]
pub struct HardwareCaps {
    pub physical_cores: usize,
    pub logical_cores: usize,
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_neon: bool,
    pub gpu_available: bool,
    pub gpu_name: Option<String>,
    pub gpu_vram_mb: Option<u64>,
    /// True when the GPU is a software renderer (llvmpipe/lavapipe) — always slower than CPU.
    pub gpu_is_software: bool,
    pub total_memory_mb: Option<u64>,
    pub io_uring_available: bool,
    /// True when the `simd` feature is compiled in AND Hyperscan initialized.
    pub hyperscan_available: bool,
}

static HW_PROBE: OnceLock<HardwareCaps> = OnceLock::new();

/// Probe hardware once and cache the result.
pub fn probe_hardware() -> &'static HardwareCaps {
    HW_PROBE.get_or_init(|| {
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let physical_cores = physical_core_count().unwrap_or(logical_cores);

        #[cfg(target_arch = "x86_64")]
        let (has_avx2, has_avx512, has_neon) = (
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("avx512f"),
            false,
        );
        #[cfg(target_arch = "aarch64")]
        let (has_avx2, has_avx512, has_neon) = (false, false, true);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let (has_avx2, has_avx512, has_neon) = (false, false, false);

        let (gpu_available, gpu_name, gpu_vram_mb) = crate::gpu::gpu_probe();

        let gpu_is_software = gpu_name.as_deref().is_some_and(|name: &str| {
            let lower = name.to_ascii_lowercase();
            lower.contains("llvmpipe")
                || lower.contains("lavapipe")
                || lower.contains("swiftshader")
        });
        if gpu_is_software {
            tracing::warn!(
                gpu = ?gpu_name,
                "Software GPU detected — GPU scanning disabled (slower than CPU)"
            );
        }

        let hyperscan_available = cfg!(feature = "simd");
        let total_memory_mb = detect_total_memory_mb();
        let io_uring_available = detect_io_uring();

        let caps = HardwareCaps {
            physical_cores,
            logical_cores,
            has_avx2,
            has_avx512,
            has_neon,
            gpu_available,
            gpu_name: gpu_name.clone(),
            gpu_vram_mb,
            gpu_is_software,
            total_memory_mb,
            io_uring_available,
            hyperscan_available,
        };

        tracing::info!(
            physical_cores,
            logical_cores,
            gpu_available,
            gpu_name = ?gpu_name,
            has_avx512 = caps.has_avx512,
            has_avx2 = caps.has_avx2,
            has_neon = caps.has_neon,
            hyperscan = hyperscan_available,
            io_uring = io_uring_available,
            "hardware probe complete"
        );

        caps
    })
}

/// Routing crossover thresholds. Public so benchmarks and the
/// `keyhog backend` debug subcommand can reference the same numbers.
///
/// Thresholds are now **GPU-tier-aware** instead of one-size-fits-all.
/// The legacy single-value `GPU_MIN_BYTES` / `GPU_BYTES_BREAKEVEN_SOLO`
/// constants are kept as the conservative (low-tier) defaults; the
/// router consults [`gpu_min_bytes_for_tier`] / [`gpu_solo_bytes_for_tier`]
/// to pick the right breakeven for the actual adapter.
///
/// The tier→threshold map is calibrated against the published dispatch
/// latency of each GPU class:
///
/// | Tier   | Adapter examples                | Dispatch latency | GPU activates at |
/// |--------|---------------------------------|------------------|-------------------|
/// | High   | RTX 40/50, A100, H100, M-series Max | 100-300 µs   | **2 MiB**         |
/// | Mid    | RTX 20/30, GTX 16, Arc, M-series base | 600-1500 µs | 16 MiB            |
/// | Low    | iGPU (UHD/Iris), Vega, older cards   | 2-5 ms         | 64 MiB            |
///
/// At Hyperscan's typical 3 GB/s, breakeven workload = dispatch_latency × 3 GB/s.
/// 100 µs × 3000 bytes/µs ≈ 300 KB (round up to 2 MiB for safety margin
/// + per-batch parallel-CPU contention).
pub mod thresholds {
    /// **Conservative** (low-tier) minimum total scan-buffer size before
    /// we'll dispatch to GPU. Top-tier GPUs (RTX 40/50, A100/H100,
    /// M-series Max) get the much lower [`GPU_MIN_BYTES_HIGH_TIER`]
    /// threshold instead.
    pub const GPU_MIN_BYTES: u64 = 64 * 1024 * 1024;
    /// Mid-tier (RTX 20/30, GTX 16, Intel Arc, M-series base): 16 MiB.
    pub const GPU_MIN_BYTES_MID_TIER: u64 = 16 * 1024 * 1024;
    /// High-tier (RTX 40/50, A100/H100, M-series Max): 2 MiB.
    /// At ~100 µs dispatch latency on these GPUs vs Hyperscan's
    /// 3 GB/s, breakeven workload is ~300 KB; 2 MiB gives headroom
    /// for the per-batch parallel-CPU contention that Hyperscan
    /// benefits from.
    pub const GPU_MIN_BYTES_HIGH_TIER: u64 = 2 * 1024 * 1024;
    /// Pattern count above which GPU literal matching becomes worthwhile
    /// regardless of buffer size — many patterns saturate Hyperscan's
    /// scratch space and serial AC. Conservative (low-tier) default;
    /// see [`gpu_pattern_breakeven_for_tier`] for the tier-aware value.
    pub const GPU_PATTERN_BREAKEVEN: usize = 2_000;
    /// High-tier GPUs (RTX 40/50, A100/H100, M-Max) win on as few as
    /// 100 patterns once dispatch overhead is sub-millisecond.
    pub const GPU_PATTERN_BREAKEVEN_HIGH_TIER: usize = 100;
    /// Mid-tier crossover: 500 patterns.
    pub const GPU_PATTERN_BREAKEVEN_MID_TIER: usize = 500;
    /// Single-file size that justifies GPU even at low pattern counts.
    /// One device dispatch beats saturating one CPU core with Hyperscan
    /// when the file alone is this big.
    pub const GPU_BYTES_BREAKEVEN_SOLO: u64 = 256 * 1024 * 1024;
    /// High-tier solo cap: 16 MiB single file already justifies GPU
    /// dispatch on a 5090-class adapter.
    pub const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 = 16 * 1024 * 1024;
    /// Mid-tier solo cap: 64 MiB.
    pub const GPU_BYTES_BREAKEVEN_SOLO_MID_TIER: u64 = 64 * 1024 * 1024;
}

/// GPU performance tier inferred from the adapter name. Coarse but
/// matches measured dispatch latency well enough to drive routing.
/// `Unknown` keeps the legacy conservative thresholds, so an unfamiliar
/// adapter is never wrongly routed to the lower-threshold path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuTier {
    /// RTX 40/50-series, A100/H100, M-series Max/Ultra, RX 7900 XTX.
    /// Sub-300µs dispatch latency.
    High,
    /// RTX 20/30-series, GTX 16, Intel Arc, M-series base/Pro,
    /// RX 6000-series. ~600-1500µs dispatch latency.
    Mid,
    /// iGPU, older discrete cards, anything we can't classify.
    /// Multi-millisecond dispatch latency assumed.
    Low,
}

/// Classify a GPU adapter name into a performance tier. Pure
/// substring heuristics — bumped only when a new high-volume part
/// ships (or the user reports a misclassification).
#[must_use]
pub fn classify_gpu_tier(adapter_name: Option<&str>) -> GpuTier {
    let Some(name) = adapter_name else {
        return GpuTier::Low;
    };
    let lower = name.to_ascii_lowercase();

    // High-tier discretes.
    if lower.contains("rtx 40")
        || lower.contains("rtx 50")
        || lower.contains("rtx 4090")
        || lower.contains("rtx 4080")
        || lower.contains("rtx 4070")
        || lower.contains("rtx 5090")
        || lower.contains("rtx 5080")
        || lower.contains("rtx 5070")
        || lower.contains("a100")
        || lower.contains("h100")
        || lower.contains("h200")
        || lower.contains("rx 7900 xtx")
        || lower.contains("rx 7900 xt")
        || lower.contains("m4 max")
        || lower.contains("m3 max")
        || lower.contains("m2 max")
        || lower.contains("m1 max")
        || lower.contains("m4 ultra")
        || lower.contains("m3 ultra")
        || lower.contains("m2 ultra")
        || lower.contains("m1 ultra")
    {
        return GpuTier::High;
    }

    // Mid-tier discretes.
    if lower.contains("rtx 20")
        || lower.contains("rtx 30")
        || lower.contains("gtx 16")
        || lower.contains("arc")
        || lower.contains("rx 6")
        || lower.contains("rx 7")
        || lower.contains("apple m1")
        || lower.contains("apple m2")
        || lower.contains("apple m3")
        || lower.contains("apple m4")
        || lower.contains("m1 pro")
        || lower.contains("m2 pro")
        || lower.contains("m3 pro")
        || lower.contains("m4 pro")
    {
        return GpuTier::Mid;
    }

    GpuTier::Low
}

/// GPU minimum-bytes routing threshold for the given tier.
#[must_use]
pub fn gpu_min_bytes_for_tier(tier: GpuTier) -> u64 {
    match tier {
        GpuTier::High => thresholds::GPU_MIN_BYTES_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_MIN_BYTES_MID_TIER,
        GpuTier::Low => thresholds::GPU_MIN_BYTES,
    }
}

/// GPU single-file solo-breakeven threshold for the given tier.
#[must_use]
pub fn gpu_solo_bytes_for_tier(tier: GpuTier) -> u64 {
    match tier {
        GpuTier::High => thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_BYTES_BREAKEVEN_SOLO_MID_TIER,
        GpuTier::Low => thresholds::GPU_BYTES_BREAKEVEN_SOLO,
    }
}

/// Pattern-count threshold for the given tier. Below this and below
/// the solo-cap, GPU dispatch costs more than Hyperscan saves —
/// stay on SIMD.
#[must_use]
pub fn gpu_pattern_breakeven_for_tier(tier: GpuTier) -> usize {
    match tier {
        GpuTier::High => thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_PATTERN_BREAKEVEN_MID_TIER,
        GpuTier::Low => thresholds::GPU_PATTERN_BREAKEVEN,
    }
}

/// Auto-route a scan to the best backend for this hardware + workload.
///
/// Routing rules (highest-priority match wins):
///
/// 0. **Env override** — `KEYHOG_BACKEND={gpu,simd,cpu}` forces a specific
///    backend. Used by benchmarks and CI to assert routing decisions.
///    Invalid values fall through to the auto-selection rules below.
/// 1. **GPU** — discrete non-software adapter is present AND the workload is
///    large enough to amortize device-dispatch overhead AND we have either
///    enough patterns to benefit from massively-parallel literal matching, OR
///    a single very large file (>= 256 MiB) where one device dispatch beats
///    saturating one CPU core with Hyperscan.
/// 2. **SimdCpu** — Hyperscan is compiled in and CPU has SIMD (AVX-512/AVX2/
///    NEON). This is the default high-throughput path for most deployments.
/// 3. **SimdCpu (no-Hyperscan)** — bare SIMD prefilter without Hyperscan when
///    SIMD CPU features exist but the Hyperscan crate failed to load.
/// 4. **CpuFallback** — pure scalar AC + regex. Works everywhere.
///
/// The crossover thresholds were tuned against the standard corpus (Django +
/// kubernetes/kubernetes + linux/linux). See `hw_probe::thresholds`.
#[must_use]
pub fn select_backend(
    caps: &HardwareCaps,
    workload_bytes: u64,
    pattern_count: usize,
) -> ScanBackend {
    if let Some(forced) = backend_env_override() {
        return forced;
    }

    if caps.gpu_available && !caps.gpu_is_software {
        let tier = classify_gpu_tier(caps.gpu_name.as_deref());
        let solo = gpu_solo_bytes_for_tier(tier);
        let min = gpu_min_bytes_for_tier(tier);
        let pattern_floor = gpu_pattern_breakeven_for_tier(tier);
        if workload_bytes >= solo
            || (workload_bytes >= min && pattern_count >= pattern_floor)
        {
            return ScanBackend::Gpu;
        }
    }

    if caps.hyperscan_available {
        return ScanBackend::SimdCpu;
    }

    if caps.has_avx512 || caps.has_avx2 || caps.has_neon {
        return ScanBackend::SimdCpu;
    }

    ScanBackend::CpuFallback
}

/// Parse `KEYHOG_BACKEND` env var into a forced [`ScanBackend`].
/// Recognized values: `gpu`, `mega-scan`, `simd`, `cpu` (case-
/// insensitive). `mega-scan` selects the regex-NFA pipeline
/// (`RulePipeline`) instead of the literal-set engine.
fn backend_env_override() -> Option<ScanBackend> {
    let raw = std::env::var("KEYHOG_BACKEND").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "gpu" | "gpu-zero-copy" | "literal-set" => Some(ScanBackend::Gpu),
        "mega-scan" | "gpu-mega-scan" | "regex-nfa" | "rule-pipeline" => {
            Some(ScanBackend::MegaScan)
        }
        "simd" | "simd-regex" | "hyperscan" => Some(ScanBackend::SimdCpu),
        "cpu" | "cpu-fallback" | "scalar" => Some(ScanBackend::CpuFallback),
        _ => None,
    }
}

/// Format a one-line startup banner summarizing detected hardware.
pub fn startup_banner(caps: &HardwareCaps, detector_count: usize, pattern_count: usize) -> String {
    let gpu = if let Some(name) = &caps.gpu_name {
        if caps.gpu_is_software {
            // Software-only adapters (llvmpipe, lavapipe, swiftshader) get
            // detected and probed, but `select_backend` rejects them
            // because dispatching the literal-set pipeline through CPU-
            // emulated GL/Vulkan is slower than just running the SIMD
            // path directly. Surface this in the banner so users on
            // headless boxes (CI runners, containers) understand why
            // their scan is using SIMD even though `keyhog backend`
            // shows a "GPU" line.
            format!("GPU: {name} (software, ignored)")
        } else {
            format!("GPU: {name}")
        }
    } else {
        "GPU: none".to_string()
    };

    let simd = if caps.has_avx512 {
        "AVX-512"
    } else if caps.has_avx2 {
        "AVX2"
    } else if caps.has_neon {
        "NEON"
    } else {
        "scalar"
    };

    let hs = if caps.hyperscan_available {
        "Hyperscan"
    } else {
        "AC"
    };
    let uring = if caps.io_uring_available {
        " io_uring"
    } else {
        ""
    };

    format!(
        "{} cores | {} | SIMD: {} | {} | {detector_count} detectors ({pattern_count} patterns){uring}",
        caps.physical_cores, gpu, simd, hs,
    )
}

// ── Platform-specific detection ─────────────────────────────────────

fn physical_core_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        linux_physical_cores()
    }
    #[cfg(target_os = "macos")]
    {
        macos_physical_cores()
    }
    #[cfg(target_os = "windows")]
    {
        windows_physical_cores()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_physical_cores() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut pairs = std::collections::HashSet::new();
    let mut physical_id = None::<usize>;
    let mut core_id = None::<usize>;
    for line in content.lines() {
        if line.starts_with("physical id") {
            physical_id = line.split(':').nth(1)?.trim().parse().ok();
        } else if line.starts_with("core id") {
            core_id = line.split(':').nth(1)?.trim().parse().ok();
        } else if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (physical_id, core_id) {
                pairs.insert((p, c));
            }
            physical_id = None;
            core_id = None;
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.len())
    }
}

#[cfg(target_os = "macos")]
fn macos_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-sysctl. Resolve absolute path.
    let bin = keyhog_core::safe_bin::resolve_or_fallback("sysctl");
    std::process::Command::new(&bin)
        .args(["-n", "hw.physicalcpu"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
}

#[cfg(target_os = "windows")]
fn windows_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-powershell/wmic. Resolve
    // each binary against trusted system32 dir; fall through to None if
    // not found there. Refuses unconditional $PATH lookup.
    let ps = keyhog_core::safe_bin::resolve_or_fallback("powershell");
    let core_count = std::process::Command::new(&ps)
        .args([
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Processor).NumberOfCores",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok());
    if core_count.is_some() {
        return core_count;
    }
    let wmic = keyhog_core::safe_bin::resolve_or_fallback("wmic");
    std::process::Command::new(&wmic)
        .args(["cpu", "get", "NumberOfCores", "/value"])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|l| l.starts_with("NumberOfCores="))
                .and_then(|l| l.split('=').nth(1))
                .and_then(|v| v.trim().parse().ok())
        })
}

fn detect_total_memory_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb / 1024);
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let bin = keyhog_core::safe_bin::resolve_or_fallback("sysctl");
        std::process::Command::new(&bin)
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| {
                let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?;
                Some(bytes / 1024 / 1024)
            })
    }
    #[cfg(target_os = "windows")]
    {
        let ps = keyhog_core::safe_bin::resolve_or_fallback("powershell");
        let memory = std::process::Command::new(&ps)
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()
            .and_then(|o| {
                let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?;
                Some(bytes / 1024 / 1024)
            });
        if memory.is_some() {
            return memory;
        }
        let wmic = keyhog_core::safe_bin::resolve_or_fallback("wmic");
        std::process::Command::new(&wmic)
            .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.starts_with("TotalPhysicalMemory="))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|bytes| bytes / 1024 / 1024)
            })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

fn detect_io_uring() -> bool {
    #[cfg(target_os = "linux")]
    {
        let kernel_ok = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| {
                let parts: Vec<&str> = s.trim().split('.').collect();
                if parts.len() >= 2 {
                    let major = parts[0].parse::<u32>().ok()?;
                    let minor = parts[1].parse::<u32>().ok()?;
                    Some(major > 5 || (major == 5 && minor >= 1))
                } else {
                    None
                }
            })
            .unwrap_or(false);
        if !kernel_ok {
            return false;
        }
        io_uring::IoUring::new(1).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Cargo runs tests in parallel; mutating the process env is racy across
    /// threads. Serialize every test that touches `KEYHOG_BACKEND` through
    /// this mutex so we don't trample each other's writes.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn caps_with(gpu: bool, soft: bool, hs: bool, avx2: bool) -> HardwareCaps {
        HardwareCaps {
            physical_cores: 8,
            logical_cores: 16,
            has_avx2: avx2,
            has_avx512: false,
            has_neon: false,
            gpu_available: gpu,
            gpu_name: gpu.then(|| "Test GPU".to_string()),
            gpu_vram_mb: gpu.then_some(8192),
            gpu_is_software: soft,
            total_memory_mb: Some(32_768),
            io_uring_available: false,
            hyperscan_available: hs,
        }
    }

    fn clear_env() {
        // SAFETY: env mutation is only safe in single-threaded context;
        // ENV_GUARD makes that true within this test module.
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    }

    #[test]
    fn gpu_picked_when_workload_huge_solo() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(true, false, true, true);
        // 256 MiB single file, low pattern count → still GPU (solo
        // crossover).
        assert_eq!(
            select_backend(&caps, thresholds::GPU_BYTES_BREAKEVEN_SOLO, 50),
            ScanBackend::Gpu
        );
    }

    #[test]
    fn gpu_picked_when_buffer_big_and_many_patterns() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(true, false, true, true);
        // 64 MiB + 2K patterns → GPU.
        assert_eq!(
            select_backend(
                &caps,
                thresholds::GPU_MIN_BYTES,
                thresholds::GPU_PATTERN_BREAKEVEN
            ),
            ScanBackend::Gpu
        );
    }

    #[test]
    fn gpu_skipped_below_buffer_threshold() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(true, false, true, true);
        // 63 MiB even with 5K patterns → SimdCpu (under MIN_BYTES).
        assert_eq!(
            select_backend(&caps, thresholds::GPU_MIN_BYTES - 1, 5_000),
            ScanBackend::SimdCpu
        );
    }

    #[test]
    fn gpu_skipped_when_software_renderer() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        // GPU available, but it's llvmpipe — must NEVER pick it.
        let caps = caps_with(true, true, true, true);
        assert_eq!(
            select_backend(&caps, 1024 * 1024 * 1024, 10_000),
            ScanBackend::SimdCpu
        );
    }

    #[test]
    fn simd_cpu_when_no_gpu_with_hyperscan() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(false, false, true, true);
        assert_eq!(
            select_backend(&caps, 1024 * 1024, 100),
            ScanBackend::SimdCpu
        );
    }

    #[test]
    fn simd_cpu_when_no_gpu_no_hyperscan_but_avx2() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(false, false, false, true);
        // SIMD CPU features alone still pick the SIMD path (sans Hyperscan).
        assert_eq!(
            select_backend(&caps, 1024 * 1024, 100),
            ScanBackend::SimdCpu
        );
    }

    #[test]
    fn cpu_fallback_when_no_gpu_no_hyperscan_no_simd() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with(false, false, false, false);
        assert_eq!(
            select_backend(&caps, 1024 * 1024, 100),
            ScanBackend::CpuFallback
        );
    }

    #[test]
    fn env_override_forces_gpu_even_without_workload() {
        let _g = ENV_GUARD.lock().unwrap();
        // SAFETY: ENV_GUARD held above serializes env-mutating tests.
        unsafe { std::env::set_var("KEYHOG_BACKEND", "gpu") };
        let caps = caps_with(false, false, true, true);
        // No GPU available, no large workload — env still wins.
        assert_eq!(select_backend(&caps, 1024, 10), ScanBackend::Gpu);
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    }

    #[test]
    fn env_override_forces_cpu_fallback() {
        let _g = ENV_GUARD.lock().unwrap();
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::set_var("KEYHOG_BACKEND", "cpu") };
        let caps = caps_with(true, false, true, true);
        // Big workload + GPU available — env still pins CPU fallback.
        assert_eq!(
            select_backend(&caps, 1024 * 1024 * 1024, 10_000),
            ScanBackend::CpuFallback
        );
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    }

    #[test]
    fn env_override_invalid_value_falls_through_to_auto() {
        let _g = ENV_GUARD.lock().unwrap();
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::set_var("KEYHOG_BACKEND", "garbage-value") };
        let caps = caps_with(false, false, true, true);
        // Garbage value ignored → falls back to auto routing.
        assert_eq!(
            select_backend(&caps, 1024 * 1024, 100),
            ScanBackend::SimdCpu
        );
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    }

    #[test]
    fn backend_label_is_stable() {
        // Stable labels are part of our CLI banner contract.
        assert_eq!(ScanBackend::Gpu.label(), "gpu-zero-copy");
        assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
        assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
    }

    #[test]
    fn env_override_accepts_label_aliases() {
        let _g = ENV_GUARD.lock().unwrap();
        let caps = caps_with(false, false, true, true);

        // Each backend has multiple opt-in aliases; CI runners and Dockerfiles
        // routinely use the human-readable label as the env value, so all
        // forms must route to the same backend.
        for value in ["gpu", "GPU", "Gpu-Zero-Copy", " gpu "] {
            // SAFETY: ENV_GUARD held above.
            unsafe { std::env::set_var("KEYHOG_BACKEND", value) };
            assert_eq!(
                select_backend(&caps, 0, 0),
                ScanBackend::Gpu,
                "value {value:?} must route to Gpu"
            );
        }
        for value in ["simd", "SIMD", "simd-regex", "hyperscan", "HYPERSCAN"] {
            // SAFETY: ENV_GUARD held above.
            unsafe { std::env::set_var("KEYHOG_BACKEND", value) };
            assert_eq!(
                select_backend(&caps, 0, 0),
                ScanBackend::SimdCpu,
                "value {value:?} must route to SimdCpu"
            );
        }
        for value in ["cpu", "Cpu", "cpu-fallback", "scalar"] {
            // SAFETY: ENV_GUARD held above.
            unsafe { std::env::set_var("KEYHOG_BACKEND", value) };
            assert_eq!(
                select_backend(&caps, 0, 0),
                ScanBackend::CpuFallback,
                "value {value:?} must route to CpuFallback"
            );
        }
        // SAFETY: ENV_GUARD held above.
        unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    }

    fn caps_with_named_gpu(name: &str) -> HardwareCaps {
        HardwareCaps {
            physical_cores: 8,
            logical_cores: 16,
            has_avx2: true,
            has_avx512: false,
            has_neon: false,
            gpu_available: true,
            gpu_name: Some(name.to_string()),
            gpu_vram_mb: Some(8192),
            gpu_is_software: false,
            total_memory_mb: Some(32_768),
            io_uring_available: false,
            hyperscan_available: true,
        }
    }

    #[test]
    fn classify_high_tier_gpus() {
        for name in [
            "NVIDIA GeForce RTX 5090",
            "NVIDIA GeForce RTX 4090",
            "NVIDIA H100 PCIe",
            "NVIDIA A100-SXM4-80GB",
            "Apple M3 Max",
            "AMD Radeon RX 7900 XTX",
        ] {
            assert_eq!(
                classify_gpu_tier(Some(name)),
                GpuTier::High,
                "expected High tier for {name:?}"
            );
        }
    }

    #[test]
    fn classify_mid_tier_gpus() {
        for name in [
            "NVIDIA GeForce RTX 3060",
            "NVIDIA GeForce RTX 2080 Ti",
            "NVIDIA GeForce GTX 1660",
            "Intel(R) Arc(TM) A770 Graphics",
            "Apple M1 Pro",
        ] {
            assert_eq!(
                classify_gpu_tier(Some(name)),
                GpuTier::Mid,
                "expected Mid tier for {name:?}"
            );
        }
    }

    #[test]
    fn classify_low_tier_gpus() {
        for name in [
            "Intel(R) UHD Graphics 620",
            "Intel(R) Iris Xe Graphics",
            "AMD Radeon Vega 8",
            "Mystery GPU 9000",
        ] {
            assert_eq!(
                classify_gpu_tier(Some(name)),
                GpuTier::Low,
                "expected Low tier for {name:?}"
            );
        }
        assert_eq!(classify_gpu_tier(None), GpuTier::Low);
    }

    #[test]
    fn high_tier_gpu_activates_at_2mib() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with_named_gpu("NVIDIA GeForce RTX 5090");
        // 2 MiB workload + 2K patterns → GPU on RTX 5090.
        assert_eq!(
            select_backend(&caps, 2 * 1024 * 1024, thresholds::GPU_PATTERN_BREAKEVEN),
            ScanBackend::Gpu
        );
        // 2 MiB single file (no pattern threshold needed) shouldn't
        // hit the solo cap (16 MiB on high tier), so falls back to SIMD
        // when pattern count is low.
        assert_eq!(
            select_backend(&caps, 2 * 1024 * 1024, 50),
            ScanBackend::SimdCpu
        );
        // 16 MiB single file → solo cap on high tier → GPU.
        assert_eq!(
            select_backend(&caps, 16 * 1024 * 1024, 50),
            ScanBackend::Gpu
        );
    }

    #[test]
    fn mid_tier_gpu_activates_at_16mib() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        let caps = caps_with_named_gpu("NVIDIA GeForce RTX 3070");
        // 2 MiB on mid-tier is too small — SIMD wins.
        assert_eq!(
            select_backend(&caps, 2 * 1024 * 1024, thresholds::GPU_PATTERN_BREAKEVEN),
            ScanBackend::SimdCpu
        );
        // 16 MiB + 2K patterns → GPU.
        assert_eq!(
            select_backend(
                &caps,
                thresholds::GPU_MIN_BYTES_MID_TIER,
                thresholds::GPU_PATTERN_BREAKEVEN
            ),
            ScanBackend::Gpu
        );
    }

    #[test]
    fn low_tier_gpu_keeps_legacy_64mib_threshold() {
        let _g = ENV_GUARD.lock().unwrap();
        clear_env();
        // Unknown adapter name → Low tier → original 64 MiB threshold.
        let caps = caps_with_named_gpu("Mystery GPU");
        // 16 MiB even with many patterns → SIMD (Low tier needs 64 MiB).
        assert_eq!(
            select_backend(&caps, 16 * 1024 * 1024, 5_000),
            ScanBackend::SimdCpu
        );
        assert_eq!(
            select_backend(
                &caps,
                thresholds::GPU_MIN_BYTES,
                thresholds::GPU_PATTERN_BREAKEVEN
            ),
            ScanBackend::Gpu
        );
    }
}
