//! Hardware capability probing with once-cached results.
//!
//! Detects CPU features (AVX-512, AVX2, NEON), GPU compute (wgpu/Vulkan),
//! Hyperscan availability, io_uring support, memory, and core counts.
//! All detection is done once at startup and cached for the process
//! lifetime.
//!
//! Split into focused submodules by hardware-probe responsibility:
//!
//!   * `thresholds` - GPU routing crossover constants consumed through
//!     the public tier lookup functions.
//!   * [`tier`] - GPU adapter classification + tier threshold profiles.
//!   * [`select`] - [`select_backend`] routing logic + env-override
//!     parsing.
//!   * [`banner`] - `startup_banner` formatter for the CLI header.
//!   * [`platform`] - per-OS detection of physical cores, memory,
//!     and io_uring availability.

use std::sync::OnceLock;

mod banner;
pub(crate) mod platform;
pub(crate) mod select;
mod tier;

pub(crate) mod thresholds;

pub use banner::startup_banner;
pub use select::{
    gpu_could_engage, parse_backend_str, select_backend, select_backend_verdict,
    BackendRoutingReason, BackendRoutingVerdict, BACKEND_OVERRIDE_VALUES,
};
pub use tier::{gpu_routing_profile, gpu_routing_profiles, GpuRoutingProfile};

/// Scan execution backend selected for a given workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanBackend {
    /// GPU region-presence phase 1 via vyre's literal-set engine
    /// (`GpuLiteralSet`). The default GPU path; it produces per-chunk
    /// detector-presence bitmaps and the shared CPU phase-2 tail confirms
    /// findings.
    Gpu,
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
            Self::Gpu => "gpu-region-presence",
            Self::SimdCpu => "simd-regex",
            Self::CpuFallback => "cpu-fallback",
        }
    }
}

/// True when this build compiled a scan backend beyond the always-present scalar
/// [`ScanBackend::CpuFallback`]. Hyperscan (`simd`) and/or the GPU stack (`gpu`).
///
/// When this is `false` there is no routing choice: every scan can only run
/// `CpuFallback`, so autoroute calibration is neither needed nor possible and the
/// caller resolves the lone backend directly instead of failing closed. This is a
/// COMPILE-time fact, owned here in the scanner where the `simd`/`gpu` feature gates
/// actually live: a consumer's own feature flags can diverge (e.g. the CLI's
/// `ci-lean` enables `keyhog-scanner/simd` without the CLI's own `simd` feature), so
/// consumers MUST ask the scanner rather than checking their own `cfg!`.
#[must_use]
pub const fn multiple_backends_compiled() -> bool {
    simd_backend_compiled() || gpu_backend_compiled()
}

/// True when this scanner crate was compiled with the Hyperscan/SIMD backend.
/// Consumers must query this owner instead of their own Cargo feature namespace:
/// workspace feature unification can enable a dependency backend without
/// enabling a same-named feature on the consuming crate.
#[must_use]
pub const fn simd_backend_compiled() -> bool {
    cfg!(feature = "simd")
}

/// True when this scanner crate was compiled with the GPU backend stack.
/// Autoroute host identity and persisted build evidence use this dependency-owned
/// fact so a GPU-selected calibration can never be stored without GPU identity.
#[must_use]
pub const fn gpu_backend_compiled() -> bool {
    cfg!(feature = "gpu")
}

/// Single owner of the SIMD-tier label precedence chain.
///
/// The label reported by the startup banner, `keyhog backend`, `keyhog doctor`,
/// and the backend store must always agree, so the `"AVX-512" > "AVX2" > "NEON"
/// > "scalar"` precedence lives in exactly ONE place. Callers pass the three
/// probed CPU-feature booleans (typically `caps.has_avx512`, `caps.has_avx2`,
/// `caps.has_neon`) and receive the highest-priority label that is available.
///
/// Precedence is strict and independent of the lower bits: if `has_avx512` is
/// true the result is `"AVX-512"` regardless of the other two, and so on down
/// to `"scalar"` when none are present.
#[must_use]
pub const fn simd_label(has_avx512: bool, has_avx2: bool, has_neon: bool) -> &'static str {
    if has_avx512 {
        "AVX-512"
    } else if has_avx2 {
        "AVX2"
    } else if has_neon {
        "NEON"
    } else {
        "scalar"
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
    pub gpu_runtime_identity: Option<String>,
    /// True when the GPU is a software renderer (llvmpipe/lavapipe) - always slower than CPU.
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
            .unwrap_or(1); // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        let physical_cores = platform::physical_core_count().unwrap_or(logical_cores); // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant

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
        let gpu_runtime_identity = crate::gpu::gpu_runtime_identity();

        let gpu_is_software = gpu_name.as_deref().is_some_and(|name: &str| {
            let lower = name.to_ascii_lowercase();
            lower.contains("llvmpipe")
                || lower.contains("lavapipe")
                || lower.contains("swiftshader")
        });
        if gpu_is_software {
            tracing::warn!(
                gpu = ?gpu_name,
                "Software GPU detected: GPU scanning disabled (slower than CPU)"
            );
        }

        let hyperscan_available = cfg!(feature = "simd");
        let total_memory_mb = platform::detect_total_memory_mb();
        let io_uring_available = platform::detect_io_uring();

        let caps = HardwareCaps {
            physical_cores,
            logical_cores,
            has_avx2,
            has_avx512,
            has_neon,
            gpu_available,
            gpu_name: gpu_name.clone(),
            gpu_vram_mb,
            gpu_runtime_identity,
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

#[cfg(test)]
#[doc(hidden)]
pub mod testing {
    pub use super::{
        gpu_could_engage, parse_backend_str, probe_hardware, select_backend,
        select_backend_verdict, startup_banner, BackendRoutingReason, BackendRoutingVerdict,
        HardwareCaps, ScanBackend,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GpuTier {
        High,
        Mid,
        Low,
    }

    fn from_inner(tier: super::tier::GpuTier) -> GpuTier {
        match tier {
            super::tier::GpuTier::High => GpuTier::High,
            super::tier::GpuTier::Mid => GpuTier::Mid,
            super::tier::GpuTier::Low => GpuTier::Low,
        }
    }

    fn to_inner(tier: GpuTier) -> super::tier::GpuTier {
        match tier {
            GpuTier::High => super::tier::GpuTier::High,
            GpuTier::Mid => super::tier::GpuTier::Mid,
            GpuTier::Low => super::tier::GpuTier::Low,
        }
    }

    /// Select the CPU scan backend (SIMD/scalar tier) for the given hardware
    /// capabilities, ignoring any GPU. Delegates to [`super::select`].
    pub fn cpu_tier_backend(caps: &HardwareCaps) -> ScanBackend {
        super::select::cpu_tier_backend(caps)
    }

    /// Classify a GPU adapter name into a routing [`GpuTier`] (High/Mid/Low).
    /// `None` (no adapter) classifies to the lowest tier.
    pub fn classify_gpu_tier(adapter_name: Option<&str>) -> GpuTier {
        from_inner(super::tier::classify_gpu_tier(adapter_name))
    }

    /// Minimum workload size (bytes) at which the GPU backend is allowed to
    /// engage at all for this tier (below it, CPU always wins).
    pub fn gpu_min_bytes_for_tier(tier: GpuTier) -> u64 {
        super::tier::gpu_min_bytes_for_tier(to_inner(tier))
    }

    /// Minimum workload size (bytes) at which the GPU runs *solo* (no CPU
    /// co-scan) for this tier.
    pub fn gpu_solo_bytes_for_tier(tier: GpuTier) -> u64 {
        super::tier::gpu_solo_bytes_for_tier(to_inner(tier))
    }

    /// Pattern-count break-even above which GPU scanning beats CPU at this tier.
    pub fn gpu_pattern_breakeven_for_tier(tier: GpuTier) -> usize {
        super::tier::gpu_pattern_breakeven_for_tier(to_inner(tier))
    }

    /// Choose the scan backend for a batch from hardware caps, total workload
    /// size, pattern count, and the largest single-chunk size.
    pub fn select_backend_for_batch(
        caps: &HardwareCaps,
        workload_bytes: u64,
        pattern_count: usize,
        large_chunk_bytes: u64,
    ) -> ScanBackend {
        super::select::select_backend_for_batch(
            caps,
            workload_bytes,
            pattern_count,
            large_chunk_bytes,
        )
    }

    /// Like [`select_backend_for_batch`] but returns the full
    /// [`BackendRoutingVerdict`] (the chosen backend plus the inputs and reason
    /// behind the decision) for diagnostics/telemetry.
    pub fn select_backend_for_batch_verdict(
        caps: &HardwareCaps,
        workload_bytes: u64,
        pattern_count: usize,
        large_chunk_bytes: u64,
    ) -> BackendRoutingVerdict {
        super::select::select_backend_for_batch_verdict(
            caps,
            workload_bytes,
            pattern_count,
            large_chunk_bytes,
        )
    }

    /// Test-only forced backend override (from the `KEYHOG_*` routing env), or
    /// `None` when routing is not overridden.
    pub fn forced_backend_override_for_test() -> Option<ScanBackend> {
        super::select::forced_backend_override_for_test()
    }

    /// Parse the physical CPU core count from `/proc/cpuinfo` contents (Linux).
    #[cfg(target_os = "linux")]
    pub fn linux_physical_cores_from_cpuinfo(content: &str) -> Option<usize> {
        super::platform::linux_physical_cores_from_cpuinfo(content)
    }

    /// Parse total system memory (MiB) from `/proc/meminfo` contents (Linux).
    #[cfg(target_os = "linux")]
    pub fn linux_total_memory_mb_from_meminfo(content: &str) -> Option<u64> {
        super::platform::linux_total_memory_mb_from_meminfo(content)
    }
}
