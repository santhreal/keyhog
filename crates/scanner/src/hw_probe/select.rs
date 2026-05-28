//! Workload-aware backend routing. [`select_backend`] picks one of
//! [`super::ScanBackend`] per scan based on hardware caps, workload
//! size, pattern count, and the optional `KEYHOG_BACKEND` env override.

use super::tier::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier,
};
use super::{HardwareCaps, ScanBackend};

/// Auto-route a scan to the best backend for this hardware + workload.
///
/// Routing rules (highest-priority match wins):
///
/// 0. **Env override** - `KEYHOG_BACKEND={gpu,simd,cpu}` forces a specific
///    backend. Used by benchmarks and CI to assert routing decisions.
///    Invalid values fall through to the auto-selection rules below.
/// 1. **GPU** - discrete non-software adapter is present AND the workload is
///    large enough to amortize device-dispatch overhead AND we have either
///    enough patterns to benefit from massively-parallel literal matching, OR
///    a single very large file (>= 256 MiB) where one device dispatch beats
///    saturating one CPU core with Hyperscan.
/// 2. **SimdCpu** - Hyperscan is compiled in and CPU has SIMD (AVX-512/AVX2/
///    NEON). This is the default high-throughput path for most deployments.
/// 3. **SimdCpu (no-Hyperscan)** - bare SIMD prefilter without Hyperscan when
///    SIMD CPU features exist but the Hyperscan crate failed to load.
/// 4. **CpuFallback** - pure scalar AC + regex. Works everywhere.
///
/// The crossover thresholds were tuned against the standard corpus (Django +
/// kubernetes/kubernetes + linux/linux). See [`super::thresholds`].
#[must_use]
pub fn select_backend(
    caps: &HardwareCaps,
    workload_bytes: u64,
    pattern_count: usize,
) -> ScanBackend {
    if let Some(forced) = backend_env_override() {
        return forced;
    }

    // CI runners have no discrete GPU. Skip GPU consideration here so
    // the routing decision matches what the GPU init paths will
    // actually do (env_no_gpu() returns true on CI, so any GPU choice
    // we make here gets degraded back to SIMD anyway, but at a 250 ms
    // cold-start cost). This branch saves that round trip. Honours
    // KEYHOG_NO_GPU=0 as the self-hosted-GPU-runner override.
    if crate::gpu::env_no_gpu() {
        if caps.hyperscan_available || caps.has_avx512 || caps.has_avx2 || caps.has_neon {
            return ScanBackend::SimdCpu;
        }
        return ScanBackend::CpuFallback;
    }

    if caps.gpu_available && !caps.gpu_is_software {
        let tier = classify_gpu_tier(caps.gpu_name.as_deref());
        let solo = gpu_solo_bytes_for_tier(tier);
        let min = gpu_min_bytes_for_tier(tier);
        let pattern_floor = gpu_pattern_breakeven_for_tier(tier);
        if workload_bytes >= solo || (workload_bytes >= min && pattern_count >= pattern_floor) {
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
pub fn forced_backend_from_env() -> Option<ScanBackend> {
    backend_env_override()
}

/// Like [`forced_backend_from_env`] but bypasses the process-lifetime cache.
///
/// Callers that read the env exactly once at scan startup (e.g. the CLI's
/// `explicit_backend_override`) should prefer this. The cache exists for the
/// per-file hot path inside [`select_backend`]; cold-path callers don't need
/// it, and bypassing it lets integration tests change `KEYHOG_BACKEND`
/// between cases inside a single test binary without the first observed
/// value freezing the rest.
pub fn forced_backend_from_env_uncached() -> Option<ScanBackend> {
    parse_backend_env()
}

#[cfg(not(test))]
fn backend_env_override() -> Option<ScanBackend> {
    // Cached at process start outside of test builds. `select_backend`
    // is called per-file on multi-thousand-file scans, so reading the
    // env var inside every call was a measurable syscall tax on Apple
    // Silicon (~3% scan throughput hit measured against 30k-file linux
    // clone). The env is process-global and the operator can't
    // sensibly change it mid-run anyway. Cache once, read forever.
    //
    // Tests need the unchecked path because the hw_probe test suite
    // sets/unsets KEYHOG_BACKEND inside individual cases to verify the
    // override semantics; a cache from the first test would freeze
    // those checks. `cfg(test)` swaps in the uncached variant only
    // when this crate's own tests compile.
    static CACHED: std::sync::OnceLock<Option<ScanBackend>> = std::sync::OnceLock::new();
    *CACHED.get_or_init(parse_backend_env)
}

#[cfg(test)]
pub(super) fn backend_env_override() -> Option<ScanBackend> {
    parse_backend_env()
}

pub(super) fn parse_backend_env() -> Option<ScanBackend> {
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
