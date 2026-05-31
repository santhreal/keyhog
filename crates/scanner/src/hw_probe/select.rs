//! Workload-aware backend routing. [`select_backend`] picks one of
//! [`super::ScanBackend`] per scan based on hardware caps, workload
//! size, pattern count, and the optional `KEYHOG_BACKEND` env override.

use super::tier::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier,
};
use super::{HardwareCaps, ScanBackend};

thread_local! {
    pub(crate) static TEST_BACKEND_OVERRIDE: std::cell::RefCell<Option<Option<ScanBackend>>> = const { std::cell::RefCell::new(None) };
}

pub fn set_test_backend_override(val: Option<ScanBackend>) {
    TEST_BACKEND_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = Some(val);
    });
}

pub fn clear_test_backend_override() {
    TEST_BACKEND_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

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

    if gpu_could_engage(caps, workload_bytes, pattern_count) {
        return ScanBackend::Gpu;
    }

    if caps.hyperscan_available {
        return ScanBackend::SimdCpu;
    }

    if caps.has_avx512 || caps.has_avx2 || caps.has_neon {
        return ScanBackend::SimdCpu;
    }

    ScanBackend::CpuFallback
}

/// Batch-aware backend routing. Identical to [`select_backend`] for the CPU
/// tiers, but adds a structural guard before the GPU branch: `large_chunk_bytes`
/// is the number of bytes in the batch that live in *large* chunks - chunks at
/// or above the tier's `gpu_min_bytes` floor (the per-file size below which a
/// chunk can never carry its share of the device-dispatch cost).
///
/// `select_backend` decides on `workload_bytes` alone - the coalesced batch
/// total. That conflates two workloads the GPU treats very differently:
///
///   * a batch *dominated* by genuinely large files (e.g. minified bundles,
///     data blobs, generated headers) - the GPU's massively-parallel literal/
///     AC kernel scans those contiguous regions far faster than one Hyperscan
///     core, amortizing the fixed per-batch device-dispatch + PCIe-copy +
///     readback + host-side match-attribution cost; and
///   * a *swarm* of tiny files whose sizes merely SUM past the GPU floor
///     (the Linux kernel: 94k files, 1.5 GiB, but only 55 files >= 2 MiB and a
///     single 22 MiB max - the tiny files coalesce into 256 MiB batches). Here
///     the GPU re-scans every byte, surfaces a literal hit for every detector-
///     prefix occurrence across the whole buffer, then hands the CPU the SAME
///     per-chunk phase-2 confirmation it would have run anyway - plus the
///     coalesce/copy/readback the SIMD path never pays. Measured on the kernel
///     this routes ~2.1x SLOWER (204 s vs 96 s) at ~3x peak RSS (4.1 vs 2.3
///     GiB), and the unbounded device wait can stall the whole scan when the
///     driver drops a completion.
///
/// A largest-chunk guard is not enough: the kernel's 55 large files are
/// sprinkled through the walk, so nearly every 4096-file batch catches one and
/// would still route to GPU. The robust signal is DOMINANCE - GPU engages only
/// when large-chunk bytes are at least half the batch, so a tiny-file swarm
/// never qualifies no matter how the large files cluster, while a batch that is
/// mostly big-file data still gets the device. An explicit `KEYHOG_BACKEND`
/// override still wins (forced/diagnostic GPU path unchanged), and benchmarks
/// pin `KEYHOG_BACKEND=simd`, so this only changes the *default* routing for
/// many-small-file trees - the common real-world scan.
#[must_use]
pub fn select_backend_for_batch(
    caps: &HardwareCaps,
    workload_bytes: u64,
    pattern_count: usize,
    large_chunk_bytes: u64,
) -> ScanBackend {
    if let Some(forced) = backend_env_override() {
        return forced;
    }

    if crate::gpu::env_no_gpu() {
        if caps.hyperscan_available || caps.has_avx512 || caps.has_avx2 || caps.has_neon {
            return ScanBackend::SimdCpu;
        }
        return ScanBackend::CpuFallback;
    }

    // Structural guard: GPU only when large-chunk bytes DOMINATE the batch
    // (>= half the total). The device cost is paid on the whole coalesced
    // buffer, so it pays off only when most of those bytes are genuinely
    // large-file data the GPU can accelerate - not tiny files riding along.
    // A swarm of small files can never clear this no matter how a few large
    // files cluster in the walk; a big-file-dominated batch still does.
    let large_dominates =
        large_chunk_bytes > 0 && large_chunk_bytes.saturating_mul(2) >= workload_bytes;
    if large_dominates && gpu_could_engage(caps, workload_bytes, pattern_count) {
        return ScanBackend::Gpu;
    }

    if caps.hyperscan_available {
        return ScanBackend::SimdCpu;
    }

    if caps.has_avx512 || caps.has_avx2 || caps.has_neon {
        return ScanBackend::SimdCpu;
    }

    ScanBackend::CpuFallback
}

/// Cheap, side-effect-free pre-check: could a scan of `workload_bytes` over
/// `pattern_count` patterns *ever* route to [`ScanBackend::Gpu`] on this
/// hardware? This is exactly the GPU branch condition inside
/// [`select_backend`], factored out so cold-path callers can gate the
/// expensive wgpu/CUDA device acquisition (the ~250 ms adapter-enumeration
/// cold-start in `engine::compile`) on whether the workload can clear the
/// tier's GPU floor at all.
///
/// On a many-tiny-file corpus the per-batch byte total never reaches the
/// high-tier 2 MiB floor (see [`super::thresholds`]), so this returns `false`
/// and the caller can skip paying for a device no chunk will ever touch.
/// It does **not** consult `KEYHOG_BACKEND` or `KEYHOG_NO_GPU`; callers that
/// need the env override should check [`forced_backend_from_env`] /
/// [`crate::gpu::env_no_gpu`] separately, matching `select_backend`'s order.
#[must_use]
pub fn gpu_could_engage(caps: &HardwareCaps, workload_bytes: u64, pattern_count: usize) -> bool {
    if !caps.gpu_available || caps.gpu_is_software {
        return false;
    }
    let tier = classify_gpu_tier(caps.gpu_name.as_deref());
    let solo = gpu_solo_bytes_for_tier(tier);
    let min = gpu_min_bytes_for_tier(tier);
    let pattern_floor = gpu_pattern_breakeven_for_tier(tier);
    workload_bytes >= solo || (workload_bytes >= min && pattern_count >= pattern_floor)
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

pub(super) fn backend_env_override() -> Option<ScanBackend> {
    let is_test = cfg!(test)
        || std::env::var("CARGO_MANIFEST_DIR").is_ok()
        || std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.contains("/deps/")))
            .unwrap_or(false);

    if is_test {
        parse_backend_env()
    } else {
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
        // those checks. `cfg!(test)` swaps in the uncached variant only
        // when this crate's own tests compile.
        static CACHED: std::sync::OnceLock<Option<ScanBackend>> = std::sync::OnceLock::new();
        *CACHED.get_or_init(parse_backend_env)
    }
}

pub(super) fn parse_backend_env() -> Option<ScanBackend> {
    if let Some(forced) = TEST_BACKEND_OVERRIDE.with(|cell| *cell.borrow()) {
        return forced;
    }
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
