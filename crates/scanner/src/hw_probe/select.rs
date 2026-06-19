//! Workload-aware backend routing. File and batch entry points delegate to one
//! private workload selector so explicit test overrides, GPU suppression, GPU
//! thresholds, and CPU-tier fallback cannot drift.

use super::tier::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier,
};
use super::{HardwareCaps, ScanBackend};

thread_local! {
    pub(crate) static TEST_BACKEND_OVERRIDE: std::cell::RefCell<Option<Option<ScanBackend>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_backend_override(val: Option<ScanBackend>) {
    TEST_BACKEND_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = Some(val);
    });
}

#[cfg(test)]
pub(crate) fn clear_test_backend_override() {
    TEST_BACKEND_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// The CPU-only backend tier for this hardware: `SimdCpu` when Hyperscan is
/// compiled in OR the CPU has an accelerated SIMD ISA (AVX-512 / AVX2 / NEON),
/// else the pure-scalar `CpuFallback`. This is the SINGLE source of truth for
/// the "no GPU in play" decision — every router that needs a non-GPU backend
/// (`select_backend`, `select_backend_for_file`, `select_backend_for_batch`,
/// and the CLI's measured
/// autoroute default) routes through here so the four-way ladder can never
/// drift between sites.
#[must_use]
pub(crate) fn cpu_tier_backend(caps: &HardwareCaps) -> ScanBackend {
    if caps.hyperscan_available || caps.has_avx512 || caps.has_avx2 || caps.has_neon {
        ScanBackend::SimdCpu
    } else {
        ScanBackend::CpuFallback
    }
}

#[derive(Debug, Clone, Copy)]
struct BackendWorkload {
    bytes: u64,
    pattern_count: usize,
    large_chunk_bytes: Option<u64>,
}

impl BackendWorkload {
    fn file(bytes: u64, pattern_count: usize) -> Self {
        Self {
            bytes,
            pattern_count,
            large_chunk_bytes: None,
        }
    }

    #[cfg(test)]
    fn batch(bytes: u64, pattern_count: usize, large_chunk_bytes: u64) -> Self {
        Self {
            bytes,
            pattern_count,
            large_chunk_bytes: Some(large_chunk_bytes),
        }
    }

    fn gpu_dominates_dispatch_cost(self) -> bool {
        match self.large_chunk_bytes {
            None => true,
            Some(large_chunk_bytes) => {
                large_chunk_bytes > 0 && large_chunk_bytes.saturating_mul(2) >= self.bytes
            }
        }
    }
}

fn select_backend_for_workload(caps: &HardwareCaps, workload: BackendWorkload) -> ScanBackend {
    if let Some(forced) = test_backend_override() {
        return forced;
    }

    // Skip GPU consideration when the resolved scanner runtime policy disables
    // GPU init, so the routing decision matches what the GPU init paths will
    // actually do.
    if crate::gpu::env_no_gpu() {
        return cpu_tier_backend(caps);
    }

    if workload.gpu_dominates_dispatch_cost()
        && gpu_could_engage(caps, workload.bytes, workload.pattern_count)
    {
        return ScanBackend::Gpu;
    }

    cpu_tier_backend(caps)
}

/// Auto-route a scan to the best backend for this hardware + workload.
///
/// Routing rules (highest-priority match wins):
///
/// 0. **Test override** - scanner tests may force a backend through the
///    race-free testing facade. Shipped CLI scans pass explicit `--backend`
///    choices directly to `scan_with_backend` instead of mutating process env.
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
    select_backend_for_workload(caps, BackendWorkload::file(workload_bytes, pattern_count))
}

#[must_use]
pub(crate) fn select_backend_for_file(
    caps: &HardwareCaps,
    file_bytes: u64,
    pattern_count: usize,
) -> ScanBackend {
    select_backend_for_workload(caps, BackendWorkload::file(file_bytes, pattern_count))
}

/// Batch-aware backend routing — a pure, hardware-only library router.
///
/// NOTE on the live CLI path: the shipped scan dispatcher does NOT call this;
/// it uses the measured, parity-checked `MeasuredBackendRouter`
/// (`crates/cli/src/orchestrator/dispatch/backend.rs`), which benchmarks the
/// candidate backends on a real sample and gates the GPU behind explicit
/// `--autoroute-gpu` calibration eligibility (the megakernel is slower than
/// SIMD on keyhog's workload at every measured size). This function is the deterministic,
/// side-effect-free dominance heuristic used by the `keyhog backend` report and
/// by callers that want a backend decision without running the scanner — it
/// shares [`cpu_tier_backend`] and [`gpu_could_engage`] with the live router so
/// the CPU-tier verdict never diverges.
///
/// Identical to [`select_backend`] for the CPU tiers, but adds a structural
/// guard before the GPU branch: `large_chunk_bytes`
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
/// mostly big-file data still gets the device. An explicit CLI backend override
/// still wins (forced/diagnostic GPU path unchanged), and benchmarks should pin
/// `--backend simd`, so this only changes the *default* routing for many-small-
/// file trees - the common real-world scan.
#[must_use]
#[cfg(test)]
pub(crate) fn select_backend_for_batch(
    caps: &HardwareCaps,
    workload_bytes: u64,
    pattern_count: usize,
    large_chunk_bytes: u64,
) -> ScanBackend {
    select_backend_for_workload(
        caps,
        BackendWorkload::batch(workload_bytes, pattern_count, large_chunk_bytes),
    )
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
/// It does **not** consult explicit backend overrides or `--no-gpu`;
/// callers that need an override should pass it through their own resolved
/// config before falling back to this hardware-only predicate.
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

/// Test-only forced backend override.
#[cfg(test)]
pub(crate) fn forced_backend_override_for_test() -> Option<ScanBackend> {
    test_backend_override()
}

pub(super) fn test_backend_override() -> Option<ScanBackend> {
    match TEST_BACKEND_OVERRIDE.with(|cell| *cell.borrow()) {
        Some(backend) => backend,
        None => None,
    }
}

/// Pure backend string → [`ScanBackend`] mapping, with no env or
/// thread-local override read. Tests that only verify the string→backend
/// mapping MUST call this directly rather than mutating global process state.
/// Keeping the mapping pure removes parallel-test hazards while staying the
/// single source of truth for CLI/config backend parsing.
pub fn parse_backend_str(raw: &str) -> Option<ScanBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gpu" | "gpu-zero-copy" | "literal-set" => Some(ScanBackend::Gpu),
        // Both spellings are advertised `--backend` values (clap
        // `PossibleValuesParser` in `args/scan.rs` accepts `mega-scan` AND
        // `megascan`); the no-hyphen form was previously dropped to `None` here,
        // so `--backend megascan` silently fell through to auto-routing instead
        // of forcing the megakernel. Recognized here so the canonical parser
        // matches the advertised CLI surface (coherence).
        "mega-scan" | "megascan" | "gpu-mega-scan" | "regex-nfa" | "rule-pipeline" => {
            Some(ScanBackend::MegaScan)
        }
        "simd" | "simd-regex" | "hyperscan" => Some(ScanBackend::SimdCpu),
        "cpu" | "cpu-fallback" | "scalar" => Some(ScanBackend::CpuFallback),
        _ => None,
    }
}
