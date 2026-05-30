//! GPU-accelerated batch inference for the MoE classifier via wgpu compute shaders.
//!
//! Processes N feature vectors in a single GPU dispatch, achieving ~10-100x
//! throughput over CPU for large batches. Falls back to CPU when no GPU is
//! available or for batches smaller than the crossover threshold.
//!
//! Architecture mirrors ml_scorer.rs exactly:
//! - Gate: Linear(41→6) + softmax
//! - 6 experts: Linear(41→32)+ReLU → Linear(32→16)+ReLU → Linear(16→1)
//! - Output: sigmoid(weighted sum of expert logits)

// Both submodules lean on the wgpu device/queue + bytemuck cast helpers.
// They only exist in `gpu`-on builds; the public API in this module
// short-circuits to "no GPU" via the `cfg` arms below when off.
#[cfg(feature = "gpu")]
#[path = "gpu_shader.rs"]
mod gpu_shader;

#[cfg(feature = "gpu")]
#[path = "gpu_moe_backend.rs"]
mod backend;

/// Score multiple (credential, context) pairs in a single batch.
///
/// Uses GPU compute shaders when available and the batch is large enough.
/// Falls back to CPU for small batches or when no GPU is present.
/// Score a batch of `(text, context)` candidates, using GPU when available.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::gpu::batch_ml_inference;
/// use keyhog_scanner::ScannerConfig;
/// let config = ScannerConfig::default();
/// let scores = batch_ml_inference(&[("demo_ABC12345", "API_KEY=")], &config);
/// assert_eq!(scores.len(), 1);
/// ```
///
/// Callers pass `(&str, &str)` so a hot-path scan with N matches no longer
/// allocates 2N owned strings just to enter ML scoring. The MlPendingMatch
/// `String` fields stay live for the duration of the call - the borrow is
/// safe.
pub fn batch_ml_inference(
    candidates: &[(&str, &str)],
    config: &crate::types::ScannerConfig,
) -> Vec<f64> {
    if candidates.is_empty() {
        return Vec::new();
    }

    #[cfg(feature = "ml")]
    {
        use rayon::prelude::*;
        // Auto-route: try GPU batch first, fall back to CPU MoE on failure or
        // when the batch is below the GPU crossover threshold.
        let features: Vec<[f32; crate::ml_scorer::NUM_FEATURES]> = candidates
            .par_iter()
            .map(|(text, ctx)| {
                crate::ml_scorer::compute_features_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            })
            .collect();

        #[cfg(feature = "gpu")]
        if let Some(scores) = backend::batch_score_features(&features) {
            return scores;
        }
        // Bind `features` so the no-`gpu` build doesn't lint it unused.
        let _ = &features;

        candidates
            .par_iter()
            .map(|(text, ctx)| {
                crate::ml_scorer::score_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            })
            .collect()
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = candidates;
        let _ = config;
        Vec::new()
    }
}

/// Check if GPU acceleration is available.
/// Return `true` when GPU scoring support is available in this build/runtime.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::gpu::gpu_available;
/// let _ = gpu_available();
/// ```
pub fn gpu_available() -> bool {
    #[cfg(feature = "gpu")]
    {
        backend::get_gpu().is_some()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

/// Result from an explicit GPU adapter and dispatch self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuSelfTest {
    /// Human-readable adapter name reported by wgpu.
    pub adapter_name: String,
    /// Approximate storage-buffer capability in MiB when available.
    pub vram_mb: Option<u64>,
    /// Number of scores produced by the compute dispatch.
    pub scores: usize,
}

/// Result from an explicit vyre GPU scanner self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VyreGpuSelfTest {
    /// Number of direct GPU matches produced by `GpuLiteralSet::scan`.
    pub direct_matches: usize,
    /// Number of matches produced by one coalesced scanner GPU dispatch.
    pub coalesced_matches: usize,
}

#[cfg(feature = "gpu")]
static GPU_SELF_TEST_CACHE: std::sync::OnceLock<std::result::Result<GpuSelfTest, String>> =
    std::sync::OnceLock::new();

/// Force a GPU compute dispatch and validate the returned scores.
///
/// This is stricter than [`gpu_available`]: it proves that a non-fallback wgpu
/// adapter initialized and that the MoE compute shader can run at least one
/// production-sized batch.
pub fn gpu_self_test() -> Result<GpuSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        return Err(
            "GPU support not compiled in (lean ci build). Rebuild with `--features gpu` \
             (or the default profile) to exercise the wgpu/CUDA path."
                .to_string(),
        );
    }
    #[cfg(feature = "gpu")]
    GPU_SELF_TEST_CACHE
        .get_or_init(|| {
            const SELF_TEST_BATCH: usize = 64;

            let gpu = backend::get_gpu().ok_or_else(|| {
                "GPU adapter unavailable; install or enable a non-software GPU adapter and driver"
                    .to_string()
            })?;

            let features = [[0.0_f32; crate::ml_scorer::NUM_FEATURES]; SELF_TEST_BATCH];
            let scores = backend::batch_score_features(&features)
                .ok_or_else(|| "GPU dispatch produced no result".to_string())?;

            if scores.len() != SELF_TEST_BATCH {
                return Err(format!(
                    "GPU dispatch returned {} scores for {SELF_TEST_BATCH} inputs",
                    scores.len()
                ));
            }

            if let Some((index, score)) = scores
                .iter()
                .enumerate()
                .find(|(_, score)| !score.is_finite() || !(0.0..=1.0).contains(*score))
            {
                return Err(format!(
                    "GPU dispatch returned invalid score {score} at index {index}"
                ));
            }

            Ok(GpuSelfTest {
                adapter_name: gpu.gpu_name().to_string(),
                vram_mb: gpu.vram_mb(),
                scores: scores.len(),
            })
        })
        .clone()
}

/// Force the vyre GPU scanner and coalesced scanner paths.
///
/// Proves the scanner-side GPU dependency is available independently from
/// Keyhog's MoE GPU scorer. Both `direct_matches` and `coalesced_matches` are
/// populated from real GPU scans - see audit release-2026-04-26 for the prior
/// rigged-test bug where `coalesced_matches` was hardcoded.
#[cfg(not(feature = "gpu"))]
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    Err(
        "vyre GPU self-test not available in the lean ci build (no wgpu driver compiled in). \
         Rebuild with `--features gpu`."
            .to_string(),
    )
}

#[cfg(feature = "gpu")]
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    use vyre_driver_wgpu::WgpuBackend;
    use vyre_libs::scan::GpuLiteralSet;

    let patterns: Vec<Vec<u8>> = vec![b"needle".to_vec()];
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();

    let backend = WgpuBackend::shared().map_err(|e| format!("failed to init wgpu backend: {e}"))?;
    let scanner = GpuLiteralSet::compile(&pattern_refs);

    let direct = scanner
        .scan(backend.as_ref(), b"needle", 100)
        .map_err(|error| format!("vyre direct GPU scan failed: {error}"))?;
    if direct.len() != 1 || direct[0].pattern_id != 0 || direct[0].start != 0 {
        return Err(format!(
            "vyre direct GPU scan returned unexpected matches: {direct:?}"
        ));
    }

    // Coalesced: 100 needles concatenated; expect 100 real matches.
    let items: Vec<Vec<u8>> = (0..100)
        .map(|index| format!("id-{index:03}-needle").into_bytes())
        .collect();
    let mut buffer = Vec::with_capacity(items.iter().map(Vec::len).sum());
    for item in &items {
        buffer.extend_from_slice(item);
    }

    let coalesced = scanner
        .scan(backend.as_ref(), &buffer, 10_000)
        .map_err(|error| format!("vyre coalesced GPU scan failed: {error}"))?;

    Ok(VyreGpuSelfTest {
        direct_matches: direct.len(),
        coalesced_matches: coalesced.len(),
    })
}

/// Status report from the AC-kernel GPU self-test. Returned by
/// [`vyre_ac_kernel_self_test`] so the diagnostic CLI can display
/// the active backend and match count rather than just PASS/FAIL.
pub struct VyreAcKernelSelfTest {
    /// Number of GPU phase-1 match triples emitted.
    pub matches: usize,
    /// `VyreBackend::id()` of the backend that ran the test, e.g.
    /// `"cuda"` or `"wgpu"`. Lets the caller surface "PASS via cuda"
    /// vs "PASS via wgpu" so an operator can tell which driver was
    /// actually exercised.
    pub backend_id: &'static str,
}

/// Build a minimal one-detector `CompiledScanner` and dispatch a
/// scan through the AC-kernel GPU phase-1 path. This is the GPU
/// scan path the production flow uses (the literal-set program is
/// rejected by vyre's canonical pre-emit lowering until the IR
/// gap is closed). A PASS here means the GPU scan path is healthy
/// end to end on this host: device acquired, AC program compiled
/// and lowered successfully, dispatch executed, hits returned to
/// the host.
///
/// # Errors
///
/// Returns `Err` when GPU acquisition didn't happen during
/// compile, when phase-1 returned the CPU-degrade variant, or when
/// the dispatch returned zero hits for the planted literal.
#[cfg(not(feature = "gpu"))]
pub fn vyre_ac_kernel_self_test() -> Result<VyreAcKernelSelfTest, String> {
    Err(
        "vyre AC-kernel self-test not available in the lean ci build. \
         Rebuild with `--features gpu` to exercise the GPU AC phase-1 path."
            .to_string(),
    )
}

#[cfg(feature = "gpu")]
pub fn vyre_ac_kernel_self_test() -> Result<VyreAcKernelSelfTest, String> {
    use crate::engine::{CompiledScanner, GpuPhase1Output};
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};

    let detector = DetectorSpec {
        id: "kh-gpu-self-test".into(),
        name: "GPU self-test".into(),
        service: "test".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "needle".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["needle".into()],
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector])
        .map_err(|e| format!("CompiledScanner::compile failed during self-test: {e}"))?;

    let backend_id = scanner
        .gpu_backend_label()
        .ok_or_else(|| "no GPU backend acquired during self-test compile".to_string())?;

    let chunk = Chunk {
        data: "the quick brown needle jumps over the lazy fox".into(),
        metadata: ChunkMetadata::default(),
    };

    match scanner.scan_coalesced_gpu_ac_phase1(&[chunk]) {
        GpuPhase1Output::Hits(hits) => {
            let total: usize = hits.iter().map(Vec::len).sum();
            if total == 0 {
                return Err(
                    "AC kernel ran on GPU but reported zero hits for the planted 'needle' \
literal. Indicates either a phase-1 lowering regression or a workgroup-size mismatch."
                        .to_string(),
                );
            }
            Ok(VyreAcKernelSelfTest {
                matches: total,
                backend_id,
            })
        }
        GpuPhase1Output::Done(_) => Err(
            "AC phase 1 returned Done (CPU fallback) instead of Hits. The GPU AC \
program, the GPU matcher, or the GPU backend wasn't available at scan time even \
though compile said one was acquired."
                .to_string(),
        ),
    }
}

/// Probe GPU availability and adapter metadata without panicking.
///
/// Honours `KEYHOG_NO_GPU=1` (and the usual on/off/true/false/0
/// negatives) by reporting "no GPU available" without ever calling
/// `backend::get_gpu()`. The MoE compute-shader init happens lazily
/// inside `get_gpu()`, so this short-circuit is the difference
/// between "Metal adapter request blocks for minutes on certain Mac
/// configurations" (the v0.5.27 reproduction on Apple M4 Pro that
/// the env var was added to escape) and "scanner starts in ~10ms
/// like every other CPU-only tool".
#[must_use]
pub fn gpu_probe() -> (bool, Option<String>, Option<u64>) {
    if env_no_gpu() {
        return (false, None, None);
    }
    #[cfg(feature = "gpu")]
    if let Some(gpu) = backend::get_gpu() {
        return (true, Some(gpu.gpu_name().to_string()), gpu.vram_mb());
    }
    (false, None, None)
}

pub fn env_no_gpu() -> bool {
    if let Ok(v) = std::env::var("KEYHOG_NO_GPU") {
        // Explicit user choice wins both directions. "0"/"false"/"off"
        // is the override that says "yes I want the GPU even though
        // CI is detected" (self-hosted GPU runners exist).
        return !matches!(v.as_str(), "" | "0" | "false" | "FALSE" | "off" | "OFF");
    }
    // No explicit setting. Auto-skip GPU init on CI runners: they
    // have no discrete GPU, the wgpu adapter probe enumerates the
    // llvmpipe/swiftshader software fallback, gpu.rs:83 rightly
    // rejects it as a software adapter, and the operator gets a
    // confusing "GPU MoE init failed" warning that costs ~250ms of
    // cold-start time for nothing. Detecting CI here turns that
    // failure into a silent no-op (the user is on CPU + SIMD which
    // is the right path on a CI runner anyway). Set
    // KEYHOG_NO_GPU=0 to opt back in on self-hosted GPU runners.
    is_ci_environment()
}

/// True when we are running inside a CI system. Used by the GPU
/// init paths to auto-skip the wgpu adapter probe (which always
/// fails on hosted CI runners and costs ~250ms of pointless cold-
/// start time + emits a confusing warning).
///
/// Checks `CI=true` (the de-facto standard, set by GitHub Actions,
/// GitLab CI, CircleCI, Travis, Buildkite, Drone, AppVeyor,
/// Codeship, Wercker, and most others) plus a handful of platform-
/// specific markers that some runners set without also setting the
/// generic `CI` (Jenkins, TeamCity, Azure Pipelines, Bitbucket
/// Pipelines).
pub fn is_ci_environment() -> bool {
    // The generic CI marker. Some runners set CI=true, some set
    // CI=1, GitHub Actions sets both. Treat any non-empty non-false
    // value as truthy.
    if let Ok(v) = std::env::var("CI") {
        if !matches!(v.as_str(), "" | "0" | "false" | "FALSE" | "off" | "OFF") {
            return true;
        }
    }
    // Platform-specific markers. Some legacy CI systems set their
    // own variable but not the generic CI=. Hit the common ones.
    const CI_MARKERS: &[&str] = &[
        "GITHUB_ACTIONS",         // GitHub Actions
        "GITLAB_CI",              // GitLab CI
        "JENKINS_URL",            // Jenkins
        "TF_BUILD",               // Azure Pipelines
        "TEAMCITY_VERSION",       // TeamCity
        "BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
        "BUILDKITE",              // Buildkite
        "CIRCLECI",               // CircleCI
        "DRONE",                  // Drone CI
        "TRAVIS",                 // Travis CI
        "APPVEYOR",               // AppVeyor
        "CODEBUILD_BUILD_ID",     // AWS CodeBuild
        "WERCKER",                // Wercker
        "SEMAPHORE",              // Semaphore CI
    ];
    CI_MARKERS.iter().any(|k| std::env::var(k).is_ok())
}
