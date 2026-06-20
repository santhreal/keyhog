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
/// This is stricter than [`crate::gpu::gpu_available`]: it proves that a
/// non-software wgpu adapter initialized and that the MoE compute shader can run
/// at least one production-sized batch.
pub fn gpu_self_test() -> Result<GpuSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(
            "GPU support not compiled in (lean ci build). Rebuild with `--features gpu` \
             (or the default profile) to exercise the wgpu/CUDA path."
                .to_string(),
        )
    }
    #[cfg(feature = "gpu")]
    {
        GPU_SELF_TEST_CACHE
            .get_or_init(|| {
                const SELF_TEST_BATCH: usize = 64;

                let gpu = super::backend::get_gpu().ok_or_else(|| {
                    "GPU adapter unavailable; install or enable a non-software GPU adapter and driver"
                        .to_string()
                })?;

                let features = [[0.0_f32; crate::ml_scorer::NUM_FEATURES]; SELF_TEST_BATCH];
                let scores = super::backend::batch_score_features(
                    &features,
                    std::time::Duration::from_millis(
                        crate::scanner_config::ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT,
                    ),
                )
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
}

/// Force the vyre GPU scanner and coalesced scanner paths.
///
/// Proves the scanner-side GPU dependency is available independently from
/// Keyhog's MoE GPU scorer. Both counts are populated from real GPU scans.
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(
            "vyre GPU self-test not available in the lean ci build (no wgpu driver compiled in). \
             Rebuild with `--features gpu`."
                .to_string(),
        )
    }
    #[cfg(feature = "gpu")]
    {
        vyre_gpu_self_test_impl()
    }
}

#[cfg(feature = "gpu")]
fn vyre_gpu_self_test_impl() -> Result<VyreGpuSelfTest, String> {
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
/// [`vyre_ac_kernel_self_test`] so the diagnostic CLI can display the active
/// backend and match count rather than just PASS/FAIL.
pub struct VyreAcKernelSelfTest {
    /// Number of GPU phase-1 match triples emitted.
    pub matches: usize,
    /// `VyreBackend::id()` of the backend that ran the test.
    pub backend_id: &'static str,
}

/// Build a minimal one-detector `CompiledScanner` and dispatch a scan through
/// the production GPU backend. A PASS proves device acquisition, compilation,
/// lowering, dispatch, and host readback on this host.
pub fn vyre_ac_kernel_self_test() -> Result<VyreAcKernelSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(
            "vyre AC-kernel self-test not available in the lean ci build. \
             Rebuild with `--features gpu` to exercise the GPU AC phase-1 path."
                .to_string(),
        )
    }
    #[cfg(feature = "gpu")]
    {
        vyre_ac_kernel_self_test_impl()
    }
}

#[cfg(feature = "gpu")]
fn vyre_ac_kernel_self_test_impl() -> Result<VyreAcKernelSelfTest, String> {
    use crate::engine::CompiledScanner;
    use crate::hw_probe::ScanBackend;
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};

    let detector = DetectorSpec {
        tests: Vec::new(),
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
        min_confidence: None,
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

    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);
    if let Some(detail) = scanner.last_gpu_degrade_reason() {
        return Err(format!(
            "GPU region-presence scan degraded to SIMD/CPU at runtime despite an acquired GPU stack: {detail}"
        ));
    }
    let total: usize = results.iter().map(Vec::len).sum();
    if total == 0 {
        return Err(
            "GPU region-presence scan ran on GPU but reported zero matches for the planted 'needle' literal. \
Indicates a literal-set lowering regression or a dispatch/workgroup-size mismatch."
                .to_string(),
        );
    }
    Ok(VyreAcKernelSelfTest {
        matches: total,
        backend_id,
    })
}
