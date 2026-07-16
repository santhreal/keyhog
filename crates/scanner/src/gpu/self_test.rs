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

/// Result from an explicit VYRE GPU scanner self-test.
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
                let gpu = super::backend::get_gpu().ok_or_else(|| {
                    "GPU adapter unavailable; install or enable a non-software GPU adapter and driver"
                        .to_string()
                })?;

                // PARITY, not "in range". The prior check scored ALL-ZERO feature
                // vectors and only asserted each result was finite and within
                // [0,1], which a GPU that returns 0.0 for EVERY input trivially
                // passes. That masked a real shipped fault: the MoE shader scored
                // genuine secrets ~0.0 (CPU scored them ~1.0), so on a GPU host the
                // ML gate silently dropped findings and `--self-test` still reported
                // HEALTHY. Assert the actual contract instead: the GPU MoE must
                // reproduce the CPU MoE (`ml_scorer::score_features`, the reference
                // every confidence floor is tuned/benched against) within tolerance
                // on a probe that includes real secrets. This is the SAME verdict
                // the scan path enforces (`batch_score_features` fails closed to CPU
                // on the same divergence), so doctor and the scanner never disagree.
                let max_abs = super::backend::gpu_moe_parity_max_divergence(
                    std::time::Duration::from_millis(
                        crate::scanner_config::ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT,
                    ),
                )?;
                if max_abs > super::backend::GPU_MOE_PARITY_TOLERANCE {
                    return Err(format!(
                        "GPU MoE compute shader diverges from the CPU MoE reference by {max_abs:.4} \
                         (tolerance {:.4}); the GPU would score findings differently from the \
                         CPU/SIMD path. Indicates a shader miscompile, weights-packing mismatch, \
                         or driver bug. Scans record the GPU MoE degrade and use the CPU MoE \
                         (correct + deterministic), \
                         so detection is unaffected, but GPU ML acceleration is OFF on this host.",
                        super::backend::GPU_MOE_PARITY_TOLERANCE
                    ));
                }

                Ok(GpuSelfTest {
                    adapter_name: gpu.gpu_name().to_string(),
                    vram_mb: gpu.vram_mb(),
                    scores: crate::ml_scorer::GPU_BATCH_THRESHOLD,
                })
            })
            .clone()
    }
}

/// Force the VYRE GPU scanner and coalesced scanner paths.
///
/// Proves the scanner-side GPU dependency is available independently from
/// KeyHog's MoE GPU scorer. Both counts are populated from real GPU scans.
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(
            "VYRE GPU self-test not available in the lean CI build (no WGPU driver compiled in). \
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

/// One acquired peer proven by the production GPU region-presence self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresencePeerSelfTest {
    /// Exact scanner route exercised by the test.
    pub backend: crate::hw_probe::ScanBackend,
    /// `VyreBackend::id()` of the driver that ran the test.
    pub backend_id: &'static str,
    /// Number of findings emitted through the production GPU trigger path.
    pub matches: usize,
}

/// Status report from the production GPU region-presence self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresenceSelfTest {
    /// Every acquired CUDA or WGPU peer. All entries passed exact CPU parity.
    pub peers: Vec<GpuRegionPresencePeerSelfTest>,
}

/// Honest aggregate failure from the peer self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresenceSelfTestFailure {
    /// Exact peers acquired before parity execution began.
    pub acquired_backends: Vec<crate::hw_probe::ScanBackend>,
    /// Peer-specific acquisition, dispatch, or parity diagnostics.
    pub message: String,
}

impl std::fmt::Display for GpuRegionPresenceSelfTestFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GpuRegionPresenceSelfTestFailure {}

/// Build a minimal one-detector `CompiledScanner` and dispatch a scan through
/// the production GPU backend. A PASS proves device acquisition, compilation,
/// lowering, dispatch, and host readback on this host.
pub fn gpu_region_presence_self_test(
) -> Result<GpuRegionPresenceSelfTest, GpuRegionPresenceSelfTestFailure> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends: Vec::new(),
            message: "GPU region-presence self-test not available in the lean ci build. Rebuild with `--features gpu` to exercise the production GPU trigger path.".to_string(),
        })
    }
    #[cfg(feature = "gpu")]
    {
        gpu_region_presence_self_test_impl()
    }
}

#[cfg(feature = "gpu")]
fn gpu_region_presence_self_test_impl(
) -> Result<GpuRegionPresenceSelfTest, GpuRegionPresenceSelfTestFailure> {
    use crate::engine::CompiledScanner;
    use crate::hw_probe::ScanBackend;
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};

    // The probe MUST be a credential keyhog actually REPORTS, not one it
    // suppresses. A plain dictionary word (e.g. "needle") triggers phase-1 and
    // extracts, but is then correctly dropped by low-entropy/placeholder
    // suppression on EVERY backend - so asserting "GPU found > 0" on such a word
    // is a false failure that has nothing to do with the GPU kernel. This probe
    // mirrors the proven `scan_engine_self_test` shape: a distinctive literal
    // PREFIX ("KHGPUSELFTEST_") that the GPU literal-set anchors on to drive
    // region-presence -> trigger, followed by a mixed-case high-entropy suffix
    // that survives suppression so the match is emitted end to end.
    const PLANTED: &str = "KHGPUSELFTEST_A1b2C3d4E5f6";
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "kh-gpu-self-test".into(),
        name: "GPU self-test".into(),
        service: "test".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "KHGPUSELFTEST_[A-Za-z0-9]{12}".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        keywords: vec!["KHGPUSELFTEST".into()],
        min_confidence: None,
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector]).map_err(|error| {
        GpuRegionPresenceSelfTestFailure {
            acquired_backends: Vec::new(),
            message: format!("CompiledScanner::compile failed during self-test: {error}"),
        }
    })?;

    let candidates = scanner.gpu_backend_candidates();
    let acquired_backends: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.is_eligible())
        .map(|candidate| candidate.backend)
        .collect();
    if acquired_backends.is_empty() {
        let diagnostics = candidates
            .iter()
            .map(|candidate| {
                let diagnostic = match candidate.acquisition_error.as_deref() {
                    Some(reason) => reason,
                    None => "driver was not acquired and returned no diagnostic",
                };
                format!("{}: {diagnostic}", candidate.backend.label())
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: format!("no GPU region-presence peer was acquired ({diagnostics})"),
        });
    }

    let make_chunk = || Chunk {
        data: format!("gpu_secret = {PLANTED}").into(),
        metadata: ChunkMetadata::default(),
    };

    // CPU baseline on the SAME detector+chunk. This is the oracle: it proves the
    // planted secret is detectable AT ALL on this build, so a low GPU count means
    // a real GPU phase-1 divergence rather than an invalid/suppressed probe.
    let cpu_results = scanner.scan_chunks_with_backend(&[make_chunk()], ScanBackend::CpuFallback);
    let cpu_total: usize = cpu_results.iter().map(Vec::len).sum();
    if cpu_total == 0 {
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: "GPU self-test probe matched on no backend (CPU baseline is zero); fix the self-test probe so it survives suppression.".to_string(),
        });
    }

    let mut peers = Vec::with_capacity(acquired_backends.len());
    let mut failures = Vec::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| candidate.is_eligible())
    {
        let route = candidate.backend;
        let Some(backend_id) = candidate.driver_id else {
            failures.push(format!(
                "{}: acquired driver returned no identity",
                route.label()
            ));
            continue;
        };
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = match scanner.try_scan_coalesced_gpu_region_presence(&[make_chunk()], route) {
            Ok(results) => results,
            Err(error) => {
                failures.push(format!(
                    "{} ({backend_id}): dispatch failed: {error}",
                    route.label()
                ));
                continue;
            }
        };
        if scanner.runtime_status().gpu_degrade_count > degrade_before {
            let diagnostic = match scanner.last_gpu_degrade_reason() {
                Some(reason) => reason,
                None => "runtime degrade recorded without a diagnostic".to_owned(),
            };
            failures.push(format!("{} ({backend_id}): {diagnostic}", route.label()));
            continue;
        }
        let total: usize = results.iter().map(Vec::len).sum();
        if total != cpu_total {
            failures.push(format!(
                "{} ({backend_id}): found {total} match(es), CPU found {cpu_total}",
                route.label()
            ));
            continue;
        }
        peers.push(GpuRegionPresencePeerSelfTest {
            backend: route,
            backend_id,
            matches: total,
        });
    }
    if !failures.is_empty() {
        let passed = peers
            .iter()
            .map(|peer| format!("{} ({})", peer.backend.label(), peer.backend_id))
            .collect::<Vec<_>>()
            .join(", ");
        let passed = if passed.is_empty() {
            "none".to_string()
        } else {
            passed
        };
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: format!(
                "GPU region-presence peer parity failed: {}; passed peers: {passed}",
                failures.join("; ")
            ),
        });
    }
    Ok(GpuRegionPresenceSelfTest { peers })
}
